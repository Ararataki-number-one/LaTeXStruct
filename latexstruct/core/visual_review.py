# -*- coding: utf-8 -*-
"""All-page visual audit and inventory-bound targeted repair suggestions."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .ai import ALLOWED_WRAP_ENVS, LLMError
from .formal_inventory import FormalInventory
from .ocrstruct import PAGE_RE
from .visual_quality import (
    CANDIDATE_SCOPE_AUTO,
    CANDIDATE_SCOPE_REFLOW,
    build_page_alignment,
    frozen_page_alignment_from_report,
)


_STRUCTURAL_PROBLEMS = frozenset({"missing-env", "wrong-env", "overwrapped"})
_MANUAL_PROBLEMS = frozenset({"layout", "formula", "content-loss"})
_ALL_PROBLEMS = _STRUCTURAL_PROBLEMS | _MANUAL_PROBLEMS
_PAGE_RESPONSE_KEYS = frozenset({
    "source_page", "candidate_page", "verdict", "issues", "reason",
    "checked_finding_codes",
})
_ISSUE_KEYS = frozenset({
    "inventory_id", "problem", "env", "confidence", "evidence",
})


VISUAL_AUDIT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "source_page", "candidate_page", "verdict", "issues", "reason",
        "checked_finding_codes",
    ],
    "properties": {
        "source_page": {"type": "integer"},
        "candidate_page": {"type": "integer"},
        "verdict": {"type": "string", "enum": ["ok", "repair", "manual"]},
        "reason": {"type": "string"},
        "checked_finding_codes": {
            "type": "array",
            "items": {"type": "string"},
        },
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "inventory_id", "problem", "env", "confidence", "evidence",
                ],
                "properties": {
                    "inventory_id": {"type": "string"},
                    "problem": {
                        "type": "string",
                        "enum": [
                            "missing-env", "wrong-env", "overwrapped", "layout",
                            "formula", "content-loss",
                        ],
                    },
                    "env": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "evidence": {"type": "string"},
                },
            },
        },
    },
}

_SYSTEM = """你是 LaTeXStruct 编译后逐页视觉复核器。图片左侧是不可变源 PDF 页，右侧是
当前 LaTeX 实际编译页。检查内容是否遗漏、公式或编号是否明显异常、formal 条目是否漏套/
错套/多套环境，以及页面是否空白、截断或严重溢出。普通字体、边距、换行和模板风格变化
不是错误。

只能引用请求中列出的 inventory_id，并且结构建议必须逐字匹配该条目的
allowed_visual_repairs；不得生成 LaTeX、body span 或改写正文。若问题不能绑定到一个真实
inventory_id（例如纯布局、公式内容或整页缺失），problem 使用 layout/formula/
content-loss，inventory_id 与 env 都留空，verdict=manual。没有实际问题时 verdict=ok 且
issues=[]。只有存在可由宿主既有可逆 Decision 定点修复的 missing-env/wrong-env/
overwrapped 时 verdict=repair。每页必须单独回显宿主给出的源页和编译页。严格输出 JSON。"""


def _deterministic_findings_by_mapping(
    report: dict | None,
    mappings,
) -> Dict[Tuple[int, int], List[dict]]:
    """Route every deterministic REVIEW warning to one frozen page pair."""

    result: Dict[Tuple[int, int], List[dict]] = {}

    def add(pair: Tuple[int, int], finding) -> None:
        if not isinstance(finding, dict):
            return
        code = str(finding.get("code") or "")[:80]
        if not code or finding.get("needs_model_review") is not True:
            return
        result.setdefault(pair, []).append({
            "code": code,
            "message": str(finding.get("message") or "")[:240],
            "evidence": dict(finding.get("evidence") or {}),
        })

    frozen_pairs = [
        (int(item.source_page), int(item.candidate_page))
        for item in mappings if item.candidate_page is not None
    ]
    if not isinstance(report, dict) or not frozen_pairs:
        return result
    # Global warnings are attached to the first selected page so they cannot be
    # silently lost while still being acknowledged exactly once.
    first_pair = frozen_pairs[0]
    for finding in report.get("findings") or []:
        add(first_pair, finding)
    selected = set(frozen_pairs)
    for page_record in report.get("pages") or []:
        if not isinstance(page_record, dict):
            continue
        try:
            pair = (
                int(page_record.get("source_page")),
                int(page_record.get("candidate_page")),
            )
        except (TypeError, ValueError):
            continue
        if pair not in selected:
            continue
        for finding in page_record.get("findings") or []:
            add(pair, finding)
    for pair, findings in result.items():
        unique = {item["code"]: item for item in findings}
        result[pair] = [unique[code] for code in sorted(unique)]
    return result


@dataclass(frozen=True)
class VisualRepairSuggestion:
    source_page: int
    candidate_page: int
    inventory_id: str
    problem: str
    env: str
    confidence: float
    evidence: str

    def to_dict(self) -> dict:
        return {
            "source_page": self.source_page,
            "candidate_page": self.candidate_page,
            "inventory_id": self.inventory_id,
            "problem": self.problem,
            "env": self.env,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class VisualAuditResult:
    checked: bool
    ok: bool
    page_count: int
    pages: List[dict] = field(default_factory=list)
    suggestions: List[VisualRepairSuggestion] = field(default_factory=list)
    invalid: List[dict] = field(default_factory=list)
    unresolved: List[dict] = field(default_factory=list)
    usage: Dict = field(default_factory=dict)
    alignment_sha256: str = ""
    schema: str = "latexstruct-visual-ai-audit-v1"

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "checked": self.checked,
            "ok": self.ok,
            "page_count": self.page_count,
            "pages": list(self.pages),
            "suggestions": [item.to_dict() for item in self.suggestions],
            "invalid": list(self.invalid),
            "unresolved": list(self.unresolved),
            "usage": dict(self.usage),
            "alignment_sha256": self.alignment_sha256,
        }


def _load_renderer():
    try:
        import pymupdf  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    return pymupdf


def _page_by_line(text: str) -> List[int | None]:
    result: List[int | None] = [None]
    current = None
    for line in text.split("\n"):
        match = PAGE_RE.match(line)
        if match:
            current = int(match.group(1))
        result.append(current)
    return result


def _canonical_allowed_env(value: str) -> str:
    env = str(value or "").strip().removesuffix("*")
    return env if env in ALLOWED_WRAP_ENVS else ""


def _allowed_visual_repairs(inventory: FormalInventory) -> Dict[str, set[Tuple[str, str]]]:
    """Derive target-kind authority from the immutable source inventory.

    These pairs only authorize a suggestion.  The host still has to bind it to
    an existing reversible Decision; this module never accepts a model span.
    """
    result: Dict[str, set[Tuple[str, str]]] = {}
    for anchor in inventory.anchors:
        expected = _canonical_allowed_env(anchor.suggested_env)
        allowed = {("overwrapped", "")}
        if expected:
            allowed.update({
                ("missing-env", expected),
                ("wrong-env", expected),
            })
        result[anchor.id] = allowed
    findings_by_environment: Dict[str, List] = {}
    for finding in inventory.findings:
        if finding.environment_id:
            findings_by_environment.setdefault(
                finding.environment_id, []
            ).append(finding)
    for environment in inventory.environments:
        allowed: set[Tuple[str, str]] = set()
        for finding in findings_by_environment.get(environment.id, []):
            if finding.kind == "wrong-env":
                expected = _canonical_allowed_env(finding.suggested_env)
                if expected and expected != _canonical_allowed_env(
                    environment.original_env
                ):
                    allowed.add(("wrong-env", expected))
            elif finding.kind == "duplicate":
                current = _canonical_allowed_env(environment.original_env)
                if current:
                    allowed.add(("overwrapped", current))
        result[environment.id] = allowed
    return result


def _inventory_by_page(text: str, inventory: FormalInventory) -> Dict[int, List[dict]]:
    pages = _page_by_line(text)
    result: Dict[int, List[dict]] = {}
    allowed_repairs = _allowed_visual_repairs(inventory)
    for kind, items in (
        ("anchor", inventory.anchors),
        ("environment", inventory.environments),
    ):
        for item in items:
            page = pages[item.start_line] if item.start_line < len(pages) else None
            if not page:
                continue
            record = item.as_dict()
            # Images must not cause the model to copy raw source text back.  IDs,
            # line ranges and visible heading metadata are enough for targeting.
            record.pop("raw_text", None)
            record["kind"] = kind
            record["allowed_visual_repairs"] = [
                {"problem": problem, "env": env}
                for problem, env in sorted(allowed_repairs.get(item.id, set()))
            ]
            result.setdefault(int(page), []).append(record)
    return result


def _composite_page_png(
    module,
    source,
    candidate,
    source_page: int,
    candidate_page: int,
    source_label: str = "SOURCE PDF",
):
    src = source.load_page(source_page - 1)
    cur = candidate.load_page(candidate_page - 1)
    panel_width = 720.0
    header = 28.0
    src_scale = panel_width / max(1.0, float(src.rect.width))
    cur_scale = panel_width / max(1.0, float(cur.rect.width))
    src_height = float(src.rect.height) * src_scale
    cur_height = float(cur.rect.height) * cur_scale
    height = header + max(src_height, cur_height)
    output = module.open()
    try:
        page = output.new_page(width=panel_width * 2, height=height)
        page.insert_text((8, 18), f"{source_label} PAGE {source_page}", fontsize=10)
        page.insert_text(
            (panel_width + 8, 18),
            f"COMPILED PDF PAGE {candidate_page}",
            fontsize=10,
        )
        page.show_pdf_page(
            module.Rect(0, header, panel_width, header + src_height),
            source,
            source_page - 1,
        )
        page.show_pdf_page(
            module.Rect(
                panel_width,
                header,
                panel_width * 2,
                header + cur_height,
            ),
            candidate,
            candidate_page - 1,
        )
        pixmap = page.get_pixmap(
            matrix=module.Matrix(1.25, 1.25),
            alpha=False,
        )
        return pixmap.tobytes("png")
    finally:
        output.close()


def _confidence(value) -> Tuple[float, bool]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0, False
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return 0.0, False
    return number, True


def _iter_indexed_batches(items, batch_size):
    """Yield every item while bounding the temporary mapping window."""

    size = max(1, int(batch_size))
    for start in range(0, len(items), size):
        yield from enumerate(items[start:start + size], start + 1)


def audit_compiled_pages(
    client,
    *,
    source_pdf_bytes: bytes,
    candidate_pdf_bytes: bytes,
    page_range,
    source_text: str,
    inventory: FormalInventory,
    deterministic_report: dict | None = None,
    source_label: str = "SOURCE PDF",
    candidate_scope: str = CANDIDATE_SCOPE_AUTO,
    max_pages: int = 80,
    progress_callback=None,
    control_callback=None,
) -> VisualAuditResult:
    """Inspect each aligned page pair and return only inventory-bound repairs.

    ``max_pages`` is retained for API compatibility and now bounds each
    processing batch, not the total audit.  Every aligned page remains part of
    the explicit quality closure.
    """

    from ..pricing import add_usage

    source_label = str(source_label or "").strip().upper()
    if source_label not in {"SOURCE PDF", "SOURCE IMAGE"}:
        raise ValueError("source_label must be SOURCE PDF or SOURCE IMAGE")

    module = _load_renderer()
    if module is None:
        return VisualAuditResult(
            checked=False,
            ok=False,
            page_count=0,
            unresolved=[{"page": 0, "reason": "视觉渲染器不可用"}],
        )
    source = candidate = None
    usage: Dict = {}
    pages: List[dict] = []
    suggestions: List[VisualRepairSuggestion] = []
    invalid: List[dict] = []
    unresolved: List[dict] = []
    inventory_pages = _inventory_by_page(source_text, inventory)
    allowed_repairs = _allowed_visual_repairs(inventory)
    all_items = {
        item.id: ("anchor", item) for item in inventory.anchors
    }
    all_items.update({
        item.id: ("environment", item) for item in inventory.environments
    })
    expected_page_count = 0
    valid_page_count = 0
    alignment_complete = False
    alignment_sha256 = ""
    reviewed_source_pages: set[int] = set()
    reviewed_candidate_pages: set[int] = set()
    try:
        source = module.open(stream=bytes(source_pdf_bytes), filetype="pdf")
        candidate = module.open(stream=bytes(candidate_pdf_bytes), filetype="pdf")
        frozen_contract_present = bool(
            isinstance(deterministic_report, dict)
            and (
                "page_alignment" in deterministic_report
                or "evidence_sha256" in deterministic_report
            )
        )
        if frozen_contract_present:
            try:
                alignment = frozen_page_alignment_from_report(
                    deterministic_report,
                    source_page_count=int(source.page_count),
                    candidate_page_count=int(candidate.page_count),
                    page_range=page_range,
                    candidate_scope=candidate_scope,
                    source_pdf_sha256=hashlib.sha256(
                        bytes(source_pdf_bytes)
                    ).hexdigest(),
                    candidate_pdf_sha256=hashlib.sha256(
                        bytes(candidate_pdf_bytes)
                    ).hexdigest(),
                )
            except (TypeError, ValueError, OverflowError):
                invalid.append({
                    "page": 0,
                    "reason": "确定性报告中的宿主冻结页映射无效或已被篡改",
                })
                alignment = None
        else:
            # Backward-compatible direct callers can still use strict index
            # alignment.  Reflow is never guessed here: it requires a frozen
            # deterministic report produced from the actual PDF text layers.
            if str(candidate_scope or "").strip().lower() == CANDIDATE_SCOPE_REFLOW:
                invalid.append({
                    "page": 0,
                    "reason": "reflow 视觉复核缺少宿主冻结的确定性页映射",
                })
                alignment = None
            else:
                alignment = build_page_alignment(
                    int(source.page_count),
                    int(candidate.page_count),
                    page_range,
                    candidate_scope=candidate_scope,
                )
        if alignment is None:
            mappings = []
            expected_page_count = 0
            deterministic_by_mapping = {}
        else:
            alignment_sha256 = alignment.mapping_sha256
            expected_page_count = len(alignment.mappings)
            deterministic_by_mapping = _deterministic_findings_by_mapping(
                deterministic_report,
                alignment.mappings,
            )
            alignment_complete = True
            mappings = [
                item for item in alignment.mappings
                if item.candidate_page is not None
            ]
        if alignment is not None and len(mappings) != len(alignment.mappings):
            alignment_complete = False
            unresolved.append({
                "page": 0,
                "pages": [
                    int(item.source_page)
                    for item in alignment.mappings
                    if item.candidate_page is None
                ],
                "reason": "编译 PDF 缺少与源范围对应的页面",
            })
        if alignment is not None and (
            alignment.candidate_scope != CANDIDATE_SCOPE_AUTO
            and alignment.candidate_scope != CANDIDATE_SCOPE_REFLOW
            and int(candidate.page_count) != alignment.expected_candidate_page_count
        ):
            alignment_complete = False
            unresolved.append({
                "page": 0,
                "reason": (
                    "候选 PDF 页数不符合宿主冻结的范围策略："
                    f"期望 {alignment.expected_candidate_page_count} 页，"
                    f"实际 {int(candidate.page_count)} 页"
                ),
                "candidate_scope": alignment.candidate_scope,
            })
            # Do not let a model inspect a convenient subset and accidentally
            # turn an invalid candidate-page closure into a complete audit.
            mappings = []
        # Keep the historical argument without allowing it to truncate the
        # user-selected range.  Images are still rendered and sent one page at
        # a time; batching only bounds the temporary mapping slice.
        for index, mapping in _iter_indexed_batches(mappings, max_pages):
            if control_callback:
                control_callback()
            source_page = int(mapping.source_page)
            candidate_page = int(mapping.candidate_page)
            image = _composite_page_png(
                module,
                source,
                candidate,
                source_page,
                candidate_page,
                source_label,
            )
            inventory_items = inventory_pages.get(source_page, [])
            deterministic_findings = deterministic_by_mapping.get(
                (source_page, candidate_page),
                [],
            )
            required_finding_codes = [
                str(item.get("code") or "") for item in deterministic_findings
            ]
            request = json.dumps({
                "source_page": source_page,
                "candidate_page": candidate_page,
                "source_visual_label": source_label,
                "candidate_scope": alignment.candidate_scope,
                "alignment_mapping_sha256": alignment.mapping_sha256,
                "inventory_items_on_source_page": inventory_items,
                "deterministic_findings_to_close": deterministic_findings,
                "instruction": (
                    "左源右编译；逐项视觉核对。只能引用本页 inventory_id；"
                    "checked_finding_codes 必须逐字回显全部确定性告警 code。"
                ),
            }, ensure_ascii=False, indent=1)
            method = getattr(client, "chat_vision_json_bytes", None)
            if not callable(method):
                raise LLMError("当前视觉模型客户端不支持结构化逐页复核")
            obj, call_usage = method(_SYSTEM, request, image, VISUAL_AUDIT_SCHEMA)
            add_usage(
                usage,
                call_usage if isinstance(call_usage, dict) else {},
                getattr(getattr(client, "cfg", None), "model", ""),
            )
            image_sha256 = hashlib.sha256(image).hexdigest()
            response = obj if isinstance(obj, dict) else {}
            verdict = response.get("verdict")
            reason = response.get("reason")
            raw_issues = response.get("issues")
            checked_codes = response.get("checked_finding_codes")
            page_record = {
                "source_page": source_page,
                "candidate_page": candidate_page,
                "composite_sha256": image_sha256,
                "verdict": verdict if isinstance(verdict, str) else "",
                "reason": reason[:240] if isinstance(reason, str) else "",
                "issue_count": len(raw_issues) if isinstance(raw_issues, list) else 0,
                "required_finding_codes": required_finding_codes,
                "checked_finding_codes": (
                    list(checked_codes) if isinstance(checked_codes, list) else []
                ),
                "valid": True,
            }

            page_valid = True

            def reject_page(reason_text: str) -> None:
                nonlocal page_valid
                page_valid = False
                invalid.append({
                    "page": source_page,
                    "reason": reason_text,
                })

            if not isinstance(obj, dict) or set(obj) != _PAGE_RESPONSE_KEYS:
                reject_page("视觉复核 JSON 顶层字段无效")
            echoed_source = response.get("source_page")
            echoed_candidate = response.get("candidate_page")
            if (
                isinstance(echoed_source, bool)
                or not isinstance(echoed_source, int)
                or echoed_source != source_page
                or isinstance(echoed_candidate, bool)
                or not isinstance(echoed_candidate, int)
                or echoed_candidate != candidate_page
            ):
                reject_page("视觉复核没有回显宿主冻结的页码映射")
            if not isinstance(reason, str):
                reject_page("视觉复核 reason 不是字符串")
            if (
                not isinstance(checked_codes, list)
                or any(not isinstance(code, str) for code in checked_codes)
                or sorted(checked_codes) != sorted(required_finding_codes)
                or len(set(checked_codes)) != len(checked_codes)
            ):
                reject_page("视觉复核没有逐条关闭宿主确定性告警")
            if verdict not in {"ok", "repair", "manual"} or not isinstance(raw_issues, list):
                reject_page("视觉复核 JSON 结构无效")
                raw_issues = []
            if verdict == "ok" and raw_issues:
                reject_page("verdict=ok 但仍返回 issues")
            if verdict in {"repair", "manual"} and not raw_issues:
                reject_page("视觉问题结论缺少 issues")
            page_item_ids = {str(item.get("id") or "") for item in inventory_items}
            page_suggestions: List[VisualRepairSuggestion] = []
            page_unresolved: List[dict] = []
            for issue in raw_issues:
                if not isinstance(issue, dict):
                    reject_page("视觉 issue 不是对象")
                    continue
                if set(issue) != _ISSUE_KEYS:
                    reject_page("视觉 issue 字段无效或包含禁止的修复坐标")
                    continue
                inventory_value = issue.get("inventory_id")
                problem_value = issue.get("problem")
                env_value = issue.get("env")
                evidence_value = issue.get("evidence")
                if not all(
                    isinstance(value, str)
                    for value in (
                        inventory_value,
                        problem_value,
                        env_value,
                        evidence_value,
                    )
                ):
                    reject_page("视觉 issue 的文本字段类型无效")
                    continue
                inventory_id = inventory_value.strip()
                problem = problem_value.strip()
                env = env_value.strip()
                evidence = evidence_value.strip()[:240]
                confidence, confidence_valid = _confidence(issue.get("confidence"))
                if problem not in _ALL_PROBLEMS:
                    reject_page("视觉 problem 非法")
                    continue
                if not confidence_valid:
                    reject_page("视觉 confidence 必须是 0 到 1 的有限数值")
                    continue
                if problem in _MANUAL_PROBLEMS:
                    if verdict != "manual" or inventory_id or env or len(evidence) < 2:
                        reject_page("非结构问题必须使用 manual 且不得绑定结构目标")
                        continue
                    page_unresolved.append({
                        "page": source_page,
                        "problem": problem,
                        "reason": evidence or page_record["reason"] or "视觉问题无法用结构补丁修复",
                    })
                    continue
                if verdict != "repair":
                    reject_page("结构修复建议必须使用 verdict=repair")
                    continue
                if inventory_id not in page_item_ids or inventory_id not in all_items:
                    reject_page("视觉修复引用了本页不存在的 inventory_id")
                    continue
                if (problem, env) not in allowed_repairs.get(inventory_id, set()):
                    reject_page("视觉修复的目标类型或环境不在宿主白名单")
                    continue
                if confidence < 0.95 or len(evidence) < 2:
                    reject_page("视觉修复的置信度或证据不合法")
                    continue
                page_suggestions.append(VisualRepairSuggestion(
                    source_page=source_page,
                    candidate_page=candidate_page,
                    inventory_id=inventory_id,
                    problem=problem,
                    env=env,
                    confidence=confidence,
                    evidence=evidence,
                ))
            if page_valid:
                suggestions.extend(page_suggestions)
                unresolved.extend(page_unresolved)
                valid_page_count += 1
                reviewed_source_pages.add(source_page)
                reviewed_candidate_pages.add(candidate_page)
            page_record["valid"] = page_valid
            pages.append(page_record)
            if progress_callback:
                progress_callback({
                    "done": index,
                    "total": len(mappings),
                    "usage": usage,
                    "source_page": source_page,
                })
    except LLMError:
        raise
    except Exception:  # noqa: BLE001 - PDF parser/renderer boundary
        return VisualAuditResult(
            checked=False,
            ok=False,
            page_count=len(pages),
            pages=pages,
            suggestions=suggestions,
            invalid=invalid,
            unresolved=unresolved + [{"page": 0, "reason": "逐页视觉复核无法完成"}],
            usage=usage,
        )
    finally:
        for document in (candidate, source):
            if document is not None:
                try:
                    document.close()
                except Exception:  # noqa: BLE001
                    pass
    checked = bool(
        alignment_complete
        and len(pages) == expected_page_count
        and valid_page_count == expected_page_count
        and (
            alignment is None
            or set(alignment.selected_source_pages) == reviewed_source_pages
        )
        and (
            alignment is None
            or alignment.candidate_scope != CANDIDATE_SCOPE_REFLOW
            or set(range(1, int(alignment.candidate_page_count) + 1))
            == reviewed_candidate_pages
        )
    )
    return VisualAuditResult(
        checked=checked,
        ok=checked and not invalid and not unresolved and not suggestions,
        page_count=len(pages),
        pages=pages,
        suggestions=suggestions,
        invalid=invalid,
        unresolved=unresolved,
        usage=usage,
        alignment_sha256=alignment_sha256,
    )


__all__ = [
    "VISUAL_AUDIT_SCHEMA",
    "VisualAuditResult",
    "VisualRepairSuggestion",
    "audit_compiled_pages",
]

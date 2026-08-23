# -*- coding: utf-8 -*-
"""处理流水线编排（M1 MVP）。

阶段：解析 → 扫描 → 决策（规则 / AI+规则混合） → 区间冲突消解 → 补丁应用 →
      内容不变校验 + 环境配平 → AI 复查（可选，自动修正） → 汇报。

- mode="rule"：确定性规则（无 Key 降级路径）；
- mode="ai"：定理类/proof/范围修正候选交 AI 决策，双语标题/习题节/导言区仍走确定性规则；
  AI 不可用（无 Key/调用失败）时明确失败并保留原项目，绝不静默伪装成 AI 结果。
任何校验失败 → 返回原始文本，绝不导出被改坏的内容。
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ai import (
    ALLOWED_WRAP_ENVS,
    AIConfig,
    AI_KINDS,
    LLMError,
    build_text_client,
    decide_candidates,
)
from .parser import detect_newline, line_starts, normalize_newlines, offset_to_line, parse_latex
from .ocrstruct import (
    build_ocr_structure_ops,
    check_ocr_structure,
    is_ocr_document,
    parse_ocr_metadata,
)
from .ocr_sources import MULTI_IMAGE_DERIVATION_ID
from .patch import (
    AMSTHM_BLOCK,
    AppliedPatch,
    Decision,
    SUPPRESS_AUTO_QED_PAYLOAD_KEY,
    NEW_THEOREM_RE,
    PatchContext,
    apply_patches,
    build_ops,
    content_invariant,
    validate_ops,
)
from .report import build_report
from .review import run_review
from .rules import RuleConfig, build_rule_decisions
from .scanner import _declared_theorem_envs, scan
from .semantic_ir import build_ocr_semantic_ops
from .verify import check_display_tag_safety, compare_braces, compare_env_balance, known_issues
from .visual_quality import (
    GEOMETRY_POLICY_DERIVED_IMAGE,
    GEOMETRY_POLICY_STRICT_SOURCE,
    GEOMETRY_POLICY_TEMPLATE_REFLOW,
)

DOC_CLASS_RE = re.compile(r"\\documentclass(?:\[[^\]]*\])?\s*\{([^{}]*)\}")
DETERMINISTIC_SEMANTIC_ANCHOR_KEY = "_deterministic_semantic_anchor"
OCR_EXPLICIT_FORMAL_STYLE_RE = re.compile(
    r"^\s*(?:\\noindent\s*)?(?:"
    r"\\(?:textbf|textit|emph|textsc)\s*\{"
    r"|\{\s*\\(?:bfseries|itshape|slshape|scshape)\b"
    r")"
)

VISUAL_SOURCE_PROVENANCE_SCHEMA = "latexstruct-visual-source-provenance-v1"
IMAGE_TO_VISUAL_PDF_DERIVATION_ID = (
    "latexstruct.raster-image-to-single-page-visual-pdf.v1"
)
PDF_IDENTITY_VISUAL_DERIVATION_ID = "latexstruct.original-pdf-as-visual-source.v1"

_USAGE_SUMMARY_METADATA_KEYS = frozenset({
    "model",
    "backend",
    "billing_mode",
    "pricing_source",
    "pricing_note",
    "pricing_checked_at",
})


def _merge_usage_summaries(current: Optional[dict], addition: Optional[dict]) -> Dict:
    """Merge already-aggregated usage without inventing an extra model call."""

    merged = dict(current or {})
    for key, value in (addition or {}).items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            merged[key] = merged.get(key, 0) + value
        elif key in _USAGE_SUMMARY_METADATA_KEYS and value not in (None, ""):
            merged[key] = value
    return merged


def _verify_source_visual_provenance(
    source_pdf_bytes: bytes,
    supplied: Optional[dict],
) -> Dict:
    """Bind host-recorded upload provenance to the exact visual PDF bytes.

    The core never invents an original-upload hash.  Missing or contradictory
    host facts remain visible and fail closed whenever visual source bytes were
    supplied to the pipeline.
    """
    visual_bytes = bytes(source_pdf_bytes or b"")
    actual_visual_hash = (
        hashlib.sha256(visual_bytes).hexdigest() if visual_bytes else ""
    )
    result = {
        "schema": VISUAL_SOURCE_PROVENANCE_SCHEMA,
        "checked": bool(visual_bytes),
        "ok": not bool(visual_bytes),
        "source_type": "",
        "original_upload_bytes": 0,
        "original_upload_sha256": "",
        "visual_pdf_bytes": len(visual_bytes),
        "visual_pdf_sha256": actual_visual_hash,
        "visual_pdf_is_derived": None,
        "derivation_id": "",
        "issues": [],
    }
    if not visual_bytes:
        return result

    issues: List[str] = []
    raw = supplied if isinstance(supplied, dict) else {}
    if not raw:
        issues.append("缺少宿主冻结的原始上传哈希与视觉 PDF 派生记录")
    if raw.get("schema") != VISUAL_SOURCE_PROVENANCE_SCHEMA:
        issues.append("视觉来源 provenance schema 缺失或不受支持")

    source_type = str(raw.get("source_type") or "").strip().lower()
    if source_type not in {"image", "images", "pdf"}:
        issues.append("原始上传类型必须明确为 image、images 或 pdf")
        source_type = ""

    original_hash = str(raw.get("original_upload_sha256") or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", original_hash) is None:
        issues.append("原始上传 bytes SHA-256 缺失或无效")
        original_hash = ""

    original_size_raw = raw.get("original_upload_bytes")
    if isinstance(original_size_raw, bool):
        original_size = 0
    else:
        try:
            original_size = int(original_size_raw)
        except (TypeError, ValueError):
            original_size = 0
    if original_size <= 0:
        issues.append("原始上传 byte count 缺失或无效")
        original_size = 0

    recorded_visual_hash = str(raw.get("visual_pdf_sha256") or "").strip().lower()
    if recorded_visual_hash != actual_visual_hash:
        issues.append("记录的视觉 PDF SHA-256 与实际 pipeline 输入不一致")
    recorded_visual_size = raw.get("visual_pdf_bytes")
    if isinstance(recorded_visual_size, bool):
        recorded_visual_size = -1
    try:
        recorded_visual_size = int(recorded_visual_size)
    except (TypeError, ValueError):
        recorded_visual_size = -1
    if recorded_visual_size != len(visual_bytes):
        issues.append("记录的视觉 PDF byte count 与实际 pipeline 输入不一致")
    if not visual_bytes.startswith(b"%PDF-"):
        issues.append("视觉比对输入不是可识别的 PDF bytes")

    derived = raw.get("visual_pdf_is_derived")
    if not isinstance(derived, bool):
        issues.append("是否派生必须由宿主明确记录为布尔值")
        derived = None
    derivation_id = str(raw.get("derivation_id") or "").strip()
    expected_derivation = (
        IMAGE_TO_VISUAL_PDF_DERIVATION_ID
        if source_type == "image"
        else MULTI_IMAGE_DERIVATION_ID
        if source_type == "images"
        else PDF_IDENTITY_VISUAL_DERIVATION_ID
        if source_type == "pdf"
        else ""
    )
    if not expected_derivation or derivation_id != expected_derivation:
        issues.append("视觉 PDF derivation 标识缺失或与原始上传类型矛盾")
    if source_type == "image" and derived is not True:
        issues.append("图片输入必须明确记录为派生视觉 PDF")
    source_images: List[dict] = []
    original_image_count = 0
    derived_from_source_sha256 = str(
        raw.get("derived_from_source_sha256") or ""
    ).strip().lower()
    if source_type == "images":
        if derived is not True:
            issues.append("多图片输入必须明确记录为派生视觉 PDF")
        raw_images = raw.get("source_images")
        if not isinstance(raw_images, list) or len(raw_images) < 2:
            issues.append("多图片输入缺少宿主冻结的有序源图片清单")
            raw_images = []
        for index, raw_image in enumerate(raw_images, 1):
            if not isinstance(raw_image, dict):
                issues.append(f"多图片输入第 {index} 项不是有效记录")
                continue
            order = raw_image.get("order")
            filename = str(raw_image.get("original_filename") or "")
            image_hash = str(raw_image.get("sha256") or "").strip().lower()
            image_size = raw_image.get("bytes")
            valid = True
            if isinstance(order, bool) or order != index:
                issues.append(f"多图片输入第 {index} 项顺序无效")
                valid = False
            if (
                not filename
                or filename in {".", ".."}
                or "/" in filename
                or "\\" in filename
                or any(ord(char) < 32 or ord(char) == 127 for char in filename)
            ):
                issues.append(f"多图片输入第 {index} 项原始文件名无效")
                valid = False
            if re.fullmatch(r"[0-9a-f]{64}", image_hash) is None:
                issues.append(f"多图片输入第 {index} 项 SHA-256 无效")
                valid = False
            if (
                isinstance(image_size, bool)
                or not isinstance(image_size, int)
                or image_size <= 0
            ):
                issues.append(f"多图片输入第 {index} 项 byte count 无效")
                valid = False
            if valid:
                source_images.append({
                    "order": order,
                    "original_filename": filename,
                    "bytes": image_size,
                    "sha256": image_hash,
                })
        count_raw = raw.get("original_image_count")
        if isinstance(count_raw, bool) or not isinstance(count_raw, int):
            issues.append("多图片输入的原始图片数量无效")
        else:
            original_image_count = count_raw
            if count_raw != len(raw_images) or count_raw < 2:
                issues.append("多图片输入的原始图片数量与有序清单不一致")
        if derived_from_source_sha256 != original_hash:
            issues.append("多图片视觉 PDF 未绑定到原始来源 ZIP SHA-256")
    if source_type == "pdf":
        if derived is not False:
            issues.append("PDF 输入必须明确记录为原始 bytes 直接用于视觉比对")
        if original_hash and original_hash != actual_visual_hash:
            issues.append("PDF 输入的原始上传哈希与视觉 PDF 哈希不一致")
        if original_size and original_size != len(visual_bytes):
            issues.append("PDF 输入的原始 byte count 与视觉 PDF 不一致")

    result.update({
        "ok": not issues,
        "source_type": source_type,
        "original_upload_bytes": original_size,
        "original_upload_sha256": original_hash,
        "visual_pdf_is_derived": derived,
        "derivation_id": derivation_id,
        "issues": issues,
    })
    if source_type == "images":
        result.update({
            "derived_from_source_sha256": derived_from_source_sha256,
            "original_image_count": original_image_count,
            "source_images": source_images,
        })
    return result


@dataclass
class PipelineResult:
    ok: bool
    original: str
    result: str  # 规范化换行的结果
    export_text: str  # 按原始换行风格还原的结果
    newline: str
    decisions: List[Decision]
    applied: List[AppliedPatch]
    rejected: List[AppliedPatch]
    ambiguous: List[dict]
    verification: Dict
    report_md: str
    mode: str
    ai_notes: List[dict] = field(default_factory=list)
    review: Dict = field(default_factory=dict)
    decision_items: List[dict] = field(default_factory=list)  # 审阅式 UI 决策清单
    error: str = ""
    compiled_pdf: bytes = b""
    compiled_pdf_name: str = ""
    compiled_tex: str = ""
    compiled_snapshot: str = ""
    compiled_extra_files: Dict[str, bytes] = field(default_factory=dict)
    # OCR 原始转写的真实编译工件与最终稿分开保存；失败编译若已产生可读 PDF，
    # 仍作为 PARTIAL_COMPILED 证据保留，不能被源码预览替代。
    raw_compiled_pdf: bytes = b""
    raw_compiled_pdf_name: str = ""
    raw_compiled_tex: str = ""
    raw_compiled_extra_files: Dict[str, bytes] = field(default_factory=dict)
    # Immutable, host-produced stage snapshots for the external audit bundle.
    # They are descriptive evidence only and never participate in patching or
    # verification decisions.
    analyzed_tex: str = ""
    reviewed_tex: str = ""


def _build_context(doc, structured_envs=None) -> PatchContext:
    m = DOC_CLASS_RE.search(doc.text)
    cls = m.group(1) if m else ""
    is_elegant = "elegantbook" in cls.lower()
    used_env_names = {r[0] for r in doc.env_ranges}
    theorem_declarations = list(NEW_THEOREM_RE.finditer(doc.masked))
    newtheorem_names = _declared_theorem_envs(doc.masked)
    newtheorem_names.update(
        str(name).strip() for name in (structured_envs or ()) if name
    )
    numbered_envs = {m.group(2) for m in theorem_declarations if not m.group(1)}
    unnumbered_envs = {
        m.group(2) for m in theorem_declarations if m.group(1)
    } - numbered_envs
    if is_elegant:
        from .template import (
            ELEGANTBOOK_BUILTIN_ENVS,
            ELEGANT_NEW_THEOREM_RE,
        )

        elegant_declared = {m.group(1) for m in ELEGANT_NEW_THEOREM_RE.finditer(doc.masked)}
        elegant_envs = set(ELEGANTBOOK_BUILTIN_ENVS) | elegant_declared
        newtheorem_names |= elegant_envs | {f"{name}*" for name in elegant_envs}
        unnumbered_envs |= {f"{name}*" for name in elegant_envs}
    available_env_names = used_env_names | newtheorem_names
    packages = set()
    for match in re.finditer(r"\\usepackage(?:\[[^\]]*\])?\{([^{}]+)\}", doc.masked):
        packages.update(name.strip() for name in match.group(1).split(","))
    theorem_package = "amsthm" if "amsthm" in packages else ("ntheorem" if "ntheorem" in packages else "")
    # 习题节需要"列表语义"环境；elegantbook 的 exercise 是定理式单题环境（放 \item 会报
    # Lonely \item），故仅 problemset（列表式）可复用，否则统一用 enumerate
    if "problemset" in available_env_names:
        exercise_env = "problemset"
    else:
        exercise_env = "enumerate"
    doc_range = next((r for r in doc.env_ranges if r[0] == "document"), None)
    anchor = offset_to_line(line_starts(doc.text), doc_range[1]) if doc_range else 0
    return PatchContext(
        is_elegantbook=is_elegant,
        existing_envs=newtheorem_names,
        unnumbered_envs=unnumbered_envs,
        theorem_package=theorem_package,
        exercise_env=exercise_env,
        preamble_anchor=anchor,
    )


def build_preamble_decision(
    doc, ctx: PatchContext, decisions: List[Decision] = None
) -> Optional[Decision]:
    if ctx.is_elegantbook:
        return None
    if ctx.preamble_anchor <= 0:
        return None
    known_envs = {
        NEW_THEOREM_RE.match(line).group(2)
        for line in AMSTHM_BLOCK
        if line.startswith("\\newtheorem")
    }
    if decisions is None:
        required_envs = known_envs
        needs_proof = True
    else:
        required_envs = {
            d.env for d in decisions
            if d.action in {"wrap", "change-env"} and d.env in known_envs
        }
        needs_proof = any(d.action == "wrap" and d.env == "proof" for d in decisions)
    missing_envs = required_envs - ctx.existing_envs
    needs_package = not ctx.theorem_package and (bool(required_envs) or needs_proof)
    if not missing_envs and not needs_package:
        return None
    return Decision(
        candidate_id="preamble",
        action="preamble-add",
        source="rule",
        reason="导言区缺少定理环境定义",
        confidence=1.0,
        payload={"required_envs": sorted(missing_envs)},
    )


def _semantic_span_hash(doc, body_span: Tuple[int, int]) -> str:
    """Hash the exact normalized source bytes covered by a semantic anchor."""
    start, end = body_span
    lines = doc.text.split("\n")
    if not (1 <= start <= end <= len(lines)):
        return ""
    source = "\n".join(lines[start - 1:end]).encode("utf-8")
    return hashlib.sha256(source).hexdigest()


def _is_ocr_formal_inventory_candidate(candidate) -> bool:
    """Return whether an OCR candidate must be resolved before publication.

    Proof starts and numbered result titles are always explicit.  An unnumbered
    result is also explicit when OCR preserved a dedicated visual title wrapper
    (for example ``\\textbf{Remark.}``).  Plain unnumbered words remain AI-owned
    candidates so prose such as ``Note.`` is not promoted into a mandatory
    theorem merely because it begins a paragraph.
    """
    if candidate.kind == "proof":
        return True
    if candidate.kind != "theorem-like":
        return False
    if str(candidate.payload.get("number", "") or "").strip():
        return True
    return bool(OCR_EXPLICIT_FORMAL_STYLE_RE.match(str(candidate.title_text or "")))


def _build_ocr_semantic_anchors(
    doc,
    scan_res,
    ctx: PatchContext,
    rule_config: RuleConfig = None,
    pack=None,
) -> Tuple[List[Decision], set]:
    """Build model-independent formal-entry decisions for OCR documents.

    Only an explicit numbered theorem-like title, or a scanner-confirmed proof
    whose complete boundary independently passes ``legalize_deterministic_wrap``,
    is locked.  The exact kind, source span, and source hash travel with the
    decision and are revalidated immediately before every patch application.
    Any item that misses one gate is omitted here and remains on the normal AI
    path; this function never guesses a fallback range.
    """
    from .legalize import legalize_deterministic_wrap

    candidates_by_id = {candidate.id: candidate for candidate in scan_res.candidates}
    rule_decisions, _rule_ambiguous = build_rule_decisions(
        doc,
        scan_res,
        rule_config,
        kinds={"theorem-like", "proof"},
        pack=pack,
    )
    anchors: List[Decision] = []
    locked_ids = set()
    for decision in rule_decisions:
        candidate = candidates_by_id.get(decision.candidate_id)
        if candidate is None or decision.action != "wrap" or not decision.body_span:
            continue
        if candidate.kind == "theorem-like":
            if (
                candidate.rule_id != "bare-title"
                or not str(candidate.payload.get("number", "") or "").strip()
            ):
                continue
        elif candidate.kind == "proof":
            if candidate.rule_id != "proof-start":
                continue
        else:
            continue

        legalize_deterministic_wrap(
            doc,
            decision,
            candidate,
            ctx.existing_envs,
        )
        if getattr(decision, "_legalize_error", ""):
            continue
        source_hash = _semantic_span_hash(doc, decision.body_span)
        if not source_hash:
            continue
        start, end = decision.body_span
        decision.source = "rule"
        decision.reason = (
            "OCR 显式编号标题经规则与独立边界门确认"
            if candidate.kind == "theorem-like"
            else "OCR 证明起始语经规则与 QED/下一结构边界门确认"
        )
        decision.payload = dict(decision.payload)
        decision.payload[DETERMINISTIC_SEMANTIC_ANCHOR_KEY] = {
            "candidate_id": candidate.id,
            "kind": candidate.kind,
            "env": candidate.env_hint if candidate.kind == "theorem-like" else "proof",
            "body_span": [start, end],
            "source_sha256": source_hash,
        }
        anchors.append(decision)
        locked_ids.add(candidate.id)
    return anchors, locked_ids


def _merge_semantic_anchors(
    decisions: List[Decision],
    anchors: List[Decision],
) -> List[Decision]:
    """Replace stale/model decisions for locked IDs with canonical anchors."""
    locked_ids = {decision.candidate_id for decision in anchors}
    return [
        decision for decision in decisions
        if decision.candidate_id not in locked_ids
    ] + copy.deepcopy(anchors)


def _interval(d: Decision) -> Tuple[int, int]:
    if d.action == "wrap" and d.body_span:
        return d.body_span
    if d.action in {"change-env", "unwrap"}:
        return (
            int(d.payload.get("begin_line", 0) or 0),
            int(d.payload.get("end_line", 0) or 0),
        )
    if d.action == "move-boundary":
        a = d.payload.get("old_end_line", 0)
        b = d.payload.get("new_end_line", 0)
        return (min(a, b), max(a, b))
    if d.action == "convert-to-exercise-env":
        items = d.payload.get("item_lines", [0, 0])
        return (items[0], items[-1])
    if d.action == "merge-bilingual-title":
        return (d.payload.get("section_line", 0), d.payload.get("box_lines", (0, 0))[1])
    if d.action == "preamble-add":
        return (0, 0)
    return (0, 0)


def resolve_overlaps(
    planned: List[Tuple[Decision, List]], lines: List[str]
) -> Tuple[List[Tuple[Decision, List]], List[Tuple[Decision, str]]]:
    if not planned:
        return planned, []
    # 修改区间相交时无法证明两项组合仍符合原意。与其凭置信度猜一项，保守地
    # 将冲突双方都交给人工审阅；导言区固定插入 (0, 0) 不参与冲突判断。
    spans = []
    for idx, (d, _) in enumerate(planned):
        s, e = _interval(d)
        if (s, e) != (0, 0):
            spans.append((s, e, idx, d))
    spans.sort(key=lambda item: (item[0], item[1]))
    active: List[Tuple[int, int, Decision]] = []  # (end, index, decision)
    conflicts: Dict[int, set] = {}
    for s, e, idx, d in spans:
        active = [item for item in active if item[0] >= s]
        for _, other_idx, other_d in active:
            conflicts.setdefault(idx, set()).add(other_d.candidate_id)
            conflicts.setdefault(other_idx, set()).add(d.candidate_id)
        active.append((e, idx, d))
    kept = [item for idx, item in enumerate(planned) if idx not in conflicts]
    dropped = []
    for idx in sorted(conflicts):
        d = planned[idx][0]
        peers = "、".join(sorted(conflicts[idx]))
        dropped.append((d, f"与决策 {peers} 的修改区间重叠，已保守跳过并等待人工确认"))
    return kept, dropped


def _apply_decisions(doc, decisions: List[Decision], ctx: PatchContext, ambiguous: List[dict],
                     candidates_by_id: dict = None):
    if candidates_by_id:
        from .legalize import legalize_decisions

        legalize_decisions(
            doc,
            decisions,
            candidates_by_id,
            ctx.existing_envs,
        )  # AI span 段落边界合法化
    lines = doc.text.split("\n")
    planned: List[Tuple[Decision, List]] = []
    rejected: List[AppliedPatch] = []
    for d in decisions:
        candidate = _candidate_for_decision(d, candidates_by_id or {})
        unsafe_reason = _unsafe_candidate_env_reason(d, candidate, doc)
        if not unsafe_reason:
            unsafe_reason = str(getattr(d, "_legalize_error", "") or "")
        if not unsafe_reason:
            unsafe_reason = _normalize_theorem_wrap_start(d, candidate)
        if not unsafe_reason:
            _restore_theorem_title_metadata(d, candidate)
            _restore_proof_qed_metadata(d, candidate, doc)
            _adapt_elegantbook_theorem_env(d, candidate, ctx)
            unsafe_reason = _unsafe_numbered_theorem_reason(d, candidate, ctx)
        if not unsafe_reason and d.action in {
            "wrap",
            "move-boundary",
            "convert-to-exercise-env",
            "merge-bilingual-title",
            "none",
        }:
            _start, _end, unsafe_reason = _current_candidate_action_span(
                d,
                candidate,
                ctx,
                line_count=len(doc.text.split("\n")),
            )
            if not unsafe_reason:
                # Fresh rule/model output is host-bound only after the common
                # legalizer has fixed its final range.  This exact digest is
                # persisted with the decision and is mandatory on cache reuse.
                d.payload = dict(d.payload or {})
                d.payload["source_sha256"] = _semantic_span_hash(
                    doc, (_start, _end)
                )
        if unsafe_reason:
            item = {
                "candidate_id": d.candidate_id,
                "line": candidate.span.start_line if candidate is not None else (_interval(d)[0] or 1),
                "reason": unsafe_reason,
            }
            if not any(
                old.get("candidate_id") == item["candidate_id"]
                and old.get("reason") == item["reason"]
                for old in ambiguous
            ):
                ambiguous.append(item)
            continue
        ops, err = build_ops(d, lines, ctx)
        if err:
            rejected.append(AppliedPatch(decision=d, edits=[], error=err))
        elif ops:
            planned.append((d, ops))
    planned, dropped = resolve_overlaps(planned, lines)
    out, applied, rejected2 = apply_patches(lines, planned)
    return out, applied, rejected + rejected2, dropped


def _unsafe_candidate_env_reason(decision: Decision, candidate, doc=None) -> str:
    """最终应用门：复查/缓存也不能把 proof 候选改成定理，反之亦然。"""
    if decision.action != "wrap" or candidate is None:
        return ""
    if candidate.kind == "proof" and decision.env != "proof":
        return "证明候选只能使用 proof 环境；不兼容的 AI/复查环境已保守跳过"
    if candidate.kind == "theorem-like" and decision.env == "proof":
        return "定理类候选不能改成 proof 环境；不兼容的 AI/复查环境已保守跳过"
    anchor = (
        decision.payload.get(DETERMINISTIC_SEMANTIC_ANCHOR_KEY)
        if isinstance(decision.payload, dict) else None
    )
    if anchor is not None:
        if not isinstance(anchor, dict) or doc is None:
            return "确定性语义锚点缺少可复验的源文档证据"
        expected_env = str(anchor.get("env", "") or "")
        actual_env = str(decision.env or "")
        expected_span = anchor.get("body_span")
        if anchor.get("candidate_id") != candidate.id:
            return "确定性语义锚点的候选 ID 与当前源候选不一致"
        if anchor.get("kind") != candidate.kind:
            return "确定性语义锚点的结构类型与当前源候选不一致"
        if actual_env.removesuffix("*") != expected_env.removesuffix("*"):
            return "确定性语义锚点的目标环境被改写，已保守拒绝"
        if (
            not isinstance(expected_span, list)
            or len(expected_span) != 2
            or decision.body_span != tuple(expected_span)
        ):
            return "确定性语义锚点的源范围被改写，已保守拒绝"
        if _semantic_span_hash(doc, decision.body_span) != anchor.get("source_sha256"):
            return "确定性语义锚点覆盖的源内容或数学文本已变化，已保守拒绝"
    return ""


def _candidate_for_decision(decision: Decision, candidates_by_id: dict):
    candidate = candidates_by_id.get(decision.candidate_id)
    if candidate is None and decision.candidate_id.startswith("review-missed-"):
        candidate = candidates_by_id.get(decision.candidate_id[len("review-missed-"):])
    return candidate


_REUSABLE_DECISION_ACTIONS = frozenset({
    "wrap",
    "change-env",
    "unwrap",
    "move-boundary",
    "convert-to-exercise-env",
    "merge-bilingual-title",
    "none",
})


def _current_environment_for_reused_decision(
    decision: Decision,
    candidate,
    formal_inventory,
):
    environments_by_id = {
        environment.id: environment for environment in formal_inventory.environments
    }
    if decision.candidate_id in environments_by_id:
        return environments_by_id[decision.candidate_id]
    if decision.candidate_id.startswith("visual:"):
        environment_id = decision.candidate_id[len("visual:"):]
        payload = decision.payload if isinstance(decision.payload, dict) else {}
        if str(payload.get("visual_inventory_id") or "") != environment_id:
            return None
        return environments_by_id.get(environment_id)
    if candidate is None or candidate.kind != "formal-audit":
        return None
    payload = candidate.payload if isinstance(candidate.payload, dict) else {}
    environment_id = str(payload.get("environment_id") or "")
    return environments_by_id.get(environment_id)


def _exact_line_number(value):
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _exact_line_list(value) -> Optional[List[int]]:
    if not isinstance(value, (list, tuple)):
        return None
    result = [_exact_line_number(item) for item in value]
    if any(item is None for item in result):
        return None
    return result


def _current_candidate_action_span(
    decision: Decision,
    candidate,
    ctx: PatchContext,
    *,
    line_count: int,
) -> Tuple[int, int, str]:
    """Return the exact current-source span owned by a reusable action.

    Every coordinate and semantic field is compared with the current scanner
    candidate.  Nothing is repaired from cached payload data here: a mismatch
    is an invalid cache entry and must fail closed.
    """

    if candidate is None:
        return 0, 0, "未绑定当前 scanner candidate ID"
    payload = decision.payload if isinstance(decision.payload, dict) else {}
    action = decision.action

    if action == "wrap":
        if candidate.kind not in {"theorem-like", "proof"}:
            return 0, 0, f"{candidate.kind} 候选不允许 wrap"
        if candidate.kind == "proof":
            if decision.env != "proof":
                return 0, 0, "proof 候选只能绑定 proof 环境"
        elif (
            not decision.env
            or decision.env.removesuffix("*") not in ALLOWED_WRAP_ENVS
            or (
                candidate.env_hint
                and decision.env.removesuffix("*")
                != candidate.env_hint.removesuffix("*")
            )
        ):
            return 0, 0, "wrap 环境与当前标题关键词/安全白名单不一致"
        if (
            not isinstance(decision.body_span, (list, tuple))
            or len(decision.body_span) != 2
        ):
            return 0, 0, "wrap 缺少精确 body_span"
        start = _exact_line_number(decision.body_span[0])
        end = _exact_line_number(decision.body_span[1])
        if (
            start != candidate.span.start_line
            or end is None
            or end < candidate.span.end_line
            or end > line_count
        ):
            return 0, 0, "wrap 范围未精确绑定当前 scanner 候选"
        return start, end, ""

    if action == "move-boundary":
        if candidate.kind != "scope-fix" or candidate.rule_id not in {
            "env-body-outside",
            "env-missing-display",
        }:
            return 0, 0, "当前候选没有可证明的边界移动证据"
        old_end = _exact_line_number(payload.get("old_end_line"))
        new_end = _exact_line_number(payload.get("new_end_line"))
        expected_old = candidate.span.end_line
        expected_new = candidate.payload.get("next_end_line")
        expected_env = str(
            candidate.payload.get("env_name") or candidate.env_hint or ""
        )
        if (
            old_end != expected_old
            or new_end != expected_new
            or decision.env != expected_env
            or old_end is None
            or new_end is None
            or not (1 <= old_end < new_end <= line_count)
        ):
            return 0, 0, "move-boundary 坐标或环境与当前 scanner 证据不一致"
        return old_end, new_end, ""

    if action == "convert-to-exercise-env":
        if candidate.kind != "exercise-section":
            return 0, 0, "当前候选不是习题节"
        items = _exact_line_list(payload.get("item_lines"))
        expected_items = _exact_line_list(candidate.payload.get("item_lines"))
        if (
            items is None
            or expected_items is None
            or items != expected_items
            or len(items) < 2
            or items != sorted(set(items))
            or not all(1 <= item <= line_count for item in items)
            or decision.env != ctx.exercise_env
        ):
            return 0, 0, "习题条目、范围或环境与当前 scanner 候选不一致"
        return items[0], items[-1], ""

    if action == "merge-bilingual-title":
        if candidate.kind != "bilingual-title" or decision.env:
            return 0, 0, "当前候选不是可合并的双语标题"
        expected = candidate.payload
        section_line = _exact_line_number(payload.get("section_line"))
        box_lines = _exact_line_list(payload.get("box_lines"))
        expected_box = _exact_line_list(expected.get("box_lines"))
        if (
            section_line != expected.get("section_line")
            or str(payload.get("section_cmd") or "")
            != str(expected.get("section_cmd") or "")
            or str(payload.get("en_title") or "")
            != str(expected.get("en_title") or "")
            or str(payload.get("cn_title") or "")
            != str(expected.get("cn_title") or "")
            or box_lines is None
            or box_lines != expected_box
            or len(box_lines) != 2
            or not (1 <= section_line <= line_count)
            or not (1 <= box_lines[0] <= box_lines[1] <= line_count)
        ):
            return 0, 0, "双语标题字段或范围与当前 scanner 候选不一致"
        return min(section_line, box_lines[0]), max(
            section_line, box_lines[1]
        ), ""

    if action == "none":
        if decision.env or decision.body_span or decision.title_span:
            return 0, 0, "none 决策不得携带修改范围或目标环境"
        return candidate.span.start_line, candidate.span.end_line, ""

    return 0, 0, f"动作 {action!r} 不是 scanner candidate 动作"


def _validate_reused_decisions(
    decisions: List[Decision],
    candidates_by_id: dict,
    formal_inventory,
    doc,
    ctx: PatchContext,
    current_rule_decisions: List[Decision],
) -> Tuple[List[Decision], List[dict]]:
    """Rebind untrusted cached decisions to this exact scan and inventory.

    Cached preamble edits are discarded and regenerated later.  Every other
    decision must own a current scanner candidate; existing-environment edits
    may instead own the current immutable FormalEnvironment ID.  Missing hashes
    or legacy coordinates are surfaced for manual review rather than guessed.
    """

    accepted: List[Decision] = []
    invalid: List[dict] = []
    seen_ids: set[str] = set()

    def exact_current_rule_wrap(decision: Decision) -> bool:
        """Recognize only the host's freshly reconstructed rule decision.

        Some deterministic rule ranges intentionally use stronger source
        evidence than the generic model-range legalizer.  They remain cache
        compatible only when every semantic field equals the decision rebuilt
        from *this* scan; a persisted ``source='rule'`` label has no authority.
        """

        for current in current_rule_decisions:
            if (
                current.candidate_id == decision.candidate_id
                and current.action == "wrap"
                and decision.action == "wrap"
                and tuple(current.body_span or ()) == tuple(decision.body_span or ())
                and current.env.removesuffix("*")
                == decision.env.removesuffix("*")
            ):
                return True
        return False

    for decision in decisions:
        if decision.action == "preamble-add":
            continue
        candidate = _candidate_for_decision(decision, candidates_by_id)
        environment = None
        reason = ""
        if decision.action not in _REUSABLE_DECISION_ACTIONS:
            reason = f"动作 {decision.action!r} 不在可复用白名单"
        elif not decision.candidate_id:
            reason = "缺少当前 scanner/formal inventory ID"
        elif decision.candidate_id in seen_ids:
            reason = "同一当前 scanner/formal inventory ID 出现重复缓存决策"
        elif decision.action in {"change-env", "unwrap"}:
            environment = _current_environment_for_reused_decision(
                decision,
                candidate,
                formal_inventory,
            )
            payload = decision.payload if isinstance(decision.payload, dict) else {}
            if environment is None:
                reason = "未绑定当前 scanner formal-audit 或 FormalEnvironment ID"
            elif str(payload.get("old_env") or "") != environment.original_env:
                reason = "original_env 与当前 formal inventory 不一致"
            elif (
                _exact_line_number(payload.get("begin_line")) != environment.start_line
                or _exact_line_number(payload.get("end_line")) != environment.end_line
            ):
                reason = "begin/end 与当前 formal inventory 精确范围不一致"
            elif str(payload.get("source_sha256") or "").strip().lower() != (
                environment.source_sha256
            ):
                reason = "source_sha256 与当前 formal inventory 不一致或缺失"
            elif decision.action == "change-env" and (
                decision.env not in ALLOWED_WRAP_ENVS
                or decision.env.removesuffix("*")
                == environment.original_env.removesuffix("*")
            ):
                reason = "change-env 目标环境不在白名单或与原环境相同"
            elif decision.action == "unwrap" and decision.env:
                reason = "unwrap 不允许携带目标环境"
        elif candidate is None:
            reason = "未绑定当前 scanner candidate ID"
        else:
            # Re-run the current host legalizer on a probe.  Cached ``source``
            # labels are untrusted, and a range that the legalizer would alter
            # is not the exact range that was previously reviewed.
            if decision.action == "wrap" and not exact_current_rule_wrap(decision):
                from .legalize import legalize_decisions

                probe = copy.deepcopy(decision)
                original_span = tuple(decision.body_span or ())
                legalize_decisions(
                    doc,
                    [probe],
                    candidates_by_id,
                    ctx.existing_envs,
                    force=True,
                )
                legalize_error = str(
                    getattr(probe, "_legalize_error", "") or ""
                )
                if legalize_error:
                    reason = f"当前 legalizer 拒绝该 wrap：{legalize_error}"
                elif tuple(probe.body_span or ()) != original_span:
                    reason = "缓存 wrap 范围不是当前 legalizer 的精确合法范围"
            if not reason:
                start, end, reason = _current_candidate_action_span(
                    decision,
                    candidate,
                    ctx,
                    line_count=len(doc.text.split("\n")),
                )
            if not reason:
                expected_hash = _semantic_span_hash(doc, (start, end))
                supplied_hash = str(
                    (decision.payload or {}).get("source_sha256") or ""
                ).strip().lower()
                if supplied_hash != expected_hash:
                    reason = "source_sha256 与当前精确动作范围不一致或缺失"

        if reason:
            line = (
                candidate.span.start_line
                if candidate is not None
                else environment.start_line
                if environment is not None
                else (_interval(decision)[0] or 1)
            )
            invalid.append({
                "candidate_id": decision.candidate_id,
                "line": line,
                "action": decision.action,
                "reason": f"缓存决策未通过当前源绑定：{reason}",
            })
            continue
        seen_ids.add(decision.candidate_id)
        accepted.append(decision)
    return accepted, invalid


def _normalize_theorem_wrap_start(decision: Decision, candidate) -> str:
    """定理/证明包裹必须从扫描器确认的标题行开始，复查不得绕过锚点。"""
    if (
        decision.action != "wrap"
        or candidate is None
        or candidate.kind not in ("theorem-like", "proof")
        or not decision.body_span
    ):
        return ""
    _start, end = decision.body_span
    title_line = candidate.span.start_line
    if end < title_line:
        return "复查包裹范围未覆盖扫描器确认的标题，已保守跳过并等待人工确认"
    decision.body_span = (title_line, end)
    return ""


def _restore_theorem_title_metadata(decision: Decision, candidate) -> None:
    """复用/复查决策也只能使用扫描器从原文确定提取的标题元数据。"""
    if (
        decision.action != "wrap"
        or candidate is None
        or candidate.kind not in ("theorem-like", "proof")
        or not decision.body_span
        or decision.body_span[0] != candidate.span.start_line
    ):
        return
    if candidate.kind == "proof":
        prefix = candidate.payload.get("strip_prefix", "")
        number = candidate.payload.get("proof_arg") or ""
    else:
        prefix = candidate.payload.get("title_prefix", "")
        number = candidate.payload.get("number") or ""
    remainder = str(candidate.payload.get("title_remainder", "")).strip()
    title_line_old = candidate.payload.get("title_line_old", "")
    title_line_new = candidate.payload.get("title_line_new", "")
    decision.optional_arg = str(number)[:120]
    has_body = bool(remainder) or decision.body_span[1] > decision.body_span[0]
    can_rewrite = bool(title_line_old and title_line_new)
    decision.keep_title_text = not ((prefix or can_rewrite) and has_body)
    decision.payload = dict(decision.payload)
    decision.payload["title_prefix"] = prefix if prefix and has_body else ""
    decision.payload["title_line_old"] = (
        title_line_old if can_rewrite and has_body else ""
    )
    decision.payload["title_line_new"] = (
        title_line_new if can_rewrite and has_body else ""
    )


def _restore_proof_qed_metadata(decision: Decision, candidate, doc) -> None:
    """Derive per-proof auto-QED suppression from the final trusted source span."""
    decision.payload = dict(decision.payload)
    # Never trust this structural flag from an AI response, review, or cache.
    decision.payload.pop(SUPPRESS_AUTO_QED_PAYLOAD_KEY, None)
    if (
        decision.action != "wrap"
        or decision.env != "proof"
        or candidate is None
        or candidate.kind != "proof"
        or not decision.body_span
        or decision.body_span[0] != candidate.span.start_line
    ):
        return
    from .legalize import proof_body_has_terminal_explicit_qed

    start, end = decision.body_span
    if proof_body_has_terminal_explicit_qed(doc, start, end):
        decision.payload[SUPPRESS_AUTO_QED_PAYLOAD_KEY] = True


def _adapt_elegantbook_theorem_env(decision: Decision, candidate, ctx: PatchContext) -> None:
    """Use ElegantBook's unnumbered box while preserving an OCR/source number as note."""
    if (
        not ctx.is_elegantbook
        or decision.action != "wrap"
        or candidate is None
        or candidate.kind != "theorem-like"
        or decision.env.endswith("*")
    ):
        return
    starred = f"{decision.env}*"
    if starred in ctx.unnumbered_envs:
        decision.env = starred


def _unsafe_numbered_theorem_reason(decision: Decision, candidate, ctx: PatchContext) -> str:
    """源编号遇到会自动计数或编号语义未知的目标环境时，宁可不包裹。"""
    if decision.action != "wrap" or decision.env == "proof" or candidate is None:
        return ""
    if candidate.kind != "theorem-like" or not candidate.payload.get("number"):
        return ""
    if decision.env in ctx.unnumbered_envs:
        return ""
    if decision.env in ctx.existing_envs:
        return (
            f"源标题含显式编号，但已有 {decision.env} 声明不是无编号环境；"
            "为避免双编号，已保守跳过并等待人工确认"
        )
    if ctx.is_elegantbook:
        return (
            f"源标题含显式编号，但 elegantbook 提供的 {decision.env} 编号语义无法证明安全；"
            "为避免双编号，已保守跳过并等待人工确认"
        )
    return ""


def run_pipeline(
    text: str,
    mode: str = "rule",
    rule_config: RuleConfig = None,
    ai_config: AIConfig = None,
    ai_client=None,
    review_client=None,
    template: str = None,
    template_context: dict = None,
    compile_check: bool = False,
    pack=None,
    exclude: set = None,
    decisions_override: List[Decision] = None,
    ambiguous_override: List[dict] = None,
    ai_notes_override: List[dict] = None,
    progress_callback=None,
    control_callback=None,
    require_compile: bool = False,
    require_compile_when_available: bool = False,
    resource_root: str = None,
    require_resources: bool = False,
    compile_extra_files: dict = None,
    compile_project_main_rel: str = None,
    capture_compile_artifact: bool = False,
    known_structured_envs=None,
    source_pdf_bytes: bytes = b"",
    source_pdf_page_range=None,
    source_visual_provenance: Optional[dict] = None,
    quality_loop: bool = False,
    visual_client=None,
    ocr_project: bool = False,
) -> PipelineResult:
    def control():
        if control_callback:
            control_callback()

    def emit(phase: str, progress: float, message: str, **data):
        control()
        if progress_callback:
            progress_callback(phase, progress, message, data)

    emit("prepare", 0.02, "正在准备文档")
    source_newline = detect_newline(text)
    source_text = normalize_newlines(text)
    text = source_text
    # The host already knows whether an imported project came from OCR.  Keep
    # the historical text heuristic for direct/library callers, but never let
    # an explicitly declared OCR project downgrade itself by losing or hiding
    # the metadata marker in its TEX payload.  AI OCR always owns the complete
    # compile/render/visual gate; callers cannot disable it accidentally.
    explicit_ocr_project = ocr_project is True
    if explicit_ocr_project and mode == "ai":
        quality_loop = True
    source_visual_provenance_info = _verify_source_visual_provenance(
        source_pdf_bytes,
        source_visual_provenance,
    )
    frozen_ocr_metadata = parse_ocr_metadata(source_text)

    def explicit_page_numbers(value: object) -> Optional[Tuple[int, ...]]:
        """Normalize the host-frozen source-page selector for contract checks.

        ``()`` means that the host omitted a selector and the embedded metadata
        may be used.  ``None`` means that a selector was supplied but malformed.
        """
        if value is None:
            return ()
        raw_pages = None
        if isinstance(value, dict):
            raw_pages = value.get("pages")
            if raw_pages is None and {"start", "end"} <= set(value):
                raw_pages = (value.get("start"), value.get("end"))
        else:
            raw_pages = value
        if not isinstance(raw_pages, (list, tuple)) or not raw_pages:
            return None
        if len(raw_pages) == 2 and not isinstance(value, dict):
            try:
                start, end = (int(raw_pages[0]), int(raw_pages[1]))
            except (TypeError, ValueError):
                return None
            if (
                isinstance(raw_pages[0], bool)
                or isinstance(raw_pages[1], bool)
                or start < 1
                or end < start
            ):
                return None
            return tuple(range(start, end + 1))
        if (
            isinstance(value, dict)
            and value.get("pages") is None
            and len(raw_pages) == 2
        ):
            try:
                start, end = (int(raw_pages[0]), int(raw_pages[1]))
            except (TypeError, ValueError):
                return None
            if (
                isinstance(raw_pages[0], bool)
                or isinstance(raw_pages[1], bool)
                or start < 1
                or end < start
            ):
                return None
            return tuple(range(start, end + 1))
        pages: List[int] = []
        for raw_page in raw_pages:
            if isinstance(raw_page, bool):
                return None
            try:
                page = int(raw_page)
            except (TypeError, ValueError):
                return None
            if page < 1 or page in pages:
                return None
            pages.append(page)
        return tuple(pages)

    ocr_project_contract_required = bool(explicit_ocr_project and mode == "ai")
    ocr_project_contract_issues: List[str] = []
    metadata_pages = tuple(frozen_ocr_metadata.get("pages") or ())
    host_pages = explicit_page_numbers(source_pdf_page_range)
    if ocr_project_contract_required:
        if not frozen_ocr_metadata:
            ocr_project_contract_issues.append(
                "OCR AI 项目缺少有效的 LaTeXStruct OCR metadata"
            )
        elif not metadata_pages:
            ocr_project_contract_issues.append("OCR metadata 缺少不可变源页清单")
        if not source_pdf_bytes:
            ocr_project_contract_issues.append("OCR AI 项目缺少不可变原始视觉输入")
        elif source_visual_provenance_info.get("ok") is not True:
            ocr_project_contract_issues.append(
                "OCR AI 项目的原始上传与视觉 PDF provenance 不完整"
            )
        if host_pages is None:
            ocr_project_contract_issues.append("OCR 宿主源页范围记录无效")
        elif host_pages and metadata_pages and host_pages != metadata_pages:
            ocr_project_contract_issues.append(
                "OCR metadata 页清单与宿主冻结的源页范围不一致"
            )
    ocr_project_contract = {
        "required": ocr_project_contract_required,
        "checked": explicit_ocr_project,
        "ok": not ocr_project_contract_issues,
        "explicit_ocr_project": explicit_ocr_project,
        "metadata_present": bool(frozen_ocr_metadata),
        "metadata_pages": list(metadata_pages),
        "host_pages": list(host_pages or ()),
        "source_evidence_present": bool(source_pdf_bytes),
        "issues": ocr_project_contract_issues,
    }
    from .template import normalize_template_id, template_label

    template = normalize_template_id(template)
    template_name = template_label(template) if template else ""
    if template:
        visual_geometry_policy = GEOMETRY_POLICY_TEMPLATE_REFLOW
    elif source_visual_provenance_info.get("source_type") in {"image", "images"}:
        visual_geometry_policy = GEOMETRY_POLICY_DERIVED_IMAGE
    else:
        visual_geometry_policy = GEOMETRY_POLICY_STRICT_SOURCE
    ocr_structure_notes: List[dict] = []
    ocr_structure_patches: List[AppliedPatch] = []
    ocr_equation_evidence_patches: List[AppliedPatch] = []
    ocr_equation_evidence_report = {
        "checked": False,
        "upgraded": False,
        "ok": True,
        "status": "not_requested",
        "evidence_count": 0,
        "evidence": [],
        "issues": [],
        "source_pdf_sha256": "",
    }
    ocr_semantic_notes: List[dict] = []
    ocr_semantic_patches: List[AppliedPatch] = []
    ocr_semantic_report = {
        "checked": False, "ok": True, "issues": [], "operations": 0,
    }
    ocr_semantic_lock_enabled = explicit_ocr_project or is_ocr_document(text)
    if ocr_semantic_lock_enabled:
        if source_pdf_bytes:
            emit("equation-evidence", 0.03, "正在用原始视觉输入复验公式编号位置")
            from .equation_evidence import build_legacy_equation_evidence_ops

            evidence_ops, evidence_result = build_legacy_equation_evidence_ops(
                text,
                source_pdf_bytes,
            )
            ocr_equation_evidence_report = evidence_result.to_dict()
            if evidence_ops:
                evidence_lines = text.split("\n")
                evidence_planned, evidence_rejected = validate_ops(
                    evidence_lines,
                    [(
                        Decision(candidate_id="ocr-equation-evidence", action="none"),
                        evidence_ops,
                    )],
                )
                if not evidence_rejected:
                    upgraded, ocr_equation_evidence_patches, _ = apply_patches(
                        evidence_lines,
                        evidence_planned,
                    )
                    text = "\n".join(upgraded)
                else:
                    reason = (
                        "公式编号证据 metadata 补丁无法复验："
                        f"{evidence_rejected[0].error}"
                    )
                    ocr_equation_evidence_report.update({
                        "ok": False,
                        "upgraded": False,
                        "status": "patch_rejected",
                    })
                    ocr_equation_evidence_report.setdefault("issues", []).append({
                        "line": 1,
                        "reason": reason,
                    })
        emit("outline", 0.035, "正在根据 PDF 大纲校正章节与目录")
        ocr_ops, ocr_structure_notes = build_ocr_structure_ops(text)
        if ocr_ops:
            ocr_lines = text.split("\n")
            ok_planned, ocr_rejected = validate_ops(
                ocr_lines,
                [(Decision(candidate_id="ocr-outline", action="none"), ocr_ops)],
            )
            if not ocr_rejected:
                out, ocr_structure_patches, _ = apply_patches(ocr_lines, ok_planned)
                text = "\n".join(out)
            else:
                ocr_structure_notes.append({
                    "line": 1,
                    "status": "rejected",
                    "reason": f"章节树补丁校验失败，已保留原文：{ocr_rejected[0].error}",
                })
        emit("semantic", 0.045, "正在核对公式编号、前置信息与参考文献清单")
        semantic_ops, ocr_semantic_notes, ocr_semantic_report = (
            build_ocr_semantic_ops(text)
        )
        if semantic_ops:
            semantic_lines = text.split("\n")
            semantic_planned, semantic_rejected = validate_ops(
                semantic_lines,
                [(Decision(candidate_id="ocr-semantic-ir", action="none"), semantic_ops)],
            )
            if not semantic_rejected:
                out, ocr_semantic_patches, _ = apply_patches(
                    semantic_lines, semantic_planned,
                )
                text = "\n".join(out)
            else:
                reason = (
                    "语义 IR 补丁校验失败，已保留该阶段原文："
                    f"{semantic_rejected[0].error}"
                )
                ocr_semantic_notes.append({
                    "line": 1, "status": "rejected", "reason": reason,
                })
                ocr_semantic_report["ok"] = False
                ocr_semantic_report.setdefault("issues", []).append({
                    "line": 1, "reason": reason,
                })
        ocr_semantic_report["notes"] = list(ocr_semantic_notes)
    pre_template_text = text
    template_notes: List[dict] = []
    template_applied = False
    template_patches: List[AppliedPatch] = []
    if template:
        emit("template", 0.05, f"正在检查{template_name}排版")
        from .template import build_template_ops

        t_ops, template_notes = build_template_ops(
            text,
            template=template,
            context=template_context,
        )
        if t_ops:
            t_lines = text.split("\n")
            ok_planned, t_rejected = validate_ops(
                t_lines, [(Decision(candidate_id="tpl", action="none"), t_ops)]
            )
            if not t_rejected:
                out, template_patches, _ = apply_patches(t_lines, ok_planned)
                text = "\n".join(out)
                template_applied = True
            else:
                template_notes.append(
                    {
                        "line": 1,
                        "status": "rejected",
                        "reason": f"模板转换编辑校验失败，已跳过：{t_rejected[0].error}",
                    }
                )

    template_safe = not any(
        note.get("status") == "rejected" for note in template_notes
    )
    transformed_source_text = text

    emit("parse", 0.10, "正在解析 LaTeX 结构")
    doc = parse_latex(text)
    emit("scan", 0.17, "正在扫描定理、证明与章节候选")
    ctx = _build_context(doc, known_structured_envs)
    scan_res = scan(doc, pack, structured_envs=ctx.existing_envs)
    from .formal_inventory import inventory_document

    formal_inventory = inventory_document(doc, structured_envs=ctx.existing_envs)
    candidates_by_id = {c.id: c for c in scan_res.candidates}
    semantic_anchors: List[Decision] = []
    locked_semantic_ids = set()
    ocr_formal_candidate_ids = {
        candidate.id for candidate in scan_res.candidates
        if ocr_semantic_lock_enabled
        and _is_ocr_formal_inventory_candidate(candidate)
    }
    if ocr_semantic_lock_enabled:
        semantic_anchors, locked_semantic_ids = _build_ocr_semantic_anchors(
            doc,
            scan_res,
            ctx,
            rule_config,
            pack,
        )
    emit(
        "scan",
        0.20,
        f"已发现 {len(scan_res.candidates)} 个候选，正在保守判断",
        candidate_total=len(scan_res.candidates),
        processed_candidates=0,
    )
    ambiguous: List[dict] = []
    ai_notes: List[dict] = []
    review_info: Dict = {}
    second_review_enabled = bool(
        mode == "ai" and (ai_config is None or ai_config.review_enabled)
    )
    full_review_requested = bool(quality_loop and mode == "ai")
    full_review_info: Dict = {
        "checked": False,
        "ok": not full_review_requested,
        "enabled": second_review_enabled,
        "requested": full_review_requested,
        "schema": "latexstruct-full-document-review-v1",
        "inventory": formal_inventory.as_dict(),
        "invalid": [],
        "escalations": [],
        "chunks": [],
    }
    if full_review_requested and not second_review_enabled:
        full_review_info.update({
            "status": "USER_DISABLED",
            "skip_reason": "user-disabled",
            "status_message": "用户未启用第二遍复查",
        })
    full_review_locked_ids: set[str] = set()
    ai_degraded = False
    ai_usage: Dict = {}
    decisions_reused = decisions_override is not None
    reused_decision_validation: Dict = {
        "checked": decisions_reused,
        "ok": True,
        "submitted": len(decisions_override or []) if decisions_reused else 0,
        "accepted": 0,
        "invalid": [],
    }

    if decisions_reused:
        cached_decisions = copy.deepcopy(decisions_override or [])
        current_rule_decisions, _current_rule_ambiguous = build_rule_decisions(
            doc,
            scan_res,
            rule_config,
            pack=pack,
        )
        decisions, reuse_invalid = _validate_reused_decisions(
            cached_decisions,
            candidates_by_id,
            formal_inventory,
            doc,
            ctx,
            current_rule_decisions,
        )
        ambiguous = copy.deepcopy(ambiguous_override or [])
        ambiguous.extend(reuse_invalid)
        ai_notes = copy.deepcopy(ai_notes_override or [])
        review_info = {"reused": True}
        reused_decision_validation.update({
            "ok": not reuse_invalid,
            "accepted": len(decisions),
            "invalid": copy.deepcopy(reuse_invalid),
        })
    elif mode == "ai":
        deterministic_kinds = {"bilingual-title", "exercise-section"}
        rule_decisions, ambiguous = build_rule_decisions(doc, scan_res, rule_config, kinds=deterministic_kinds, pack=pack)
        ai_candidates = [
            c for c in scan_res.candidates
            if c.kind in AI_KINDS and c.id not in locked_semantic_ids
        ]
        cfg = ai_config or AIConfig()
        client = ai_client or build_text_client(cfg, "decide")
        try:
            emit(
                "decide", 0.24, "AI 正在逐批判断候选结构",
                candidate_total=len(ai_candidates),
            )

            def decision_progress(state):
                ai_usage["decide"] = state.get("usage", {})
                total = max(1, state.get("total", 0))
                value = 0.24 + 0.30 * state.get("done", 0) / total
                preview_data = {}
                partial_decisions = state.get("_decision_objects")
                if isinstance(partial_decisions, list):
                    # Preview only at completed AI batches. Work on deep copies because
                    # legalization/title restoration intentionally mutates decisions.
                    # A preview failure must never change the verified pipeline result.
                    try:
                        preview_decisions = copy.deepcopy(
                            rule_decisions + partial_decisions
                        )
                        preview_preamble = build_preamble_decision(
                            doc, ctx, preview_decisions
                        )
                        if preview_preamble is not None:
                            preview_decisions.append(preview_preamble)
                        preview_out, preview_applied, _, _ = _apply_decisions(
                            doc,
                            preview_decisions,
                            ctx,
                            [],
                            candidates_by_id=candidates_by_id,
                        )
                        preview_data = {
                            "preview": "\n".join(preview_out),
                            "preview_label": (
                                f"批次草稿：已检查 {state.get('done', 0)}/"
                                f"{state.get('total', 0)} 个 AI 候选"
                            ),
                            "applied": len(preview_applied),
                        }
                    except Exception:  # noqa: BLE001
                        preview_data = {}
                emit(
                    "decide", value,
                    f"AI 已判断 {state.get('done', 0)}/{state.get('total', 0)} 个候选",
                    usage={"decide": state.get("usage", {})},
                    completed_candidates=state.get("decisions", []),
                    processed_candidates=state.get("done", 0),
                    candidate_total=state.get("total", 0),
                    ambiguous=state.get("ambiguous", 0),
                    **preview_data,
                )

            ai_decisions, ai_amb, ai_notes, usage = decide_candidates(
                client, doc, ctx, ai_candidates, cfg, mode,
                progress_callback=decision_progress,
                control_callback=control,
            )
            decisions = rule_decisions + semantic_anchors + ai_decisions
            ambiguous += ai_amb
            ai_usage["decide"] = usage
        except LLMError as e:
            if client.last_usage:
                from ..pricing import add_usage

                add_usage(
                    ai_usage.setdefault("decide", {}),
                    client.last_usage,
                    getattr(client.cfg, "model", ""),
                )
            emit(
                "error",
                0.24,
                "AI 结构化未完成，原项目保持不变",
                usage=ai_usage,
            )
            guidance = (
                "Codex 安装、ChatGPT 登录、订阅额度与网络"
                if cfg.analysis_backend == "codex_cli"
                else "API Key、模型与网络"
            )
            raise LLMError(
                f"AI 结构化未完成，未使用规则模式替代；请检查{guidance}后重试：{e}"
            ) from None
    else:
        emit("decide", 0.48, "正在用保守规则生成修改建议")
        decisions, ambiguous = build_rule_decisions(doc, scan_res, rule_config, pack=pack)
        emit(
            "decide",
            0.54,
            f"规则已检查 {len(scan_res.candidates)} 个候选",
            candidate_total=len(scan_res.candidates),
            processed_candidates=len(scan_res.candidates),
            completed_candidates=[d.candidate_id for d in decisions],
            ambiguous=len(ambiguous),
        )

    if mode == "ai" and semantic_anchors:
        # Cached v1.2.1 decisions and model output are both subordinate to the
        # current source-derived anchor.  Removing stale notes/manual items for
        # these IDs prevents one candidate from appearing as both safely applied
        # and unresolved.  Explicit user rejection is applied later via exclude.
        decisions = _merge_semantic_anchors(decisions, semantic_anchors)
        ambiguous = [
            item for item in ambiguous
            if str(item.get("candidate_id", "") or "") not in locked_semantic_ids
        ]
        ai_notes = [
            item for item in ai_notes
            if str(item.get("candidate_id", "") or "") not in locked_semantic_ids
        ]

    quality_review_client = None
    if (
        quality_loop
        and mode == "ai"
        and second_review_enabled
        and not ai_degraded
    ):
        from .full_review import (
            reconcile_full_review_decisions,
            run_full_document_review,
        )

        cfg = ai_config or AIConfig()
        quality_review_client = review_client or build_text_client(cfg, "review")
        emit(
            "full-review",
            0.55,
            "正在逐行独立盘点全文，而不是只复查初次候选",
            inventory=formal_inventory.as_dict().get("counts", {}),
        )

        def full_review_progress(state):
            ai_usage["full_document_review"] = state.get("usage", {})
            total = max(1, int(state.get("total") or 1))
            emit(
                "full-review",
                0.55 + 0.04 * int(state.get("done") or 0) / total,
                f"全文独立复核 {state.get('done', 0)}/{total} 个分段",
                usage={
                    "decide": ai_usage.get("decide", {}),
                    "full_document_review": state.get("usage", {}),
                },
            )

        full_result = run_full_document_review(
            quality_review_client,
            doc,
            formal_inventory,
            candidates_by_id,
            cfg,
            progress_callback=full_review_progress,
            control_callback=control,
        )
        decisions = reconcile_full_review_decisions(decisions, full_result)
        # A source-derived OCR semantic anchor is stronger than a model verdict.
        # Full-document review still has to inspect and answer the item, but it
        # cannot replace the canonical, hash-bound span with a newly selected
        # range.  Reinsert those anchors before any later review stage.
        if semantic_anchors:
            decisions = _merge_semantic_anchors(decisions, semantic_anchors)
        ai_notes = [
            note for note in ai_notes
            if str(note.get("candidate_id") or "")
            not in set(full_result.preserved_candidate_ids)
        ] + list(full_result.notes)
        for item in full_result.invalid + full_result.escalations:
            candidate_id = str(
                item.get("candidate_id") or item.get("item_id") or ""
            )
            candidate = candidates_by_id.get(candidate_id)
            ambiguous.append({
                "candidate_id": candidate_id if candidate is not None else "",
                "inventory_id": candidate_id,
                "line": int(item.get("line") or 1),
                "reason": str(item.get("reason") or "全文独立复核未完成")[:300],
            })
        full_review_info = full_result.to_dict()
        full_review_info.update({
            "enabled": True,
            "requested": True,
            "status": "COMPLETED" if full_result.checked else "INCOMPLETE",
        })
        full_review_locked_ids = set(full_result.reviewed_candidate_ids)
        ai_usage["full_document_review"] = full_result.usage

    # Revalidate cached/model ranges before deriving theorem declarations.  A
    # v1.2.1 cache may not know about newly locked OCR formal entries, so its
    # old preamble cannot be trusted to contain every required environment.
    if candidates_by_id:
        from .legalize import legalize_decisions

        legalize_decisions(
            doc, decisions, candidates_by_id, ctx.existing_envs
        )
    decisions = [
        decision for decision in decisions if decision.action != "preamble-add"
    ]
    pre = build_preamble_decision(
        doc,
        ctx,
        [
            decision for decision in decisions
            if not getattr(decision, "_legalize_error", "")
        ],
    )
    if pre is not None:
        decisions.append(pre)
    for d in decisions:
        if d.action == "convert-to-exercise-env" and not d.env:
            d.env = ctx.exercise_env
    user_rejected: List[Decision] = []
    if exclude:
        user_rejected = [d for d in decisions if d.candidate_id in exclude]
        decisions = [d for d in decisions if d.candidate_id not in exclude]  # 单项拒绝（审阅）

    emit("patch", 0.60, "正在生成并校验补丁", decision_total=len(decisions))
    out, applied, rejected, dropped = _apply_decisions(
        doc, decisions, ctx, ambiguous, candidates_by_id=candidates_by_id
    )
    for d, reason in dropped:
        ambiguous.append({"candidate_id": d.candidate_id, "line": _interval(d)[0] or 1, "reason": reason})
    for s in scan_res.skipped:
        ambiguous.append({"candidate_id": "", "line": s.get("line"), "reason": f"{s.get('reason')}（{s.get('kind')}）"})

    initial_draft = "\n".join(out)
    emit(
        "patch",
        0.64,
        f"已安全应用 {len(applied)} 项，正在复查草稿",
        preview=initial_draft,
        preview_label=(
            "初步草稿（等待 AI 复查）"
            if mode == "ai" and not decisions_reused
            else "规则草稿（等待安全检查）"
        ),
        applied=len(applied),
        rejected=len(rejected),
        ambiguous=len(ambiguous),
        completed_candidates=[d.candidate_id for d in decisions],
        audit_stage={
            "role": "ai_analyzed" if mode == "ai" else "rule_analyzed",
            "text": initial_draft,
        },
    )

    active_semantic_anchors = [
        decision for decision in decisions
        if isinstance(decision.payload, dict)
        and DETERMINISTIC_SEMANTIC_ANCHOR_KEY in decision.payload
    ]
    active_locked_semantic_ids = {
        decision.candidate_id for decision in active_semantic_anchors
    }
    active_full_review_decisions = [
        copy.deepcopy(decision) for decision in decisions
        if decision.source == "full-review"
    ]
    active_full_review_decision_ids = {
        decision.candidate_id for decision in active_full_review_decisions
    }
    reviewable_applied = [
        patch for patch in applied
        if patch.decision.candidate_id not in active_locked_semantic_ids
        and patch.decision.candidate_id not in full_review_locked_ids
        and patch.decision.candidate_id not in active_full_review_decision_ids
        and patch.decision.candidate_id in candidates_by_id
    ]
    review_executed = False

    # AI 复查（默认开启）。即使没有补丁，只要初次 AI 留下 none/歧义项，
    # 也必须给复查器真实源片段；否则漏答会被静默当作整批通过。
    if (
        mode == "ai"
        and (ai_config is None or ai_config.review_enabled)
        and (reviewable_applied or ai_notes or ambiguous)
        and not ai_degraded
        and not decisions_reused
    ):
        review_executed = True
        cfg = ai_config or AIConfig()
        rclient = (
            quality_review_client
            or review_client
            or build_text_client(cfg, "review")
        )
        # 漏报抽查：AI 判定"无需处理"的候选一并交复查复核（可 missed-extra 反悔）
        review_ambiguous = [
            item for item in ambiguous
            if str(item.get("candidate_id") or "") not in full_review_locked_ids
        ] + [
            {"candidate_id": n.get("candidate_id", ""), "line": n.get("line", 1),
             "reason": "AI 判定无需处理，请复核是否漏包：" + str(n.get("reason", ""))[:80]}
            for n in ai_notes
            if str(n.get("candidate_id") or "") not in full_review_locked_ids
        ]
        try:
            def review_progress(state):
                ai_usage["review"] = state.get("usage", {})
                emit(
                    "review",
                    0.69 + 0.13 * min(
                        1, state.get("round", 1) / max(1, state.get("rounds", 1))
                    ),
                    f"AI 正在复查第 {state.get('round', 1)} 轮",
                    usage={
                        "decide": ai_usage.get("decide", {}),
                        "review": state.get("usage", {}),
                    },
                    review_findings=state.get("findings", 0),
                )

            review_decisions = [
                decision for decision in decisions
                if decision.candidate_id not in active_locked_semantic_ids
                and decision.candidate_id not in full_review_locked_ids
                and decision.candidate_id not in active_full_review_decision_ids
            ]

            def review_apply(review_ds):
                full_decisions = _merge_semantic_anchors(
                    review_ds,
                    active_full_review_decisions,
                )
                full_decisions = _merge_semantic_anchors(
                    full_decisions,
                    active_semantic_anchors,
                )
                review_out, review_applied, review_rejected, review_dropped = (
                    _apply_decisions(
                        doc,
                        full_decisions,
                        ctx,
                        ambiguous,
                        candidates_by_id=candidates_by_id,
                    )
                )
                # Locked OCR spans are present in every preview but are not
                # exposed as editable review targets.  Thus a model cannot
                # expand their range, change their kind, or remove them.
                return (
                    review_out,
                    [
                        patch for patch in review_applied
                        if patch.decision.candidate_id not in active_locked_semantic_ids
                        and patch.decision.candidate_id
                        not in active_full_review_decision_ids
                    ],
                    [
                        patch for patch in review_rejected
                        if patch.decision.candidate_id not in active_locked_semantic_ids
                        and patch.decision.candidate_id
                        not in active_full_review_decision_ids
                    ],
                    [
                        item for item in review_dropped
                        if item[0].candidate_id not in active_locked_semantic_ids
                        and item[0].candidate_id
                        not in active_full_review_decision_ids
                    ],
                )

            review_info = run_review(
                rclient,
                doc,
                ctx,
                review_decisions,
                review_apply,
                review_ambiguous,
                cfg,
                mode,
                progress_callback=review_progress,
                control_callback=control,
                candidates_by_id=candidates_by_id,
                preserve_pending_ids={
                    str(note.get("candidate_id", "") or "")
                    for note in ai_notes
                    if str(note.get("candidate_id", "") or "")
                    and str(note.get("candidate_id", "") or "")
                    not in full_review_locked_ids
                },
            )
            out = review_info["out"]
            applied = review_info["applied"]
            rejected = review_info["rejected"]
            decisions = _merge_semantic_anchors(
                review_info["decisions"],
                active_full_review_decisions,
            )
            decisions = _merge_semantic_anchors(
                decisions,
                active_semantic_anchors,
            )
            # wrong-env / missed-extra 可能改变最终需要的定理环境。初次决策前
            # 生成的 preamble-add 已经陈旧，必须按最后一轮决策重建；否则会得到
            # ``\begin{lemma}`` 却没有 ``\newtheorem*{lemma}`` 的不可编译结果。
            decisions = [d for d in decisions if d.action != "preamble-add"]
            final_pre = build_preamble_decision(
                doc,
                ctx,
                [
                    decision for decision in decisions
                    if not getattr(decision, "_legalize_error", "")
                ],
            )
            if final_pre is not None:
                decisions.append(final_pre)
            out, applied, rejected, final_dropped = _apply_decisions(
                doc,
                decisions,
                ctx,
                ambiguous,
                candidates_by_id=candidates_by_id,
            )
            for d, reason in final_dropped:
                item = {
                    "candidate_id": d.candidate_id,
                    "line": _interval(d)[0] or 1,
                    "reason": reason,
                }
                if not any(
                    old.get("candidate_id") == item["candidate_id"]
                    and old.get("reason") == item["reason"]
                    for old in ambiguous
                ):
                    ambiguous.append(item)
            review_info["out"] = out
            review_info["applied"] = applied
            review_info["rejected"] = rejected
            review_info["decisions"] = decisions
            ai_usage["review"] = review_info["usage"]
            for escalation in review_info.get("escalations", []):
                if not any(
                    old.get("candidate_id") == escalation.get("candidate_id")
                    and old.get("reason") == escalation.get("reason")
                    for old in ambiguous
                ):
                    ambiguous.append(escalation)
            # 安全恢复的 missed-extra 已经成为最终 applied Decision；初次 none/
            # 漏答留下的说明和人工项不应继续出现在最终报告，否则同一 candidate
            # 会同时显示“已应用”和“仍待确认”。只清理由复查实际应用成功的 ID；
            # 被最终安全门拒绝的 review 决策仍保留人工项。
            reviewed_applied_ids = {
                ap.decision.candidate_id
                for ap in applied
                if ap.decision.source == "review"
            }
            if reviewed_applied_ids:
                ai_notes = [
                    note for note in ai_notes
                    if note.get("candidate_id") not in reviewed_applied_ids
                ]
                ambiguous = [
                    item for item in ambiguous
                    if item.get("candidate_id") not in reviewed_applied_ids
                ]
            # A valid should-remove or pending-ok finding is an explicit review
            # answer to preserve the source.  Clear the stale initial ambiguity
            # for every such candidate, then retain an existing action=none note
            # or create a review-sourced note.  Cached reruns therefore have both
            # full candidate coverage and no failed Decision to reapply.
            preserved_findings = review_info.get("preserved_findings") or {}
            preserved_ids = {
                str(candidate_id)
                for candidate_id in review_info.get("preserved_candidate_ids", [])
            }
            if preserved_ids:
                ambiguous = [
                    item for item in ambiguous
                    if str(item.get("candidate_id", "") or "") not in preserved_ids
                ]
            for candidate_id in sorted(preserved_ids):
                if any(
                    note.get("candidate_id") == candidate_id for note in ai_notes
                ):
                    continue
                candidate = candidates_by_id.get(candidate_id)
                finding = preserved_findings.get(candidate_id) or {}
                ai_notes.append({
                    "candidate_id": candidate_id,
                    "line": candidate.span.start_line if candidate is not None else 1,
                    "reason": str(finding.get("reason", "复查确认应保留原文"))[:120],
                    "confidence": 1.0,
                    "source": "review",
                })
        except LLMError as e:
            if rclient.last_usage:
                from ..pricing import add_usage

                add_usage(
                    ai_usage.setdefault("review", {}),
                    rclient.last_usage,
                    getattr(rclient.cfg, "model", ""),
                )
            emit(
                "error",
                0.69,
                "AI 复查未完成，原项目保持不变",
                usage=ai_usage,
            )
            guidance = (
                "Codex 安装、ChatGPT 登录、订阅额度与网络"
                if cfg.analysis_backend == "codex_cli"
                else "复查模型与网络"
            )
            raise LLMError(
                f"AI 复查未完成，未保存未经完整复查的草稿；请检查{guidance}后重试：{e}"
            ) from None

    result_text = "\n".join(out)
    visual_loop_required = bool(
        quality_loop
        and mode == "ai"
        and ocr_semantic_lock_enabled
    )
    visual_loop_info: Dict = {
        "schema": "latexstruct-compile-render-visual-repair-v1",
        "required": visual_loop_required,
        "geometry_policy": visual_geometry_policy,
        "checked": False,
        "ok": not visual_loop_required,
        "rounds": [],
        "repair_count": 0,
        "invalid": [],
        "unresolved": [],
    }
    if visual_loop_required and ocr_project_contract.get("ok") is not True:
        visual_loop_info["unresolved"].extend({
            "round": 0,
            "reason": issue,
        } for issue in ocr_project_contract.get("issues", []))
    quality_loop_compile_cache = None
    if (
        visual_loop_required
        and not visual_loop_info["unresolved"]
        and not source_pdf_bytes
    ):
        visual_loop_info["unresolved"].append({
            "round": 0,
            "reason": "OCR 核心质量闭环缺少不可变源 PDF，不能跳过逐页视觉复核",
        })
    elif (
        visual_loop_required
        and not visual_loop_info["unresolved"]
        and compile_project_main_rel
    ):
        visual_loop_info["unresolved"].append({
            "round": 0,
            "reason": "OCR 文件夹工程尚不能建立唯一源页映射，已阻止伪装为视觉闭环完成",
        })
    elif visual_loop_required:
        if source_pdf_page_range is None and not visual_loop_info["unresolved"]:
            frozen_pages = list(
                (parse_ocr_metadata(transformed_source_text) or {}).get("pages")
                or []
            )
            if frozen_pages:
                source_pdf_page_range = {"pages": frozen_pages}
            else:
                visual_loop_info["unresolved"].append({
                    "round": 0,
                    "reason": "OCR metadata 没有可复验的源页范围",
                })
        if visual_loop_info["unresolved"]:
            source_pdf_page_range = None
        else:
            # A visual loop without a real compiler artifact is not a quality loop.
            # Force capture for the immutable final evidence even when the caller did
            # not explicitly request a preview.
            compile_check = True
            capture_compile_artifact = True
            emit("quality-compile", 0.82, "正在编译全文并逐页视觉复核")
            from .compilecheck import compile_latex
            from .quality_loop import reconcile_visual_repairs
            from .visual_quality import (
                CANDIDATE_SCOPE_REFLOW,
                CANDIDATE_SCOPE_SELECTED_RANGE,
                VisualQualityStatus,
                evaluate_visual_quality,
            )
            from .visual_review import audit_compiled_pages

            # The explicit text-review opt-out also forbids reusing a supplied
            # review client as the visual client.  OCR hosts provide a distinct
            # visual client, so compile/render/visual evidence can still run.
            vclient = visual_client
            if vclient is None and second_review_enabled:
                vclient = quality_review_client or review_client
            if not callable(getattr(vclient, "chat_vision_json_bytes", None)):
                raise LLMError(
                    "核心质量闭环需要支持图片输入的视觉模型；"
                    "当前配置只能完成文字分析，未保存未经逐页复核的结果"
                )
            visual_candidate_scope = (
                CANDIDATE_SCOPE_REFLOW
                if visual_geometry_policy == GEOMETRY_POLICY_TEMPLATE_REFLOW
                else CANDIDATE_SCOPE_SELECTED_RANGE
            )
            visual_loop_info["candidate_scope"] = visual_candidate_scope

            max_repairs = 2
            for round_index in range(1, max_repairs + 2):
                control()
                compiled_round = compile_latex(
                    result_text,
                    extra_files=compile_extra_files,
                    include_pdf=True,
                )
                candidate_pdf = compiled_round.get("pdf_bytes", b"")
                if not isinstance(candidate_pdf, (bytes, bytearray, memoryview)):
                    candidate_pdf = b""
                candidate_pdf = bytes(candidate_pdf)
                compile_public = {
                    key: value for key, value in compiled_round.items()
                    if key != "pdf_bytes"
                }
                round_record = {
                    "round": round_index,
                    "tex_sha256": hashlib.sha256(
                        result_text.encode("utf-8")
                    ).hexdigest(),
                    "compile": compile_public,
                    "deterministic": {},
                    "ai_audit": {},
                    "repair_ids": [],
                }
                visual_loop_info["rounds"].append(round_record)
                preview_status = str(compiled_round.get("preview_status") or "")
                if (
                    compiled_round.get("available") is not True
                    or compiled_round.get("ok") is not True
                    or preview_status != "COMPILED"
                    or not candidate_pdf
                ):
                    visual_loop_info["unresolved"].append({
                        "round": round_index,
                        "reason": "没有得到完整、成功且可逐页复核的 LaTeX 编译 PDF",
                    })
                    quality_loop_compile_cache = (
                        result_text,
                        compiled_round,
                        dict(compile_extra_files or {}),
                    )
                    break

                deterministic = evaluate_visual_quality(
                    source_pdf_bytes,
                    candidate_pdf,
                    source_pdf_page_range,
                    preview_status=preview_status,
                    source_geometry_authoritative=(
                        source_visual_provenance_info.get("source_type")
                        not in {"image", "images"}
                        # An explicit layout-changing template owns the output
                        # paper geometry.  The source size remains evidence and
                        # must be closed by the page model, but cannot be a hard
                        # corruption error merely because the requested target
                        # uses a different stock size.
                        and not bool(template)
                    ),
                    geometry_policy=visual_geometry_policy,
                    candidate_scope=visual_candidate_scope,
                )
                round_record["deterministic"] = deterministic.to_dict()
                if deterministic.status in {
                    VisualQualityStatus.FAIL,
                    VisualQualityStatus.UNAVAILABLE,
                }:
                    visual_loop_info["unresolved"].append({
                        "round": round_index,
                        "reason": (
                            "确定性逐页检查发现缺页、空白、乱码、异常尺寸、"
                            "源页复用或渲染不可用"
                        ),
                        "status": deterministic.status.value,
                    })
                    quality_loop_compile_cache = (
                        result_text,
                        compiled_round,
                        dict(compile_extra_files or {}),
                    )
                    break

                visual_usage_before_round = dict(
                    ai_usage.get("visual_review") or {}
                )

                def visual_progress(state):
                    total = max(1, int(state.get("total") or 1))
                    emit(
                        "quality-visual",
                        0.825 + 0.045 * int(state.get("done") or 0) / total,
                        f"逐页视觉复核 {state.get('done', 0)}/{total} 页",
                        usage={
                            **ai_usage,
                            "visual_review": _merge_usage_summaries(
                                visual_usage_before_round,
                                state.get("usage", {}),
                            ),
                        },
                    )

                visual_audit = audit_compiled_pages(
                    vclient,
                    source_pdf_bytes=source_pdf_bytes,
                    candidate_pdf_bytes=candidate_pdf,
                    page_range=source_pdf_page_range,
                    source_text=transformed_source_text,
                    inventory=formal_inventory,
                    deterministic_report=deterministic.to_dict(),
                    source_label=(
                        "SOURCE IMAGE"
                        if source_visual_provenance_info.get("source_type")
                        in {"image", "images"}
                        else "SOURCE PDF"
                    ),
                    candidate_scope=visual_candidate_scope,
                    # Three independent full-resolution page pairs share one
                    # transport/model startup.  Each response remains bound to
                    # the frozen mapping and is validated fail-closed.
                    vision_batch_size=3,
                    progress_callback=visual_progress,
                    control_callback=control,
                )
                round_record["ai_audit"] = visual_audit.to_dict()
                ai_usage["visual_review"] = _merge_usage_summaries(
                    visual_usage_before_round,
                    visual_audit.usage,
                )
                quality_loop_compile_cache = (
                    result_text,
                    compiled_round,
                    dict(compile_extra_files or {}),
                )
                if visual_audit.invalid or visual_audit.unresolved:
                    visual_loop_info["invalid"].extend(visual_audit.invalid)
                    visual_loop_info["unresolved"].extend(visual_audit.unresolved)
                    break
                if not visual_audit.suggestions:
                    expected_visual_review_pages = sum(
                        page.candidate_page is not None
                        for page in deterministic.pages
                    )
                    visual_loop_info["checked"] = visual_audit.checked
                    visual_loop_info["ok"] = bool(
                        visual_audit.checked
                        and visual_audit.ok
                        and visual_audit.page_count == expected_visual_review_pages
                    )
                    if not visual_loop_info["ok"]:
                        visual_loop_info["unresolved"].append({
                            "round": round_index,
                            "reason": "视觉复核页数或最终结论不完整",
                        })
                    break
                if round_index > max_repairs:
                    visual_loop_info["unresolved"].append({
                        "round": round_index,
                        "reason": "两轮定点修复后仍有视觉结构问题",
                    })
                    break

                plan = reconcile_visual_repairs(
                    decisions,
                    visual_audit.suggestions,
                    source_text=transformed_source_text,
                    inventory=formal_inventory,
                    candidates_by_id=candidates_by_id,
                )
                if not plan.ok:
                    visual_loop_info["invalid"].extend(plan.invalid)
                    break
                repaired_decisions = [
                    decision for decision in plan.decisions
                    if decision.action != "preamble-add"
                ]
                repaired_pre = build_preamble_decision(
                    doc,
                    ctx,
                    [
                        decision for decision in repaired_decisions
                        if not getattr(decision, "_legalize_error", "")
                    ],
                )
                if repaired_pre is not None:
                    repaired_decisions.append(repaired_pre)
                repaired_out, repaired_applied, repaired_rejected, repaired_dropped = (
                    _apply_decisions(
                        doc,
                        repaired_decisions,
                        ctx,
                        ambiguous,
                        candidates_by_id=candidates_by_id,
                    )
                )
                repaired_text = "\n".join(repaired_out)
                visual_action_ids = {
                    decision.candidate_id for decision in repaired_decisions
                    if decision.source == "visual-review"
                }
                failed_visual_actions = {
                    patch.decision.candidate_id for patch in repaired_rejected
                    if patch.decision.source == "visual-review"
                } | {
                    decision.candidate_id for decision, _reason in repaired_dropped
                    if decision.source == "visual-review"
                }
                applied_visual_actions = {
                    patch.decision.candidate_id for patch in repaired_applied
                    if patch.decision.source == "visual-review"
                }
                if (
                    repaired_text == result_text
                    or failed_visual_actions
                    or not visual_action_ids.issubset(applied_visual_actions)
                ):
                    visual_loop_info["invalid"].append({
                        "round": round_index,
                        "reason": "视觉定点修复未能完整通过可逆补丁安全门",
                        "failed_candidate_ids": sorted(failed_visual_actions),
                    })
                    break
                decisions = repaired_decisions
                out = repaired_out
                applied = repaired_applied
                rejected = repaired_rejected
                result_text = repaired_text
                round_record["repair_ids"] = list(plan.repair_ids)
                visual_loop_info["repair_count"] += len(plan.repair_ids)
                if plan.preserved_candidate_ids:
                    preserved_set = set(plan.preserved_candidate_ids)
                    ambiguous = [
                        item for item in ambiguous
                        if str(item.get("candidate_id") or "") not in preserved_set
                    ]
                    ai_notes = [
                        item for item in ai_notes
                        if str(item.get("candidate_id") or "") not in preserved_set
                    ] + [
                        {
                            "candidate_id": candidate_id,
                            "line": candidates_by_id[candidate_id].span.start_line,
                            "reason": "逐页视觉复核确认该新增环境属于多套，已可逆撤销",
                            "confidence": 0.98,
                            "source": "visual-review",
                        }
                        for candidate_id in plan.preserved_candidate_ids
                        if candidate_id in candidates_by_id
                    ]

    final_document = parse_latex(result_text)
    final_context = _build_context(final_document, known_structured_envs)
    final_formal_inventory = inventory_document(
        final_document,
        structured_envs=final_context.existing_envs,
    )
    final_formal_blockers = [
        finding.as_dict() for finding in final_formal_inventory.findings
        if finding.kind in {"missing", "wrong-env", "overwide", "duplicate"}
    ]
    final_formal_safe = bool(not quality_loop or not final_formal_blockers)

    emit(
        "draft", 0.84, "结构化草稿已生成，正在执行安全检查",
        preview=result_text,
        preview_label="未完成安全检查的草稿",
        applied=len(applied),
        rejected=len(rejected),
        ambiguous=len(ambiguous),
        usage=ai_usage,
        audit_stage={
            "role": "ai_reviewed" if review_executed else "analyzed_current",
            "text": result_text,
        },
    )
    from .invariants import check_image_resources, check_invariants

    verification = {
        "content_invariant": content_invariant(
            source_text.split("\n"),
            out,
            ocr_equation_evidence_patches
            + ocr_structure_patches
            + ocr_semantic_patches
            + template_patches
            + applied,
        ),
        "env_balance": compare_env_balance(transformed_source_text, result_text),
        "braces": compare_braces(transformed_source_text, result_text),
        "invariants": check_invariants(
            transformed_source_text,
            result_text,
            check_body_text=ocr_semantic_lock_enabled,
            pack=pack,
        ),
        "known_issues": known_issues(result_text),
        "display_tags": check_display_tag_safety(result_text),
        "ocr_structure": check_ocr_structure(result_text),
        "ocr_project_contract": ocr_project_contract,
        "ocr_equation_source_evidence": ocr_equation_evidence_report,
        "source_visual_provenance": source_visual_provenance_info,
        "ocr_semantic_ir": ocr_semantic_report,
        "template": {
            "ok": template_safe,
            "applied": template_applied,
            "issues": [
                note for note in template_notes if note.get("status") == "rejected"
            ],
        },
        "resources": check_image_resources(result_text, resource_root),
        "formal_inventory": formal_inventory.as_dict(),
        "final_formal_inventory": final_formal_inventory.as_dict(),
        "full_document_review": full_review_info,
        "visual_quality_loop": visual_loop_info,
        "ai_degraded": ai_degraded,
        "ai_usage": ai_usage,
        "decisions_reused": decisions_reused,
        "reused_decision_validation": reused_decision_validation,
        "compile_required": bool(require_compile),
        "compile_required_when_available": bool(
            require_compile_when_available or template_applied
        ),
        "resources_required": bool(require_resources),
    }
    compile_check = bool(
        compile_check
        or require_compile
        or require_compile_when_available
        or template_applied
    )
    compiled_pdf = b""
    compiled_pdf_name = ""
    raw_compiled_pdf = b""
    raw_compiled_pdf_name = ""
    compiled_candidate_tex = ""
    compiled_candidate_extra_files: Dict[str, bytes] = {}
    compiled_before_tex = ""
    compiled_before_extra_files: Dict[str, bytes] = {}
    if compile_check:
        emit("compile", 0.91, "正在比较编译结果")
        from .compilecheck import compile_latex

        def compile_snapshot(
            snapshot: str,
            *,
            capture_pdf: bool = False,
        ) -> Tuple[Dict, str, Dict[str, bytes]]:
            """Compile either a single TEX file or a reconstructed folder snapshot.

            The analysis representation for folder projects deliberately contains
            inline ``LATEXSTRUCT-FILE`` blocks *and* retains the original
            ``\\input`` commands.  Compiling that flattened representation would
            duplicate every child file; compiling it without the children makes
            perfectly valid projects fail with ``File ... not found``.  Re-split
            each before/after snapshot and overlay its processed TEX files on the
            byte-for-byte original resources instead.
            """
            if not compile_project_main_rel:
                if capture_pdf:
                    compiled = compile_latex(
                        snapshot, extra_files=compile_extra_files, include_pdf=True,
                    )
                else:
                    compiled = compile_latex(
                        snapshot, extra_files=compile_extra_files,
                    )
                return compiled, snapshot, dict(compile_extra_files or {})

            from .project import project_compile_inputs, safe_project_relpath, split_project

            main_rel = safe_project_relpath(compile_project_main_rel)
            per_file = split_project(snapshot)
            compiled_candidate, files = project_compile_inputs(
                dict(compile_extra_files or {}), main_rel, per_file
            )
            if capture_pdf:
                compiled = compile_latex(
                    compiled_candidate, extra_files=files, include_pdf=True
                )
            else:
                compiled = compile_latex(compiled_candidate, extra_files=files)
            return compiled, compiled_candidate, files

        # For OCR, compile the exact imported raw transcription so
        # COMPILE_RAW_LOG really corresponds to stages/00_raw_ocr.tex.  Other
        # workflows keep the pre-template baseline used by template comparison.
        compile_before_text = source_text if ocr_semantic_lock_enabled else pre_template_text
        compile_impl_is_parallel_safe = (
            getattr(compile_latex, "__module__", "")
            == "latexstruct.core.compilecheck"
            and getattr(compile_latex, "__name__", "") == "compile_latex"
        )
        if quality_loop_compile_cache is not None:
            cached_text, cached_compile, cached_files = quality_loop_compile_cache
            if cached_text != result_text:
                raise ValueError("视觉闭环编译缓存与最终候选 TEX 不一致")
            before_result = compile_snapshot(
                compile_before_text,
                capture_pdf=bool(
                    capture_compile_artifact and ocr_semantic_lock_enabled
                ),
            )
            after_result = (
                cached_compile,
                result_text,
                cached_files,
            )
        elif compile_impl_is_parallel_safe:
            # Both snapshots use isolated temporary directories and immutable
            # inputs, so running the real compiler processes together removes
            # a full compile latency from the interactive critical path.
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=2) as executor:
                before_future = executor.submit(
                    compile_snapshot,
                    compile_before_text,
                    capture_pdf=bool(
                        capture_compile_artifact and ocr_semantic_lock_enabled
                    ),
                )
                after_future = executor.submit(
                    compile_snapshot,
                    result_text,
                    capture_pdf=capture_compile_artifact,
                )
                before_result = before_future.result()
                after_result = after_future.result()
        else:
            # Patched/custom compiler callables are not assumed thread-safe.
            before_result = compile_snapshot(
                compile_before_text,
                capture_pdf=bool(
                    capture_compile_artifact and ocr_semantic_lock_enabled
                ),
            )
            after_result = compile_snapshot(
                result_text,
                capture_pdf=capture_compile_artifact,
            )
        (
            verification["compile_before"],
            compiled_before_tex,
            compiled_before_extra_files,
        ) = before_result
        (
            verification["compile_after"],
            compiled_candidate_tex,
            compiled_candidate_extra_files,
        ) = after_result

        def normalize_compile_record(record: Dict, *, log_path: str) -> None:
            """Fill the stable audit vocabulary without inventing success."""
            record["engine"] = str(
                record.get("engine")
                or ("xelatex" if record.get("available") else "")
            )
            record["passes_attempted"] = int(
                record.get("passes_attempted")
                or record.get("passes_completed")
                or 0
            )
            exit_code = record.get("exit_code", record.get("return_code"))
            if exit_code is None and record.get("ok") is True:
                exit_code = 0
            record["exit_code"] = exit_code
            record["page_count"] = int(
                record.get("page_count") or record.get("pages") or 0
            )
            errors = record.get("errors")
            record["fatal_error"] = str(
                record.get("fatal_error")
                or (
                    errors[0]
                    if isinstance(errors, list) and errors
                    else ""
                )
            )
            record["log_path"] = log_path
            input_manifest = record.get("input_manifest")
            if isinstance(input_manifest, dict):
                record["compile_input_sha256"] = str(
                    record.get("compile_input_sha256")
                    or input_manifest.get("manifest_sha256")
                    or ""
                )
            else:
                record.setdefault("compile_input_sha256", "")
            record.setdefault("pdf_sha256", "")

        normalize_compile_record(
            verification["compile_before"],
            log_path=(
                "audit/compile_raw.log"
                if ocr_semantic_lock_enabled
                else "audit/compile_source.log"
            ),
        )
        normalize_compile_record(
            verification["compile_after"],
            log_path="audit/compile_current.log",
        )
        captured_before = verification["compile_before"].pop("pdf_bytes", b"")
        captured_after = verification["compile_after"].pop("pdf_bytes", b"")

        def bind_compile_preview(
            record: Dict,
            captured: object,
            candidate_tex: str,
            candidate_extra_files: Dict[str, bytes],
            evidence_key: str,
        ) -> tuple[bytes, str]:
            if not isinstance(captured, (bytes, bytearray, memoryview)) or not captured:
                return b"", ""
            from .preview import preview_descriptor

            payload = bytes(captured)
            descriptor = preview_descriptor(record.get("preview_status"))
            payload_sha256 = hashlib.sha256(payload).hexdigest()
            recorded_pdf_sha256 = str(record.get("pdf_sha256") or "")
            if recorded_pdf_sha256 and recorded_pdf_sha256 != payload_sha256:
                raise ValueError("编译 PDF 哈希与捕获工件不一致")
            from .compilecheck import build_compile_input_manifest
            from .preview import preview_artifact_path

            compile_inputs = build_compile_input_manifest(
                candidate_tex, candidate_extra_files
            )
            recorded_inputs = record.get("input_manifest")
            if recorded_inputs and recorded_inputs != compile_inputs:
                raise ValueError("编译输入清单与实际候选不一致")
            page_count = int(record.get("page_count") or record.get("pages") or 0)
            if page_count <= 0:
                raise ValueError("编译 PDF 没有可验证的页面，已阻止持久化")
            record["page_count"] = page_count
            record["pdf_sha256"] = payload_sha256
            record["input_manifest"] = compile_inputs
            record["compile_input_sha256"] = compile_inputs["manifest_sha256"]

            verification[evidence_key] = {
                **descriptor.as_dict(),
                "display_filename": descriptor.filename,
                "filename": preview_artifact_path(
                    descriptor.status, payload_sha256
                ),
                "sha256": payload_sha256,
                "bytes": len(payload),
                "engine": record["engine"],
                "passes_attempted": record["passes_attempted"],
                "exit_code": record["exit_code"],
                "page_count": page_count,
                "pdf_sha256": payload_sha256,
                "compile_input_sha256": compile_inputs["manifest_sha256"],
                "fatal_line": record.get("fatal_line"),
                "fatal_error": record["fatal_error"],
                "log_path": record["log_path"],
                "tex_sha256": hashlib.sha256(
                    candidate_tex.encode("utf-8")
                ).hexdigest(),
                "tex_lf_normalized_sha256": hashlib.sha256(
                    candidate_tex.replace("\r\n", "\n")
                    .replace("\r", "\n")
                    .encode("utf-8")
                ).hexdigest(),
                "compile_inputs": compile_inputs,
            }
            return payload, descriptor.filename

        raw_compiled_pdf, raw_compiled_pdf_name = bind_compile_preview(
            verification["compile_before"],
            captured_before,
            compiled_before_tex,
            compiled_before_extra_files,
            "raw_preview_artifact",
        )
        compiled_pdf, compiled_pdf_name = bind_compile_preview(
            verification["compile_after"],
            captured_after,
            compiled_candidate_tex,
            compiled_candidate_extra_files,
            "preview_artifact",
        )
        if ocr_semantic_lock_enabled:
            verification["raw_preview_state"] = (
                verification.get("raw_preview_artifact", {}).get("status")
                if raw_compiled_pdf
                else "SOURCE_PREVIEW"
            )
    compile_safe = not require_compile
    compile_unverified = False
    if compile_check:
        cb = verification["compile_before"]
        ca = verification["compile_after"]
        if require_compile:
            compile_safe = bool(ca.get("available") and ca.get("ok"))
        elif template_applied and (cb.get("available") or ca.get("available")):
            # An explicitly selected template is a material document-class
            # migration.  If a compiler exists, the converted result itself must
            # succeed; two matching failures cannot certify that migration.
            compile_safe = bool(ca.get("available") and ca.get("ok"))
        elif require_compile_when_available and ca.get("available"):
            compile_safe = bool(ca.get("ok"))
        elif cb.get("available") and ca.get("available"):
            has_compile_delta = result_text != compile_before_text
            if ca.get("ok"):
                compile_safe = True
            elif not cb.get("ok") and not has_compile_delta:
                # No final structural edit means both snapshots are identical.  The
                # pre-existing source failure is not evidence against an unchanged
                # draft, so preserve the historical no-op behaviour.
                compile_safe = True
            else:
                # xelatex uses ``-halt-on-error`` and compile_latex intentionally
                # returns only a bounded error list.  Equal first errors therefore
                # cannot prove that a modified draft introduced no later failure.
                # A changed result with two failed compiles is unverified and must
                # fail closed, even when the visible error arrays happen to match.
                compile_safe = False
                compile_unverified = bool(not cb.get("ok") and has_compile_delta)
        else:
            compile_safe = True
    resources_safe = bool(
        verification["resources"]["ok"]
        and (verification["resources"]["checked"] or not require_resources)
    )
    candidate_ids = {candidate.id for candidate in scan_res.candidates}
    answered_candidate_ids = {
        decision.candidate_id for decision in decisions + user_rejected
        if decision.candidate_id in candidate_ids
    } | {
        str(note.get("candidate_id", "") or "") for note in ai_notes
        if str(note.get("candidate_id", "") or "") in candidate_ids
    } | {
        str(candidate_id) for candidate_id in review_info.get(
            "preserved_candidate_ids", []
        )
        if str(candidate_id) in candidate_ids
    }
    missing_decision_ids = sorted(candidate_ids - answered_candidate_ids)
    unresolved_items = [
        item for item in ambiguous
        if str(item.get("candidate_id", "") or "") in candidate_ids
    ]
    applied_wrap_ids = {
        patch.decision.candidate_id for patch in applied
        if patch.decision.action == "wrap"
    }
    explicitly_rejected_ids = {
        decision.candidate_id for decision in user_rejected
    }
    residual_formal_ids = sorted(
        ocr_formal_candidate_ids
        - applied_wrap_ids
        - explicitly_rejected_ids
    )
    for candidate_id in residual_formal_ids:
        candidate = candidates_by_id.get(candidate_id)
        item = {
            "candidate_id": candidate_id,
            "line": candidate.span.start_line if candidate is not None else 1,
            "reason": (
                "OCR 显式 formal 标题仍未形成完整环境；"
                "已阻止导出，避免把漏套环境当成分析完成"
            ),
        }
        if not any(
            old.get("candidate_id") == candidate_id
            and old.get("reason") == item["reason"]
            for old in ambiguous
        ):
            ambiguous.append(item)
            unresolved_items.append(item)
    # One unsafe candidate can carry more than one diagnostic: for example the
    # legalizer explains why its proposed span was rejected and the OCR residue
    # gate then explains that the same heading remains unwrapped.  Those are two
    # reasons for one manual decision, not two people/tasks.  Keep every reason
    # in ``ambiguous`` for auditability, while reporting the human workload by
    # stable candidate identity.
    manual_candidate_ids = sorted({
        str(item.get("candidate_id", "") or "")
        for item in unresolved_items
        if str(item.get("candidate_id", "") or "") in candidate_ids
    })
    structure_safe = bool(
        not missing_decision_ids
        and not manual_candidate_ids
        and not residual_formal_ids
        and reused_decision_validation["ok"]
    )
    verification["structure_decisions"] = {
        "ok": structure_safe,
        "candidate_total": len(candidate_ids),
        "answered": len(answered_candidate_ids),
        "coverage": (
            round(len(answered_candidate_ids) / len(candidate_ids), 6)
            if candidate_ids else 1.0
        ),
        "missing_ids": missing_decision_ids,
        "manual_required": len(manual_candidate_ids),
        "manual_candidate_ids": manual_candidate_ids,
        "invalid_reused_decisions": len(
            reused_decision_validation.get("invalid") or []
        ),
        "formal_total": len(ocr_formal_candidate_ids),
        "formal_wrapped": len(ocr_formal_candidate_ids & applied_wrap_ids),
        "formal_residual_ids": residual_formal_ids,
    }
    review_checked = review_executed
    review_safe = bool(
        not review_checked
        or (
            review_info
            and not review_info.get("invalid")
            and not review_info.get("escalations")
        )
    )
    verification["ai_review"] = {
        "ok": review_safe,
        "checked": review_checked,
        "invalid": len(review_info.get("invalid", [])) if review_info else 0,
        "escalations": len(review_info.get("escalations", [])) if review_info else 0,
    }
    verification["compile"] = {
        "ok": compile_safe,
        "checked": bool(compile_check and verification.get("compile_after", {}).get("available")),
        "unverified": compile_unverified,
    }
    from .runbundle import preview_state_from_verification

    equation_evidence_safe = bool(
        not source_pdf_bytes
        or ocr_equation_evidence_report.get("ok") is True
    )
    source_visual_provenance_safe = bool(
        not source_pdf_bytes
        or source_visual_provenance_info.get("ok") is True
    )
    full_review_required = bool(full_review_requested and second_review_enabled)
    full_review_safe = bool(
        not full_review_required
        or (
            full_review_info.get("checked") is True
            and full_review_info.get("ok") is True
            and not full_review_info.get("invalid")
            and not full_review_info.get("escalations")
        )
    )
    visual_loop_safe = bool(
        not visual_loop_required
        or (
            visual_loop_info.get("checked") is True
            and visual_loop_info.get("ok") is True
            and not visual_loop_info.get("invalid")
            and not visual_loop_info.get("unresolved")
        )
    )

    verification["preview_state"] = preview_state_from_verification(verification)
    ok = (
        verification["content_invariant"]
        and verification["env_balance"]["ok"]
        and verification["braces"]["ok"]
        and verification["invariants"]["ok"]
        and verification["display_tags"]["ok"]
        and verification["ocr_structure"]["ok"]
        and verification["ocr_project_contract"]["ok"]
        and equation_evidence_safe
        and source_visual_provenance_safe
        and verification["ocr_semantic_ir"]["ok"]
        and template_safe
        and resources_safe
        and compile_safe
        and structure_safe
        and final_formal_safe
        and full_review_safe
        and visual_loop_safe
        and review_safe
    )
    verification["checks"] = [
        {"id": "content", "label": "正文可逆", "ok": verification["content_invariant"]},
        {"id": "environments", "label": "环境配平未恶化", "ok": verification["env_balance"]["ok"]},
        {"id": "braces", "label": "花括号配平未恶化", "ok": verification["braces"]["ok"]},
        {"id": "math", "label": "数学公式不变", "ok": verification["invariants"]["math"]["equal"]},
        {
            "id": "body-text",
            "label": "OCR 正文 token 顺序与重复次数不变",
            "ok": verification["invariants"]["body_text"]["equal"],
            "skipped": not verification["invariants"]["body_text"]["checked"],
        },
        {"id": "labels", "label": "label 不变", "ok": verification["invariants"]["labels"]["equal"]},
        {"id": "refs", "label": "引用不变", "ok": verification["invariants"]["refs"]["equal"]},
        {"id": "images", "label": "图片路径不变", "ok": verification["invariants"]["images"]["equal"]},
        {"id": "display-math", "label": "展示公式语法合法", "ok": verification["display_tags"]["ok"]},
        {
            "id": "outline",
            "label": "章节树与目录对应 PDF 大纲",
            "ok": verification["ocr_structure"]["ok"],
            "skipped": not verification["ocr_structure"]["checked"],
        },
        {
            "id": "ocr-project-contract",
            "label": "OCR AI 运行已绑定显式项目类型、metadata、源页与视觉证据",
            "ok": verification["ocr_project_contract"]["ok"],
            "skipped": not verification["ocr_project_contract"]["required"],
        },
        {
            "id": "ocr-equation-source-evidence",
            "label": "公式编号已绑定原始视觉输入的页内位置与整页渲染证据",
            "ok": equation_evidence_safe,
            "skipped": not bool(source_pdf_bytes),
        },
        {
            "id": "source-visual-provenance",
            "label": "原始上传与视觉 PDF 哈希及派生关系可复验",
            "ok": source_visual_provenance_safe,
            "skipped": not bool(source_pdf_bytes),
        },
        {
            "id": "ocr-semantic-ir",
            "label": "OCR 公式编号、前置信息与参考文献证据闭环",
            "ok": verification["ocr_semantic_ir"]["ok"],
            "skipped": not verification["ocr_semantic_ir"]["checked"],
        },
        {
            "id": "template",
            "label": "排版模板安全转换",
            "ok": template_safe,
            "skipped": not template,
        },
        {
            "id": "resources",
            "label": "图片资源真实存在且位于项目内",
            "ok": resources_safe,
            "skipped": not verification["resources"]["checked"],
        },
        {
            "id": "reused-decisions",
            "label": "缓存决策已绑定当前 scanner、formal inventory 与源哈希",
            "ok": reused_decision_validation["ok"],
            "skipped": not decisions_reused,
        },
        {
            "id": "structure-decisions",
            "label": "所有结构候选均有唯一且无需人工兜底的结论",
            "ok": structure_safe,
        },
        {
            "id": "full-document-review",
            "label": "独立复核覆盖全文与全部现有 formal 环境",
            # ``None`` is deliberate for an explicit opt-out: this gate is
            # neutral/skipped, not a successful review.  Consumers that only
            # inspect ``ok`` therefore cannot render a false passed state.
            "ok": (
                None
                if full_review_requested and not second_review_enabled
                else full_review_safe
            ),
            "skipped": not full_review_required,
            **(
                {
                    "reason": "用户未启用第二遍复查",
                    "skip_reason": "user-disabled",
                }
                if full_review_requested and not second_review_enabled
                else {}
            ),
        },
        {
            "id": "final-formal-inventory",
            "label": "最终 TEX 已重新盘点且无漏套、错套、多套或重复 formal 环境",
            "ok": final_formal_safe,
            "skipped": not quality_loop,
            "blockers": len(final_formal_blockers),
        },
        {
            "id": "ai-review",
            "label": "AI 复查完整且无未解决项",
            "ok": review_safe,
            "skipped": not review_checked,
        },
        {
            "id": "compile-render-visual-repair",
            "label": "真实编译、逐页视觉复核与定点修复闭环",
            "ok": visual_loop_safe,
            "skipped": not visual_loop_required,
        },
        {"id": "compile", "label": (
            "编译器可用时结果必须成功"
            if require_compile_when_available or template_applied
            else "编译结果未恶化"
        ), "ok": compile_safe,
         "skipped": not verification["compile"]["checked"]},
    ]
    verification["safe_to_export"] = bool(ok)
    verification["export_blocked"] = not ok
    verification["rolled_back"] = not ok
    final_text = result_text if ok else source_text
    export_text = final_text.replace("\n", source_newline)
    report_md = build_report(
        applied, rejected, ambiguous, verification, mode,
        ai_notes=ai_notes, review=review_info,
        template_notes=template_notes, template_applied=template_applied,
        template_name=template_name,
        ocr_structure_notes=ocr_structure_notes,
    )
    emit(
        "report", 0.97, "安全检查完成，正在生成审阅清单",
        preview=final_text,
        preview_label="安全检查通过的结果" if ok else "已安全回退到原文",
        usage=ai_usage,
        safe_to_export=ok,
        preview_state=verification["preview_state"],
    )

    # 审阅式 UI 决策清单：候选元信息 + 状态
    cand_by_id = {c.id: c for c in scan_res.candidates}
    applied_ids = {ap.decision.candidate_id for ap in applied}
    rejected_ids = {ap.decision.candidate_id for ap in rejected}
    ambiguous_ids = {a.get("candidate_id") for a in ambiguous}
    decision_items = []
    for d in decisions + user_rejected:
        c = cand_by_id.get(d.candidate_id)
        line = d.body_span[0] if d.body_span else 1
        if c is not None:
            line = c.span.start_line
        item = {
            "candidate_id": d.candidate_id,
            "kind": c.kind if c is not None else d.action,
            "env": d.env,
            "line": line,
            "title": (c.title_text[:80] if c is not None else "") or d.reason,
            "section": " / ".join(c.payload.get("section_path", ())) if c is not None else "",
            "confidence": round(d.confidence, 3),
            "source": d.source,
            "reason": d.reason,
        }
        if d.candidate_id in (exclude or set()):
            item["status"] = "rejected"
        elif d.candidate_id in applied_ids:
            item["status"] = "applied"
        elif d.candidate_id in rejected_ids:
            item["status"] = "rejected"
        elif d.candidate_id in ambiguous_ids:
            item["status"] = "ambiguous"
        else:
            item["status"] = "none"
        decision_items.append(item)
    for a in ambiguous:
        if not any(i["candidate_id"] == a.get("candidate_id") for i in decision_items):
            decision_items.append({
                "candidate_id": a.get("candidate_id", ""), "kind": "ambiguous",
                "env": "", "line": a.get("line", 1), "title": a.get("reason", "")[:80],
                "section": "", "confidence": 0.0, "source": "rule",
                "reason": a.get("reason", ""), "status": "ambiguous",
            })
    # action=none 是一个真实的 AI 结论，而不是“没有决策”。过去这些候选只在
    # Markdown 报告里出现，审阅树完全看不到，用户无法抽查漏包。现在把所有
    # 保留结论也加入清单；若同一候选后来升级为人工项，状态以 ambiguous 为准。
    ambiguous_by_id = {
        str(item.get("candidate_id", "") or ""): item for item in ambiguous
    }
    for note in ai_notes:
        cid = str(note.get("candidate_id", "") or "")
        if not cid or any(item["candidate_id"] == cid for item in decision_items):
            continue
        candidate = cand_by_id.get(cid)
        pending = ambiguous_by_id.get(cid)
        reason = str((pending or note).get("reason", "") or "")
        decision_items.append({
            "candidate_id": cid,
            "kind": candidate.kind if candidate is not None else "preserve",
            "env": candidate.env_hint if candidate is not None else "",
            "line": candidate.span.start_line if candidate is not None else note.get("line", 1),
            "title": (
                candidate.title_text[:80] if candidate is not None else reason[:80]
            ),
            "section": (
                " / ".join(candidate.payload.get("section_path", ()))
                if candidate is not None else ""
            ),
            "confidence": round(float(note.get("confidence", 0.0) or 0.0), 3),
            "source": str(note.get("source", "ai") or "ai"),
            "reason": reason,
            "status": "ambiguous" if pending is not None else "preserved",
        })
    for cid in review_info.get("preserved_candidate_ids", []):
        cid = str(cid)
        if not cid or any(item["candidate_id"] == cid for item in decision_items):
            continue
        candidate = cand_by_id.get(cid)
        finding = (review_info.get("preserved_findings") or {}).get(cid) or {}
        decision_items.append({
            "candidate_id": cid,
            "kind": candidate.kind if candidate is not None else "preserve",
            "env": candidate.env_hint if candidate is not None else "",
            "line": candidate.span.start_line if candidate is not None else 1,
            "title": candidate.title_text[:80] if candidate is not None else "",
            "section": (
                " / ".join(candidate.payload.get("section_path", ()))
                if candidate is not None else ""
            ),
            "confidence": 1.0,
            "source": "review",
            "reason": str(finding.get("reason", "复查确认应保留原文")),
            "status": "preserved",
        })

    result = PipelineResult(
        ok=ok,
        original=source_text,
        result=final_text,
        export_text=export_text,
        newline=source_newline,
        decisions=decisions,
        applied=applied,
        rejected=rejected,
        ambiguous=ambiguous,
        verification=verification,
        report_md=report_md,
        mode=mode,
        ai_notes=ai_notes,
        review=review_info,
        decision_items=decision_items,
        compiled_pdf=compiled_pdf,
        compiled_pdf_name=compiled_pdf_name,
        # Keep the exact attempted compile closure even when no final PDF was
        # produced; audit packaging needs it to explain/reproduce failures.
        compiled_tex=compiled_candidate_tex,
        compiled_snapshot=result_text if compiled_pdf else "",
        compiled_extra_files=compiled_candidate_extra_files,
        raw_compiled_pdf=raw_compiled_pdf,
        raw_compiled_pdf_name=raw_compiled_pdf_name,
        raw_compiled_tex=compiled_before_tex if raw_compiled_pdf else "",
        raw_compiled_extra_files=(
            compiled_before_extra_files if raw_compiled_pdf else {}
        ),
        analyzed_tex=initial_draft if mode == "ai" else "",
        reviewed_tex=result_text if review_executed else "",
    )
    # The pipeline result is complete in memory, but the server still has to
    # atomically commit result/report/decisions/verification.  Only the job
    # manager may publish 100% after that commit succeeds.
    emit(
        "ready", 0.985, "安全检查完成，等待保存最终结果",
        preview=final_text,
        preview_label="已验证、尚待保存的最终结果",
        usage=ai_usage,
        safe_to_export=ok,
        preview_state=verification["preview_state"],
    )
    return result

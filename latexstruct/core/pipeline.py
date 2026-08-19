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
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ai import AIConfig, AI_KINDS, LLMError, build_text_client, decide_candidates
from .parser import detect_newline, line_starts, normalize_newlines, offset_to_line, parse_latex
from .ocrstruct import (
    build_ocr_structure_ops,
    check_ocr_structure,
    is_ocr_document,
)
from .patch import (
    AMSTHM_BLOCK,
    AppliedPatch,
    Decision,
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
from .verify import check_display_tag_safety, compare_braces, compare_env_balance, known_issues

DOC_CLASS_RE = re.compile(r"\\documentclass(?:\[[^\]]*\])?\s*\{([^{}]*)\}")


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
            if d.action == "wrap" and d.env in known_envs
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


def _interval(d: Decision) -> Tuple[int, int]:
    if d.action == "wrap" and d.body_span:
        return d.body_span
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
        unsafe_reason = _unsafe_candidate_env_reason(d, candidate)
        if not unsafe_reason:
            unsafe_reason = str(getattr(d, "_legalize_error", "") or "")
        if not unsafe_reason:
            unsafe_reason = _normalize_theorem_wrap_start(d, candidate)
        if not unsafe_reason:
            _restore_theorem_title_metadata(d, candidate)
            _adapt_elegantbook_theorem_env(d, candidate, ctx)
            unsafe_reason = _unsafe_numbered_theorem_reason(d, candidate, ctx)
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


def _unsafe_candidate_env_reason(decision: Decision, candidate) -> str:
    """最终应用门：复查/缓存也不能把 proof 候选改成定理，反之亦然。"""
    if decision.action != "wrap" or candidate is None:
        return ""
    if candidate.kind == "proof" and decision.env != "proof":
        return "证明候选只能使用 proof 环境；不兼容的 AI/复查环境已保守跳过"
    if candidate.kind == "theorem-like" and decision.env == "proof":
        return "定理类候选不能改成 proof 环境；不兼容的 AI/复查环境已保守跳过"
    return ""


def _candidate_for_decision(decision: Decision, candidates_by_id: dict):
    candidate = candidates_by_id.get(decision.candidate_id)
    if candidate is None and decision.candidate_id.startswith("review-missed-"):
        candidate = candidates_by_id.get(decision.candidate_id[len("review-missed-"):])
    return candidate


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
    known_structured_envs=None,
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
    from .template import normalize_template_id, template_label

    template = normalize_template_id(template)
    template_name = template_label(template) if template else ""
    ocr_structure_notes: List[dict] = []
    ocr_structure_patches: List[AppliedPatch] = []
    if is_ocr_document(text):
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
    candidates_by_id = {c.id: c for c in scan_res.candidates}
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
    ai_degraded = False
    ai_usage: Dict = {}
    decisions_reused = decisions_override is not None

    if decisions_reused:
        decisions = copy.deepcopy(decisions_override or [])
        ambiguous = copy.deepcopy(ambiguous_override or [])
        ai_notes = copy.deepcopy(ai_notes_override or [])
        review_info = {"reused": True}
    elif mode == "ai":
        deterministic_kinds = {"bilingual-title", "exercise-section"}
        rule_decisions, ambiguous = build_rule_decisions(doc, scan_res, rule_config, kinds=deterministic_kinds, pack=pack)
        ai_candidates = [c for c in scan_res.candidates if c.kind in AI_KINDS]
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
            decisions = rule_decisions + ai_decisions
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

    if not decisions_reused:
        # Validate AI source ranges before deriving theorem declarations.  A
        # fail-closed short wrap must not leave an orphan ``\newtheorem`` in an
        # otherwise untouched document while it waits for pending review.
        if candidates_by_id:
            from .legalize import legalize_decisions

            legalize_decisions(
                doc, decisions, candidates_by_id, ctx.existing_envs
            )
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
    )

    # AI 复查（默认开启）。即使没有补丁，只要初次 AI 留下 none/歧义项，
    # 也必须给复查器真实源片段；否则漏答会被静默当作整批通过。
    if (
        mode == "ai"
        and (ai_config is None or ai_config.review_enabled)
        and (applied or ai_notes or ambiguous)
        and not ai_degraded
        and not decisions_reused
    ):
        cfg = ai_config or AIConfig()
        rclient = review_client or build_text_client(cfg, "review")
        # 漏报抽查：AI 判定"无需处理"的候选一并交复查复核（可 missed-extra 反悔）
        review_ambiguous = list(ambiguous) + [
            {"candidate_id": n.get("candidate_id", ""), "line": n.get("line", 1),
             "reason": "AI 判定无需处理，请复核是否漏包：" + str(n.get("reason", ""))[:80]}
            for n in ai_notes
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

            review_info = run_review(
                rclient,
                doc,
                ctx,
                decisions,
                lambda ds: _apply_decisions(doc, ds, ctx, ambiguous, candidates_by_id=candidates_by_id),
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
                },
            )
            out = review_info["out"]
            applied = review_info["applied"]
            rejected = review_info["rejected"]
            decisions = review_info["decisions"]
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
    emit(
        "draft", 0.84, "结构化草稿已生成，正在执行安全检查",
        preview=result_text,
        preview_label="未完成安全检查的草稿",
        applied=len(applied),
        rejected=len(rejected),
        ambiguous=len(ambiguous),
        usage=ai_usage,
    )
    from .invariants import check_image_resources, check_invariants

    verification = {
        "content_invariant": content_invariant(
            source_text.split("\n"),
            out,
            ocr_structure_patches + template_patches + applied,
        ),
        "env_balance": compare_env_balance(transformed_source_text, result_text),
        "braces": compare_braces(transformed_source_text, result_text),
        "invariants": check_invariants(transformed_source_text, result_text),
        "known_issues": known_issues(result_text),
        "display_tags": check_display_tag_safety(result_text),
        "ocr_structure": check_ocr_structure(result_text),
        "template": {
            "ok": template_safe,
            "applied": template_applied,
            "issues": [
                note for note in template_notes if note.get("status") == "rejected"
            ],
        },
        "resources": check_image_resources(result_text, resource_root),
        "ai_degraded": ai_degraded,
        "ai_usage": ai_usage,
        "decisions_reused": decisions_reused,
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
    if compile_check:
        emit("compile", 0.91, "正在比较编译结果")
        from .compilecheck import compile_latex

        def compile_snapshot(snapshot: str) -> Dict:
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
                return compile_latex(snapshot, extra_files=compile_extra_files)

            from .project import safe_project_relpath, split_project

            main_rel = safe_project_relpath(compile_project_main_rel)
            per_file = split_project(snapshot)
            files = dict(compile_extra_files or {})
            files.pop(main_rel, None)
            for rel, content in per_file.items():
                if not rel:
                    continue
                files[safe_project_relpath(rel)] = content.encode("utf-8")
            return compile_latex(per_file.get("", ""), extra_files=files)

        # The baseline must precede template conversion.  Using the converted
        # draft for both snapshots hides class/template regressions as a no-op.
        verification["compile_before"] = compile_snapshot(pre_template_text)
        verification["compile_after"] = compile_snapshot(result_text)
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
            has_compile_delta = result_text != pre_template_text
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
    structure_safe = not missing_decision_ids and not unresolved_items
    verification["structure_decisions"] = {
        "ok": structure_safe,
        "candidate_total": len(candidate_ids),
        "answered": len(answered_candidate_ids),
        "coverage": (
            round(len(answered_candidate_ids) / len(candidate_ids), 6)
            if candidate_ids else 1.0
        ),
        "missing_ids": missing_decision_ids,
        "manual_required": len(unresolved_items),
    }
    review_checked = bool(
        mode == "ai"
        and (ai_config is None or ai_config.review_enabled)
        and (applied or ai_notes or ambiguous)
        and not decisions_reused
    )
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
    ok = (
        verification["content_invariant"]
        and verification["env_balance"]["ok"]
        and verification["braces"]["ok"]
        and verification["invariants"]["ok"]
        and verification["display_tags"]["ok"]
        and verification["ocr_structure"]["ok"]
        and template_safe
        and resources_safe
        and compile_safe
        and structure_safe
        and review_safe
    )
    verification["checks"] = [
        {"id": "content", "label": "正文可逆", "ok": verification["content_invariant"]},
        {"id": "environments", "label": "环境配平未恶化", "ok": verification["env_balance"]["ok"]},
        {"id": "braces", "label": "花括号配平未恶化", "ok": verification["braces"]["ok"]},
        {"id": "math", "label": "数学公式不变", "ok": verification["invariants"]["math"]["equal"]},
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
            "id": "structure-decisions",
            "label": "所有结构候选均有唯一且无需人工兜底的结论",
            "ok": structure_safe,
        },
        {
            "id": "ai-review",
            "label": "AI 复查完整且无未解决项",
            "ok": review_safe,
            "skipped": not review_checked,
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
    )
    return result

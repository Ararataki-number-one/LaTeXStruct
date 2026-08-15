# -*- coding: utf-8 -*-
"""处理流水线编排（M1 MVP）。

阶段：解析 → 扫描 → 决策（规则 / AI+规则混合） → 区间冲突消解 → 补丁应用 →
      内容不变校验 + 环境配平 → AI 复查（可选，自动修正） → 汇报。

- mode="rule"：确定性规则（无 Key 降级路径）；
- mode="ai"：定理类/proof/范围修正候选交 AI 决策，双语标题/习题节/导言区仍走确定性规则；
  AI 不可用（无 Key/调用失败）时自动降级为规则决策（ai_degraded=True）。
任何校验失败 → 返回原始文本，绝不导出被改坏的内容。
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ai import AIConfig, AI_KINDS, LLMClient, LLMError, decide_candidates
from .parser import detect_newline, line_starts, normalize_newlines, offset_to_line, parse_latex
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
from .scanner import scan
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


def _build_context(doc) -> PatchContext:
    m = DOC_CLASS_RE.search(doc.text)
    cls = m.group(1) if m else ""
    is_elegant = "elegantbook" in cls.lower()
    used_env_names = {r[0] for r in doc.env_ranges}
    theorem_declarations = list(NEW_THEOREM_RE.finditer(doc.masked))
    newtheorem_names = {m.group(2) for m in theorem_declarations}
    numbered_envs = {m.group(2) for m in theorem_declarations if not m.group(1)}
    unnumbered_envs = {
        m.group(2) for m in theorem_declarations if m.group(1)
    } - numbered_envs
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

        legalize_decisions(doc, decisions, candidates_by_id)  # AI span 段落边界合法化
    lines = doc.text.split("\n")
    planned: List[Tuple[Decision, List]] = []
    rejected: List[AppliedPatch] = []
    for d in decisions:
        candidate = _candidate_for_decision(d, candidates_by_id or {})
        unsafe_reason = _normalize_theorem_wrap_start(d, candidate)
        if not unsafe_reason:
            _restore_theorem_title_metadata(d, candidate)
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


def _candidate_for_decision(decision: Decision, candidates_by_id: dict):
    candidate = candidates_by_id.get(decision.candidate_id)
    if candidate is None and decision.candidate_id.startswith("review-missed-"):
        candidate = candidates_by_id.get(decision.candidate_id[len("review-missed-"):])
    return candidate


def _normalize_theorem_wrap_start(decision: Decision, candidate) -> str:
    """定理类包裹必须从扫描器确认的标题行开始，复查不得绕过该锚点。"""
    if (
        decision.action != "wrap"
        or candidate is None
        or candidate.kind != "theorem-like"
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
        or candidate.kind != "theorem-like"
        or not decision.body_span
        or decision.body_span[0] != candidate.span.start_line
    ):
        return
    prefix = candidate.payload.get("title_prefix", "")
    remainder = candidate.title_text[len(prefix):].strip() if prefix else ""
    number = candidate.payload.get("number") or ""
    decision.optional_arg = str(number)[:120]
    decision.keep_title_text = not (prefix and remainder)
    decision.payload = dict(decision.payload)
    decision.payload["title_prefix"] = prefix if prefix and remainder else ""


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
    compile_check: bool = False,
    pack=None,
    exclude: set = None,
    decisions_override: List[Decision] = None,
    ambiguous_override: List[dict] = None,
    ai_notes_override: List[dict] = None,
    progress_callback=None,
    control_callback=None,
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
    template_notes: List[dict] = []
    template_applied = False
    template_patches: List[AppliedPatch] = []
    if template == "elegantbook":
        emit("template", 0.05, "正在检查模板转换")
        from .template import build_template_ops

        t_ops, template_notes = build_template_ops(text)
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
                    {"line": 1, "reason": f"模板转换编辑校验失败，已跳过：{t_rejected[0].error}"}
                )

    emit("parse", 0.10, "正在解析 LaTeX 结构")
    doc = parse_latex(text)
    emit("scan", 0.17, "正在扫描定理、证明与章节候选")
    scan_res = scan(doc, pack)
    ctx = _build_context(doc)
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
        client = ai_client or LLMClient((ai_config or AIConfig()).decide)
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
                client, doc, ctx, ai_candidates, ai_config or AIConfig(), mode,
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
            fallback, amb2 = build_rule_decisions(doc, scan_res, rule_config, kinds=AI_KINDS, pack=pack)
            decisions = rule_decisions + fallback
            ambiguous += amb2
            ai_degraded = True
            ai_notes.append({"candidate_id": "-", "line": 1, "reason": f"AI 不可用，已降级为规则决策：{e}"})
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
        pre = build_preamble_decision(doc, ctx, decisions)
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

    # AI 复查（默认开启；降级或无补丁时跳过）
    if (
        mode == "ai"
        and (ai_config is None or ai_config.review_enabled)
        and applied
        and not ai_degraded
        and not decisions_reused
    ):
        cfg = ai_config or AIConfig()
        rclient = review_client or LLMClient(cfg.review)
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
            )
            out = review_info["out"]
            applied = review_info["applied"]
            rejected = review_info["rejected"]
            decisions = review_info["decisions"]
            ai_usage["review"] = review_info["usage"]
        except LLMError as e:
            if rclient.last_usage:
                from ..pricing import add_usage

                add_usage(
                    ai_usage.setdefault("review", {}),
                    rclient.last_usage,
                    getattr(rclient.cfg, "model", ""),
                )
            review_info = {"error": str(e)}
            ai_notes.append({"candidate_id": "-", "line": 1, "reason": f"AI 复查失败，沿用初次结果：{e}"})

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
    from .invariants import check_invariants

    verification = {
        "content_invariant": content_invariant(
            source_text.split("\n"), out, template_patches + applied
        ),
        "env_balance": compare_env_balance(source_text, result_text),
        "braces": compare_braces(source_text, result_text),
        "invariants": check_invariants(source_text, result_text),
        "known_issues": known_issues(result_text),
        "display_tags": check_display_tag_safety(result_text),
        "ai_degraded": ai_degraded,
        "ai_usage": ai_usage,
        "decisions_reused": decisions_reused,
    }
    if compile_check:
        emit("compile", 0.91, "正在比较编译结果")
        from .compilecheck import compile_latex

        verification["compile_before"] = compile_latex(source_text)
        verification["compile_after"] = compile_latex(result_text)
    compile_safe = True
    if compile_check:
        cb = verification["compile_before"]
        ca = verification["compile_after"]
        if cb.get("available") and ca.get("available"):
            compile_safe = bool(
                ca.get("ok")
                or (not cb.get("ok") and cb.get("errors", []) == ca.get("errors", []))
            )
    verification["compile"] = {
        "ok": compile_safe,
        "checked": bool(compile_check and verification.get("compile_before", {}).get("available")),
    }
    ok = (
        verification["content_invariant"]
        and verification["env_balance"]["ok"]
        and verification["braces"]["ok"]
        and verification["invariants"]["ok"]
        and verification["display_tags"]["ok"]
        and compile_safe
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
        {"id": "compile", "label": "编译结果未恶化", "ok": compile_safe,
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
    emit(
        "done", 1.0, "处理完成",
        preview=final_text,
        preview_label="最终结果",
        usage=ai_usage,
        safe_to_export=ok,
    )
    return result

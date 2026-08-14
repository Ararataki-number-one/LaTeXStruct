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

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ai import AIConfig, AI_KINDS, LLMClient, LLMError, decide_candidates
from .parser import line_starts, offset_to_line, parse_latex
from .patch import (
    AppliedPatch,
    Decision,
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
from .verify import check_braces, check_env_balance, known_issues

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
    env_names = {r[0] for r in doc.env_ranges}
    newtheorem_names = set(re.findall(r"\\newtheorem\s*\{([^{}]*)\}", doc.text))
    env_names |= newtheorem_names
    # 习题节需要"列表语义"环境；elegantbook 的 exercise 是定理式单题环境（放 \item 会报
    # Lonely \item），故仅 problemset（列表式）可复用，否则统一用 enumerate
    if "problemset" in env_names:
        exercise_env = "problemset"
    else:
        exercise_env = "enumerate"
    doc_range = next((r for r in doc.env_ranges if r[0] == "document"), None)
    anchor = offset_to_line(line_starts(doc.text), doc_range[1]) if doc_range else 0
    return PatchContext(
        is_elegantbook=is_elegant,
        existing_envs=env_names,
        exercise_env=exercise_env,
        preamble_anchor=anchor,
    )


def build_preamble_decision(doc, ctx: PatchContext) -> Optional[Decision]:
    if ctx.is_elegantbook:
        return None
    if re.search(r"\\usepackage(?:\[[^\]]*\])?\{(?:amsthm|ntheorem)\}", doc.text):
        return None
    if re.search(r"\\newtheorem\s*\{theorem\}", doc.text):
        return None
    if ctx.preamble_anchor <= 0:
        return None
    return Decision(
        candidate_id="preamble",
        action="preamble-add",
        source="rule",
        reason="导言区缺少定理环境定义",
        confidence=1.0,
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
    indexed = sorted(
        enumerate(planned), key=lambda t: (_interval(t[1][0])[0], -t[1][0].confidence)
    )
    kept: List[Tuple[Decision, List]] = []
    dropped: List[Tuple[Decision, str]] = []
    cur_end = -1
    cur_d = None
    for _, (d, ops) in indexed:
        s, e = _interval(d)
        if cur_d is not None and s <= cur_end and not (s == 0 and e == 0):
            dropped.append((d, f"与决策 {cur_d.candidate_id} 的修改区间重叠，保守保留较低置信度项"))
            continue
        kept.append((d, ops))
        cur_end = e
        cur_d = d
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
        ops, err = build_ops(d, lines, ctx)
        if err:
            rejected.append(AppliedPatch(decision=d, edits=[], error=err))
        elif ops:
            planned.append((d, ops))
    planned, dropped = resolve_overlaps(planned, lines)
    out, applied, rejected2 = apply_patches(lines, planned)
    return out, applied, rejected + rejected2, dropped


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
) -> PipelineResult:
    template_notes: List[dict] = []
    template_applied = False
    if template == "elegantbook":
        from .template import build_template_ops

        t_ops, template_notes = build_template_ops(text)
        if t_ops:
            t_lines = text.split("\n")
            ok_planned, t_rejected = validate_ops(
                t_lines, [(Decision(candidate_id="tpl", action="none"), t_ops)]
            )
            if not t_rejected:
                out, _, _ = apply_patches(t_lines, ok_planned)
                text = "\n".join(out)
                template_applied = True
            else:
                template_notes.append(
                    {"line": 1, "reason": f"模板转换编辑校验失败，已跳过：{t_rejected[0].error}"}
                )

    doc = parse_latex(text)
    scan_res = scan(doc, pack)
    ctx = _build_context(doc)
    ambiguous: List[dict] = []
    ai_notes: List[dict] = []
    review_info: Dict = {}
    ai_degraded = False
    ai_usage: Dict = {}

    if mode == "ai":
        deterministic_kinds = {"bilingual-title", "exercise-section"}
        rule_decisions, ambiguous = build_rule_decisions(doc, scan_res, rule_config, kinds=deterministic_kinds, pack=pack)
        ai_candidates = [c for c in scan_res.candidates if c.kind in AI_KINDS]
        client = ai_client or LLMClient((ai_config or AIConfig()).decide)
        try:
            ai_decisions, ai_amb, ai_notes, usage = decide_candidates(
                client, doc, ctx, ai_candidates, ai_config or AIConfig(), mode
            )
            decisions = rule_decisions + ai_decisions
            ambiguous += ai_amb
            ai_usage["decide"] = usage
        except LLMError as e:
            fallback, amb2 = build_rule_decisions(doc, scan_res, rule_config, kinds=AI_KINDS, pack=pack)
            decisions = rule_decisions + fallback
            ambiguous += amb2
            ai_degraded = True
            ai_notes.append({"candidate_id": "-", "line": 1, "reason": f"AI 不可用，已降级为规则决策：{e}"})
    else:
        decisions, ambiguous = build_rule_decisions(doc, scan_res, rule_config, pack=pack)

    pre = build_preamble_decision(doc, ctx)
    if pre is not None:
        decisions.append(pre)
    for d in decisions:
        if d.action == "convert-to-exercise-env" and not d.env:
            d.env = ctx.exercise_env
    if exclude:
        decisions = [d for d in decisions if d.candidate_id not in exclude]  # 单项拒绝（审阅）

    candidates_by_id = {c.id: c for c in scan_res.candidates}
    out, applied, rejected, dropped = _apply_decisions(
        doc, decisions, ctx, ambiguous, candidates_by_id=candidates_by_id
    )
    for d, reason in dropped:
        ambiguous.append({"candidate_id": d.candidate_id, "line": _interval(d)[0] or 1, "reason": reason})
    for s in scan_res.skipped:
        ambiguous.append({"candidate_id": "", "line": s.get("line"), "reason": f"{s.get('reason')}（{s.get('kind')}）"})

    # AI 复查（默认开启；降级或无补丁时跳过）
    if (
        mode == "ai"
        and (ai_config is None or ai_config.review_enabled)
        and applied
        and not ai_degraded
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
            review_info = run_review(
                rclient,
                doc,
                ctx,
                decisions,
                lambda ds: _apply_decisions(doc, ds, ctx, ambiguous, candidates_by_id=candidates_by_id),
                review_ambiguous,
                cfg,
                mode,
            )
            out = review_info["out"]
            applied = review_info["applied"]
            rejected = review_info["rejected"]
            decisions = review_info["decisions"]
            ai_usage["review"] = review_info["usage"]
        except LLMError as e:
            review_info = {"error": str(e)}
            ai_notes.append({"candidate_id": "-", "line": 1, "reason": f"AI 复查失败，沿用初次结果：{e}"})

    result_text = "\n".join(out)
    from .invariants import check_invariants

    verification = {
        "content_invariant": content_invariant(doc.text.split("\n"), out, applied),
        "env_balance": check_env_balance(result_text),
        "braces": check_braces(result_text),
        "invariants": check_invariants(doc.text, result_text),
        "known_issues": known_issues(result_text),
        "ai_degraded": ai_degraded,
        "ai_usage": ai_usage,
    }
    if compile_check:
        from .compilecheck import compile_latex

        verification["compile_before"] = compile_latex(doc.text)
        verification["compile_after"] = compile_latex(result_text)
    ok = (
        verification["content_invariant"]
        and verification["env_balance"]["ok"]
        and verification["invariants"]["ok"]
    )
    final_text = result_text if ok else doc.text
    export_text = final_text.replace("\n", doc.newline)
    report_md = build_report(
        applied, rejected, ambiguous, verification, mode,
        ai_notes=ai_notes, review=review_info,
        template_notes=template_notes, template_applied=template_applied,
    )

    # 审阅式 UI 决策清单：候选元信息 + 状态
    cand_by_id = {c.id: c for c in scan_res.candidates}
    applied_ids = {ap.decision.candidate_id for ap in applied}
    rejected_ids = {ap.decision.candidate_id for ap in rejected}
    ambiguous_ids = {a.get("candidate_id") for a in ambiguous}
    decision_items = []
    for d in decisions:
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
        if d.candidate_id in applied_ids:
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

    return PipelineResult(
        ok=ok,
        original=doc.text,
        result=final_text,
        export_text=export_text,
        newline=doc.newline,
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

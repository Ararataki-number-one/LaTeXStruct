# -*- coding: utf-8 -*-
"""极简汇报生成（Markdown）。"""

from __future__ import annotations

from typing import Dict, List

from .patch import AppliedPatch


def build_report(
    applied: List[AppliedPatch],
    rejected: List[AppliedPatch],
    ambiguous: List[dict],
    verification: Dict,
    mode: str,
    ai_notes: List[dict] = None,
    review: Dict = None,
    template_notes: List[dict] = None,
    template_applied: bool = False,
) -> str:
    ai_notes = ai_notes or []
    review = review or {}
    template_notes = template_notes or []
    L: List[str] = ["# LaTeXStruct 结构化整理汇报", ""]
    L.append(f"- 模式：{mode}")
    L.append(f"- 应用补丁：{len(applied)}；被拒绝：{len(rejected)}；歧义保留：{len(ambiguous)}")
    L.append("")
    n = 1

    def section(title: str):
        nonlocal n
        L.append(f"## {n}、{title}")
        n += 1
        L.append("")

    def by_action(action: str) -> List[AppliedPatch]:
        return [ap for ap in applied if ap.decision.action == action]

    wraps = by_action("wrap")
    if wraps:
        section("新增环境包裹")
        for ap in wraps:
            d = ap.decision
            s = d.body_span[0] if d.body_span else "?"
            arg = f"[{d.optional_arg}]" if d.optional_arg else ""
            L.append(f"- `{d.env}{arg}`：第 {s} 行起（{d.reason}）")
        L.append("")

    moves = by_action("move-boundary")
    if moves:
        section("环境范围修正")
        for ap in moves:
            d = ap.decision
            L.append(
                f"- `{d.env}`：边界从第 {d.payload.get('old_end_line')} 行移至第 "
                f"{d.payload.get('new_end_line')} 行（{d.reason}）"
            )
        L.append("")

    ex = by_action("convert-to-exercise-env")
    if ex:
        section("习题节转换")
        for ap in ex:
            d = ap.decision
            L.append(
                f"- `{d.payload.get('section_title', '')}`："
                f"{len(d.payload.get('item_lines', []))} 题 → `{d.env}` 环境"
            )
        L.append("")

    bi = by_action("merge-bilingual-title")
    if bi:
        section("双语标题合并")
        for ap in bi:
            d = ap.decision
            L.append(
                f"- `{d.payload.get('en_title')}（{d.payload.get('cn_title')}）`："
                f"第 {d.payload.get('section_line')} 行，翻译框已合并并加入目录"
            )
        L.append("")

    pre = by_action("preamble-add")
    if pre:
        section("导言区补充")
        L.append("- 补充 amsthm 与定理环境定义（原有体系缺失时）")
        L.append("")

    if rejected:
        section("被拒绝的修改（保守回退）")
        for ap in rejected:
            L.append(f"- {ap.decision.candidate_id}：{ap.error}")
        L.append("")

    if ambiguous:
        section("歧义项（保留原文，未做修改）")
        for a in ambiguous:
            L.append(f"- 第 {a.get('line', '?')} 行（{a.get('candidate_id', '')}）：{a.get('reason', '')}")
        L.append("")

    if mode == "ai":
        section("AI 决策与复查")
        usage = verification.get("ai_usage", {})
        dec = usage.get("decide", {})
        rev = usage.get("review", {})
        if dec:
            L.append(f"- 决策模型：{dec.get('model', '')}；tokens：{dec.get('total_tokens', 0)}")
        if review.get("findings"):
            fixes = [f for f in review["findings"] if f["verdict"] != "ok"]
            L.append(f"- 复查发现：{len(review['findings'])} 项，其中需修正 {len(fixes)} 项")
            for f in fixes:
                L.append(f"  - {f['candidate_id']}: {f['verdict']}（{f.get('reason', '')}）")
        if review.get("invalid"):
            L.append(f"- 复查无效项（升级人工）：{len(review['invalid'])}")
            for f in review["invalid"]:
                L.append(f"  - {f.get('candidate_id', '-')}：{f.get('reason', '')}")
        if rev:
            L.append(f"- 复查模型：{rev.get('model', '')}；tokens：{rev.get('total_tokens', 0)}")
        if verification.get("ai_degraded"):
            L.append("- **AI 不可用，已降级为规则决策**")
        if ai_notes:
            L.append("- AI 说明：")
            for note in ai_notes:
                L.append(f"  - {note.get('candidate_id', '-')}：{note.get('reason', '')}")
        L.append("")

    if template_applied or template_notes:
        section("模板转换（elegantbook）")
        for t in template_notes:
            L.append(f"- 第 {t.get('line')} 行：{t.get('reason')}")
        if template_applied:
            L.append("- 内容不变校验以模板转换后的文本为基准")
        L.append("")

    section("机器校验")
    ci = verification.get("content_invariant")
    eb = verification.get("env_balance", {})
    br = verification.get("braces", {})
    ki = verification.get("known_issues", [])
    L.append(f"- 内容不变校验：{'通过（与原文逐字符一致）' if ci else '失败（已自动回退）'}")
    L.append(
        f"- 环境配平：{'通过' if eb.get('ok') else '失败 ' + str(eb.get('unbalanced_begins')) + '/' + str(eb.get('unbalanced_ends'))}"
    )
    L.append(f"- 花括号配平：{'通过' if br.get('ok') else '提示（' + str(br.get('depth')) + '）'}（仅参考）")
    if ki:
        L.append("")
        L.append("### 已知问题（原书既有，未做修改，仅供参考）")
        for k in ki[:20]:
            L.append(f"- 第 {k.get('line')} 行：{k.get('reason')}")
        if len(ki) > 20:
            L.append(f"- ……共 {len(ki)} 处")
    return "\n".join(L)

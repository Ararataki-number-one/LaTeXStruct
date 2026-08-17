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
    template_name: str = "",
    ocr_structure_notes: List[dict] = None,
) -> str:
    ai_notes = ai_notes or []
    review = review or {}
    template_notes = template_notes or []
    ocr_structure_notes = ocr_structure_notes or []
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
        if ai_notes:
            L.append("- AI 说明：")
            for note in ai_notes:
                L.append(f"  - {note.get('candidate_id', '-')}：{note.get('reason', '')}")
        L.append("")

    if template_applied or template_notes:
        section(f"模板排版（{template_name or '固定模板'}）")
        for t in template_notes:
            L.append(f"- 第 {t.get('line')} 行：{t.get('reason')}")
        if template_applied:
            L.append("- 模板也以可逆补丁应用；正文、公式与引用仍参与统一安全检查")
        L.append("")

    if ocr_structure_notes:
        section("OCR 章节树与目录")
        mapped = [item for item in ocr_structure_notes if item.get("status") == "mapped"]
        removed = [
            item for item in ocr_structure_notes
            if item.get("status") == "removed-header"
        ]
        missing = [
            item for item in ocr_structure_notes
            if item.get("status") in ("missing", "rejected")
        ]
        L.append(f"- 已映射大纲/目录：{len(mapped)} 项；移除重复页眉：{len(removed)} 项")
        for item in missing[:20]:
            L.append(f"- ⚠ 第 {item.get('line', '?')} 行：{item.get('reason', '')}")
        L.append("")

    section("机器校验")
    ci = verification.get("content_invariant")
    eb = verification.get("env_balance", {})
    br = verification.get("braces", {})
    ki = verification.get("known_issues", [])
    inv = verification.get("invariants", {})
    display_tags = verification.get("display_tags", {})
    ocr_structure = verification.get("ocr_structure", {})
    resources = verification.get("resources", {})
    L.append(f"- 内容不变校验：{'通过（与原文逐字符一致）' if ci else '失败（已自动回退）'}")
    L.append(
        f"- 环境配平：{'通过' if eb.get('ok') else '失败（整理后异常：' + str(eb.get('after_unbalanced', [])) + '）'}"
    )
    L.append(f"- 花括号配平：{'通过' if br.get('ok') else '失败（已自动回退）'}")
    if inv:
        names = {"math": "数学公式 token", "labels": "\\label 集合", "refs": "\\ref 集合",
                 "cites": "\\cite 集合", "images": "图片路径集合"}
        L.append("- 多层不变量校验（整理前后必须完全一致）：")
        for key, label in names.items():
            d = inv.get(key)
            if d:
                status = "一致" if d["equal"] else f"不一致（{d['before_count']}→{d['after_count']}）"
                L.append(f"  - {label}：{status}")
    if display_tags:
        if display_tags.get("ok"):
            L.append("- 展示公式语法：通过")
        else:
            lines = sorted({
                item.get("line") for item in display_tags.get("issues", [])
                if isinstance(item.get("line"), int)
            })
            locations = "、".join(str(line) for line in lines[:6]) or "未知"
            L.append(
                "- 展示公式语法：失败"
                f"（第 {locations} 行；\\[ / \\] 分隔符或 \\tag 用法异常，已阻止导出）"
            )
            reasons = []
            for item in display_tags.get("issues", []):
                reason = str(item.get("reason", "")).strip()
                if reason and reason not in reasons:
                    reasons.append(reason)
            for reason in reasons[:3]:
                L.append(f"  - {reason}")
    if ocr_structure.get("checked"):
        L.append(
            "- PDF 大纲与目录："
            + (
                f"通过（{ocr_structure.get('matched', 0)}/"
                f"{ocr_structure.get('expected', 0)} 个节点）"
                if ocr_structure.get("ok")
                else "失败（已阻止导出）"
            )
        )
        for item in ocr_structure.get("issues", [])[:10]:
            where = f"第 {item.get('line')} 行：" if item.get("line") else ""
            L.append(f"  - {where}{item.get('reason', '')}")
    if resources.get("checked"):
        if resources.get("ok"):
            L.append(f"- 图片资源：通过（{resources.get('count', 0)} 项）")
        else:
            L.append("- 图片资源：失败（缺失或路径不安全，已阻止导出）")
            for path in resources.get("missing", [])[:10]:
                L.append(f"  - 缺失：{path}")
            for path in resources.get("unsafe", [])[:10]:
                L.append(f"  - 不安全路径：{path}")
    cb = verification.get("compile_before")
    ca = verification.get("compile_after")
    if cb and ca and cb.get("available"):
        L.append("- 编译校验（xelatex）：")
        L.append(
            f"  - 整理前：{'成功 ' + str(cb.get('pages')) + ' 页' if cb.get('ok') else '失败 ' + '; '.join(cb.get('errors', [])[:2])}"
        )
        L.append(
            f"  - 整理后：{'成功 ' + str(ca.get('pages')) + ' 页' if ca.get('ok') else '失败 ' + '; '.join(ca.get('errors', [])[:2])}"
        )
    elif verification.get("compile_required"):
        L.append("- 编译校验（xelatex）：不可用；OCR 成品已按保守原则阻止导出")
    elif verification.get("compile_required_when_available"):
        L.append("- 编译校验（xelatex）：本机不可用；已执行静态公式、章节与资源安全检查")
    L.append(
        f"- 导出门禁：{'通过' if verification.get('safe_to_export') else '未通过（结果已回退且禁止危险导出）'}"
    )
    if ki:
        L.append("")
        L.append("### 已知问题（原书既有，未做修改，仅供参考）")
        grouped = {}
        for item in ki:
            reason = str(item.get("reason", ""))
            group = grouped.setdefault(reason, {"count": 0, "lines": set()})
            group["count"] += max(1, int(item.get("count", 1) or 1))
            line = item.get("line")
            if isinstance(line, int) and line > 0:
                group["lines"].add(line)
        for reason, group in grouped.items():
            lines = sorted(group["lines"])
            shown = "、".join(str(line) for line in lines[:6])
            if len(lines) > 6:
                shown += " 等"
            location = f"第 {shown} 行" if shown else "位置未知"
            suffix = ""
            if group["count"] > 1:
                suffix = f"（共 {group['count']} 处，涉及 {len(lines)} 行）"
            L.append(f"- {location}：{reason}{suffix}")
    return "\n".join(L)

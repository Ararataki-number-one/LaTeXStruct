# -*- coding: utf-8 -*-
"""Human-readable audit report for one LaTeXStruct pipeline run."""

from __future__ import annotations

from typing import Dict, List

from .patch import AppliedPatch


def reconcile_report_status(
    report_md: str,
    verification: Dict,
    *,
    terminal_status: str,
) -> str:
    """Make an existing report reflect the final, post-pipeline export gates.

    ``build_report`` runs inside the core pipeline.  Hosts may apply additional
    fail-closed checks afterwards (for example, project-file completeness or
    lossless source-encoding checks).  Rebuilding the entire report at that
    point would discard pipeline-only explanatory sections, so this function
    rewrites the conclusion and export-gate line in place after every host gate
    has finished.

    A report may claim ``VERIFIED`` only when both the persisted verification
    record and the terminal state explicitly say that the run succeeded.
    """
    verification = verification if isinstance(verification, dict) else {}
    requested_terminal = str(terminal_status or "").strip().upper()
    safe = (
        verification.get("safe_to_export") is True
        and requested_terminal == "SUCCESS"
    )
    terminal = "SUCCESS" if safe else "UNVERIFIED"

    failures = verification.get("failures")
    reasons = []
    if isinstance(failures, list):
        for item in failures:
            if not isinstance(item, dict):
                continue
            reason = str(item.get("label") or item.get("summary") or item.get("id") or "").strip()
            if reason and reason not in reasons:
                reasons.append(reason)
    if not reasons:
        for item in verification.get("checks", []):
            if not isinstance(item, dict) or item.get("ok") is not False:
                continue
            reason = str(item.get("label") or item.get("id") or "未命名检查").strip()
            if reason and reason not in reasons:
                reasons.append(reason)
    if not safe and not reasons:
        reasons.append("最终导出门禁未明确通过")

    lines = str(report_md or "").splitlines()
    try:
        conclusion_heading = lines.index("## 结论")
    except ValueError:
        conclusion_heading = -1

    if conclusion_heading >= 0:
        conclusion_end = len(lines)
        for index in range(conclusion_heading + 1, len(lines)):
            if lines[index].startswith("## "):
                conclusion_end = index
                break
        conclusion = lines[conclusion_heading + 1:conclusion_end]
        variable_prefixes = (
            "- 状态：",
            "- 运行终态：",
            "- 未验证原因：",
            "- 阻断项：",
            "- 建议先打开：",
        )
        fixed = [
            line for line in conclusion
            if not line.startswith(variable_prefixes)
        ]
        while fixed and not fixed[0].strip():
            fixed.pop(0)
        while fixed and not fixed[-1].strip():
            fixed.pop()
        fixed.insert(
            0,
            "- 状态："
            + ("VERIFIED（可安全导出）" if safe else "UNVERIFIED（禁止作为已验证成品）"),
        )
        fixed.insert(1, f"- 运行终态：{terminal}")
        if safe:
            fixed.extend([
                "- 阻断项：0",
                "- 建议先打开：项目主 TEX；交付时同时保留完整 ZIP 证据包",
            ])
        else:
            fixed.extend([
                "- 未验证原因：" + "、".join(reasons),
                "- 建议先打开：`LATEXSTRUCT-REPORT.md`，按失败检查逐项修复",
            ])
        lines = (
            lines[:conclusion_heading + 1]
            + [""]
            + fixed
            + [""]
            + lines[conclusion_end:]
        )

    gate_line = (
        "- 导出门禁：通过"
        if safe
        else "- 导出门禁：未通过（结果已回退且禁止危险导出）"
    )
    replaced_gate = False
    for index, line in enumerate(lines):
        if line.startswith("- 导出门禁："):
            lines[index] = gate_line
            replaced_gate = True
    if not replaced_gate:
        lines.extend(["", gate_line])
    return "\n".join(lines)


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
    safe_to_export = verification.get("safe_to_export") is True
    checks_by_id = {
        str(item.get("id") or ""): item
        for item in verification.get("checks", [])
        if isinstance(item, dict) and item.get("id")
    }
    failed_checks = [
        str(item.get("label") or item.get("id") or "未命名检查")
        for item in verification.get("checks", [])
        if isinstance(item, dict) and item.get("ok") is False
    ]
    if not safe_to_export and not failed_checks:
        failed_checks = [
            str(item.get("summary") or item.get("reason") or item.get("code") or "").strip()
            for item in verification.get("failures", [])
            if isinstance(item, dict)
            and str(item.get("summary") or item.get("reason") or item.get("code") or "").strip()
        ]
    if not safe_to_export and not failed_checks:
        failed_checks = ["最终导出门禁未明确通过"]
    L: List[str] = ["# LaTeXStruct 结构化整理汇报", "", "## 结论", ""]
    L.append(f"- 状态：{'VERIFIED（可安全导出）' if safe_to_export else 'UNVERIFIED（禁止作为已验证成品）'}")
    L.append("- 输入：当前项目中冻结的原始 TEX / OCR 转写与其来源证据")
    L.append("- 生成：结构化 TEX、机器校验记录和可复算的项目证据包")
    L.append(f"- 模式：{mode}")
    L.append(
        f"- 修改统计：应用 {len(applied)}；被拒绝 {len(rejected)}；"
        f"待人工核对 {len(ambiguous)}"
    )
    if failed_checks:
        L.append("- 未验证原因：" + "、".join(failed_checks))
        L.append("- 建议先打开：`LATEXSTRUCT-REPORT.md`，按失败检查逐项修复")
    else:
        L.append("- 阻断项：0")
        L.append("- 建议先打开：项目主 TEX；交付时同时保留完整 ZIP 证据包")
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

    source_visual = verification.get("source_visual_provenance") or {}
    source_visual_issues = list(source_visual.get("issues") or [])
    if source_visual.get("checked") is True or source_visual_issues:
        section("原始上传与视觉 PDF 证据链")
        if source_visual.get("ok") is True:
            L.append("- 状态：通过；pipeline 使用的视觉 PDF 已绑定原始上传记录")
        else:
            L.append("- 状态：未通过；来源哈希或派生关系不完整，已阻止验证")
        source_type = str(source_visual.get("source_type") or "UNKNOWN").upper()
        L.append(f"- 原始上传类型：`{source_type}`")
        L.append(
            f"- 原始上传：{int(source_visual.get('original_upload_bytes', 0) or 0)} bytes；"
            f"SHA-256 `{source_visual.get('original_upload_sha256') or 'UNKNOWN'}`"
        )
        L.append(
            f"- 视觉 PDF：{int(source_visual.get('visual_pdf_bytes', 0) or 0)} bytes；"
            f"SHA-256 `{source_visual.get('visual_pdf_sha256') or 'UNKNOWN'}`"
        )
        derived = source_visual.get("visual_pdf_is_derived")
        derived_label = "是" if derived is True else "否" if derived is False else "未知"
        L.append(
            f"- 是否派生：{derived_label}；固定 derivation："
            f"`{source_visual.get('derivation_id') or 'UNKNOWN'}`"
        )
        if derived is True:
            L.append(
                "- 说明：原始图片仅为逐页视觉比对包装成单页 PDF；"
                "该包装 PDF 不是用户上传的 PDF，也不是 LaTeX 编译产物"
            )
        for issue in source_visual_issues[:12]:
            L.append(f"  - ⚠ {issue}")
        L.append("")

    full_review = verification.get("full_document_review") or {}
    full_review_check = checks_by_id.get("full-document-review", {})
    if full_review or full_review_check:
        section("全文独立结构复核")
        full_review_skipped = full_review_check.get("skipped") is True
        chunks = list(full_review.get("chunks") or [])
        invalid = list(full_review.get("invalid") or [])
        escalations = list(full_review.get("escalations") or [])
        if (
            full_review.get("skip_reason") == "user-disabled"
            or full_review_check.get("skip_reason") == "user-disabled"
        ):
            L.append("- 状态：用户未启用第二遍复查（不是检查通过）")
        elif full_review_skipped:
            L.append("- 状态：本次工作流未要求出版级全文复核（不是检查通过）")
        elif full_review.get("checked") is True and full_review.get("ok") is True:
            L.append(f"- 状态：通过；已逐段复核 {len(chunks)} 个全文分段")
        else:
            L.append("- 状态：未完成或仍有未解决项；已阻止作为已验证成品导出")
        inventory_counts = (full_review.get("inventory") or {}).get("counts") or {}
        if inventory_counts:
            L.append(
                "- 复核输入库存："
                f"formal 标题 {int(inventory_counts.get('anchors', 0) or 0)}；"
                f"既有环境 {int(inventory_counts.get('environments', 0) or 0)}；"
                f"初始发现 {int(inventory_counts.get('findings', 0) or 0)}"
            )
        L.append(f"- 无效回复：{len(invalid)}；需人工处理：{len(escalations)}")
        for item in (invalid + escalations)[:12]:
            line = item.get("line")
            where = f"第 {line} 行" if isinstance(line, int) and line > 0 else "位置未知"
            L.append(f"  - {where}：{item.get('reason') or '全文复核没有给出可验证结论'}")
        usage = (verification.get("ai_usage") or {}).get("full_document_review") or {}
        if usage:
            L.append(
                f"- 复核模型：{usage.get('model') or '未记录'}；"
                f"tokens：{int(usage.get('total_tokens', 0) or 0)}"
            )
        L.append("")

    visual_loop = verification.get("visual_quality_loop") or {}
    visual_check = checks_by_id.get("compile-render-visual-repair", {})
    if visual_loop or visual_check:
        section("真实编译与逐页视觉质量闭环")
        required = visual_loop.get("required") is True
        rounds = list(visual_loop.get("rounds") or [])
        invalid = list(visual_loop.get("invalid") or [])
        unresolved = list(visual_loop.get("unresolved") or [])
        if visual_check.get("skipped") is True or not required:
            L.append("- 状态：本次工作流未要求逐页视觉闭环（不是视觉检查通过）")
        elif (
            visual_loop.get("checked") is True
            and visual_loop.get("ok") is True
            and not invalid
            and not unresolved
        ):
            L.append("- 状态：通过；最后一轮为完整编译且所选页面均已逐页复核")
        else:
            L.append("- 状态：未完成；缺页、编译失败、无效回复或未解决问题会阻止导出")
        L.append(
            f"- 运行轮次：{len(rounds)}；已执行可逆定点修复 "
            f"{int(visual_loop.get('repair_count', 0) or 0)} 项"
        )
        for round_record in rounds:
            round_no = int(round_record.get("round", 0) or 0)
            compiled = round_record.get("compile") or {}
            deterministic = round_record.get("deterministic") or {}
            ai_audit = round_record.get("ai_audit") or {}
            compile_ok = (
                compiled.get("ok") is True
                and str(compiled.get("preview_status") or "") == "COMPILED"
            )
            L.append(
                f"- 第 {round_no} 轮真实编译："
                + (
                    f"成功（{int(compiled.get('pages', 0) or 0)} 页，COMPILED）"
                    if compile_ok
                    else "未得到完整 COMPILED PDF"
                )
            )
            if deterministic:
                L.append(
                    "  - 确定性渲染检查："
                    f"{deterministic.get('status') or 'UNKNOWN'}；"
                    f"比较 {int(deterministic.get('compared_page_count', 0) or 0)} 页"
                )
            if ai_audit:
                L.append(
                    "  - AI 逐页复核："
                    f"{'完整' if ai_audit.get('checked') is True else '不完整'}；"
                    f"回答 {int(ai_audit.get('page_count', 0) or 0)} 页；"
                    f"建议 {len(ai_audit.get('suggestions') or [])} 项；"
                    f"未解决 {len(ai_audit.get('unresolved') or [])} 项"
                )
        for item in (invalid + unresolved)[:16]:
            page = item.get("page") or item.get("source_page")
            source_label = (
                "原始图片"
                if source_visual.get("source_type") in {"image", "images"}
                else "源 PDF"
            )
            where = (
                f"原始图片（视觉页 {page}）"
                if source_label == "原始图片" and page
                else f"{source_label} 第 {page} 页"
                if page
                else f"第 {item.get('round', '?')} 轮"
            )
            L.append(f"  - ⚠ {where}：{item.get('reason') or '视觉质量闭环未完成'}")
        L.append("")

    final_inventory = verification.get("final_formal_inventory") or {}
    final_inventory_check = checks_by_id.get("final-formal-inventory", {})
    if final_inventory or final_inventory_check:
        section("最终 formal 结构清单")
        counts = final_inventory.get("counts") or {}
        findings = list(final_inventory.get("findings") or [])
        blocking_kinds = {"missing", "wrong-env", "overwide", "duplicate"}
        blockers = [item for item in findings if item.get("kind") in blocking_kinds]
        L.append(
            f"- 最终 TEX 清点：formal 标题 {int(counts.get('anchors', 0) or 0)}；"
            f"环境 {int(counts.get('environments', 0) or 0)}；"
            f"发现 {len(findings)}；阻断项 {len(blockers)}"
        )
        if final_inventory_check.get("skipped") is True:
            L.append("- 门禁：本次未启用出版级最终清点门；下列库存仅供诊断")
        elif not blockers and final_inventory_check.get("ok") is True:
            L.append("- 门禁：通过；未发现漏套、错套、范围过宽或重复环境")
        else:
            L.append("- 门禁：未通过；以下问题必须修复后重新运行")
        kind_labels = {
            "missing": "漏套环境",
            "wrong-env": "环境类型不符",
            "overwide": "环境范围过宽或多套",
            "duplicate": "重复 formal 环境",
        }
        for item in blockers[:20]:
            start = item.get("start_line")
            end = item.get("end_line")
            where = (
                f"第 {start}–{end} 行"
                if start and end and start != end
                else f"第 {start or '?'} 行"
            )
            env_change = ""
            if item.get("original_env") or item.get("suggested_env"):
                env_change = (
                    f"（{item.get('original_env') or '无环境'} → "
                    f"{item.get('suggested_env') or '待确认'}）"
                )
            L.append(
                f"  - {where}：{kind_labels.get(item.get('kind'), item.get('kind'))}"
                f"{env_change}；{item.get('reason') or '需人工确认'}"
            )
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
    structure = verification.get("structure_decisions", {})
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
    if structure:
        formal_total = int(structure.get("formal_total", 0) or 0)
        formal_wrapped = int(structure.get("formal_wrapped", 0) or 0)
        residual = list(structure.get("formal_residual_ids") or [])
        L.append(
            "- 显式 formal 结构库存："
            f"{formal_wrapped}/{formal_total} 已完整结构化；残留 {len(residual)}"
        )
        for candidate_id in residual[:10]:
            L.append(f"  - 未结构化：{candidate_id}")
    cb = verification.get("compile_before")
    ca = verification.get("compile_after")
    if cb and ca and cb.get("available"):
        compile_engines = []
        for record in (cb, ca):
            engine = str(record.get("engine") or "xelatex").strip()
            if engine.lower().endswith(".exe"):
                engine = engine[:-4]
            if engine and engine not in compile_engines:
                compile_engines.append(engine)
        L.append(f"- 编译校验（{' / '.join(compile_engines)}）：")
        L.append(
            f"  - 整理前：{'成功 ' + str(cb.get('pages')) + ' 页' if cb.get('ok') else '失败 ' + '; '.join(cb.get('errors', [])[:2])}"
        )
        L.append(
            f"  - 整理后：{'成功 ' + str(ca.get('pages')) + ' 页' if ca.get('ok') else '失败 ' + '; '.join(ca.get('errors', [])[:2])}"
        )
        preview_artifact = verification.get("preview_artifact") or {}
        L.append(
            "  - 预览状态："
            + str(verification.get("preview_state") or "SOURCE_PREVIEW")
            + (
                f"（工件：{preview_artifact.get('filename')}）"
                if preview_artifact.get("filename")
                else "（无编译 PDF 工件）"
            )
        )
        if verification.get("compile", {}).get("unverified"):
            L.append(
                "  - 结论：整理前后均编译失败，首个错误相同不足以证明补丁未引入后续错误；"
                "已按未验证结果阻止安全导出"
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

# -*- coding: utf-8 -*-
"""Deterministic prompts for a LaTeXStruct AI audit submission.

This module has no model client.  It renders only facts already recorded in an
``AuditSubmissionManifest`` and therefore cannot select files or promote a
verification status.
"""

from __future__ import annotations

from .audit_schema import (
    ArtifactRole,
    AuditSubmissionManifest,
    AuditWorkflow,
)


_ROLE_LABELS = {
    ArtifactRole.SOURCE_TEX: "原始 TeX 输入",
    ArtifactRole.SOURCE_PDF: "原始 PDF 输入",
    ArtifactRole.SOURCE_IMAGE: "原始图片输入",
    ArtifactRole.STAGE_SOURCE_TEX: "源文本阶段快照",
    ArtifactRole.RAW_OCR_TEX: "原始 OCR TeX",
    ArtifactRole.AI_ANALYZED_TEX: "AI 分析阶段 TeX",
    ArtifactRole.RULE_ANALYZED_TEX: "规则分析阶段 TeX",
    ArtifactRole.AI_REVIEWED_TEX: "AI 审阅阶段 TeX",
    ArtifactRole.CURRENT_TEX: "当前 TeX",
    ArtifactRole.CURRENT_PREVIEW: "当前预览",
    ArtifactRole.RAW_OCR_PREVIEW: "原始 OCR 预览",
    ArtifactRole.REPORT: "运行报告",
    ArtifactRole.VERIFICATION: "机器验证记录",
    ArtifactRole.DECISIONS: "审阅决策记录",
    ArtifactRole.RAW_TO_CURRENT_DIFF: "原始内容到当前内容的差异",
    ArtifactRole.COMPILE_CURRENT_LOG: "当前 TeX 编译日志",
    ArtifactRole.COMPILE_RAW_LOG: "原始 OCR 编译日志",
    ArtifactRole.ERROR_LOG: "错误日志",
    ArtifactRole.OUTLINE: "页面与结构提纲证据",
    ArtifactRole.PAGE_IMAGE: "源页面图像证据",
    ArtifactRole.FORMULA_CROP: "公式裁片证据",
    ArtifactRole.PROJECT_FILE: "多文件工程成员",
    ArtifactRole.EVIDENCE: "补充证据",
    ArtifactRole.README: "首先阅读的说明",
    ArtifactRole.PROMPT_SHORT: "简短提交话术",
    ArtifactRole.PROMPT_FULL: "完整审计提示词",
    ArtifactRole.SUBMISSION_MANIFEST: "权威提交清单",
    ArtifactRole.SHA256SUMS: "可重算哈希清单",
}


_WORKFLOW_CHECKS = {
    AuditWorkflow.ANALYSIS_REVIEW_ONLY: (
        "逐项比较源 TeX、各可用中间阶段与当前 TeX，检查内容守恒和结构环境边界。",
        "核对分析与审阅决策是否有证据支撑，特别留意漏套、误套和过度修改。",
    ),
    AuditWorkflow.OCR_ONLY: (
        "把源 PDF/图片/页面证据与原始 OCR TeX 对照，检查文字、数学符号、公式编号和页序。",
        "区分 OCR 转写错误、预览降级和真实 LaTeX 编译错误。",
    ),
    AuditWorkflow.OCR_ANALYSIS_REVIEW: (
        "沿源 PDF/图片 → 原始 OCR → 分析/审阅阶段 → 当前 TeX 的父子链逐阶段核对。",
        "分别报告 OCR 忠实度、结构识别、公式与引用、编译预览和审阅决策问题。",
    ),
    AuditWorkflow.TEMPLATE_CONVERSION: (
        "检查模板转换前后正文、公式、引用和结构是否守恒，并区分内容变化与版式变化。",
        "核对模板资源、编译证据及降级预览声明。",
    ),
    AuditWorkflow.MULTIFILE_PROJECT: (
        "按清单中的父子关系检查主文件、子文件和资源依赖，不根据文件名猜测角色。",
        "检查工程文件集合、引用关系、编译日志和当前成品是否互相一致。",
    ),
}

_CONTROL_ROLES = {
    ArtifactRole.README,
    ArtifactRole.PROMPT_SHORT,
    ArtifactRole.PROMPT_FULL,
    ArtifactRole.SUBMISSION_MANIFEST,
    ArtifactRole.SHA256SUMS,
}


def _path_for_role(manifest: AuditSubmissionManifest, role: str) -> str:
    for item in manifest.artifacts:
        if item.artifact_role == role:
            return item.path
    raise ValueError(f"manifest has no required control artifact role {role}")


def _optional_path_for_role(manifest: AuditSubmissionManifest, role: str) -> str:
    for item in manifest.artifacts:
        if item.artifact_role == role:
            return item.path
    return ""


def _escape_table(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_short_prompt(manifest: AuditSubmissionManifest) -> str:
    """Return exactly one copy-ready sentence using only manifest paths."""
    readme = _path_for_role(manifest, ArtifactRole.README)
    manifest_path = _path_for_role(manifest, ArtifactRole.SUBMISSION_MANIFEST)
    full = _path_for_role(manifest, ArtifactRole.PROMPT_FULL)
    return (
        f"请审计我上传的 LaTeXStruct 材料包，先读取 {readme}、{manifest_path} "
        f"和 {full}，以 manifest 中的文件角色、状态、哈希与父子关系为唯一依据完成审计。"
    )


def render_full_prompt(manifest: AuditSubmissionManifest) -> str:
    """Render the full external-audit prompt from recorded manifest facts."""
    lines = [
        "# LaTeXStruct 外部 AI 审计任务",
        "",
        "请对本提交包做独立、可复核的审计。不得根据文件名猜测文件角色；"
        "`submission_manifest.json` 中的 `artifact_role`、状态、哈希和父子关系是唯一权威来源。",
        "",
        "## 已由宿主程序冻结的运行事实",
        "",
        f"- 工作流：`{manifest.workflow.value}`",
        f"- 任务终态：`{manifest.terminal_status.value}`",
        f"- 机器验证状态：`{manifest.verification_status}`",
        f"- 审计深度：`{manifest.depth.value}`",
        f"- 模型：`{manifest.model}`",
        f"- LaTeXStruct 版本：`{manifest.app_version}`",
        f"- 模板：`{manifest.template}`",
        f"- 页范围：`{manifest.page_range}`",
        f"- 不可变快照：`{manifest.snapshot_id}`",
        "",
        "> `VERIFIED` 仅代表包内已有机器验证记录；不得因为任务为 SUCCESS、能够打开 PDF，"
        "或提示词的表述而自行提升验证状态。",
        "",
    ]
    if manifest.audit_focus:
        lines.extend([
            "## 用户希望重点关注",
            "",
            manifest.audit_focus,
            "",
        ])

    lines.extend([
        "## 实际可用审计工件",
        "",
        "下表只列出本包中实际存在的文件。重复字节只保存一次；逻辑别名记录在 manifest 的 "
        "`aliases` 中。",
        "",
        "| artifact_role | 路径 | SHA-256 | 预览状态 | 说明 |",
        "|---|---|---|---|---|",
    ])
    for item in manifest.artifacts:
        # Control documents would create a self-referential hash cycle: the full
        # prompt cannot truthfully print its own final digest.  They are named in
        # README/short prompt instead; this table is the audited evidence set.
        if item.artifact_role in _CONTROL_ROLES:
            continue
        digest = item.bytes_sha256 or "由 SHA256SUMS/文件本身校验"
        preview = item.preview_status or "—"
        label = _ROLE_LABELS.get(item.artifact_role, "宿主程序分类的补充工件")
        lines.append(
            "| "
            + " | ".join(
                _escape_table(value)
                for value in (item.artifact_role, item.path, digest, preview, label)
            )
            + " |"
        )
        for alias in item.aliases:
            alias_role = str(alias.get("artifact_role") or "UNKNOWN")
            alias_preview = str(alias.get("preview_status") or "—")
            alias_description = (
                f"逻辑节点 {alias.get('artifact_id') or 'unknown'}；"
                f"物理字节复用本行实际路径"
            )
            lines.append(
                "| "
                + " | ".join(
                    _escape_table(value)
                    for value in (
                        alias_role,
                        item.path,
                        digest,
                        alias_preview,
                        alias_description,
                    )
                )
                + " |"
            )

    lines.extend(["", "## 已记录的 blockers", ""])
    if manifest.blockers:
        lines.extend(f"- {item}" for item in manifest.blockers)
    else:
        lines.append("- 无已记录 blocker；这不等于外部审计已通过。")
    if manifest.missing_expected_roles:
        lines.extend([
            "",
            "## 缺失的预期角色",
            "",
            "以下角色在快照中不存在，因此不要假装已检查对应文件：",
            "",
        ])
        lines.extend(f"- `{role}`" for role in manifest.missing_expected_roles)
    if manifest.unavailable_parent_artifact_ids:
        lines.extend([
            "",
            "## 本档位未包含的父节点",
            "",
            "以下父节点 ID 由宿主快照记录，但对应工件因导出档位或用户选项未进入本包；"
            "不得猜测其内容或假装已完成跨阶段比较：",
            "",
        ])
        lines.extend(
            f"- `{artifact_id}`"
            for artifact_id in manifest.unavailable_parent_artifact_ids
        )

    lines.extend([
        "",
        "## 本工作流审计重点",
        "",
    ])
    lines.extend(f"- {item}" for item in _WORKFLOW_CHECKS[manifest.workflow])
    sums_path = _optional_path_for_role(manifest, ArtifactRole.SHA256SUMS)
    lines.extend([
        "",
        "## 必须执行的审计要求",
        "",
    ])
    if sums_path:
        lines.append(
            f"1. 先校验 `{sums_path}`；如有不一致，立即报告，不继续把材料当作同一快照。"
        )
    else:
        lines.append(
            "1. 当前只有轻量控制文件，没有哈希清单或审计工件；不得作内容审计结论，"
            "请先在 LaTeXStruct 中生成完整 ZIP。"
        )
    lines.extend([
        "2. 对包内可解析的节点严格沿 manifest 的 `parent_artifact_ids` 比较阶段差异；"
        "列入 `unavailable_parent_artifact_ids` 的父节点只能报告为证据缺失，不得猜测。",
        "3. 对公式、编号、定理环境、目录、引用、图片和多文件依赖，只在实际证据存在时给出结论。",
        "4. 把 `COMPILED`、`PARTIAL_COMPILED`、`SOURCE_PREVIEW` 严格区分；"
        "SOURCE_PREVIEW 不是 LaTeX 编译结果。",
        "5. 将问题按 blocker / major / minor 分类，每项给出证据文件、定位、预期、实际和修复建议。",
        "6. 最终分别报告：可确认结论、无法确认事项、缺失材料、风险和建议的下一步验证。",
        "7. 不要修改包内文件，也不要声称不存在的文件已被检查。",
        "",
        "## 建议输出结构",
        "",
        "- 总体结论及可信范围",
        "- 哈希与材料完整性",
        "- 按严重度排列的问题清单",
        "- 内容与结构准确性",
        "- 编译/预览与视觉质量",
        "- 决策记录一致性",
        "- 缺失证据与后续建议",
        "",
    ])
    return "\n".join(lines)


def render_readme(manifest: AuditSubmissionManifest) -> str:
    """Render a human first-open guide without inventing file paths."""
    short = _path_for_role(manifest, ArtifactRole.PROMPT_SHORT)
    full = _path_for_role(manifest, ArtifactRole.PROMPT_FULL)
    manifest_path = _path_for_role(manifest, ArtifactRole.SUBMISSION_MANIFEST)
    sums = _optional_path_for_role(manifest, ArtifactRole.SHA256SUMS)
    steps = []
    if sums:
        steps.append(f"1. 使用 `{sums}` 校验文件完整性；")
        next_number = 2
    else:
        steps.extend([
            "1. 这是自动保存的轻量控制集，并不包含源文件、阶段工件或哈希清单；",
            "2. 请先在 LaTeXStruct 中点击“生成 AI 审计提交包”，再上传生成的完整 ZIP；",
        ])
        next_number = 3
    steps.extend([
        f"{next_number}. 读取 `{manifest_path}`，只以其中的 `artifact_role` 判定文件角色；",
        f"{next_number + 1}. 将 `{short}` 的一句话连同完整 ZIP 提交给 ChatGPT/Codex；",
        f"{next_number + 2}. 审计方按 `{full}` 执行完整审计。",
    ])
    return "\n".join([
        "# 请先阅读：LaTeXStruct AI 审计提交包",
        "",
        f"这是运行 `{manifest.run_id}` 的不可变快照 `{manifest.snapshot_id}`。",
        f"任务终态为 **{manifest.terminal_status.value}**，机器验证状态为 "
        f"**{manifest.verification_status}**。两者不是同一概念。",
        "",
        "建议顺序：",
        "",
        *steps,
        "",
        "重复字节文件已经按 bytes SHA-256 去重，逻辑原路径保存在 manifest 的 "
        "`aliases` 中。ZIP 不保存用户机器绝对路径；开启清理时，文本中的凭据与本机路径已被替换。",
        "",
        "预览状态只能是 `COMPILED`、`PARTIAL_COMPILED` 或 `SOURCE_PREVIEW`。"
        "任何 SOURCE_PREVIEW 都不是 LaTeX 编译结果。",
        "",
    ])

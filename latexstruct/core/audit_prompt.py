# -*- coding: utf-8 -*-
"""Deterministic prompts for a LaTeXStruct AI audit submission.

This module has no model client.  It renders only facts already recorded in an
``AuditSubmissionManifest`` and therefore cannot select files or promote a
verification status.
"""

from __future__ import annotations

import json

from .audit_schema import (
    ArtifactRole,
    AuditPackageStatus,
    AuditSubmissionManifest,
    StageExecutionStatus,
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
    ArtifactRole.REPORT_JSON: "机器可读运行报告",
    ArtifactRole.ISSUES_CSV: "机器可读问题清单",
    ArtifactRole.METRICS: "机器可读指标",
    ArtifactRole.TEMPLATE_MANIFEST: "模板资产清单",
    ArtifactRole.COMPILE_INPUT_MANIFEST: "编译输入清单",
    ArtifactRole.RAW_COMPILE_INPUT_MANIFEST: "原始 OCR 编译输入清单",
    ArtifactRole.PACKAGING_INTEGRITY: "打包内容守恒记录",
    ArtifactRole.PACKAGING_ERROR: "打包失败记录",
    ArtifactRole.README: "首先阅读的说明",
    ArtifactRole.PROMPT_SHORT: "简短提交话术",
    ArtifactRole.PROMPT_FULL: "完整审计提示词",
    ArtifactRole.SUBMISSION_MANIFEST: "权威提交清单",
    ArtifactRole.SHA256SUMS: "可重算哈希清单",
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


_STAGE_LABELS = {
    "ocr": "OCR",
    "analysis": "AI/规则分析",
    "review": "独立 AI 审阅",
    "template": "模板转换",
}


def _physical_paths(manifest: AuditSubmissionManifest) -> set[str]:
    return {item.path for item in manifest.artifacts}


def _artifacts_for_role(manifest: AuditSubmissionManifest, role: str):
    return tuple(item for item in manifest.artifacts if item.artifact_role == role)


def _aliases_for_role(manifest: AuditSubmissionManifest, role: str):
    return tuple(
        alias
        for item in manifest.artifacts
        for alias in item.aliases
        if alias.get("artifact_role") == role
    )


def _has_logical_role(manifest: AuditSubmissionManifest, role: str) -> bool:
    return bool(_artifacts_for_role(manifest, role) or _aliases_for_role(manifest, role))


def _role_problem_details(
    manifest: AuditSubmissionManifest, role: str
) -> tuple[dict[str, object], ...]:
    return tuple(
        dict(item)
        for item in manifest.missing_expected_role_details
        if str(item.get("role") or "") == role
    )


def _stage_status(manifest: AuditSubmissionManifest, name: str) -> StageExecutionStatus:
    execution = manifest.stages.get(name)
    return (
        execution.status
        if execution is not None
        else StageExecutionStatus.NOT_REQUESTED
    )


def _stage_fact_sentence(manifest: AuditSubmissionManifest) -> str:
    descriptions = []
    for name in ("ocr", "analysis", "review", "template"):
        execution = manifest.stages[name]
        label = _STAGE_LABELS[name]
        status_text = {
            StageExecutionStatus.NOT_REQUESTED: "未请求",
            StageExecutionStatus.PENDING: "尚未执行",
            StageExecutionStatus.RUNNING: "运行中",
            StageExecutionStatus.COMPLETED: "已完成",
            StageExecutionStatus.SKIPPED: "已跳过",
            StageExecutionStatus.FAILED: "失败",
            StageExecutionStatus.CANCELLED: "已取消",
        }[execution.status]
        detail = f"{label}{status_text}"
        if execution.reason:
            detail += f"（{execution.reason}）"
        descriptions.append(detail)
    return "；".join(descriptions) + "。"


def _stage_audit_checks(manifest: AuditSubmissionManifest) -> list[str]:
    checks: list[str] = []
    if _stage_status(manifest, "ocr") is StageExecutionStatus.COMPLETED:
        checks.append(
            "OCR 阶段已记录为完成：仅使用包内实际源文件、RAW_OCR_TEX 与页面证据检查"
            "文字、数学符号、公式编号和页序。"
        )
    if _stage_status(manifest, "analysis") is StageExecutionStatus.COMPLETED:
        checks.append(
            "分析阶段已记录为完成：沿实际 parent_artifact_ids 比较分析输入、分析输出与"
            "当前 TeX，检查内容守恒和结构环境边界。"
        )
    review_status = _stage_status(manifest, "review")
    if review_status is StageExecutionStatus.COMPLETED:
        if _has_logical_role(manifest, ArtifactRole.AI_REVIEWED_TEX):
            checks.append(
                "独立 AI 审阅已记录为完成：核对 AI_REVIEWED_TEX 逻辑节点、canonical_path "
                "及审阅决策是否一致；字节去重只表示存储复用。"
            )
        else:
            checks.append(
                "独立 AI 审阅被记录为完成，但没有 AI_REVIEWED_TEX 逻辑节点；先报告 manifest "
                "一致性问题，不得假装已检查审阅输出。"
            )
    elif review_status in {
        StageExecutionStatus.SKIPPED,
        StageExecutionStatus.NOT_REQUESTED,
        StageExecutionStatus.CANCELLED,
        StageExecutionStatus.FAILED,
    }:
        checks.append(
            "本次没有可确认完成的独立 AI 审阅；不得给出‘审阅已完成’或独立复查已经覆盖问题的结论。"
        )
    if _stage_status(manifest, "template") is StageExecutionStatus.COMPLETED:
        checks.append(
            "模板转换已记录为完成：只在模板资产和编译输入清单实际存在时判断可复现性，"
            "并区分正文变化与版式变化。"
        )
    if _has_logical_role(manifest, ArtifactRole.PROJECT_FILE):
        checks.append(
            "包内存在多文件工程节点：按 artifact_role、canonical_path 和父子关系检查依赖，"
            "不得按文件名猜测主从关系。"
        )
    return checks or ["没有阶段被宿主记录为 COMPLETED；只能审计包完整性和现有静态工件。"]


def _render_provenance(manifest: AuditSubmissionManifest) -> list[str]:
    provenance = manifest.provenance.to_dict()
    if not any(provenance.values()):
        return [
            "- 该快照未持久化结构化 runtime/models/prompts/template provenance；",
            f"- 旧字段中的模型标签为 `{manifest.model}`，不得把它解释成各阶段模型身份；",
            "- 未知的 commit、build、模型或 prompt 版本必须报告为 UNKNOWN，不得用当前环境补写。",
        ]
    rendered = json.dumps(provenance, ensure_ascii=False, sort_keys=True, indent=2)
    return ["```json", rendered, "```"]


def render_short_prompt(manifest: AuditSubmissionManifest) -> str:
    """Return exactly one copy-ready sentence using only manifest paths."""
    readme = _path_for_role(manifest, ArtifactRole.README)
    manifest_path = _path_for_role(manifest, ArtifactRole.SUBMISSION_MANIFEST)
    full = _path_for_role(manifest, ArtifactRole.PROMPT_FULL)
    if manifest.audit_package_status is not AuditPackageStatus.VALID:
        return (
            f"请优先审计我上传的 LaTeXStruct 材料包完整性，先读取 {readme}、"
            f"{manifest_path} 和 {full}，在确认包状态与物理工件一致前不要审计论文结果。"
        )
    return (
        f"请审计我上传的 LaTeXStruct 材料包，先读取 {readme}、{manifest_path} "
        f"和 {full}，以 manifest 中的文件角色、状态、哈希与父子关系为唯一依据完成审计。"
    )


def render_full_prompt(manifest: AuditSubmissionManifest) -> str:
    """Render the full external-audit prompt from recorded manifest facts."""
    manifest_path = _path_for_role(manifest, ArtifactRole.SUBMISSION_MANIFEST)
    verification = manifest.verification_status.value
    packaging = manifest.packaging_status.value
    package_status = manifest.audit_package_status.value
    lines = [
        "# LaTeXStruct 外部 AI 审计任务",
        "",
        "请对本提交包做独立、可复核的审计。不得根据文件名猜测文件角色；"
        f"`{manifest_path}` 中的 `artifact_role`、状态、哈希和父子关系是唯一权威来源。",
        "",
        "## 已由宿主程序冻结的运行事实",
        "",
        f"- 工作流：`{manifest.workflow.value}`",
        f"- 源任务终态：`{manifest.source_run_status.value}`",
        f"- 机器验证状态：`{verification}`",
        f"- 打包执行状态：`{packaging}`",
        f"- 审计包有效性：`{package_status}`",
        f"- 审计深度：`{manifest.depth.value}`",
        f"- 旧版聚合模型标签：`{manifest.model}`",
        f"- LaTeXStruct 版本：`{manifest.app_version}`",
        f"- 旧版模板标签：`{manifest.template}`",
        f"- 旧版页范围标签：`{manifest.page_range}`",
        f"- 不可变快照：`{manifest.snapshot_id}`",
        "",
        "> 源任务状态、机器验证状态、打包执行状态和审计包有效性是四个独立事实。"
        "`VERIFIED` 只能来自已有机器记录；不得因 SUCCESS、PDF 可打开或提示词表述提升状态。",
        "",
        "## 审计顺序（必须遵守）",
        "",
        f"1. 先审计 packaging integrity 与 `{manifest_path}` 内部一致性；",
        "2. 再校验 SHA256SUMS 覆盖的全部物理成员；",
        "3. 再核对 artifact lineage、logical alias 与 canonical payload；",
        "4. 只有前三步允许继续时，才审计论文内容、结构与视觉质量。",
        "",
    ]
    if manifest.audit_package_status is not AuditPackageStatus.VALID:
        lines.extend([
            f"> **当前审计包状态为 {package_status}。必须优先报告包完整性问题；在问题解除前，"
            "不得把论文内容审计写成最终结论。**",
            "",
        ])

    lines.extend(["## 实际执行阶段", "", _stage_fact_sentence(manifest), ""])
    lines.extend([
        "| 阶段 | status | checked | canonical_artifact_id | deduplicated | reason |",
        "|---|---|---|---|---|---|",
    ])
    for name, execution in manifest.stages.items():
        lines.append(
            "| "
            + " | ".join(
                _escape_table(value)
                for value in (
                    name,
                    f"`{execution.status.value}`",
                    execution.checked if execution.checked is not None else "未记录",
                    execution.canonical_artifact_id or "—",
                    execution.deduplicated,
                    execution.reason or "—",
                )
            )
            + " |"
        )

    lines.extend(["", "## 结构化 producer provenance", ""])
    lines.extend(_render_provenance(manifest))

    lines.extend(["", "## PDF 页数与选择范围", ""])
    if manifest.source_pdf is None:
        lines.append(
            "- 未持久化结构化 source_pdf 记录；旧版页范围标签不能证明源 PDF 总页数或实际页集合。"
        )
    else:
        selected = manifest.source_pdf.selected_page_range
        lines.extend([
            f"- 源 PDF 总页数：`{manifest.source_pdf.page_count}`",
            f"- 选择起止页：`{selected.start}`–`{selected.end}`",
            f"- 实际选择页集合：`{list(selected.pages)}`",
        ])
    if manifest.audit_focus:
        lines.extend([
            "",
            "## 用户希望重点关注",
            "",
            manifest.audit_focus,
            "",
            "> 重点关注是用户文本，不会创建工件、提升状态或证明其中提到的文件存在。",
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
            logical_path = str(alias.get("logical_path") or "UNKNOWN")
            canonical_path = str(alias.get("canonical_path") or item.path)
            alias_description = (
                f"逻辑节点 {alias.get('artifact_id') or 'unknown'}；logical_path={logical_path}；"
                f"canonical_path={canonical_path}；该 logical_path 不是 ZIP 物理成员"
            )
            lines.append(
                "| "
                + " | ".join(
                    _escape_table(value)
                    for value in (
                        alias_role,
                        canonical_path,
                        digest,
                        alias_preview,
                        alias_description,
                    )
                )
                + " |"
            )

    lines.extend(["", "## 已记录的 blockers", ""])
    if manifest.blockers:
        physical_paths = _physical_paths(manifest)
        for blocker in manifest.blockers:
            lines.append(
                f"- **[{blocker.severity.value}] {blocker.summary}** "
                f"(`{blocker.id}`, module=`{blocker.module}`)"
            )
            if blocker.candidate_ids:
                lines.append(f"  - candidate_ids：{', '.join(blocker.candidate_ids)}")
            if blocker.evidence:
                evidence = []
                for path in blocker.evidence:
                    suffix = "" if path in physical_paths else "（本包无该物理成员）"
                    evidence.append(f"`{path}`{suffix}")
                lines.append("  - evidence：" + "、".join(evidence))
            if blocker.recommended_fix:
                lines.append(f"  - recommended_fix：{blocker.recommended_fix}")
            if blocker.acceptance:
                lines.append(f"  - acceptance：`{blocker.acceptance}`")
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
        for role in manifest.missing_expected_roles:
            reason = "宿主未在本包记录该预期角色"
            details = _role_problem_details(manifest, role)
            if details:
                reason = "；".join(
                    f"{item.get('status') or 'MISSING'}: {item.get('reason') or reason}"
                    for item in details
                )
            elif role == ArtifactRole.AI_REVIEWED_TEX:
                review = manifest.stages["review"]
                if review.status is StageExecutionStatus.SKIPPED:
                    reason = review.reason or "AI review was skipped"
            elif role == ArtifactRole.OUTLINE:
                reason = "无法审计 PDF outline 映射"
            elif role in {
                ArtifactRole.TEMPLATE_MANIFEST,
                ArtifactRole.COMPILE_INPUT_MANIFEST,
                ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
            }:
                reason = "缺少可复现编译所需的模板或输入清单"
            lines.append(f"- `{role}`：{reason}")
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

    lines.extend(["", "## 证据可用性与降级语义", ""])
    partial_previews = [
        (item.path, item.artifact_role)
        for item in manifest.artifacts
        if item.preview_status == "PARTIAL_COMPILED"
    ]
    partial_previews.extend(
        (str(alias.get("canonical_path")), str(alias.get("artifact_role")))
        for item in manifest.artifacts
        for alias in item.aliases
        if alias.get("preview_status") == "PARTIAL_COMPILED"
    )
    if partial_previews:
        for path, role in partial_previews:
            lines.append(
                f"- `{path}` 是 `{role}` 的真实 PARTIAL_COMPILED 物理 PDF；必须检查其已有页面、"
                "编译日志与 compile input 绑定，不能当作完整编译。"
            )
    else:
        lines.append("- 本包没有声明为 PARTIAL_COMPILED 的物理 PDF。")
    source_previews = [
        item.path for item in manifest.artifacts if item.preview_status == "SOURCE_PREVIEW"
    ]
    for path in source_previews:
        lines.append(f"- `{path}` 是 SOURCE_PREVIEW，不是 LaTeX 编译结果。")

    outlines = _artifacts_for_role(manifest, ArtifactRole.OUTLINE)
    outline_problems = _role_problem_details(manifest, ArtifactRole.OUTLINE)
    if outline_problems:
        lines.append(
            "- 包内 OUTLINE 工件未通过机器一致性检查，不能作为有效 outline 证据："
            + "；".join(str(item.get("reason") or "invalid outline") for item in outline_problems)
        )
    elif outlines:
        for outline in outlines:
            if outline.byte_count == 0:
                lines.append(
                    f"- `{outline.path}` 是空 outline 工件，不能作为有效 outline 证据；报告包不完整。"
                )
            else:
                lines.append(f"- 仅依据实际存在的 `{outline.path}` 审计 PDF outline 映射。")
    else:
        lines.append("- 本包没有 OUTLINE 物理工件，无法审计 PDF outline 映射。")

    has_template_manifest = _has_logical_role(manifest, ArtifactRole.TEMPLATE_MANIFEST)
    has_compile_inventory = _has_logical_role(manifest, ArtifactRole.COMPILE_INPUT_MANIFEST)
    template_problems = _role_problem_details(
        manifest, ArtifactRole.TEMPLATE_MANIFEST
    )
    compile_problems = _role_problem_details(
        manifest, ArtifactRole.COMPILE_INPUT_MANIFEST
    )
    if template_problems or compile_problems:
        lines.append(
            "- 模板资产或编译输入清单未通过完整性检查，无法证明能在干净环境完全复现本次编译。"
        )
    elif has_template_manifest and has_compile_inventory:
        lines.append("- 模板资产清单与编译输入清单均有逻辑节点，可按 canonical_path 核对可复现性。")
    elif (
        _stage_status(manifest, "template") is StageExecutionStatus.COMPLETED
        or str(manifest.template).strip().lower() not in {"", "none", "unknown"}
    ):
        lines.append(
            "- 模板资产清单或编译输入清单缺失，无法证明能在干净环境完全复现本次编译。"
        )

    lines.extend(["", "## 依据实际 stages 生成的审计重点", ""])
    lines.extend(f"- {item}" for item in _stage_audit_checks(manifest))
    sums_path = _optional_path_for_role(manifest, ArtifactRole.SHA256SUMS)
    lines.extend([
        "",
        "## 必须执行的审计要求",
        "",
    ])
    if sums_path:
        lines.append(
            f"1. 校验 `{sums_path}`；如有不一致，立即报告，不继续把材料当作同一快照。"
        )
    else:
        lines.append(
            "1. 当前只有轻量控制文件，没有哈希清单或审计工件；不得作内容审计结论，"
            "请先在 LaTeXStruct 中生成完整 ZIP。"
        )
    lines.extend([
        f"2. 核对 `{manifest_path}` 的四类状态、stages、物理 path 与 alias canonical_path；"
        "任何 INVALID/INCOMPLETE 或自相矛盾均优先于内容结论。",
        "3. 对包内可解析的节点严格沿 manifest 的 `parent_artifact_ids` 比较阶段差异；"
        "列入 `unavailable_parent_artifact_ids` 的父节点只能报告为证据缺失，不得猜测。",
        "4. 对公式、编号、定理环境、目录、引用、图片和多文件依赖，只在实际证据存在时给出结论。",
        "5. 把 `COMPILED`、`PARTIAL_COMPILED`、`SOURCE_PREVIEW` 严格区分；"
        "SOURCE_PREVIEW 不是 LaTeX 编译结果。",
        "6. 将问题按 blocker / major / minor 分类，每项给出证据文件、定位、预期、实际和修复建议。",
        "7. 最终分别报告：可确认结论、无法确认事项、缺失材料、风险和建议的下一步验证。",
        "8. 不要修改包内文件，也不要声称不存在的文件已被检查。",
        "",
        "## 建议输出结构",
        "",
        "- 总体结论及可信范围",
        "- 审计包有效性、manifest 一致性与哈希完整性",
        "- artifact lineage 与 alias canonical payload",
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
    short = _optional_path_for_role(manifest, ArtifactRole.PROMPT_SHORT)
    full = _optional_path_for_role(manifest, ArtifactRole.PROMPT_FULL)
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
    steps.append(
        f"{next_number}. 读取 `{manifest_path}`，只以其中的 `artifact_role` 判定文件角色；"
    )
    if short and full:
        steps.extend([
            f"{next_number + 1}. 将 `{short}` 的一句话连同完整 ZIP 提交给 ChatGPT/Codex；",
            f"{next_number + 2}. 审计方按 `{full}` 执行完整审计。",
        ])
    else:
        integrity = _optional_path_for_role(
            manifest, ArtifactRole.PACKAGING_INTEGRITY
        )
        packaging_error = _optional_path_for_role(
            manifest, ArtifactRole.PACKAGING_ERROR
        )
        steps.append(
            f"{next_number + 1}. 本包是 fail-closed 最小失败包；先检查 "
            f"`{integrity or 'audit/packaging-integrity.json'}` 和 "
            f"`{packaging_error or 'audit/packaging-error.json'}`，不要据此审计论文结果。"
        )
    return "\n".join([
        "# 请先阅读：LaTeXStruct AI 审计提交包",
        "",
        f"这是运行 `{manifest.run_id}` 的不可变快照 `{manifest.snapshot_id}`。",
        f"源任务终态为 **{manifest.source_run_status.value}**，机器验证状态为 "
        f"**{manifest.verification_status.value}**，打包执行状态为 "
        f"**{manifest.packaging_status.value}**，审计包有效性为 "
        f"**{manifest.audit_package_status.value}**。四者不是同一概念。",
        *(
            [
                "",
                "**本包不是 VALID：请先审计打包完整性和 manifest 一致性，在问题解除前不要"
                "把论文内容审计写成最终结论。",
            ]
            if manifest.audit_package_status is not AuditPackageStatus.VALID
            else []
        ),
        "",
        "建议顺序：",
        "",
        *steps,
        "",
        "重复字节文件已经按 bytes SHA-256 去重。`artifacts[].path` 只表示 ZIP 物理成员；"
        "alias 的 `logical_path` 不是物理成员，`canonical_path` 才是它复用的真实 ZIP 路径。",
        "ZIP 不保存用户机器绝对路径；开启清理时，仅允许按工件类型和宿主证据执行脱敏。",
        "",
        "预览状态只能是 `COMPILED`、`PARTIAL_COMPILED` 或 `SOURCE_PREVIEW`。"
        "任何 SOURCE_PREVIEW 都不是 LaTeX 编译结果。",
        "",
    ])

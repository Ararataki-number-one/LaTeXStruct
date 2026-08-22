# -*- coding: utf-8 -*-
"""Deterministic README and prompt generation for audit submission bundles."""

from __future__ import annotations

from .audit_schema import AuditSubmissionManifest

ROLE_LABELS = {
    "source_pdf": "源 PDF",
    "source_image": "源图片",
    "source_tex": "输入 TeX",
    "original_source_tex": "原始输入 TeX（字节保留）",
    "raw_ocr_tex": "OCR 原始 TeX",
    "preflight_tex": "语法预检后 TeX",
    "ai_analyzed_tex": "AI 分析后 TeX",
    "ai_reviewed_tex": "AI 独立审阅后 TeX",
    "current_reviewed_tex": "当前审阅结果 TeX",
    "current_unverified_tex": "当前未验证 TeX",
    "pre_template_tex": "模板转换前 TeX",
    "post_template_tex": "模板转换后 TeX",
    "compiled_preview_pdf": "真实完整编译 PDF",
    "partial_compiled_pdf": "真实部分编译 PDF",
    "source_preview_pdf": "源码预览 PDF（不是 LaTeX 编译结果）",
    "report_markdown": "审计/处理报告",
    "verification_json": "机器验证记录",
    "decisions_json": "结构决策与审阅记录",
    "issues_csv": "问题清单",
    "compile_raw_log": "原始/OCR TeX 编译日志",
    "compile_current_log": "当前 TeX 编译日志",
    "diff_raw_to_current": "原始到当前的完整差异",
    "outline_json": "PDF/OCR 大纲证据",
    "ocr_quality_json": "OCR 质量与证据记录",
    "source_project_zip": "原始多文件项目",
    "reviewed_project_zip": "当前审阅后多文件项目",
    "page_image": "源页图像证据",
    "formula_crop": "公式裁片证据",
    "metadata_json": "项目元数据（已清理）",
}


def role_label(role: str) -> str:
    return ROLE_LABELS.get(role, role)


def _artifact_lines(manifest: AuditSubmissionManifest) -> list[str]:
    lines: list[str] = []
    for artifact in manifest.snapshot.artifacts:
        suffix = ""
        if artifact.preview_status is not None:
            suffix += f"；preview={artifact.preview_status.value}"
        if artifact.aliases:
            suffix += f"；aliases={', '.join(artifact.aliases)}"
        if artifact.alias_roles:
            suffix += f"；alias_roles={', '.join(artifact.alias_roles)}"
        lines.append(
            f"- `{artifact.path}` — {role_label(artifact.artifact_role)}；"
            f"SHA-256 `{artifact.bytes_sha256}`{suffix}"
        )
    return lines


def build_short_prompt(_manifest: AuditSubmissionManifest) -> str:
    return (
        "请按本审计提交包执行 LaTeXStruct 全链路审计。先读取 "
        "00_README_FIRST.md、submission_manifest.json 和 02_PROMPT_FULL.md；"
        "文件角色一律以 manifest 中的 artifact_role 为准，不要根据文件名猜测。"
    )


def build_readme(manifest: AuditSubmissionManifest) -> str:
    snapshot = manifest.snapshot
    blockers = "\n".join(
        f"- [{item.get('severity', 'P0')}] {item.get('summary') or item.get('id') or '未说明'}"
        for item in snapshot.blockers
    ) or "- 未记录 blocker；仍须由外部审计独立核对。"
    missing = "\n".join(
        f"- `{item.get('role', 'unknown')}`：{item.get('reason', '本次运行未产生')}"
        for item in snapshot.missing_artifacts
    ) or "- 无"
    warnings = "\n".join(f"- {item}" for item in manifest.warnings) or "- 无"
    artifacts = "\n".join(_artifact_lines(manifest)) or "- 未发现可打包材料"
    first = next(
        (
            item.path
            for item in snapshot.artifacts
            if item.artifact_role in {"current_reviewed_tex", "current_unverified_tex"}
        ),
        "submission_manifest.json",
    )
    return f"""# LaTeXStruct AI 审计提交包

本包由宿主程序根据真实文件、机器验证记录和 SHA-256 自动生成。文件角色、状态和父子关系没有交给语言模型猜测。

## 建议阅读顺序

1. `submission_manifest.json`
2. `02_PROMPT_FULL.md`
3. `{first}`
4. `audit/report.md`、`audit/verification.json`、`audit/issues.csv`

## 本次运行

- 项目：{snapshot.project_name}
- 工作流：{snapshot.workflow_type.value}
- 任务终态：**{snapshot.terminal_status.value}**
- 机器验证状态：**{snapshot.verification_status}**
- 审计档位：{manifest.profile.value}
- 生成时间：{snapshot.generated_at_utc}
- 项目快照：`{snapshot.project_fingerprint}`

## 已知阻断项

{blockers}

## 实际包含的材料

{artifacts}

## 本次未产生的材料

{missing}

## 警告

{warnings}

## 预览状态说明

- `COMPILED`：真实完整 LaTeX 编译 PDF。
- `PARTIAL_COMPILED`：编译失败前真实产生的部分 PDF。
- `SOURCE_PREVIEW`：带行号的源码预览，不是 LaTeX 编译结果。

任何非 `SUCCESS/VERIFIED` 状态都不得被外部模型自行提升为已验证成品。
"""


def _comparison_requirements(roles: set[str]) -> list[str]:
    requirements: list[str] = []
    if "source_pdf" in roles and "raw_ocr_tex" in roles:
        requirements.append(
            "源 PDF → OCR 原始 TeX：逐页核对标题、正文、公式、编号、脚注、图表、图注与参考文献。"
        )
    if "raw_ocr_tex" in roles and roles.intersection({"current_reviewed_tex", "current_unverified_tex"}):
        requirements.append(
            "OCR 原始 TeX → 当前 TeX：执行全文 diff，区分纯结构改动、确定性修复、正文增删、数学变化与模板变化。"
        )
    if "source_tex" in roles and roles.intersection({"current_reviewed_tex", "current_unverified_tex"}):
        requirements.append(
            "输入 TeX → 当前 TeX：检查正文有序守恒、数学 token、环境边界、模板与依赖变化。"
        )
    if roles.intersection({"compiled_preview_pdf", "partial_compiled_pdf"}):
        requirements.append(
            "检查真实编译 PDF 的首页、目录、章首页、formal/proof 环境、跨页盒、References 与异常页面。"
        )
    elif "source_preview_pdf" in roles:
        requirements.append(
            "当前只有 SOURCE_PREVIEW；不得据此声称编译成功，须结合 TeX 与编译日志分析。"
        )
    if "source_project_zip" in roles:
        requirements.append(
            "核对多文件依赖图、主文件、子文件、图片、bib、cls/sty 和相对路径是否完整。"
        )
    return requirements or [
        "依据实际存在的材料检查结构、内容守恒、可编译性与 provenance；明确说明无法核对的范围。"
    ]


def build_full_prompt(manifest: AuditSubmissionManifest, audit_focus: str = "") -> str:
    snapshot = manifest.snapshot
    runtime = snapshot.runtime
    roles = {artifact.artifact_role for artifact in snapshot.artifacts}
    for artifact in snapshot.artifacts:
        roles.update(artifact.alias_roles)
    comparisons = "\n".join(
        f"{index}. {item}"
        for index, item in enumerate(_comparison_requirements(roles), start=1)
    )
    artifacts = "\n".join(_artifact_lines(manifest)) or "- 无"
    blockers = "\n".join(
        f"- `{item.get('id', 'blocker')}`：{item.get('summary', '未说明')}"
        for item in snapshot.blockers
    ) or "- 无已记录 blocker；仍需独立检查。"
    missing = "\n".join(
        f"- `{item.get('role', 'unknown')}`：{item.get('reason', '本次未产生')}"
        for item in snapshot.missing_artifacts
    ) or "- 无"
    focus = audit_focus.strip() or (
        "优先核对 manifest 中的 blockers、缺失材料和残留 formal/proof；不要补造不存在的阶段产物。"
    )
    page_range = ", ".join(map(str, snapshot.page_range)) if snapshot.page_range else "未知/不适用"
    return f"""# LaTeXStruct 全链路外部审计任务

你收到的是 LaTeXStruct 自动生成的标准审计提交包。请先读取 `submission_manifest.json`，再执行本提示词。

## 一、读取与真实性规则

1. `artifact_role` 是文件角色的唯一权威来源；不要根据文件名、内容相似度或时间自行重分配角色。
2. manifest 声明缺失的文件就是缺失，不得用其他文件静默替代。
3. `COMPILED`、`PARTIAL_COMPILED`、`SOURCE_PREVIEW` 必须严格区分；SOURCE_PREVIEW 不是编译结果。
4. 不得把“编译成功”等同于“内容正确”或“出版就绪”。
5. 不得自动纠正源论文可能存在的数学错误；只列为 `semantic-risk`。
6. VERIFIED 只能来自宿主机器验证；外部审计可以降级结论，但不能无证据升级。
7. 无法由材料支持的结论必须明确写为未知或无法核对。

## 二、本次任务上下文

- 项目：{snapshot.project_name}
- 工作流：{snapshot.workflow_type.value}
- 任务终态：{snapshot.terminal_status.value}
- 机器验证状态：{snapshot.verification_status}
- 模板：{snapshot.template or '未指定/保持原版'}
- 页范围：{page_range}
- LaTeXStruct：{runtime.get('app_version', 'unknown')}
- Git commit：{runtime.get('git_commit', 'unknown')}
- build_id：{runtime.get('build_id', 'unknown')}
- decide model：{runtime.get('decide_model', 'unknown')}
- review model：{runtime.get('review_model', 'unknown')}
- OCR model：{runtime.get('ocr_model', 'unknown')}
- prompt version：{runtime.get('prompt_version', 'unknown')}
- 项目快照 SHA-256：{snapshot.project_fingerprint}

## 三、本次重点

{focus}

## 四、实际可用材料

{artifacts}

## 五、已知 blocker

{blockers}

## 六、缺失材料

{missing}

## 七、必须执行的比较

{comparisons}

## 八、必须量化

- 源 PDF 页数和处理页范围；
- 章节节点总数、精确覆盖数和 residual；
- theorem/lemma/problem/conjecture/definition/remark 总数、环境化数和 residual；
- proof 总数、环境化数和 residual；
- 公式编号集合、活动 `equation/tag` 数和交叉引用完整性；
- 脚注、图片、表格、图注数量；
- 参考文献条目数、`bibitem` 数和跨页连续性；
- hard page break 数；
- 编译状态、页数、返回码和首个 fatal error；
- BODY_TEXT ordered recall 与数学 token 守恒；
- manifest、文件 SHA-256、版本和父子关系是否可复算。

## 九、问题归因

分别判断问题属于：PDF 对象层/OCR、确定性 scanner/parser、AI decision、AI review、template renderer、内容安全门、编译器、visual QA、provenance/packaging。不要把所有问题笼统归因于“模型不够强”。

## 十、输出要求

1. 给出 `VERIFIED / UNVERIFIED / FAILED / PARTIAL` 结论，并说明是否能覆盖原始 OCR、是否能直接发布；
2. 输出详细报告、量化指标和完整问题清单；
3. 按 P0/P1/P2 给出每项问题的证据、根因、具体代码/数据结构修改、回归测试和验收条件；
4. 列出无法核对的范围，不补造事实；
5. 优先引用包内文件路径、行号、页码和 hash。
"""

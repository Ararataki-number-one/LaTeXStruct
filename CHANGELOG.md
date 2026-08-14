# Changelog

本项目采用「tag 即发布」的自动化流程：`git tag vX.Y.Z && git push` 触发 CI
（ruff → 全量测试 → PyInstaller → Inno Setup → 安装器冒烟测试 → 签名 → GitHub Release）。

## v0.5.0（2025-08）

### 修复（P0）
- 版本号单一事实来源：`latexstruct/_version.py`，pyproject 动态读取，CI 校验 tag↔版本；
- CI 新增安装器冒烟测试（静默安装 → 运行健康检查 → 静默卸载），发布链路全环节验证；
- 清理误提交的 CI 调试产物（jobs.json）并加入 .gitignore。

### 文档
- 补齐 LICENSE（MIT）、CHANGELOG、CONTRIBUTING；设计文档入仓。

## v0.4.0（2025-08）
- 复查分块（review_batch，整书规模）；全书级 AI 实测（Godsil 3.58 万行：827 补丁、735 项复查修正、内容不变校验通过）。

## v0.3.3（2025-08）
- 决策提示词强化（PROMPT_VERSION 3.1：盒内翻译/(a)(b)条目/图注否定示例、span 语义）；
- 漏报抽查复查（AI 判 none 的候选交复查可 missed-extra 反悔）；
- CI ruff 质量门禁。

## v0.3.2（2025-08）
- AI 决策 span 段落边界合法化（wrong-range 10→1、复查 token -36%）；
- 复查成本优化（规则确定性编辑免复查）。

## v0.3.1（2025-08）
- OCR 友好错误提示（非视觉模型 400）、OCR Key 回退链修复；
- 构建脚本 --clean（修复 PyInstaller 增量缓存打包旧版本）；
- 安装器本地 E2E 验证；真实书稿 1.7 节回归样例。

## v0.3.0（2025-08）
- OCR 转写模块（PDF/图片 → 视觉模型逐页转写 → ElegantBook 书稿，模型可选）；
- 真实 AI Key 全流程验证（决策 + deepseek-reasoner 复查真实纠错）；
- CI 代码签名（secrets 配置后自动签名 exe 与安装器）、版本资源、自助签名脚本；
- 中文安装器默认界面。

## v0.2.1 / v0.2.0（2025-08）
- 安装版客户端（PyInstaller 单文件 exe + Inno Setup 安装器）与主动更新
  （GitHub Releases 检测 → 下载安装器 → 静默升级，E2E 验证）；
- GitHub Actions 全自动测试/构建/发布流水线。

## v0.1.x（开发期）
- 核心引擎：解析（等长屏蔽/精确偏移）→ 规则扫描 → AI 决策 → 可逆补丁 →
  内容不变机器校验 → AI 复查 → 汇报；
- 真实书稿打磨（双语盒、编号提取、整段证明、习题节、ElegantBook 模板转换、目录替换）。

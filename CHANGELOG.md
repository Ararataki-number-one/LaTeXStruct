# Changelog

本项目采用「tag 即发布」的自动化流程：`git tag vX.Y.Z && git push` 触发 CI
（ruff → 全量测试 → PyInstaller → Inno Setup → 安装器冒烟测试 → 签名 → GitHub Release）。

## v0.8.0（2025-08）
- **系统凭据管理器（keyring）**：开启后 API Key 写入 Windows 凭据管理器
  （advapi32 CredWrite/CredRead/CredDelete，零依赖），config.json 只存 `__keyring__`
  占位符不再落明文；关闭时自动清理系统凭据；非 Windows 平台自动回退原明文行为；
  设置页开关 + 「已配置(系统凭据)」来源标识；后端可注入测试（FakeBackend 6 例）。

## v0.7.1（2025-08）
- Monaco 三栏审阅工作台：决策树（按章节分组）+ 双向 Diff 编辑器（行号居中定位）+
  检视器（单项拒绝/同类批量拒绝/全部重置），三栏联动；
- OCR 逐页验证：任务进度按页细粒度展示、页面 PNG 预览 + LaTeX 逐页校对、
  低置信度标注（[?]/过短/失败）与单页重试端点；无 Key 时任务优雅完成并逐页报错；
- /legacy 目录重定向修复 + OCR 状态接口内部回调键过滤；服务器测试扩至 7 组（113 例）。

## v0.7.0（2025-08）
- React+Vite+Monaco 前端重建（本地打包 Monaco，离线可用；旧 UI 移至 /legacy）；
- 后端能力全暴露：文件夹导入（依赖图展示）、规则包选择、结构化文件夹 zip 导出、
  三角色模型设置；CI 自动构建前端并打进安装器。

## v0.6.2（2025-08）
- Benchmark 扩充：14 金标集 / 200 标签（真实书稿 10 组开发 + 2 组 hold-out），
  汇总 P/R/F1 + 正文零改动率/引用保持率/编译成功率；行号锚定标签；
- 基线对比环境平衡（部分输入原文不平衡时按"不新增不平衡"门禁）。

## v0.6.1（2025-08）
- Compile CI：TinyTeX + Benchmark --compile 前后编译对比门禁（报告编译列真实数据）；
- Lint 门禁升级（F+E741+W605）；pyproject 动态版本核实。

## v0.6.0（2025-08）
- 审阅式 UI：决策清单（章节/环境/行号/置信度/原因/状态）+ 过滤器 +
  单项拒绝重跑（exclude 重处理 + 全量重新校验）+ diff 行号定位；
- 评审重构收官：P0→P2 八轮全部落地（见 设计文档.md 评审重构总报告）。

## v0.5.6（2025-08）
- OCR 两阶段解耦：Stage A 视觉忠实转写（禁止结构判断），Stage B 复用结构化流水线；
  ocr_pipeline() 一步到位，两阶段语义测试锁定。

## v0.5.5（2025-08）
- Benchmark 金标评测：四组金标集（合成/中文/真实切片/陷阱），
  分类型 P/R/F1 + 内容指标 + Markdown 报告；CI 门禁；当前成绩全 100%、零误报。

## v0.5.4（2025-08）
- Rule Pack 配置化：内置 bilingual/english/chinese/academic-paper 规则包 +
  用户自定义 JSON（标题关键词映射/证明起始与续段词/习题关键词/双语开关），
  全链路 pack 参数贯通；default 包与旧行为完全一致。

## v0.5.3（2025-08）
- 多文件 LaTeX 项目支持：main.tex 发现、\input/\include 依赖图（缺失/循环检测）、
  带标记展开→流水线→拆分回文件→副本导出；CLI tools/process_project.py。

## v0.5.2（2025-08）
- 平衡括号解析器（core/texparse.py）：节标题支持嵌套花括号与数学内花括号、
  可选参数嵌套；双语翻译框识别同步升级；真实书稿回归零差异。

## v0.5.1（2025-08）
- 多层内容不变量校验：数学公式 token 多重集、`\label`/`\ref`/`\cite`/图片路径集合，
  整理前后必须完全一致（纳入 ok 判定）；
- 编译校验（可选，本机有 xelatex 时）：整理前后各编译一次对比页数与错误；
- 汇报展示五类不变量与编译对比；test_invariants 套件（含真实 xelatex 编译测试）。

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

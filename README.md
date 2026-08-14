# LaTeXStruct

LaTeX 数学书结构化整理本地客户端（Windows 优先，安装版 + 主动更新）。
仓库：<https://github.com/Ararataki-number-one/LaTeXStruct>
完整设计文档见仓库根目录 `设计文档.md`（v0.3 定稿，位于开发工作区，随版本发布）。

## 安装与更新

- **安装版**：GitHub Releases 下载 `LaTeXStruct-setup-*.exe` 双击安装（每用户、无需管理员）；
- **便携版**：Releases 中的 `LaTeXStruct.exe` 单文件免安装；
- **主动更新**：启动时自动检查 Releases 最新版，有新版即显示更新横幅，一键下载安装器静默升级；
  更新源默认 `Ararataki-number-one/LaTeXStruct`（可用环境变量 `LATEXSTRUCT_UPDATE_REPO` 覆盖）。
- **OCR 转写**：OCR 页签上传 PDF/图片 → 视觉模型逐页转写为 ElegantBook LaTeX（模型可选，
  设置页 OCR 模型；支持页码范围与 DPI）→ 一键导入项目继续结构化整理；
- **代码签名**：CI 已内置签名步骤——把证书放进 GitHub Secrets（`WINDOWS_CERT_BASE64` +
  `WINDOWS_CERT_PASSWORD`）后每次发布自动签名 exe 与安装器；本地可用 `scripts/sign_local.ps1`
  生成自签证书签名（仅本机信任）。**消除 SmartScreen 警告需购买 EV/OV 代码签名证书**
  （如 DigiCert/Sectigo），拿到 pfx 后按上述方式配置即可；
- 安装器界面默认**简体中文**（`packaging/installer.iss` 使用官方 ChineseSimplified 语言包）；
- 依赖 DeepSeek（或任意 OpenAI 兼容端点）API Key 才启用 AI 模式；无 Key 自动降级规则模式。

## 发布新版本（全自动）

```powershell
# 1) 改版本号 latexstruct/__init__.py 的 __version__
# 2) 提交并打 tag 推送 → CI 自动：测试 → 构建 exe → 构建安装器 → 发布 Release
git add -A; git commit -m "v0.2.1 ..."; git push
git tag v0.2.1; git push origin v0.2.1
# 3) 已安装客户端下次启动自动提示更新
```

## 当前状态（五轮持续优化完成）

- [x] 合成测试集全量通过（71 个测试：解析 10 / 扫描 11 / 补丁 13 / 流水线 7 / AI 9 / 模板 4 / 存储 2 / 服务 2 / 更新 3 / OCR 5 / 合法化 4）
- [x] **真实书稿打磨**：Godsil《代数图论》与 Jukna《极值组合学》双语书稿端到端跑通；
      `\begin{tcolorbox}\relax` 双语盒、编号提取进可选参数、Proof 起始语剥离、
      习题节盒内译文不改写、扫描性能修复（>600s → 0.04s）
- [x] **整段证明**：proof 覆盖同一证明的全部段落/公式/中文译文框
- [x] **ElegantBook 模板转换**：换文档类 + 章结构 + 删旧目录加 `\tableofcontents`；
      诊断编译 654 页全部通过
- [x] **OCR 转写**：PDF/图片 → 视觉模型逐页转写（模型可选；DeepSeek chat 不支持图片，
      需 qwen-vl/glm-4v 等视觉模型，界面与报错均有提示）
- [x] **AI 全链路**：真实 DeepSeek 实测——决策 + deepseek-reasoner 复查 +
      span 段落边界合法化（wrong-range 10→1、复查 token -36%）+ 漏报抽查 + 复查分块（整书规模）
- [x] **安装版 + 主动更新**：Inno Setup 中文安装器（本地 E2E 验证）+ GitHub Releases 自动检查更新 +
      CI 全自动发布（tag 触发：ruff → 测试 → 构建 → Release）
- [x] 质量门禁：CI ruff（F 规则）+ 版本一致性校验 + 11 套件全量测试
- [x] **审阅式界面**：决策清单（章节/环境/置信度/原因）+ 过滤器 + 单项拒绝恢复原文 +
  diff 行号跳转；Benchmark 金标评测（全 100%）；Rule Pack 配置化；多文件项目支持

核心保证：只改结构不改内容（撤销全部编辑后与原文逐字符一致的机器校验，失败自动回退）、
AI 只做决策不生成正文、歧义项一律保守保留并列入汇报。

## 目录结构

```
latexstruct/
├── .github/workflows/build.yml   # CI：测试 → 构建 exe → 安装器 → Release（全自动）
├── latexstruct/
│   ├── __init__.py               # 版本号 + 更新源
│   ├── __main__.py               # 启动器（windowed 兼容修复）
│   ├── updater.py                # 主动更新（GitHub Releases）
│   ├── config.py                 # 应用配置（三角色模型/复查开关）
│   ├── store.py                  # 项目存储（本地磁盘）
│   ├── core/                     # 核心流水线（纯标准库，可独立测试）
│   │   ├── parser.py             # LaTeX 轻量结构解析器
│   │   ├── scanner.py            # 规则扫描引擎
│   │   ├── patch.py              # 补丁模型 + 内容不变校验
│   │   ├── verify.py             # 环境/花括号配平 + 已知问题报告
│   │   ├── rules.py              # 规则模式决策（无 Key 降级）
│   │   ├── ai.py                 # AI 决策引擎（OpenAI 兼容客户端）
│   │   ├── review.py             # AI 复查引擎
│   │   ├── prompts.py            # 母提示词 v3 + Schema + 上下文组装
│   │   ├── template.py           # ElegantBook 模板转换
│   │   ├── report.py             # 极简汇报
│   │   └── pipeline.py           # 流水线编排
│   └── server/
│       ├── app.py                # FastAPI 本地服务（含更新接口）
│       └── static/               # 界面（无构建步骤）
├── packaging/
│   ├── LaTeXStruct.spec          # PyInstaller 单文件 exe
│   ├── installer.iss             # Inno Setup 安装器
│   ├── generate_icon.py          # 图标生成（纯标准库）
│   └── run.py                    # 打包入口
├── scripts/build.ps1             # 本地构建脚本
├── tests/                        # 9 个测试套件 + 合成/真实摘录语料
├── tools/                        # 真实书稿摸底/抽查脚本
├── requirements.txt
└── pyproject.toml
```

## 安装与运行

```powershell
# 1) 安装依赖
python -m pip install --user -r requirements.txt

# 2) 运行（三选一）
python -m latexstruct                 # 桌面窗口（pywebview；未装则自动回退浏览器模式）
python -m latexstruct --server        # 仅本地服务 → 浏览器打开 http://127.0.0.1:8080
python -m latexstruct --port 8765     # 指定端口
```

## 使用流程

1. **项目页**：粘贴/选择 `.tex` 全文，选择模式（规则 / AI），创建项目；
2. **处理与审阅页**：点击「运行结构化整理」→ 自动 解析→扫描→决策→补丁→校验→（AI 复查）→ 汇报；
3. 查看**前后对照 diff** 与极简汇报（含歧义项清单），下载 `result.tex` / `report.md`；
4. **AI 设置页**：配置决策/复查模型（默认 DeepSeek；复查默认 `deepseek-reasoner`）；
   Key 仅存本机 `%APPDATA%\LaTeXStruct\config.json`，也可用环境变量
   `LATEXSTRUCT_DECIDE_KEY` / `LATEXSTRUCT_REVIEW_KEY`。无 Key 时 AI 模式自动降级为规则模式。

## 运行测试

```powershell
cd latexstruct
python tests/test_parser.py
python tests/test_scanner.py
python tests/test_patch.py
python tests/test_pipeline.py
python tests/test_ai.py
python tests/test_store.py
python tests/test_server.py
```

## 核心保证

- **只改结构不改内容**：所有修改都是可逆编辑日志，机器校验"撤销全部编辑后与原文逐字符一致"，
  校验失败自动回退原文，绝不导出被改坏的内容；
- **最小改动**：按候选打补丁，绝不重写全文；
- **保守回退**：歧义项一律保留原文并列入汇报；
- **AI 只做决策**：AI 输出结构化 JSON（动作 + 行号区间），从不生成正文文本。

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

## 当前状态（M1 MVP 完成）

- [x] 设计定稿（v0.3）
- [x] LaTeX 轻量解析器（`core/parser.py`，纯标准库，等长屏蔽 + 精确行号偏移）
- [x] 规则扫描引擎（`core/scanner.py`：候选识别 + 硬排除）
- [x] 补丁模型 + 内容不变校验（`core/patch.py`：可逆编辑日志 + 逆序撤销比对）
- [x] 机器校验（`core/verify.py`：环境/花括号配平）
- [x] 规则模式决策（`core/rules.py`：无 Key 降级路径）
- [x] AI 决策引擎（`core/ai.py`：OpenAI 兼容，纯 urllib，角色独立配置，坐标白名单校验）
- [x] AI 复查引擎（`core/review.py`：wrong-env/wrong-range/should-remove/missed-extra 自动修正）
- [x] 提示词管理（`core/prompts.py`：母提示词 v3 + 决策/复查 Schema）
- [x] 流水线编排（`core/pipeline.py`：rule/ai 双模式，AI 不可用自动降级，失败自动回退原文）
- [x] 极简汇报（`core/report.py`）
- [x] 项目存储（`store.py`：本地磁盘，无数据库）
- [x] 应用配置（`config.py`：三角色模型，Key 仅存本机）
- [x] FastAPI 本地服务 + 无构建步骤 Web 界面（`server/`：项目/处理/审阅 diff/汇报/设置）
- [x] 启动器（`python -m latexstruct`：pywebview 窗口 / `--server` 浏览器模式）
- [x] 合成测试集全量通过（55 个测试：解析 10 / 扫描 11 / 补丁 13 / 流水线 6 / AI 7 / 模板 4 / 存储 2 / 服务 2）
- [x] **真实书稿打磨**：Godsil《代数图论》与 Jukna《极值组合学》两份双语书稿（各 3 万余行）
      端到端跑通（各 1–6 秒），合计 1900+ 个补丁全部通过内容不变校验；
      新增：`\begin{tcolorbox}\relax` 双语盒识别、编号提取进可选参数（`\begin{theorem}[1.7.2]`）、
      Proof 起始语剥离、习题节盒内译文不改写、扫描性能修复（>600s → 0.04s）；
      xelatex 编译自检：67 页 PDF，错误仅来自原书既有数学内容，与结构化插入无关
- [x] **整段证明**：proof 环境覆盖同一证明的全部段落/显示公式/中文译文框
      （续段连接词启发式 + □/证毕结束符 + 定理标题/节标题停点 + 叙述重启停点；
      两本书 603 个证明全部整段包裹，最长 111 行）
- [x] **ElegantBook 模板转换**：`documentclass` 换 elegantbook、章标题转 `\chapter*` + 章计数器、
      删除原书手工目录并插入 `\tableofcontents`（配合已生成的 addcontentsline 自动成目）、
      移除与 elegantbook 冲突的包/宏（geometry/ctex/tcolorbox[most]/\circled）；客户端可选开关；
      **编译验证**：诊断编译（仅注释原书既有 matrix 行）654 页全部通过 exit 0，
      已知问题（`\left(` 内嵌 matrix，TeX Live 2026 内核 bug）自动列入汇报不修改内容

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

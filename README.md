# LaTeXStruct

LaTeX 数学书结构化整理本地客户端（Windows 优先，安装版 + 主动更新）。
仓库：<https://github.com/Ararataki-number-one/LaTeXStruct>
完整设计与约束见仓库根目录 `设计文档.md`；文档顶部已同步当前实现状态，后续章节保留
早期需求决策作为历史依据。

## 安装与更新

- **安装版**：GitHub Releases 下载 `LaTeXStruct-setup-*.exe` 双击安装（每用户、无需管理员）；
- **便携版**：Releases 中的 `LaTeXStruct.exe` 单文件免安装；
- **主动更新**：启动时自动检查 Releases 最新版，有新版即显示更新横幅，一键下载安装器静默升级；
  更新源默认 `Ararataki-number-one/LaTeXStruct`（可用环境变量 `LATEXSTRUCT_UPDATE_REPO` 覆盖）。
- **OCR 转写**：OCR 页签上传 PDF/图片 → 视觉模型逐页忠实转写（支持页码范围、DPI、
  分页进度、失败页重试）→ 完成后把原始 OCR 导入独立项目，再进入结构化流水线；
  原始转写与结构化结果分开保存；
- **代码签名**：CI 已内置签名步骤——把证书放进 GitHub Secrets（`WINDOWS_CERT_BASE64` +
  `WINDOWS_CERT_PASSWORD`）后每次发布自动签名 exe 与安装器；本地可用 `scripts/sign_local.ps1`
  生成自签证书签名（仅本机信任）。**消除 SmartScreen 警告需购买 EV/OV 代码签名证书**
  （如 DigiCert/Sectigo），拿到 pfx 后按上述方式配置即可；
- 安装器界面默认**简体中文**（`packaging/installer.iss` 使用官方 ChineseSimplified 语言包）；
- 依赖 DeepSeek（或任意 OpenAI 兼容端点）API Key 才启用 AI 模式；无 Key 自动降级规则模式。

## Qwen 视觉模型配置

截至 2026-08-14，阿里云 Model Studio 已正式提供 `qwen3.7-flash`：它是支持
图片、文本和视频输入的 Qwen3.7 原生视觉 Flash 模型。LaTeXStruct 已将它作为首选
视觉预设，同时保留 `qwen3-vl-flash`、`qwen3.6-flash` 和 `qwen3.7-plus` 兼容选项。
调用使用 OpenAI 兼容 Chat Completions 的 `image_url` 格式，本地图片以 Base64 Data URL
传入。

推荐先在阿里云控制台**作废聊天中暴露过的 Key 并创建新 Key**，再通过环境变量启动：

```powershell
$env:LATEXSTRUCT_OCR_PROVIDER = "qwen3.7-flash-cn"
$env:DASHSCOPE_API_KEY = "<轮换后的新 Key>"
python -m latexstruct
```

中国内地预设使用仍受官方支持的兼容地址
`https://dashscope.aliyuncs.com/compatible-mode/v1`。若 Model Studio 控制台提供了
workspace 专属 API Host，按控制台值覆盖即可：

```powershell
$env:LATEXSTRUCT_OCR_BASE_URL = "https://<WorkspaceId>.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
```

也可以在「AI 设置 → OCR 视觉模型」选择 Qwen 预设，开启「系统凭据管理器」后再输入
新 Key；密钥会存入 Windows 凭据管理器，`config.json` 只留占位符。环境变量优先，
且普通设置保存不会把环境变量 Key 写入磁盘或凭据管理器。

官方依据：[Qwen3.7-Flash 型号与能力](https://www.alibabacloud.com/help/en/model-studio/qwen3-7-flash)、
[OpenAI 兼容 Chat 与图片输入](https://www.alibabacloud.com/help/en/model-studio/qwen-api-via-openai-chat-completions)、
[API Key 安全建议](https://www.alibabacloud.com/help/en/model-studio/get-api-key)。

## 发布新版本（全自动）

```powershell
# 1) 只改 latexstruct/_version.py 的 __version__
# 2) 提交并打 tag 推送 → CI 自动：测试 → 构建 exe → 构建安装器 → 发布 Release
git add -A
git commit -m "release: v1.0.1"
git push
git tag v1.0.1
git push origin v1.0.1
# 3) 已安装客户端下次启动自动提示更新
```

## 当前状态（v1.0.0 稳定版，功能冻结）

- 核心流水线已具备解析、扫描、保守决策、可逆补丁和统一安全检查；正文、数学、
  label/ref、图片路径、环境、花括号、项目文件集合与可选编译对比共同决定能否导出；
- 审阅工作台支持逐项接受/拒绝、上一项/下一项、筛选、低置信度提示、撤销和源码定位；
  审阅状态变化复用已有决策，不重复发起 AI 调用；
- 多文件项目保留原始二进制资源，并校验 `input/include` 依赖、文件数量和导出安全门；
- OCR 保持“原始逐页转写 → 人工检查/失败重试 → 结构化流水线”分层，部分失败不会伪装成功；
- Windows 凭据管理器开启后，配置文件只存占位符；凭据写入失败会中止保存，不会静默
  降级为明文。未开启时，界面会明确提示密钥保存在本机配置文件中；
- 每次发布均由 CI 重跑完整测试、编译基准、前端构建和 Windows 安装/运行/卸载冒烟；
  任一门禁失败都不会生成 GitHub Release。

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
│   ├── config.py                 # 应用配置（三角色模型/复查开关/keyring）
│   ├── keystore.py               # Windows 凭据管理器密钥存储（可注入后端）
│   ├── providers.py              # 已验证的模型供应商/视觉模型预设
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
│       ├── static/               # 开发期旧界面资源（生产构建存在时不再挂载）
│       └── static-react/         # React+Monaco 主界面（frontend/ 构建产物）
├── frontend/                     # React 18 + Vite + Monaco 前端源码（npm run build）
├── packaging/
│   ├── LaTeXStruct.spec          # PyInstaller 单文件 exe
│   ├── installer.iss             # Inno Setup 安装器
│   ├── generate_icon.py          # 图标生成（纯标准库）
│   └── run.py                    # 打包入口
├── scripts/build.ps1             # 本地构建脚本
├── tests/                        # 18 个测试套件 + 合成/真实摘录语料
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

1. **导入项目**：粘贴单个 `.tex`，或选择完整项目文件夹；
2. **分析与审阅**：运行结构化整理，逐项查看 diff、置信度和原因，接受或拒绝修改；
3. **应用与验证**：只有全部应用项完成审阅且统一安全检查通过时，才允许导出结果；
4. **OCR 导入**：先逐页取得并保留原始 OCR，处理失败页，再导入结构化审阅；
5. **设置**：配置决策/复查模型（默认 DeepSeek）与 OCR 视觉模型；未开启凭据管理器时，
   Key 保存在本机 `%APPDATA%\LaTeXStruct\config.json`，开启后改存
   Windows 凭据管理器（配置文件仅占位符）；也可用环境变量
   `LATEXSTRUCT_DECIDE_KEY` / `LATEXSTRUCT_REVIEW_KEY`；OCR 还支持
   `DASHSCOPE_API_KEY` / `LATEXSTRUCT_OCR_KEY`。无 Key 时 AI 模式自动降级为规则模式。

## 运行测试

```powershell
cd latexstruct
python -m pytest -q
python tools/benchmark.py

# 前端生产构建
cd frontend
npm ci
npm run build

# 可选：使用真实 Qwen Key 对一张图片做在线冒烟测试（不会打印 Key）
python tools/qwen_vision_smoke.py path\to\page.png
```

## 核心保证

- **只改结构不改内容**：所有修改都是可逆编辑日志，机器校验"撤销全部编辑后与原文逐字符一致"，
  校验失败自动回退原文，绝不导出被改坏的内容；
- **最小改动**：按候选打补丁，绝不重写全文；
- **保守回退**：歧义项一律保留原文并列入汇报；
- **AI 只做决策**：AI 输出结构化 JSON（动作 + 行号区间），从不生成正文文本。

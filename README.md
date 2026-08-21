# LaTeXStruct

LaTeX 数学书结构化整理本地客户端（Windows 优先，安装版 + 主动更新）。
仓库：<https://github.com/Ararataki-number-one/LaTeXStruct>
完整设计与约束见仓库根目录 `设计文档.md`；文档顶部已同步当前实现状态，后续章节保留
早期需求决策作为历史依据。

## 安装与更新

- **安装版**：GitHub Releases 下载 `LaTeXStruct-setup-*.exe` 双击安装（每用户、无需管理员）；
- **便携版**：Releases 中的 `LaTeXStruct-portable-*.zip`，解压后直接运行 `LaTeXStruct.exe`；
  压缩包同时附带项目 MIT 许可证和内置 Codex runtime 的第三方许可证与归属声明；
- **主动更新**：启动时自动检查 Releases 最新版；更新包通过大小与 SHA-256 校验后，应用会
  在没有活动任务或未保存 OCR 成果时安全退出、静默升级并自动重启；
  更新弹窗会显示中文更新说明、真实下载进度与可取消状态，重启后显示旧版到新版的更新结果；
  安装器内置的恢复器会等待旧服务释放端口、重试启动，并以新版健康响应确认重启成功；
  更新源默认 `Ararataki-number-one/LaTeXStruct`（可用环境变量 `LATEXSTRUCT_UPDATE_REPO` 覆盖）。
- **OCR 转写**：OCR 页签上传 PDF/图片 → 读取 PDF 总页数、书签树并选择起止页 → 选择“出版审校”
  或“标准转写”以及成品版式 → 视觉模型逐页忠实转写（支持 DPI、原页码/任务序号进度、安全
  暂停/继续、失败页批量重试）→ 完成后把原始 OCR
  TEX 与图片保存为工程 ZIP，或导入独立项目，
  默认直接进入“AI 深度整理”；图书默认使用 155×235mm 的 faithfulbook 出版书籍版式，也可在
  启动前保持原排版或选择 ElegantBook，随后立即进入可暂停的后台工作台，
  按批次显示不断增长的结构化 TeX 草稿；Token 与费用只统计实际调用；
  原始转写与结构化结果分开保存；书签仅用于所选页的章节/目录映射，没有可靠书签时不会
  凭空臆造缺失层级；
- **代码签名**：CI 已内置签名步骤——把证书放进 GitHub Secrets（`WINDOWS_CERT_BASE64` +
  `WINDOWS_CERT_PASSWORD`）后每次发布自动签名 exe 与安装器；本地可用 `scripts/sign_local.ps1`
  生成自签证书签名（仅本机信任）。**消除 SmartScreen 警告需购买 EV/OV 代码签名证书**
  （如 DigiCert/Sectigo），拿到 pfx 后按上述方式配置即可；
- 安装器界面默认**简体中文**（`packaging/installer.iss` 使用官方 ChineseSimplified 语言包）；
- OCR、分析与审阅可统一选择 API，或使用安装包内置的官方 Codex CLI 运行时与本机
  ChatGPT 登录。Codex 模式不会读取项目 API Key，也不会在不可用时静默回退到按量计费 API。

## 本机 Codex OCR、分析与审阅（ChatGPT 订阅）

在「设置 → AI 引擎」选择“Codex CLI”后，PDF/图片逐页转写、文字结构判断和 AI 复查都会由
安装包内置、固定版本的官方 Codex CLI 运行时执行。它复用本机已有的 **ChatGPT 登录**，
消耗对应套餐的 Codex 使用额度，而不是项目中配置的 OpenAI 兼容 API Key；界面可刷新运行时、
登录方式和就绪状态，并可单独选择模型与推理强度。为避免意外产生 API 账单，只接受
ChatGPT 登录：检测到 API Key 登录、未登录或运行时故障时，本次任务会明确停止并保留已有结果，
**不会自动切回 API 后端**。

首次使用前，请在同一个 Windows 账户的终端运行一次：

```powershell
codex login
```

并选择 **Sign in with ChatGPT**。若系统提示找不到 `codex`，请先按
[官方 Codex CLI 安装说明](https://github.com/openai/codex#installing-and-running-codex-cli)安装；
仅登录 Codex Desktop 不保证 CLI 登录状态可被读取。完成后回到设置页点击“刷新状态”。安装包内置
的是与本应用固定匹配的运行时，实际登录凭据仍由官方 CLI 在当前用户目录中创建和管理。

“本机 Codex”指 Codex 程序在本机受限进程中运行，并不代表模型离线运行：推理仍需联网访问
OpenAI 服务，也会受 ChatGPT 套餐额度和服务可用性影响。应用不会复制或展示 Codex 登录令牌，
也不会把项目中的 API Key 传给该子进程。

Codex OCR 使用 CLI 官方 `--image` 输入逐页传递受控的 PNG/JPEG；每次调用都在临时空目录、
只读沙箱和禁用工具的条件下运行，完成后清理页面副本。现有 OCR 的安全暂停、失败页重试、
原始 TEX/图片工程包与后续结构审阅流程保持不变。

官方说明：[Codex 认证方式](https://learn.chatgpt.com/docs/auth)、
[Codex 非交互模式](https://learn.chatgpt.com/docs/non-interactive-mode)、
[Codex CLI 图片输入](https://learn.chatgpt.com/docs/developer-commands?surface=cli)。

## API 模式的 Qwen 视觉模型配置

截至 2026-08-15，阿里云 Model Studio 已正式提供 `qwen3.7-flash`：它是支持
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

也可以直接在「设置」选择“阿里云百炼 Qwen”，只填写一次新 Key，再分别切换结构判断、
AI 复查与 OCR 模型；开启「系统凭据管理器」后，密钥会存入 Windows 凭据管理器，
`config.json` 只留占位符。环境变量优先，
且普通设置保存不会把环境变量 Key 写入磁盘或凭据管理器。

官方依据：[Qwen3.7-Flash 型号与能力](https://www.alibabacloud.com/help/en/model-studio/qwen3-7-flash)、
[OpenAI 兼容 Chat 与图片输入](https://www.alibabacloud.com/help/en/model-studio/qwen-api-via-openai-chat-completions)、
[API Key 安全建议](https://www.alibabacloud.com/help/en/model-studio/get-api-key)。

## 发布新版本（全自动）

```powershell
# 1) 修改 latexstruct/_version.py 后同步生成元数据
$version = "X.Y.Z"
python packaging/sync_version.py --version $version
# 2) 精确暂存本次改动（避免把无关未跟踪文件带入发布），再提交并打 tag 推送
git add -u
git add <本次新增文件路径...>
git status --short
git commit -m "release: v$version"
git push origin HEAD
git tag "v$version"
git push origin "v$version"
# 3) 已安装客户端下次启动自动提示更新
```

## 当前状态（v1.2.4）

- 核心流水线已具备解析、扫描、保守 AI 决策、独立复查、可逆补丁和统一安全检查；
  定理/证明边界、自定义环境、label/ref、图片路径、花括号、项目文件集合与编译前后对比
  共同决定能否标为已验证成品；
- OCR 出版审校现会锁定证据充分的显式编号定理、引理、问题、猜想、定义、问句与证明边界，
  并用生产级有序正文门禁检查结构变换前后零丢失；命名定理标题保留语义，仍未结构化、错套、
  多套或跨边界的 formal 条目会 fail-closed。用户确认的固定样本含 44 个正式条目和 11 个证明，
  独立评估 exact 55/55、正文 30,732/30,732 token、24/24 大纲节点，并只生成一个目录；该结果
  只说明这份已审阅样本通过，并非对所有文档、OCR 文字或数学语义准确率的通用保证；
- 多行 PDF 标题现在按同页连续 1--3 行候选处理，并要求与完整书签标题精确相等；只有命中的标题
  续行会被消费。OCR formal 清点同时支持 `{\bfseries ...}` 旧式标题、带展示/链接包装的 Proof
  标题和带样式的无编号 Remark。针对 17 页 Sharp Bounds 固定人工真值，9/9 个有效标题、13/13
  个定理类条目和 6/6 个证明精确命中（formal/proof 合计 19/19），正文/数学守恒并只生成一个
  目录；[人工真值清单](benchmark/sharp_bounds_tex_structure_truth_v1.json)和
  [v1.2.4 独立评测结果](benchmark/sharp_bounds_tex_structure_accuracy_v124.json)记录了口径、哈希与
  边界；原始 OCR/候选全文因版权不随仓库分发，因此该结果只代表这个已审阅样本；
- 结构决策的封闭样本、评分口径、安全门和 Wilson 区间记录在
  [外部准确率报告](benchmark/EXTERNAL_ACCURACY_REPORT.md)。该报告只衡量其固定样本与任务，不是对 OCR、
  任意书籍或出版质量的通用承诺；
- OCR 项目还会校验所选 PDF 书签节点、目录命令、真实图片文件、公式编号与脚注清单；正文左侧或
  右侧边缘的公式编号只有在邻近数学内容提供证据时才进入清点，公式编号
  必须以活动 AMS `\tag{...}` 按源页顺序匹配，清点失败、双括号写法、顺序交换或缺失证据都会
  阻止出版审校导入。本机存在 XeLaTeX 时会实际编译并标记结果是否通过。未通过检查的当前草稿
  仍可由用户以 `UNVERIFIED` TEX/ZIP 导出，但不会冒充已验证成品；
- 普通 TeX 默认保持原排版，不替换文档类、宏包、章节层级或自定义环境；只有用户明确选择时
  才转换模板。OCR 默认使用 faithfulbook 双面书籍版式，也可在付费识别前冻结其他模板；它按 PDF 页面尺寸、书签和章首页目录
  重建章节树、奇偶页眉与局部目录；faithfulbook 优先使用源标题和作者，语义分页只移除带 OCR
  所有权证据的硬分页，模板转换仍是可逆的确定性补丁；
- “出版审校”会要求至少 200 DPI，并把 Codex 的低推理强度提升到中等；低置信、待复核、来源
  或资源证据不完整时会阻止导入。质量报告与工程 manifest 保存原文件、页图、局部核验和资源
  哈希，但该流程门不测量文字/数学准确率，也不等同于出版就绪；
- 对带可靠数学字体层的 PDF，“出版审校”会保守定位每页最多 4 个高风险展示公式，直接从原
  PDF 以 420 DPI 生成局部裁片，并与整页图放在同一次 Codex 视觉请求中复核；裁片的源页、
  边界、像素哈希和尺寸会进入证据清单。普通正文、扫描页和不确定区域仍走原流程，不会把
  字体启发式结果自动改写进公式，也不会因此宣称数学语义已经正确；
- 审阅工作台支持逐项接受/拒绝、上一项/下一项、筛选、低置信度提示、撤销和源码定位；
  审阅状态变化复用已有决策，不重复发起 AI 调用；
- 单文件与多文件项目均保留原始字节；UTF-8/UTF-16 BOM、GBK/Latin-1 等可识别编码和原换行风格
  在写回时保持不变，无法按原编码安全表示的修改会闭锁。多文件项目还会校验 `input/include`
  依赖、外部 `.cls/.sty/.tex` 声明、文件数量与导出安全门；
- `.tex`、项目文件夹与 ZIP 均可拖拽导入；ZIP 自动去外层目录并识别主文件，导入完成后
  再由用户明确启动分析；
- 分阶段进度卡显示当前动作、候选进度、按 AI 批次更新的实时草稿、Token 与约人民币费用；
  处理任务支持安全暂停、继续和取消，同一项目的分析、审阅与最终写入使用单一事务锁，
  避免并发请求覆盖结果；未验证草稿永不写入正式结果；
- 分析、独立审阅与 PDF/图片 OCR 均可选择本机 Codex CLI 后端，复用 ChatGPT 登录和订阅额度；
  该模式仍需联网，不继承应用 API Key，也不会在失败时静默回退到按量计费 API。用户仍可主动
  切换到兼容 API 模式；
- 新项目和 OCR 导入默认走 AI 深度整理；视觉阶段只忠实转录，章节、真实目录命令和定理/证明
  边界由后续结构阶段统一处理。AI 决策或复查失败会明确停止并保留原文，旧规则模式仅作兼容；
- 最终安全检查未通过时会保存独立诊断草稿和逐项修复建议，重启后仍可查看；诊断草稿不能参与
  审阅应用，也不会覆盖原项目及上一份已验证结果，但可带明确警告导出 TEX、ZIP 与汇报；
- OCR 保持“选择 1-based 起止页 → 原始逐页转写 → 人工检查/失败重试 → 结构化流水线”
  分层；整本累积草稿和单页原图/LaTeX 可随时切换，部分失败不会伪装成功；页签切换后会
  恢复当前任务，运行中可在当前页结束后安全暂停；未保存的付费结果不会被自动清理或被更新过程
  静默丢弃。原始 OCR 工程 ZIP 包含 TEX、哈希 manifest、300 DPI 插图裁片及独立源页审阅预览；
- 成品可选择导出单个 TEX，或完整工程 ZIP；faithfulbook 样式直接内联于主 TEX，ZIP 同时包含
  裁切图片/子文件、工程说明和同次提交的安全汇报。两种导出都保存到固定的
  “下载/LaTeXStruct”目录且同名不覆盖；通过检查的结果标为已验证成品，未通过检查或未完成
  审阅的当前快照则以 `UNVERIFIED` 文件名和包内警告导出，hash 不一致仍会阻止读取；
- Windows 凭据管理器开启后，配置文件只存占位符；凭据写入失败会中止保存，不会静默
  降级为明文。未开启时，界面会明确提示密钥保存在本机配置文件中；
- 每次发布均由 CI 重跑完整测试、编译基准、前端构建、Windows 安装/运行/卸载以及上一版
  运行中升级冒烟；任一门禁失败都不会生成 GitHub Release。

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
│   │   ├── rules.py              # 旧规则兼容模式决策
│   │   ├── ai.py                 # AI 决策引擎（API / 本机 Codex 后端选择）
│   │   ├── codex_cli.py          # 受限 Codex CLI 调用、ChatGPT 登录检查与状态
│   │   ├── review.py             # AI 复查引擎
│   │   ├── prompts.py            # 母提示词 v3 + Schema + 上下文组装
│   │   ├── template.py           # 固定 ElegantBook 成品模板与层级适配
│   │   ├── report.py             # 极简汇报
│   │   └── pipeline.py           # 流水线编排
│   ├── assets/elegantbook/       # 固定版本类文件 + LPPL 许可证
│   ├── elegantbook.py            # 模板资产 hash 校验与工程包清单
│   └── server/
│       ├── app.py                # FastAPI 本地服务（含更新接口）
│       ├── static/               # 开发期旧界面资源（生产构建存在时不再挂载）
│       └── static-react/         # React+Monaco 主界面（frontend/ 构建产物）
├── frontend/                     # React 18 + Vite + Monaco 前端源码（npm run build）
├── packaging/
│   ├── LaTeXStruct.spec          # PyInstaller 单文件 exe
│   ├── installer.iss             # Inno Setup 安装器
│   ├── icon-source.png           # 用户确认的高分辨率品牌原图
│   ├── icon.ico / icon.png       # Windows 多尺寸图标与标准 PNG
│   ├── generate_icon.py          # 从原图生成 Windows/Web 多尺寸资源
│   └── run.py                    # 打包入口
├── scripts/build.ps1             # 本地构建脚本
├── tests/                        # 自动化测试套件 + 合成/真实摘录语料
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

### 可恢复的整书 Codex 跑批

开发者需要长时间处理整本 PDF 时，可在本地服务启动后使用编排工具。它只连接
`127.0.0.1`，先校验 Codex 的 ChatGPT 登录态，再统一启用 `codex_cli` 与 medium 推理；
OCR 工程、阶段草稿、失败诊断、当前工程包和报告都原子保存在 `output/book-runs/`。

```powershell
python tools/run_local_book.py run path\to\book.pdf --start-page 3 --end-page 473 --dpi 220

# Ctrl+C 会先请求安全暂停；也可从另一终端控制并在进程重启后续跑
python tools/run_local_book.py pause output\book-runs\book\run-state.json
python tools/run_local_book.py resume output\book-runs\book\run-state.json
python tools/run_local_book.py status output\book-runs\book\run-state.json
```

分析未通过编译/安全检查时，工具仍会保存带 `UNVERIFIED` 标记的 current 工程包与报告，
并以退出码 `2` 明确提示需要人工修复；它不会静默切换到 API Key 后端。

### 快速混合保真工作流（开发验证）

对于已有可搜索文字和嵌入字体、但 OCR 重排版尚未完成人工校对的 PDF，仓库包含一个
Bondy 17 章参考书的专用验证工具。它把源 PDF 页作为矢量页对象放入 155×235mm 纸张，
保留原可搜索文字和字体，只根据源大纲增加 17 章书签与可复核的哈希 manifest。这不是
AI/OCR 重排版，不会把每行内容转换为可编辑 LaTeX，也不是面向任意 PDF 的通用转换器。

```powershell
# 先用小范围验证本机 XeLaTeX/PyMuPDF 链路
python tools/build_bondy_fast_hybrid.py --source path\to\book.pdf --output-dir path\to\output --sample

# 确认后再构建脚本限定的完整页范围
python tools/build_bondy_fast_hybrid.py --source path\to\book.pdf --output-dir path\to\output
```

**书籍不随软件发布。** 仓库、安装包、便携包和 GitHub Release 都不包含源书、书页图像或
上述工具生成的整书 PDF。运行者必须自行提供有权使用的源 PDF，并自行确认派生输出的
版权与分发条件。快速混合输出保真源页，但不代表 OCR 或出版级重排版已经完成。

## 使用流程

1. **导入项目**：拖入/选择单个 `.tex`、完整项目文件夹或 ZIP；系统自动识别主文件；
2. **分析与审阅**：开始分析后可查看当前阶段、实时草稿、Token/费用，也可暂停、继续或
   取消；完成后逐项查看 diff、置信度和原因，接受或拒绝修改；
3. **应用与验证**：全部应用项完成审阅且统一安全检查通过后生成已验证成品；未通过时仍可导出
   带警告的当前快照继续修复；
4. **OCR 导入**：先选择工作流和成品版式，再逐页取得并保留原始 OCR、原文件证据及局部图片，
   处理失败/低置信页后选择 AI 或规则整理；项目创建后立即进入工作台，以后台任务实时展示结构
   整理过程；
5. **导出**：可选单个 TEX，或包含类文件、图片/子文件、许可证与汇报的完整工程 ZIP；界面会
   明确区分已验证成品与可能无法编译的 `UNVERIFIED` 当前快照；
6. **设置**：OCR、分析与审阅可统一选择 DeepSeek/Qwen API，或复用 ChatGPT 登录的本机 Codex；API
   后端填写一次 Key 后即可切换各角色模型，Base URL、分角色 Key 与自定义模型收在高级设置。
   Codex 后端不使用这些 Key，未就绪时会停止而不自动回退 API。未开启凭据管理器时，
   Key 保存在本机 `%APPDATA%\LaTeXStruct\config.json`，开启后改存
   Windows 凭据管理器（配置文件仅占位符）；也可用环境变量
   `LATEXSTRUCT_DECIDE_KEY` / `LATEXSTRUCT_REVIEW_KEY`；OCR 还支持
   `DASHSCOPE_API_KEY` / `LATEXSTRUCT_OCR_KEY`。这些 API Key 仅在用户主动选择 API 模式时使用。

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

## 核心保证与边界

- **TeX 结构整理只改结构不改内容**：对已导入 TeX 的修改都有可逆编辑日志，机器校验
  "撤销全部编辑后与原文逐字符一致"，
  校验失败自动回退原文，绝不导出被改坏的内容；
- **最小改动**：按候选打补丁，绝不重写全文；
- **保守回退**：歧义项一律保留原文并列入汇报；
- **AI 角色分离**：文本分析与审阅只输出结构化决策，不重写正文；视觉 OCR 会从页图生成
  转写文本，因而必须通过页级重试、资源/结构门禁与人工审阅；
- **无通用准确率保证**：模型、扫描质量、PDF 文字层、字体和数学排版都会影响结果。
  样本测试不等于对用户文档的承诺，未经人工审阅的输出不应直接用于出版。

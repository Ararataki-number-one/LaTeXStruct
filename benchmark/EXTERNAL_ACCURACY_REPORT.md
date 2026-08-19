# LaTeXStruct v1.1.10 外部结构分析准确率报告

评测日期：2026-08-19
结论：**最终 confidence-aware 证据通过发布门槛（codex-adjudicated）**。冻结外部集共 720 个结构判断单元，最终评分为 **720/720（100%）**；6 份来源文档均为 exact，协议错误、严重错误和完整性错误均为 0。

证据资格必须同时说明：结构动作、环境和自动边界是在盲态下冻结的；但旧安全门漏掉生产置信度阈值，主流程已运行过一次动作金标评分后，才补做 confidence-only 标注。因此，最终结果**不是完全未见金标的原始端到端盲测**。补标代理本身保持隔离、没有读取 gold 或 gate，且结构字段不可修改；最终证据证明的是“冻结的盲态结构决策 + 隔离的事后置信度标注 + 修复后的真实生产安全门”在本语料上的结果。

这里的“100%”只表示本报告冻结语料上的 `(action, env, start_block, end_block)` 结构决策完全匹配，以及安全门核验的内容、资源、语法配平和环境声明不变量全部通过；它不表示 LaTeXStruct 能理解所有 LaTeX 语义，也不表示对任意书籍、论文或 OCR 输出都能达到 100%。样本是从完整作品源文件分层抽取的片段，不是对六部作品逐行重排版；这些片段不能独立编译，因此文档检查如实记为 `compile_status=not-required`，没有把它计作编译成功。

## 发布判据

用户在 v3 夹具、预测输入和盲测协议已封存、预测仍在进行、金标尚未用于正式评分时，将判据从“每份文档都必须 100% exact”修订为“总体 Exact accuracy **严格大于 98%**”。已冻结的金标、样本构成和判断规则没有修改；以下保护条件继续保持严格：

- Accuracy、Precision、Recall、F1、Decision coverage、Boundary exact match、Preservation accuracy、Manual accuracy 的点估计和双侧 95% Wilson 下界均不得低于 95%；
- 文档检查覆盖率和文档完整性准确率必须为 100%；
- 协议错误、对 `preserve`/`manual` 的错误自动修改、内容或资源丢失、环境未声明等严重错误必须为 0；
- Structural document exact 和 Document exact 继续逐文档计算并公开，但不再是发布硬门槛。

完整定义见 [`benchmark/ACCURACY_PROTOCOL.md`](ACCURACY_PROTOCOL.md)。本次实际结果仍为 100% 且 6/6 文档 exact，因此也满足修订前更严的逐文档结果要求。

## 外部来源与固定版本

语料来自 3 本公开数学书和 3 篇公开数学论文。Git 来源以完整 commit 固定，arXiv 来源以明确版本和原始 e-print 归档固定；完整 archive、工作树、入口文件和许可证文件 SHA-256 记录在 `../work/external-corpus-v2/manifest.json`。

| ID | 类型与来源 | 固定版本 | 许可证 |
|---|---|---|---|
| V2B01 | [The Open Logic Text](https://github.com/OpenLogicProject/OpenLogic)；The Open Logic Project | [`1e960beff9ed7835bf3e3f1335e21af3439cd107`](https://github.com/OpenLogicProject/OpenLogic/commit/1e960beff9ed7835bf3e3f1335e21af3439cd107) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| V2B02 | [Basic Analysis: Introduction to Real Analysis, Volumes I and II](https://github.com/jirilebl/ra)；Jiří Lebl | [`e21ec524ca7d54f800c693b948020c188d21d01f`](https://github.com/jirilebl/ra/commit/e21ec524ca7d54f800c693b948020c188d21d01f) | 仓库双许可中选择 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| V2B03 | [Linear Algebra](https://github.com/siefkenj/LinearAlgebra)；Jim Siefken 等 | [`297f680f6d1b199ff5a664b9a43a080f09ed92e9`](https://github.com/siefkenj/LinearAlgebra/commit/297f680f6d1b199ff5a664b9a43a080f09ed92e9) | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| V2P01 | [A Cubical Language for Bishop Sets](https://arxiv.org/abs/2003.01491v5)；Jonathan Sterling、Carlo Angiuli、Daniel Gratzer | arXiv `2003.01491v5` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| V2P02 | [Quantum chi-squared tomography and mutual information testing](https://arxiv.org/abs/2305.18519v2)；Steven T. Flammia、Ryan O'Donnell | arXiv `2305.18519v2` | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| V2P03 | [Trakhtenbrot's Theorem in Coq: Finite Model Theory through the Constructive Lens](https://arxiv.org/abs/2104.14445v5)；Dominik Kirst、Dominique Larchey-Wendling | arXiv `2104.14445v5` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |

## 夹具与盲测方法

v3 使用 source-truth-first 构造：先从真实源环境、正文边界和语义证据确定金标，再运行被测扫描器和安全门；扫描器或安全门失败会中止构建，不能换掉困难样本。答案字段从预测包中移除，金标与验证文件封存。720 个单元按固定种子选取，覆盖每份作品的前、中、后三段，类别在模型运行前冻结为：

- 自动修改 300：`wrap` 184、`move-boundary` 116；
- `preserve` 300；
- `manual` 120。

两次独立内存构建字节一致，包与金标的有序 ID 一致且 720 个 ID 全部唯一。v3 与已使用的 v2 在源区间、规范化全文和五元词组阈值三个层面均为 **0 重叠**；选中后不允许替换或重标。

线上 API 结果未被当作本报告分数。本次按协议允许的 Codex 回退路径执行，并明确标记为 **codex-adjudicated**：每份文档由隔离上下文完成初判、独立复核和有争议项的对抗性裁决。判定阶段只允许读取分配的匿名 packet、固定盲测协议，以及复核阶段所需的本文件前序答案；不得读取 gold、validation、score、源语料、夹具构建器或生产安全门。固定协议见 [`benchmark/CODEX_BLIND_PROTOCOL.md`](CODEX_BLIND_PROTOCOL.md)。

结构裁决冻结后、第一次动作金标评分前，先经过当时版本的外部安全门。安全门复用生产 `parse/scan/legalize/context/build_ops` 路径，非法或证据不足的自动修改 fail-closed，并逐单元核验内容、资源、语法配平和环境支持；但后来独立审查发现，这个版本没有执行生产置信度阈值，因此其输出不能作为发布证据。

### 协议形状适配事件

首次将冻结裁决直接送入安全门时，裁决文件使用了旧字段形状：`unit_id` 而不是 `id`，且无操作记录的边界为 `null` 而不是 packet 的 `focus_anchor`。安全门按设计 fail-closed：720 条记录均非法，并保留为 720 个 missing ID 加 720 个 invalid record，共 1440 个原始协议错误；该输出没有评分。

随后使用确定性、可审计的形状适配器执行 `unit_id → id`、`null → focus_anchor`，并补齐 `reason`。由于错误的标注任务没有产出 `confidence`，适配器还透明补入默认值 `0.0`。适配 manifest 记录：720 次旧 ID 转换、300 条记录的 600 个空边界字段派生、`automatic_boundary_repair_count=0`、结构字段 `semantic_change_count=0`。

`confidence=0.0` 不能视为与生产行为无关：生产常量 `AUTO_APPLY_CONFIDENCE=0.75`。对拟自动执行的动作，安全门现在要求显式置信度是 `[0,1]` 内的有限、非布尔数且 `>=0.75`；缺失、布尔值、NaN/Infinity、越界或低于阈值均 fail-closed 为 `manual`。旧门没有执行这一条件，却接受了补零后的自动动作。因此旧的 `release-v3-production-predictions-normalized.json` 与 `release-v3-score.json` 虽显示 720/720，仍被独立审查判为**无效发布证据**，只保留作诊断。阈值修复及非法值、边界值和补零不可自动执行等相关回归测试共 97 项通过。

### Confidence-only 补救

旧动作金标分数已经由主流程运行后，才启动三份隔离的 confidence-only 标注。代理不读取 gold 或 gate，只能依据匿名 packet 为已经冻结的记录给出置信度；`action`、`env` 及所有自动动作的 `start_block/end_block` 不允许更改。三份结果合计 720 条，与冻结结构基线的上述字段差异为 0。

置信度范围为 0.55–0.99，共 35 条低于 0.75；其中 25 条属于拟自动动作并实际触发 `manual-low-confidence`，另 10 条属于非自动动作，不会绕过或改变自动应用阈值。修复后的安全门结果为：`accepted-wrap=184`、`accepted-move-boundary=116`、`forced-preserve-no-focus-candidate=300`、`manual-low-confidence=25`、`manual-fail-closed=95`；原始协议错误为 0，6 份文档的内容、资源、语法配平和环境支持均通过。

### 评分器证据哈希事件

早期证据链自检还发现评分器对文档检查 `evidence_sha256` 的核验实现有误。评分器 fail-closed，没有产生分数或发布结论；实现及回归测试修复后才重新运行。其后产生的旧 720/720 又因上述 confidence blocker 被降级为诊断。当前最终分数绑定 packet、gold、validation、三份 confidence-only 输入、修复后的安全门 manifest 和逐文档独立证据哈希。

## 正式结果

| 文档 | 自动修改（其中 move） | preserve | manual | exact | 内容/资源/环境/配平 |
|---|---:|---:|---:|---:|---|
| V2B01 | 141（53） | 51 | 46 | 238/238 | 通过 |
| V2B02 | 142（46） | 51 | 46 | 239/239 | 通过 |
| V2B03 | 0（0） | 50 | 15 | 65/65 | 通过 |
| V2P01 | 3（3） | 50 | 5 | 58/58 | 通过 |
| V2P02 | 7（7） | 48 | 0 | 55/55 | 通过 |
| V2P03 | 7（7） | 50 | 8 | 65/65 | 通过 |
| **合计** | **300（116）** | **300** | **120** | **720/720** | **6/6 通过** |

| 指标 | 点估计 | 95% Wilson 下界 | 门槛 |
|---|---:|---:|---:|
| Exact accuracy | 100.0000% | 99.4693% | `>98%`；下界 `≥95%` |
| Precision | 100.0000% | 98.7357% | `≥95%` |
| Recall | 100.0000% | 98.7357% | `≥95%` |
| F1 | 100.0000% | 98.7357% | `≥95%` |
| Decision coverage | 100.0000% | 99.4693% | `≥95%` |
| Boundary exact match | 100.0000% | 98.7357% | `≥95%` |
| Preservation accuracy | 100.0000% | 98.7357% | `≥95%` |
| Manual accuracy | 100.0000% | 96.8981% | `≥95%` |

补充门槛结果：TP=300、FP=0、FN=0；Structural document exact=6/6，Document check coverage=6/6，Document integrity accuracy=6/6，Document exact=6/6；response/document-check/upstream 协议错误均为 0，严重单元错误、内容/资源完整性错误均为 0。安全门最终输出为 `wrap=184`、`move-boundary=116`、`preserve=300`、`manual=120`。

## 历史结果与不可追认原则

早期 `benchmark/report.md` 的 200/200 是小型开发回归集，不是外部发布证据。外部 v1 虽扩展到 600 个单元，但样本资格仍与生产扫描器耦合（尤其 `preserve_scanner_clean_eligible`），且没有 `move-boundary` 通道，违反后来确立的 source-truth-first 原则。它仅作诊断：486/600（81.0000%），3 个严重错误，未通过发布门槛。

v2 改用独立来源真值、完整协议和安全门，在新的 720 个单元上得到 718/720（99.7222%），95% Wilson accuracy 下界 98.9929%，协议/严重/完整性错误均为 0，但只有 4/6 文档 exact。两处边界相关错误分别位于 V2B02 和 V2P01；该结果已用于修复边界判定，因此不是修复后的盲测，未被提升为发布证据。即使用户后来把逐文档硬门槛改为总体 exact 严格大于 98%，也不能倒推追认 v2 为新的盲测结果。

v3 是与 v2 不重叠的新冻结集。其结构预测、复核和裁决保持盲态并先行冻结，但旧门漏检 confidence 后产生的 720/720 已作废。补救发生在主流程看过动作金标分数之后，所以不能把最终结果重述为一次全程未见 gold 的原始端到端 pass；可发布证据是结构语义不变、补标代理隔离、生产 0.75 阈值确实执行后的最终 720/720。

## 证据链 SHA-256

所有哈希均为文件原始字节的 SHA-256：

| 证据 | 相对路径 | SHA-256 |
|---|---|---|
| 外部语料 provenance manifest | `../work/external-corpus-v2/manifest.json` | `4b6fa20bdf54e6374b7301463397f75f987ceac2b1e11bb686d4f9061f3bdc10` |
| 准确率协议 | `benchmark/ACCURACY_PROTOCOL.md` | `cc5e7e76eb90c7b9b84a5689a0bf6dd5772302703de8fe5417464c915d8acf27` |
| Codex 盲测协议 | `benchmark/CODEX_BLIND_PROTOCOL.md` | `c223960ef3fcebe2c60bc6fdf1d6c26528e803d9d29ab781c3535af5b8fe37a1` |
| v3 packet | `../work/external-results-v3/release-v3-packets.json` | `c53fdfde93f12b9eb87b5d42e12d3ddbb58ea833ad754f3d2116f842debcb1a8` |
| v3 gold | `../work/external-results-v3/release-v3-gold.json` | `0d4ac4c89c10520ecb9c8707ddee1feab337153119b9e2307c2bd2b64761834e` |
| v3 validation | `../work/external-results-v3/release-v3-validation.json` | `b69a15545e78c676934a5b67278008784de31cbaabef989bae8d69cb27b61f96` |
| Confidence-only：V2B01 | `../work/external-results-v3/confidence-V2B01.json` | `2344faeddf9d790112857947f5d2a8ad3db9d2201ec87374aebc40df8a0bc798` |
| Confidence-only：V2B02 | `../work/external-results-v3/confidence-V2B02.json` | `e047a8342fd4978de82021f00e00a2cd604708b1681b6490726f33868d688a3e` |
| Confidence-only：其余四份文档 | `../work/external-results-v3/confidence-small-docs.json` | `01df039e23dd9d83a5b5f662ff1dfc2fd6cbb7b457b3715ac94cfd9478bd9f30` |
| 最终生产安全门输出 | `../work/external-results-v3/release-v3-production-predictions-confidence.json` | `c77158e1c977ce5fe04041ef60ce4ee3549e659539041658131a25a3580f4df3` |
| 最终生产安全门 manifest | `../work/external-results-v3/release-v3-production-predictions-confidence.manifest.json` | `c99ecb29efa271f2b36336e2ed9a069dff70beffac9408a9e455fba464b69fce` |
| 独立文档检查 | `../work/external-results-v3/release-v3-document-checks.json` | `0225c5e4fc7709451cd038605ccb1880f2b789abdba2968381e517d15fda0996` |
| 最终 confidence-aware 分数 | `../work/external-results-v3/release-v3-confidence-score.json` | `e9ef78e458d21f3d25fa38765ae12aa2d1c4270344a6761e8fcee40e664b8b4f` |

以下文件只用于保留 blocker 的审计轨迹，**不是发布证据**：

| 已取代的诊断文件 | SHA-256 | 无效原因 |
|---|---|---|
| `release-v3-final-normalized.json` | `d5c535992881ece26663898e515f773b6b1ef4c1bdee96ffba7e49cba16b9fe9` | 缺失置信度被适配为 0.0 |
| `release-v3-final-normalized.manifest.json` | `12d2676af9381f7cfd570ac458dc69f5fbb40470c8fc4cc801f146140ff6b08a` | 记录补零，但当时误认为不影响生产语义 |
| `release-v3-production-predictions-normalized.json` | `ab168949af92675cd515fe2717e0a044b014b57b942100e705e46c3046659c62` | 旧门未执行 0.75 阈值 |
| `release-v3-production-predictions-normalized.manifest.json` | `59b7b7729ccd5b6bc5106659aed86646164679d0f02b98bfeff2fb9a161bfae2` | 旧门审计不含置信度阻断 |
| `release-v3-score.json` | `d37a82d204634838409ea1fa4bd1081c4f3f07eee9444db9cc79e66f963f4aef` | 基于无效旧门输出，720/720 仅作诊断 |

## 复现命令

以下命令从仓库根目录执行；`../work` 是仓库同级的证据目录。构建命令依赖完整、固定且哈希一致的 `external-corpus-v2` 与 v2 封存证据。

```powershell
python tools/build_external_release_fixture_v2.py --generation v3 --write-v3
```

三份 confidence-only 文件是隔离标注后封存的输入，不是由确定性脚本重新推断；复现安全门前必须先核对上表哈希。命令使用内容相同的通用别名 `release-packets.json`，以保证 manifest 中记录的输入文件名也逐字节一致。运行修复后的生产安全门并锁定输出哈希：

```powershell
python tools/apply_external_safety_gate.py `
  --packets ../work/external-results-v3/release-packets.json `
  --prediction ../work/external-results-v3/confidence-V2B01.json `
  --prediction ../work/external-results-v3/confidence-V2B02.json `
  --prediction ../work/external-results-v3/confidence-small-docs.json `
  --output ../work/external-results-v3/release-v3-production-predictions-confidence.json `
  --manifest ../work/external-results-v3/release-v3-production-predictions-confidence.manifest.json `
  --expect-packet-sha256 c53fdfde93f12b9eb87b5d42e12d3ddbb58ea833ad754f3d2116f842debcb1a8 `
  --expect-prediction-sha256 2344faeddf9d790112857947f5d2a8ad3db9d2201ec87374aebc40df8a0bc798 `
  --expect-prediction-sha256 e047a8342fd4978de82021f00e00a2cd604708b1681b6490726f33868d688a3e `
  --expect-prediction-sha256 01df039e23dd9d83a5b5f662ff1dfc2fd6cbb7b457b3715ac94cfd9478bd9f30 `
  --expect-output-sha256 c77158e1c977ce5fe04041ef60ce4ee3549e659539041658131a25a3580f4df3
```

最后评分；评分器会校验安全门 manifest、冻结夹具哈希、逐文档证据及全部协议计数：

```powershell
python tools/score_external_release.py `
  --results-dir ../work/external-results-v3 `
  --prediction ../work/external-results-v3/release-v3-production-predictions-confidence.json `
  --output ../work/external-results-v3/release-v3-confidence-score.json
```

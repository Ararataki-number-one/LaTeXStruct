# Contributing

感谢关注 LaTeXStruct。核心定位：**大型数学 LaTeX 项目的安全 AI 辅助结构化重构引擎**——
AI 只做结构决策、补丁可逆、机器校验"内容不变"，绝不重写正文。

## 开发环境

```powershell
python -m pip install --user -r requirements.txt ruff
python -m pip install --user -e .        # 可选：安装为可编辑包
```

## 跑测试与静态检查

```powershell
python -m pytest -q
python -m ruff check latexstruct tests tools packaging benchmark
python tools/benchmark.py
```

## 提交约定

- 一个提交只做一件事；commit message 说明动机与影响；
- 修改提示词（`core/prompts.py`）时递增 `PROMPT_VERSION`；
- 修改规则/解析逻辑必须补对应回归测试（`tests/samples/` 提供合成与真实摘录语料）。

## 发布

版本号唯一来源是 `latexstruct/_version.py`。发布时先同步生成元数据，再由 CI 完成构建与发布：

```powershell
# 1) 修改 latexstruct/_version.py 的 __version__
# 2) 同步前端与 Windows 版本元数据，并运行版本一致性测试
python packaging/sync_version.py --version X.Y.Z
python -B tests/test_version.py
# 3) 提交并推送
git add -A
git commit -m "release: vX.Y.Z"
git push
# 4) 打 tag 触发发布（ruff → 测试 → 构建 → 安装器冒烟 → 签名 → Release）
git tag vX.Y.Z
git push origin vX.Y.Z
```

## 目录速览

- `latexstruct/core/`：解析/扫描/决策/补丁/校验/复查/模板/合法化（纯标准库，可独立测试）；
- `latexstruct/server/`：FastAPI 本地服务 + 无构建步骤界面；
- `packaging/`：PyInstaller spec、Inno Setup 脚本、图标生成；
- `tests/`：pytest 测试套件 + 合成/真实摘录语料；
- `tools/`：真实书稿摸底、E2E（AI/OCR/整书）、剖析脚本。

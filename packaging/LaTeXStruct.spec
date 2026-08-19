# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：单文件 exe（GUI 模式，无控制台）。"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

# PyInstaller executes a spec with the caller's current directory unchanged, while
# relative paths passed to Analysis/datas are resolved relative to the spec file.
# Using the same explicit base for both existence checks and collected files avoids
# silently omitting the React build when CI invokes this spec from the repository root.
repo_root = Path(SPECPATH).resolve().parent
packaging_dir = repo_root / "packaging"
app_icon = packaging_dir / "icon.ico"
legacy_static_dir = repo_root / "latexstruct" / "server" / "static"
react_static_dir = repo_root / "latexstruct" / "server" / "static-react"
react_index = react_static_dir / "index.html"
react_assets_dir = react_static_dir / "assets"
elegantbook_assets_dir = repo_root / "latexstruct" / "assets" / "elegantbook"
elegantbook_class = elegantbook_assets_dir / "elegantbook.cls"
elegantbook_license = elegantbook_assets_dir / "ELEGANTBOOK-LICENSE.txt"

if not react_index.is_file() or not react_assets_dir.is_dir():
    raise SystemExit(
        "React frontend build is missing; run `npm ci && npm run build` in frontend first"
    )
if not elegantbook_class.is_file() or not elegantbook_license.is_file():
    raise SystemExit("Bundled ElegantBook class or LPPL license is missing")
if not app_icon.is_file():
    raise SystemExit("Windows application icon is missing")

codex_datas, codex_binaries, codex_hiddenimports = collect_all("codex_cli_bin")

datas = [
    (str(legacy_static_dir), "latexstruct/server/static"),
    (str(react_static_dir), "latexstruct/server/static-react"),
    (str(elegantbook_assets_dir), "latexstruct/assets/elegantbook"),
] + codex_datas
binaries = codex_binaries
hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
] + collect_submodules("webview") + codex_hiddenimports

a = Analysis(
    [str(packaging_dir / "run.py")],
    pathex=[str(repo_root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "PIL", "PyQt5", "PySide2",
        "IPython", "jupyter", "pytest", "watchfiles",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="LaTeXStruct",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(app_icon),
    version=str(packaging_dir / "version_info.txt"),
)

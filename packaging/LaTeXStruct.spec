# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：单文件 exe（GUI 模式，无控制台）。"""

from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [("latexstruct/server/static", "latexstruct/server/static")]
binaries = []
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
] + collect_submodules("webview")

a = Analysis(
    ["packaging/run.py"],
    pathex=["."],
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
    icon="packaging/icon.ico",
)

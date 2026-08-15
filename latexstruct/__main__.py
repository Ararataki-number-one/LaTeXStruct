# -*- coding: utf-8 -*-
"""LaTeXStruct 启动器。

用法：
  python -m latexstruct             # 桌面窗口（需 pywebview；否则自动回退浏览器模式）
  python -m latexstruct --server    # 仅本地服务（浏览器访问 http://127.0.0.1:8080）
  python -m latexstruct --port 8765
"""

from __future__ import annotations

import argparse
import os
import sys
import threading


def _show_startup_error(message: str) -> None:
    """Windowed builds have no console, so surface fatal packaging errors explicitly."""
    detail = (
        "LaTeXStruct 无法启动。\n\n"
        f"{message}\n\n"
        "请从官方发布页重新下载安装完整版本；重新安装不会删除本地项目。"
    )
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, detail, "LaTeXStruct 启动失败", 0x10)
            return
        except Exception:  # noqa: BLE001
            pass
    print(detail, file=sys.stderr)


def main():
    # PyInstaller windowed 模式下 stdout/stderr 为 None：uvicorn/print 首次写流会崩溃，重定向到 devnull
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")

    ap = argparse.ArgumentParser(prog="latexstruct")
    ap.add_argument("--server", action="store_true", help="只启动本地服务（浏览器访问）")
    ap.add_argument("--port", type=int, default=0, help="端口（0=自动/默认）")
    args = ap.parse_args()

    import uvicorn

    from latexstruct.server.app import create_app

    try:
        app = create_app()
    except Exception as exc:  # noqa: BLE001
        if args.server:
            print(f"LaTeXStruct 启动失败: {exc}", file=sys.stderr)
        else:
            _show_startup_error(str(exc))
        return 1
    port = args.port or 8080

    if args.server:
        uvicorn.run(app, host="127.0.0.1", port=port)
        return

    try:
        import webview  # noqa: F401
    except ImportError:
        print(f"pywebview 未安装，使用浏览器模式：http://127.0.0.1:{port}")
        uvicorn.run(app, host="127.0.0.1", port=port)
        return

    port = args.port or 8765
    t = threading.Thread(
        target=uvicorn.run,
        kwargs={"app": app, "host": "127.0.0.1", "port": port, "log_level": "warning"},
        daemon=True,
    )
    t.start()
    import webview

    webview.create_window("LaTeXStruct", f"http://127.0.0.1:{port}", width=1280, height=820)
    webview.start()


if __name__ == "__main__":
    main()

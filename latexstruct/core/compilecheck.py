# -*- coding: utf-8 -*-
"""编译校验（评审 P2 · Level 5）：本机存在 xelatex 时执行真实编译，
含目录/交叉引用时自动跑第二遍，使目录页码与书签目标进入验收范围。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import PurePosixPath
from typing import Dict, Optional

PAGES_RE = re.compile(r"Output written on .*\((\d+) pages?")
ERROR_RE = re.compile(r"^! ", re.M)


def find_xelatex() -> Optional[str]:
    exe = shutil.which("xelatex")
    if exe:
        return exe
    for p in (r"C:\texlive\2026\bin\windows\xelatex.exe",
              r"C:\Program Files\MiKTeX\miktex\bin\x64\xelatex.exe"):
        if os.path.exists(p):
            return p
    return None


def compile_latex(text: str, timeout: int = 240, extra_files: dict = None) -> Dict:
    """在临时目录编译给定文本；extra_files 为 {相对路径: bytes} 附加资源。
    返回 {available, ok, pages, errors, log}。"""
    exe = find_xelatex()
    if not exe:
        return {"available": False, "ok": None, "pages": 0, "errors": [], "log": ""}
    compile_files = dict(extra_files or {})
    from .template import uses_elegantbook_class

    if uses_elegantbook_class(text):
        from ..elegantbook import CLASS_FILENAME, elegantbook_class_bytes

        compile_files.setdefault(CLASS_FILENAME, elegantbook_class_bytes())
    workdir = tempfile.mkdtemp(prefix="ls-compile-")
    try:
        tex_path = os.path.join(workdir, "main.tex")
        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(text)
        for rel, data in compile_files.items():
            safe = PurePosixPath(str(rel).replace("\\", "/"))
            if safe.is_absolute() or any(part in ("", ".", "..") for part in safe.parts):
                raise ValueError(f"编译附加文件路径不安全：{rel!r}")
            p = os.path.join(workdir, *safe.parts)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        try:
            passes = 2 if any(token in text for token in (
                "\\tableofcontents", "\\ref{", "\\pageref{", "\\cite{",
            )) else 1
            proc = None
            for _ in range(passes):
                proc = subprocess.run(
                    [exe, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
                    cwd=workdir, capture_output=True, timeout=timeout,
                )
                if proc.returncode != 0:
                    break
        except subprocess.TimeoutExpired:
            return {"available": True, "ok": False, "pages": 0,
                    "errors": ["编译超时（>{}s）".format(timeout)], "log": ""}
        log_path = os.path.join(workdir, "main.log")
        log = open(log_path, encoding="utf-8", errors="replace").read() if os.path.exists(log_path) else ""
        errors = []
        lines = log.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("!"):
                msg = line[1:].strip() or "（错误详情见下行）"
                if i + 1 < len(lines) and lines[i + 1].startswith("l."):
                    msg += " @" + lines[i + 1].strip()
                errors.append(msg[:140])
        errors = errors[:5]
        m = PAGES_RE.search(log)
        pages = int(m.group(1)) if m else 0
        ok = proc.returncode == 0 and pages > 0 and not errors
        return {"available": True, "ok": ok, "pages": pages, "errors": errors,
                "log": log[-4000:]}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

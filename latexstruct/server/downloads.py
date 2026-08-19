# -*- coding: utf-8 -*-
"""桌面版可靠下载与打开保存位置。

网页下载在部分 WebView2 环境中会被宿主拦截，因此提供一个严格受限的本机兜底：
只能写入当前用户的 ``Downloads/LaTeXStruct``，文件名会被净化且永不覆盖。
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path


_INVALID_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_DOWNLOADS_REGISTRY_VALUE = "{374DE290-123F-4565-9164-39C4925E467B}"


def safe_download_filename(filename: str, default: str = "LaTeXStruct-result.tex") -> str:
    """生成单个、可移植且长度有界的文件名。"""
    raw = Path(str(filename or "").replace("\\", "/")).name
    cleaned = _INVALID_FILENAME_RE.sub("_", raw).strip().rstrip(". ")
    if not cleaned:
        cleaned = default
    path = Path(cleaned)
    suffix = path.suffix[:20]
    stem = path.stem.strip().rstrip(". ") or "LaTeXStruct-result"
    if stem.upper() in _WINDOWS_RESERVED_NAMES:
        stem = f"_{stem}"
    # 留出扩展名和自动添加的 `` (9999)``，避免 Windows 旧 API 的长路径问题。
    stem = stem[:120].rstrip(". ") or "LaTeXStruct-result"
    return f"{stem}{suffix}"


def _registered_windows_downloads() -> Path | None:
    if os.name != "nt":
        return None
    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _kind = winreg.QueryValueEx(key, _DOWNLOADS_REGISTRY_VALUE)
        expanded = os.path.expandvars(str(value)).strip()
        return Path(expanded) if expanded else None
    except (OSError, ValueError, TypeError):
        return None


def download_root() -> Path:
    """返回固定的用户下载目录；不会读取请求参数或项目内容。"""
    base = _registered_windows_downloads() or (Path.home() / "Downloads")
    return base / "LaTeXStruct"


def _ensure_managed_root(root: Path) -> Path:
    """创建并验证应用自己的末级目录，拒绝符号链接/Junction 绕出下载区。"""
    root.mkdir(parents=True, exist_ok=True)
    info = root.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if root.is_symlink() or (reparse and attributes & reparse):
        raise OSError("下载目录是链接或 Junction；请移除后重试")
    if not root.is_dir():
        raise OSError("下载位置不是文件夹")
    return root


def save_unique_download(data: bytes, filename: str, *, root: Path | None = None) -> Path:
    """同目录完整落盘后再原子提交；同名时追加序号且永不覆盖。"""
    if not isinstance(data, bytes):
        raise TypeError("下载内容必须是 bytes")
    target_root = _ensure_managed_root(Path(root) if root is not None else download_root())
    clean_name = safe_download_filename(filename)
    clean_path = Path(clean_name)
    stem, suffix = clean_path.stem, clean_path.suffix

    temporary = target_root / f".latexstruct-{uuid.uuid4().hex}.download"
    candidate: Path | None = None
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for index in range(0, 10_000):
            candidate_name = clean_name if index == 0 else f"{stem} ({index}){suffix}"
            candidate = target_root / candidate_name
            try:
                # 独占占位确保后续 replace 只替换本次创建的文件，不覆盖用户内容。
                with candidate.open("xb"):
                    pass
            except FileExistsError:
                candidate = None
                continue
            try:
                # Windows Defender/索引器可能在刚关闭占位文件后短暂持有句柄，
                # 使同目录的原子 replace 偶发返回 WinError 5。目标仍是本次独占
                # 创建的空占位，因此只对 Windows 的 PermissionError 做短暂重试；
                # 其他平台或其他错误继续立即失败，绝不改为覆盖未知文件。
                for attempt in range(6):
                    try:
                        os.replace(temporary, candidate)
                        break
                    except PermissionError:
                        if os.name != "nt" or attempt == 5:
                            raise
                        time.sleep(0.01 * (attempt + 1))
            except Exception:
                candidate.unlink(missing_ok=True)
                raise
            return candidate
        raise OSError("下载目录中同名文件过多，请整理后重试")
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _reveal_command(folder: Path, target: Path | None = None) -> list[str]:
    if os.name == "nt":
        return ["explorer.exe", f"/select,{target}" if target else str(folder)]
    if sys.platform == "darwin":
        return ["open", "-R", str(target)] if target else ["open", str(folder)]
    return ["xdg-open", str(folder)]


def reveal_download_location(saved_filename: str = "", *, root: Path | None = None) -> Path:
    """打开固定下载位置；可选择由本模块保存过的同目录文件。"""
    target_root = _ensure_managed_root(Path(root) if root is not None else download_root())
    target = target_root / safe_download_filename(saved_filename) if saved_filename else None
    if target is not None and not target.is_file():
        target = None
    kwargs = {"shell": False, "close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.Popen(_reveal_command(target_root, target), **kwargs)  # noqa: S603
    return target_root

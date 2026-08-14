# -*- coding: utf-8 -*-
"""主动更新模块（纯标准库；网络层与逻辑分离，逻辑可离线测试）。

流程：启动/手动触发 → 查 GitHub Releases latest → 比较版本 →
有新版时下载安装器（*-setup.exe）到临时目录 → 静默安装（/SILENT）。

更新源与当前版本见 latexstruct/__init__.py（UPDATE_REPO / __version__）。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

API_TEMPLATE = "https://api.github.com/repos/{repo}/releases/latest"
USER_AGENT = "LaTeXStruct-Updater"


@dataclass
class UpdateInfo:
    available: bool
    latest: str = ""
    url: str = ""
    notes: str = ""
    size: int = 0
    error: str = ""


def compare_versions(a: str, b: str) -> int:
    """比较语义化版本（容忍前导 v / 后缀）。a<b 返回 -1，相等 0，a>b 返回 1。"""
    def parts(v: str) -> List[int]:
        m = re.match(r"[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v.strip())
        if not m:
            return [0, 0, 0]
        return [int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)]

    pa, pb = parts(a), parts(b)
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    return 0


def parse_release(payload: Dict) -> Tuple[str, List[Dict], str]:
    """返回 (tag, assets, body)。"""
    tag = str(payload.get("tag_name") or "")
    assets = payload.get("assets") or []
    if not isinstance(assets, list):
        assets = []
    body = str(payload.get("body") or "")
    return tag, assets, body


def select_asset(assets: List[Dict]) -> Optional[Tuple[str, int]]:
    """优先选择 *-setup.exe，其次 *.exe。返回 (url, size)。"""
    exes = [a for a in assets if str(a.get("name", "")).lower().endswith(".exe")]
    if not exes:
        return None
    setups = [a for a in exes if "setup" in str(a.get("name", "")).lower()]
    pick = (setups or exes)[0]
    url = pick.get("browser_download_url")
    if not url:
        return None
    return str(url), int(pick.get("size") or 0)


def check_for_updates(
    repo: str, current_version: str, timeout: float = 12.0
) -> UpdateInfo:
    """查询 GitHub Releases latest 并与当前版本比较。任何异常 → error 字段。"""
    if not repo or "/" not in repo:
        return UpdateInfo(False, error="未配置更新仓库")
    url = API_TEMPLATE.format(repo=repo)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return UpdateInfo(False, error=f"检查更新失败：{e}")
    tag, assets, body = parse_release(payload)
    if not tag:
        return UpdateInfo(False, error="Release 无 tag 信息")
    if compare_versions(tag, current_version) <= 0:
        return UpdateInfo(False, latest=tag, error="")
    asset = select_asset(assets)
    if asset is None:
        return UpdateInfo(True, latest=tag, notes=body, error="未找到安装包资产")
    url, size = asset
    return UpdateInfo(True, latest=tag, url=url, notes=body, size=size)


def download_file(
    url: str, dest: str, progress: Optional[Callable[[int, int], None]] = None
) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    if progress:
        progress(done, total)


def run_installer(path: str) -> subprocess.Popen:
    """静默安装：/SILENT + /CLOSEAPPLICATIONS（替换文件前自动关闭运行中的实例）。"""
    if sys.platform == "win32":
        return subprocess.Popen(
            [path, "/SILENT", "/CLOSEAPPLICATIONS", "/NORESTART"],
            cwd=os.path.dirname(path) or None,
        )
    return subprocess.Popen([path])


def download_and_install(info: UpdateInfo, tmpdir: Optional[str] = None) -> str:
    """下载安装器并静默启动；返回安装器路径。"""
    if not info.url:
        raise ValueError("无安装包地址")
    tmp = tmpdir or tempfile.gettempdir()
    name = os.path.basename(info.url.split("?")[0]) or "LaTeXStruct-setup.exe"
    dest = os.path.join(tmp, name)
    download_file(info.url, dest)
    run_installer(dest)
    return dest

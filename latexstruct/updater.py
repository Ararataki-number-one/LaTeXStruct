# -*- coding: utf-8 -*-
"""主动更新模块（纯标准库；网络层与逻辑分离，逻辑可离线测试）。

流程：启动/手动触发 → 查 GitHub Releases latest → 比较版本 →
下载并校验安装器 → 退出当前单文件程序并等待文件解锁 → 静默安装并重启。

更新源与当前版本见 latexstruct/__init__.py（UPDATE_REPO / __version__）。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

API_TEMPLATE = "https://api.github.com/repos/{repo}/releases/latest"
USER_AGENT = "LaTeXStruct-Updater"


@dataclass
class UpdateInfo:
    available: bool
    latest: str = ""
    url: str = ""
    notes: str = ""
    size: int = 0
    digest: str = ""
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


def select_asset(
    assets: List[Dict], expected_version: str = ""
) -> Optional[Tuple[str, int, str]]:
    """只选择正式安装器，避免把便携版 exe 当安装包执行。"""
    expected = expected_version.lstrip("vV")
    pattern = re.compile(r"^latexstruct-setup-(\d+\.\d+\.\d+)\.exe$", re.IGNORECASE)
    setups = []
    for asset in assets:
        match = pattern.fullmatch(str(asset.get("name", "")))
        if match and (not expected or match.group(1) == expected):
            setups.append(asset)
    if not setups:
        return None
    pick = setups[0]
    url = pick.get("browser_download_url")
    if not url:
        return None
    digest = str(pick.get("digest") or "")
    return str(url), int(pick.get("size") or 0), digest


def _trusted_release_url(url: str, repo: str) -> bool:
    """Release API 只能把更新器引向本仓库的 GitHub HTTPS 下载地址。"""
    parsed = urlsplit(url)
    expected_prefix = f"/{repo.strip('/')}/releases/download/".casefold()
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").casefold() == "github.com"
        and port in (None, 443)
        and parsed.path.casefold().startswith(expected_prefix)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


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
    asset = select_asset(assets, tag)
    if asset is None:
        return UpdateInfo(True, latest=tag, notes=body, error="未找到安装包资产")
    url, size, digest = asset
    if not _trusted_release_url(url, repo):
        return UpdateInfo(True, latest=tag, notes=body, error="安装包下载地址不可信")
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        return UpdateInfo(True, latest=tag, notes=body, error="安装包缺少有效 SHA-256 校验信息")
    return UpdateInfo(
        True, latest=tag, url=url, notes=body, size=size, digest=digest
    )


def download_file(
    url: str,
    dest: str,
    progress: Optional[Callable[[int, int], None]] = None,
    expected_size: int = 0,
    expected_digest: str = "",
) -> None:
    """原子下载并校验 GitHub 提供的大小/SHA-256，失败不留下半包。"""
    digest = expected_digest.strip().lower()
    if digest:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("安装包 SHA-256 信息格式无效")
        expected_hash = digest.split(":", 1)[1]
    else:
        expected_hash = ""
    partial = f"{dest}.{os.getpid()}.part"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    done = 0
    hasher = hashlib.sha256()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            header_total = int(resp.headers.get("Content-Length") or 0)
            total = expected_size or header_total
            with open(partial, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
        if expected_size and done != expected_size:
            raise ValueError(f"安装包大小校验失败（预期 {expected_size}，实际 {done}）")
        if expected_hash and hasher.hexdigest().lower() != expected_hash:
            raise ValueError("安装包 SHA-256 校验失败，已取消更新")
        os.replace(partial, dest)
        if progress:
            progress(done, expected_size or done)
    finally:
        if os.path.exists(partial):
            try:
                os.remove(partial)
            except OSError:
                pass


WINDOWS_INSTALLER_ARGS = (
    "/VERYSILENT",
    "/SUPPRESSMSGBOXES",
    "/CLOSEAPPLICATIONS",
    "/FORCECLOSEAPPLICATIONS",
    "/NORESTART",
    "/NORESTARTAPPLICATIONS",
    "/LATEXSTRUCTUPDATE=1",
)


def run_installer(path: str) -> subprocess.Popen:
    """直接启动安装器；主要供非单文件模式与离线验证使用。"""
    if sys.platform == "win32":
        return subprocess.Popen(
            [path, *WINDOWS_INSTALLER_ARGS],
            cwd=os.path.dirname(path) or None,
            env=_minimal_windows_environment(),
        )
    return subprocess.Popen([path])


_WINDOWS_UPDATE_HELPER = r"""
$ErrorActionPreference = 'Stop'
$appProcessId = [int]$env:LATEXSTRUCT_UPDATE_PID
$target = $env:LATEXSTRUCT_UPDATE_TARGET
try {
  $processDeadline = [DateTime]::UtcNow.AddSeconds(12)
  while ((Get-Process -Id $appProcessId -ErrorAction SilentlyContinue) -and
         ([DateTime]::UtcNow -lt $processDeadline)) {
    Start-Sleep -Milliseconds 250
  }
  if (Get-Process -Id $appProcessId -ErrorAction SilentlyContinue) {
    Stop-Process -Id $appProcessId -Force -ErrorAction SilentlyContinue
  }

  $unlockDeadline = [DateTime]::UtcNow.AddSeconds(60)
  $unlocked = $false
  while (-not $unlocked -and ([DateTime]::UtcNow -lt $unlockDeadline)) {
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
      $unlocked = $true
      break
    }
    try {
      $stream = [IO.File]::Open(
        $target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
      )
      $stream.Dispose()
      $unlocked = $true
    } catch {
      Start-Sleep -Milliseconds 250
    }
  }
  if (-not $unlocked) { throw 'target remained locked' }

  $arguments = @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/CLOSEAPPLICATIONS',
    '/FORCECLOSEAPPLICATIONS', '/NORESTART', '/NORESTARTAPPLICATIONS',
    '/LATEXSTRUCTUPDATE=1'
  )
  $setup = Start-Process -FilePath $env:LATEXSTRUCT_UPDATE_INSTALLER `
    -ArgumentList $arguments -PassThru -Wait
  if ($setup.ExitCode -ne 0) { throw 'installer failed' }
} catch {
  if ((-not (Get-Process -Id $appProcessId -ErrorAction SilentlyContinue)) -and
      (Test-Path -LiteralPath $target -PathType Leaf)) {
    Start-Process -FilePath $target
  }
  exit 34
}
"""


_WINDOWS_ENV_ALLOWLIST = {
    "ALLUSERSPROFILE",
    "APPDATA",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "PUBLIC",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
}


def _minimal_windows_environment() -> Dict[str, str]:
    """只给 helper/Inno 必需环境；API Key/token 不跨进程传播。"""
    env = {
        key: value for key, value in os.environ.items()
        if key.upper() in _WINDOWS_ENV_ALLOWLIST
    }
    if not any(key.upper() == "SYSTEMROOT" for key in env):
        env["SystemRoot"] = r"C:\Windows"
    return env


def _powershell_executable() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = os.path.join(
        system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    return candidate if os.path.isfile(candidate) else "powershell.exe"


def schedule_installer_after_exit(
    path: str, app_pid: Optional[int] = None, target_executable: Optional[str] = None
) -> subprocess.Popen:
    """启动独立 helper：等本进程和单文件 bootloader 释放 exe 后再安装。"""
    if sys.platform != "win32":
        return run_installer(path)
    installer = os.path.abspath(path)
    if not os.path.isfile(installer) or not installer.lower().endswith(".exe"):
        raise ValueError("更新安装包不存在或格式不正确")
    target = os.path.abspath(target_executable or sys.executable)
    env = _minimal_windows_environment()
    env.update({
        "LATEXSTRUCT_UPDATE_INSTALLER": installer,
        "LATEXSTRUCT_UPDATE_TARGET": target,
        "LATEXSTRUCT_UPDATE_PID": str(app_pid or os.getpid()),
    })
    flags = (
        getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    )
    return subprocess.Popen(
        [
            _powershell_executable(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            _WINDOWS_UPDATE_HELPER,
        ],
        cwd=os.path.dirname(installer) or None,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
    )


def request_application_exit(delay: float = 0.8) -> None:
    """响应发给前端后关闭桌面主窗；helper 在超时后仍会兜底结束进程。"""
    time.sleep(max(0.0, delay))
    if sys.platform != "win32":
        os._exit(0)

    import ctypes
    from ctypes import wintypes

    current_pid = os.getpid()
    posted = False
    enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @enum_proc_type
    def close_window(hwnd, _lparam):
        nonlocal posted
        process_id = wintypes.DWORD()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
        if process_id.value == current_pid and ctypes.windll.user32.IsWindowVisible(hwnd):
            ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
            posted = True
        return True

    ctypes.windll.user32.EnumWindows(close_window, 0)
    if not posted:
        os._exit(0)


def download_update(info: UpdateInfo, tmpdir: Optional[str] = None) -> str:
    """下载并验证安装器，但不在当前进程仍占用 exe 时直接运行。"""
    if not info.url:
        raise ValueError("无安装包地址")
    name = os.path.basename(urlsplit(info.url).path)
    if not re.fullmatch(
        r"LaTeXStruct-setup-\d+\.\d+\.\d+\.exe", name, re.IGNORECASE
    ):
        raise ValueError("安装包文件名不符合发布规则")
    tmp = tmpdir or tempfile.gettempdir()
    os.makedirs(tmp, exist_ok=True)
    dest = os.path.join(tmp, name)
    download_file(
        info.url,
        dest,
        expected_size=info.size,
        expected_digest=info.digest,
    )
    return dest


def download_and_install(info: UpdateInfo, tmpdir: Optional[str] = None) -> str:
    """兼容入口：下载后安排在本进程退出、exe 解锁后安装。"""
    dest = download_update(info, tmpdir)
    schedule_installer_after_exit(dest)
    return dest

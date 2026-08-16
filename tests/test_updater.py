# -*- coding: utf-8 -*-
"""主动更新模块测试（逻辑层，无网络）。"""

import os
import sys
from io import BytesIO
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.updater import (  # noqa: E402
    WINDOWS_INSTALLER_ARGS,
    _trusted_release_url,
    check_for_updates,
    compare_versions,
    download_file,
    parse_release,
    run_installer,
    schedule_installer_after_exit,
    select_asset,
)


def test_compare_versions():
    assert compare_versions("0.1.0", "0.2.0") < 0
    assert compare_versions("v0.2.0", "0.2.0") == 0
    assert compare_versions("1.0", "0.9.9") > 0
    assert compare_versions("0.2", "0.2.0") == 0
    assert compare_versions("0.2.1", "0.2.0") > 0
    assert compare_versions("nonsense", "0.1.0") < 0


def test_parse_release():
    payload = {
        "tag_name": "v0.2.1",
        "body": "修复若干问题",
        "assets": [
            {"name": "LaTeXStruct-setup.exe", "browser_download_url": "https://x/setup.exe", "size": 1024},
            {"name": "src.zip", "browser_download_url": "https://x/src.zip", "size": 10},
        ],
    }
    tag, assets, body = parse_release(payload)
    assert tag == "v0.2.1" and body == "修复若干问题"
    assert len(assets) == 2


def test_select_asset_prefers_setup():
    digest = "sha256:" + "a" * 64
    assets = [
        {"name": "LaTeXStruct.exe", "browser_download_url": "https://x/app.exe", "size": 5},
        {
            "name": "LaTeXStruct-setup-1.2.3.exe",
            "browser_download_url": "https://x/setup.exe",
            "size": 99,
            "digest": digest,
        },
    ]
    url, size, selected_digest = select_asset(assets, "v1.2.3")
    assert (url, size, selected_digest) == ("https://x/setup.exe", 99, digest)
    # 自动更新绝不执行便携版，也不接受版本不一致的安装器。
    assert select_asset([assets[0]]) is None
    assert select_asset(assets, "v1.2.4") is None
    assert select_asset([{"name": "a.zip", "browser_download_url": "x"}]) is None


def test_release_url_is_pinned_to_exact_github_repo():
    good = "https://github.com/owner/repo/releases/download/v1.2.3/LaTeXStruct-setup-1.2.3.exe"
    assert _trusted_release_url(good, "owner/repo") is True
    assert _trusted_release_url(good + "?token=unexpected", "owner/repo") is False
    assert _trusted_release_url(good + "#fragment", "owner/repo") is False
    assert _trusted_release_url(good.replace("github.com", "github.com.evil.test"), "owner/repo") is False
    assert _trusted_release_url(good.replace("github.com", "github.com:8443"), "owner/repo") is False
    assert _trusted_release_url(good, "other/repo") is False


class _DownloadResponse(BytesIO):
    def __init__(self, payload: bytes):
        super().__init__(payload)
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def test_check_for_updates_requires_github_asset_digest():
    import json

    asset = {
        "name": "LaTeXStruct-setup-1.2.3.exe",
        "browser_download_url": (
            "https://github.com/owner/repo/releases/download/"
            "v1.2.3/LaTeXStruct-setup-1.2.3.exe"
        ),
        "size": 123,
        "digest": "",
    }
    payload = {"tag_name": "v1.2.3", "assets": [asset], "body": "notes"}
    response = _DownloadResponse(json.dumps(payload).encode())
    with patch("latexstruct.updater.urllib.request.urlopen", return_value=response):
        info = check_for_updates("owner/repo", "1.2.2")
    assert info.available is True and not info.url
    assert "SHA-256" in info.error

    asset["digest"] = "sha256:" + "a" * 64
    response = _DownloadResponse(json.dumps(payload).encode())
    with patch("latexstruct.updater.urllib.request.urlopen", return_value=response):
        info = check_for_updates("owner/repo", "1.2.2")
    assert info.url.endswith("LaTeXStruct-setup-1.2.3.exe")
    assert info.digest == asset["digest"]

    # 新版启动后的成功弹窗仍需读取当前 Release 说明。
    response = _DownloadResponse(json.dumps(payload).encode())
    with patch("latexstruct.updater.urllib.request.urlopen", return_value=response):
        current = check_for_updates("owner/repo", "1.2.3")
    assert current.available is False
    assert current.latest == "v1.2.3" and current.notes == "notes"


def test_download_file_checks_size_and_sha256_atomically(tmp_path):
    import hashlib

    payload = b"verified installer bytes"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    dest = tmp_path / "LaTeXStruct-setup-1.2.3.exe"
    with patch("latexstruct.updater.urllib.request.urlopen", return_value=_DownloadResponse(payload)):
        download_file(
            "https://example.invalid/setup.exe",
            str(dest),
            expected_size=len(payload),
            expected_digest=digest,
        )
    assert dest.read_bytes() == payload
    assert not list(tmp_path.glob("*.part"))

    with patch("latexstruct.updater.urllib.request.urlopen", return_value=_DownloadResponse(payload)):
        try:
            download_file(
                "https://example.invalid/setup.exe",
                str(dest),
                expected_size=len(payload) + 1,
                expected_digest=digest,
            )
        except ValueError as exc:
            assert "大小校验失败" in str(exc)
        else:
            raise AssertionError("size mismatch must fail closed")
    # 校验失败不能覆盖上一个已验证文件，也不能遗留半包。
    assert dest.read_bytes() == payload
    assert not list(tmp_path.glob("*.part"))


def test_windows_installer_arguments_suppress_ignore_dialog(tmp_path):
    setup = tmp_path / "LaTeXStruct-setup-1.2.3.exe"
    setup.write_bytes(b"MZ")
    with (
        patch("latexstruct.updater.sys.platform", "win32"),
        patch("latexstruct.updater.subprocess.Popen") as popen,
    ):
        run_installer(str(setup))
    argv = popen.call_args.args[0]
    assert argv[0] == str(setup)
    for argument in (
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/CLOSEAPPLICATIONS",
        "/FORCECLOSEAPPLICATIONS", "/NORESTARTAPPLICATIONS",
    ):
        assert argument in argv
        assert argument in WINDOWS_INSTALLER_ARGS


def test_windows_helper_waits_for_process_and_exclusive_unlock(tmp_path):
    setup = tmp_path / "LaTeXStruct-setup-1.2.3.exe"
    target = tmp_path / "LaTeXStruct.exe"
    setup.write_bytes(b"MZ")
    target.write_bytes(b"MZ")
    secret_env = {
        "DEEPSEEK_API_KEY": "must-not-leak",
        "DASHSCOPE_API_KEY": "must-not-leak",
        "PRIVATE_TOKEN": "must-not-leak",
        "AUTHORIZATION": "must-not-leak",
        "DB_PASSWORD": "must-not-leak",
    }
    with patch.dict(os.environ, secret_env, clear=False):
        with (
            patch("latexstruct.updater.sys.platform", "win32"),
            patch("latexstruct.updater._powershell_executable", return_value="powershell.exe"),
            patch("latexstruct.updater.subprocess.Popen") as popen,
        ):
            schedule_installer_after_exit(
                str(setup), app_pid=4321, target_executable=str(target)
            )
    argv = popen.call_args.args[0]
    kwargs = popen.call_args.kwargs
    script = argv[-1]
    assert "Get-Process -Id $appProcessId" in script
    assert "[IO.File]::Open" in script and "[IO.FileShare]::None" in script
    assert "Stop-Process -Id $appProcessId -Force" in script
    assert "-not (Get-Process -Id $appProcessId" in script
    assert "Start-Process -FilePath $target" in script  # 原进程已退时，失败路径尽力重开旧版
    assert kwargs["env"]["LATEXSTRUCT_UPDATE_PID"] == "4321"
    assert kwargs["env"]["LATEXSTRUCT_UPDATE_TARGET"] == str(target)
    assert kwargs["env"]["LATEXSTRUCT_UPDATE_INSTALLER"] == str(setup)
    for key in secret_env:
        assert key not in kwargs["env"]


def test_installer_script_force_closes_old_updater_and_restarts_only_upgrade():
    script = (os.path.join(os.path.dirname(os.path.dirname(__file__)), "packaging", "installer.iss"))
    text = open(script, encoding="utf-8").read()
    assert "CloseApplications=force" in text
    assert "RestartApplications=no" in text
    assert "WasInstalledBefore := FileExists" in text
    assert "update_restart.ps1" in text
    assert "UpdatePreviousVersion" in text
    assert "-ExpectedVersion \"\"{#AppVersion}\"\"" in text
    assert "runhidden skipifnotsilent; Check: RestartAfterSilentUpdate" in text

    restart_script = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "packaging", "update_restart.ps1"
    )
    restart_bytes = open(restart_script, "rb").read()
    # Windows PowerShell 5.1 treats UTF-8 without a BOM as the active ANSI code
    # page. Non-ASCII source can therefore swallow quotes and fail before the
    # helper writes its first log line. Localized text is decoded at runtime.
    assert all(byte < 128 for byte in restart_bytes)
    restart = open(restart_script, encoding="utf-8").read()
    assert "Wait-ForExpectedVersion" in restart
    assert "for ($attempt = 1; $attempt -le 2; $attempt++)" in restart
    assert "$observed -eq $ExpectedVersion" in restart
    assert "update-restart.log" in restart
    assert "FromBase64String" in restart


def main():
    import traceback

    tests = [
        (k, v)
        for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()

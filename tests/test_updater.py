# -*- coding: utf-8 -*-
"""主动更新模块测试（逻辑层，无网络）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.updater import (  # noqa: E402
    compare_versions,
    parse_release,
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
    assets = [
        {"name": "LaTeXStruct.exe", "browser_download_url": "https://x/app.exe", "size": 5},
        {"name": "LaTeXStruct-setup.exe", "browser_download_url": "https://x/setup.exe", "size": 99},
    ]
    url, size = select_asset(assets)
    assert url == "https://x/setup.exe" and size == 99
    # 无 setup 时退回任意 exe
    url2, _ = select_asset([assets[0]])
    assert url2 == "https://x/app.exe"
    # 无 exe → None
    assert select_asset([{"name": "a.zip", "browser_download_url": "x"}]) is None


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

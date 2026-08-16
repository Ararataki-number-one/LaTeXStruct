# -*- coding: utf-8 -*-
"""Vendored ElegantBook assets used by verified exports and compile checks."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

ELEGANTBOOK_VERSION = "4.7"
ELEGANTBOOK_DATE = "2026-05-01"
ELEGANTBOOK_COMMIT = "8b90c11e4a5ffd9d1e07174011303c133093d09c"
ELEGANTBOOK_SOURCE = "https://github.com/ElegantLaTeX/ElegantBook"

CLASS_FILENAME = "elegantbook.cls"
LICENSE_FILENAME = "ELEGANTBOOK-LICENSE.txt"
README_FILENAME = "ELEGANTBOOK-BUNDLE-README.md"

_ASSET_DIR = Path(__file__).with_name("assets") / "elegantbook"
_EXPECTED_SHA256 = {
    CLASS_FILENAME: "6e68bf8097b8141fe6a5ab6819a6bab7a9c56158aa9a92ebc44856cabc6330d3",
    LICENSE_FILENAME: "44f4da558127692b203619708bff5e37fb8b04241fc8d053d15cd277393f3ebb",
}


def _verified_asset(filename: str) -> bytes:
    """Read a bundled asset only when it matches the reviewed source snapshot."""
    path = _ASSET_DIR / filename
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"ElegantBook 资源缺失：{filename}") from exc
    expected = _EXPECTED_SHA256[filename]
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise RuntimeError(f"ElegantBook 资源校验失败：{filename}")
    return data


def elegantbook_class_bytes() -> bytes:
    return _verified_asset(CLASS_FILENAME)


def elegantbook_license_bytes() -> bytes:
    return _verified_asset(LICENSE_FILENAME)


def bundle_readme_bytes() -> bytes:
    text = f"""# LaTeXStruct ElegantBook 工程包

本工程使用 ElegantBook v{ELEGANTBOOK_VERSION}（{ELEGANTBOOK_DATE}）固定模板。
类文件来源：{ELEGANTBOOK_SOURCE}，固定提交：{ELEGANTBOOK_COMMIT}。

## 编译

1. 保留 `elegantbook.cls` 与主 TEX 文件在工程包内。
2. 在解压后的工程根目录运行 `xelatex`；含目录、引用或文献时至少运行两遍。
3. 图片、BibTeX、子 TEX 与其他资源均保留原相对路径，请勿只移动主文件。

`ELEGANTBOOK-LICENSE.txt` 是 ElegantBook 的 LPPL 许可证。`LATEXSTRUCT-REPORT.md`
记录本次结构化和安全检查。若只导出单个 TEX，编译环境需已安装 ElegantBook，
或把本工程包中的 `elegantbook.cls` 放在 TEX 文件旁边。
"""
    return text.encode("utf-8")


def elegantbook_bundle_assets() -> dict[str, bytes]:
    return {
        CLASS_FILENAME: elegantbook_class_bytes(),
        LICENSE_FILENAME: elegantbook_license_bytes(),
        README_FILENAME: bundle_readme_bytes(),
    }

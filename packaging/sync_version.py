# -*- coding: utf-8 -*-
"""Synchronize generated Windows and frontend metadata with the app version."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESOURCE_PATH = ROOT / "packaging" / "version_info.txt"
PACKAGE_PATH = ROOT / "frontend" / "package.json"
PACKAGE_LOCK_PATH = ROOT / "frontend" / "package-lock.json"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def sync_text(text: str, version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid semantic version: {version!r}")
    major, minor, patch = (int(part) for part in version.split("."))
    tuple_value = f"({major}, {minor}, {patch}, 0)"
    text, tuple_count = re.subn(
        r"(?m)^(\s*(?:filevers|prodvers)=)\(\d+,\s*\d+,\s*\d+,\s*\d+\)",
        rf"\g<1>{tuple_value}",
        text,
    )
    text, string_count = re.subn(
        r"(StringStruct\(u'(?:FileVersion|ProductVersion)',\s*u')[^']+('\))",
        rf"\g<1>{version}\g<2>",
        text,
    )
    if tuple_count != 2 or string_count != 2:
        raise ValueError("unexpected packaging/version_info.txt structure")
    return text


def sync_package_data(data: dict, version: str, lock: bool = False) -> dict:
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid semantic version: {version!r}")
    updated = dict(data)
    updated["version"] = version
    if lock:
        packages = dict(updated.get("packages") or {})
        root = dict(packages.get("") or {})
        root["version"] = version
        packages[""] = root
        updated["packages"] = packages
    return updated


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    current = RESOURCE_PATH.read_text(encoding="utf-8")
    updated = sync_text(current, args.version)
    if updated != current:
        RESOURCE_PATH.write_text(updated, encoding="utf-8", newline="\n")
    for path, lock in ((PACKAGE_PATH, False), (PACKAGE_LOCK_PATH, True)):
        data = json.loads(path.read_text(encoding="utf-8"))
        synced = sync_package_data(data, args.version, lock=lock)
        if synced != data:
            path.write_text(
                json.dumps(synced, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )


if __name__ == "__main__":
    main()

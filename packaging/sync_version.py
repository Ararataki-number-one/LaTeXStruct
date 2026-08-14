# -*- coding: utf-8 -*-
"""Synchronize the generated Windows version resource with the app version."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESOURCE_PATH = ROOT / "packaging" / "version_info.txt"
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    current = RESOURCE_PATH.read_text(encoding="utf-8")
    updated = sync_text(current, args.version)
    if updated != current:
        RESOURCE_PATH.write_text(updated, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

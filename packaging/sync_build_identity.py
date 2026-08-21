# -*- coding: utf-8 -*-
"""Embed an exact CI commit and run ID for the packaged application."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILD_PATH = ROOT / "latexstruct" / "_build.py"
COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}")
BUILD_ID_RE = re.compile(r"[1-9][0-9]{0,31}")


def render_build_identity(commit: str, build_id: str) -> str:
    """Return a deterministic module or reject non-exact CI identity."""
    commit = str(commit or "").strip().lower()
    build_id = str(build_id or "").strip()
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be an exact 40-character Git SHA")
    if not BUILD_ID_RE.fullmatch(build_id):
        raise ValueError("build-id must be a positive decimal GitHub run ID")
    return (
        '"""Build identity embedded by packaging/sync_build_identity.py."""\n\n'
        f'BUILD_COMMIT = "{commit}"\n'
        f'BUILD_ID = "{build_id}"\n'
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--build-id", required=True)
    args = parser.parse_args()
    BUILD_PATH.write_text(
        render_build_identity(args.commit, args.build_id),
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()

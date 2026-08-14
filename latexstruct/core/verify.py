# -*- coding: utf-8 -*-
"""机器校验：环境配平 / 花括号配平（内容不变校验在 patch.py）。"""

from __future__ import annotations

from typing import Dict, List

from .parser import find_env_ranges, mask_comments, mask_inline_verb, mask_protected


def _masked(text: str) -> str:
    t1 = mask_comments(text)
    ranges, _, _ = find_env_ranges(t1)
    return mask_inline_verb(mask_protected(t1, ranges))


def check_env_balance(text: str) -> Dict:
    _, ub, ue = find_env_ranges(mask_comments(text))
    return {"ok": not ub and not ue, "unbalanced_begins": ub, "unbalanced_ends": ue}


def check_braces(text: str) -> Dict:
    """花括号配平（跳过转义花括号）；结果仅作参考（advisory）。"""
    masked = _masked(text)
    depth = 0
    prev = ""
    for ch in masked:
        if ch == "{" and prev != "\\":
            depth += 1
        elif ch == "}" and prev != "\\":
            depth -= 1
            if depth < 0:
                return {"ok": False, "depth": depth, "note": "多余右花括号"}
        prev = ch
    return {"ok": depth == 0, "depth": depth}


KNOWN_ISSUE_PATTERNS = [
    # 原文既有问题，仅报告不修改
    (r"\\left\s*\(\s*\\begin\{matrix\}",
     "\\left( 内嵌 matrix 环境：TeX Live 2026 内核 bug，编译时内存溢出（原文既有，未修改）"),
]


def known_issues(text: str) -> List[Dict]:
    import re

    masked = _masked(text)
    out = []
    for pat, desc in KNOWN_ISSUE_PATTERNS:
        for m in re.finditer(pat, masked):
            line = masked.count("\n", 0, m.start()) + 1
            out.append({"line": line, "reason": desc})
    return out

# -*- coding: utf-8 -*-
"""机器校验：环境配平 / 花括号配平（内容不变校验在 patch.py）。"""

from __future__ import annotations

import re
from typing import Dict, List

from .parser import find_env_ranges, mask_comments, mask_inline_verb, mask_protected


DISPLAY_SAFETY_TOKEN_RE = re.compile(
    r"(?<!\\)\\(?P<delimiter>[\[\]])|(?<!\\)\\(?P<tag>tag)(?![A-Za-z@])"
)


def _masked(text: str) -> str:
    t1 = mask_comments(text)
    ranges, _, _ = find_env_ranges(t1)
    return mask_inline_verb(mask_protected(t1, ranges))


def check_env_balance(text: str) -> Dict:
    _, ub, ue = find_env_ranges(mask_comments(text))
    return {"ok": not ub and not ue, "unbalanced_begins": ub, "unbalanced_ends": ue}


def compare_env_balance(before: str, after: str) -> Dict:
    """基线对比：整理不得**新增**环境不平衡（原文自身的不平衡保持原样）。

    适用于整书切片等"原文就截断"的输入：前后不平衡集合一致即通过。
    """
    b = check_env_balance(before)
    a = check_env_balance(after)
    no_new = (
        sorted(b["unbalanced_begins"]) == sorted(a["unbalanced_begins"])
        and sorted(b["unbalanced_ends"]) == sorted(a["unbalanced_ends"])
    )
    return {
        "ok": a["ok"] or no_new,
        "no_new": no_new,
        "before_unbalanced": b["unbalanced_begins"] + b["unbalanced_ends"],
        "after_unbalanced": a["unbalanced_begins"] + a["unbalanced_ends"],
    }


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


def compare_braces(before: str, after: str) -> Dict:
    """整理不得新增花括号不平衡；原文已有且保持不变时允许继续审阅。"""
    b = check_braces(before)
    a = check_braces(after)
    no_new = b == a
    return {
        "ok": bool(a["ok"] or no_new),
        "no_new": no_new,
        "before": b,
        "after": a,
        "depth": a.get("depth", 0),
    }


def check_display_tag_safety(text: str) -> Dict:
    r"""检查活动 ``\[``/``\]`` 配对及其中的非法 ``\tag``。

    名称为兼容既有 verification 字段保留；检查范围只覆盖 bracket display，
    equation/align 等 AMS 数学环境中的合法 ``\tag`` 不受影响。
    """
    masked = _masked(text)
    issues = []
    open_offset = None
    for token in DISPLAY_SAFETY_TOKEN_RE.finditer(masked):
        delimiter = token.group("delimiter")
        if delimiter == "[":
            if open_offset is not None:
                issues.append({
                    "line": masked.count("\n", 0, token.start()) + 1,
                    "reason": "展示公式尚未闭合又出现新的 \\[，请检查公式分隔符",
                })
            else:
                open_offset = token.start()
        elif delimiter == "]":
            if open_offset is None:
                issues.append({
                    "line": masked.count("\n", 0, token.start()) + 1,
                    "reason": "发现没有对应 \\[ 的 \\]，请检查公式分隔符",
                })
            else:
                open_offset = None
        elif open_offset is not None:
            issues.append({
                "line": masked.count("\n", 0, token.start()) + 1,
                "reason": (
                    "\\tag 不能直接用于 \\[...\\] 显示公式；"
                    "请改用 equation/align 等 AMS 数学环境，或移除多余 tag"
                ),
            })
    if open_offset is not None:
        issues.append({
            "line": masked.count("\n", 0, open_offset) + 1,
            "reason": "展示公式的 \\[ 缺少对应 \\]，请补全或移除未闭合分隔符",
        })
    return {
        "ok": not issues,
        "count": len(issues),
        "issues": issues[:20],
    }


KNOWN_ISSUE_PATTERNS = [
    # 原文既有问题，仅报告不修改
    (r"\\left\s*\(\s*\\begin\{matrix\}",
     "\\left( 内嵌 matrix 环境：TeX Live 2026 内核 bug，编译时内存溢出（原文既有，未修改）"),
]


def known_issues(text: str) -> List[Dict]:
    masked = _masked(text)
    out = []
    for pat, desc in KNOWN_ISSUE_PATTERNS:
        for m in re.finditer(pat, masked):
            line = masked.count("\n", 0, m.start()) + 1
            out.append({"line": line, "reason": desc})
    return out

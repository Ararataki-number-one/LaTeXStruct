# -*- coding: utf-8 -*-
"""多层内容不变量校验（评审 P2 · Level 3/4）。

结构化编辑绝不触碰以下对象，因此它们构成"内容不变"的强验证：
- 数学公式 token 多重集（行内 \\(...\\) / $...$、显示 \\[...\\] / $$...$$、数学环境）；
- \\label / \\ref 系列 / \\cite 系列 / \\includegraphics 路径 集合。

整理前后这些集合必须完全一致；任何不一致都说明内容被改动。
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List

from .parser import find_env_ranges
from .verify import _masked

MATH_ENVS = {
    "equation", "equation*", "align", "align*", "gather", "gather*",
    "multline", "multline*", "eqnarray", "eqnarray*", "alignat", "alignat*",
    "flalign", "flalign*",
}

INLINE_PAREN_RE = re.compile(r"\\\((.*?)\\\)", re.S)
INLINE_DOLLAR_RE = re.compile(r"(?<!\\)\$([^$\n]+)\$")
DISPLAY_BRACKET_RE = re.compile(r"\\\[(.*?)\\\]", re.S)
DISPLAY_DOLLAR_RE = re.compile(r"\$\$(.*?)\$\$", re.S)
LABEL_RE = re.compile(r"\\label\{([^{}]*)\}")
REF_RE = re.compile(r"\\(?:ref|eqref|pageref|autoref|cref|Cref)\{([^{}]*)\}")
CITE_RE = re.compile(r"\\(?:cite|citep|citet|citealp|citealt|parencite|footcite)\{([^{}]*)\}")
IMG_RE = re.compile(r"\\includegraphics(?:\[[^\]]*\])?\{([^{}]*)\}")


def _norm(s: str) -> str:
    return " ".join(s.split())


def math_tokens(text: str) -> List[str]:
    """数学公式 token 多重集（排序后的可哈希列表）。"""
    masked = _masked(text)
    toks: List[str] = []
    for m in DISPLAY_DOLLAR_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    for m in DISPLAY_BRACKET_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    for m in INLINE_PAREN_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    for m in INLINE_DOLLAR_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    ranges, _, _ = find_env_ranges(masked)
    for name, bs, be, es, ee in ranges:
        if name in MATH_ENVS:
            toks.append(_norm(masked[be:es]))
    return sorted(toks)


def _collect(text: str, pattern) -> List[str]:
    return sorted({m.group(1) for m in pattern.finditer(_masked(text))})


def labels(text: str) -> List[str]:
    return _collect(text, LABEL_RE)


def refs(text: str) -> List[str]:
    return _collect(text, REF_RE)


def cites(text: str) -> List[str]:
    return _collect(text, CITE_RE)


def image_paths(text: str) -> List[str]:
    return _collect(text, IMG_RE)


def _diff(before: List[str], after: List[str]) -> Dict:
    b, a = Counter(before), Counter(after)
    missing = sorted((b - a).elements())
    extra = sorted((a - b).elements())
    return {
        "equal": missing == [] and extra == [],
        "before_count": len(before),
        "after_count": len(after),
        "missing": missing[:10],
        "extra": extra[:10],
    }


def check_invariants(before: str, after: str) -> Dict:
    """返回各不变量对比结果；ok=True 表示全部一致。"""
    out = {
        "math": _diff(math_tokens(before), math_tokens(after)),
        "labels": _diff(labels(before), labels(after)),
        "refs": _diff(refs(before), refs(after)),
        "cites": _diff(cites(before), cites(after)),
        "images": _diff(image_paths(before), image_paths(after)),
    }
    out["ok"] = all(v["equal"] for v in out.values())
    return out

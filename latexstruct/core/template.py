# -*- coding: utf-8 -*-
"""模板转换（elegantbook）：用户授权的显式变换，先于结构化流水线执行。

- ``\\documentclass{article}`` → ``\\documentclass{elegantbook}``
- 删除与 elegantbook 重复的 geometry/ctex 行（elegantbook 自带）
- 删除原书手工目录（``\\section*{Contents}`` 至第一个真实章标题之前），插入 ``\\tableofcontents``
- 章标题 ``\\section*{N Title}`` → ``\\chapter*{N Title}`` + ``\\refstepcounter{chapter}``
  （保证 elegantbook 定理计数器按章推进；目录条目因以页号结尾而天然排除）
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .parser import parse_latex
from .patch import PendingOp
from .scanner import BOX_ENVS

DOC_CLASS_LINE_RE = re.compile(r"^\s*\\documentclass(?:\[[^\]]*\])?\s*\{[^{}]*\}\s*$")
GEOMETRY_LINE_RE = re.compile(r"^\s*\\usepackage(?:\[[^\]]*\])?\{geometry\}\s*$")
CTEX_LINE_RE = re.compile(r"^\s*\\usepackage(?:\[[^\]]*\])?\{ctex\}\s*$")
# elegantbook 自带 tcolorbox[many]/geometry/ctex/\circled；书稿再次定义会冲突
TCOLORBOX_LINE_RE = re.compile(r"^\s*\\usepackage(?:\[[^\]]*\])?\{tcolorbox\}\s*$")
CIRCLED_LINE_RE = re.compile(r"^\s*\\newcommand\*?\\circled\b.*$")
CHAPTER_RE = re.compile(r"^\d+\s+\S")
TOC_ENTRY_SUFFIX_RE = re.compile(r"\s+\d+\s*$")
CONTENTS_TITLE_RE = re.compile(r"^contents$", re.I)


def _non_box_sections(doc):
    out = []
    box_ivs = [(r[1], r[3]) for r in doc.env_ranges if r[0] in BOX_ENVS]
    for s in doc.sections:
        off = s.span.start_off
        if any(bs <= off <= es for bs, es in box_ivs):
            continue
        out.append(s)
    return out


def build_template_ops(text: str) -> Tuple[List[PendingOp], List[dict]]:
    """返回 (编辑计划, 说明)。"""
    ops: List[PendingOp] = []
    notes: List[dict] = []
    doc = parse_latex(text)
    lines = text.split("\n")

    # 1) documentclass
    dc_idx = next((i for i, line in enumerate(lines) if DOC_CLASS_LINE_RE.match(line)), None)
    if dc_idx is None:
        return [], [{"line": 1, "reason": "未找到 \\documentclass 行，跳过模板转换"}]
    ops.append(PendingOp("replace_line", dc_idx + 1, old=lines[dc_idx], new="\\documentclass{elegantbook}"))

    # 2) 删除与 elegantbook 重复（可能选项冲突）的包与宏
    for i, line in enumerate(lines):
        if GEOMETRY_LINE_RE.match(line) or CTEX_LINE_RE.match(line) or TCOLORBOX_LINE_RE.match(line) or CIRCLED_LINE_RE.match(line):
            ops.append(PendingOp("delete_line", i + 1, old=line))

    sections = _non_box_sections(doc)
    contents = next((s for s in sections if CONTENTS_TITLE_RE.match(s.title)), None)
    chapter = next(
        (s for s in sections
         if CHAPTER_RE.match(s.title) and not TOC_ENTRY_SUFFIX_RE.search(s.title)
         and (contents is None or s.span.start_line > contents.span.end_line)),
        None,
    )

    # 3) 旧目录删除 + \tableofcontents
    if contents is not None and chapter is not None:
        L = contents.span.start_line
        ops.append(PendingOp("replace_line", L, old=lines[L - 1], new="\\tableofcontents"))
        for i in range(L + 1, chapter.span.start_line):
            ops.append(PendingOp("delete_line", i, old=lines[i - 1]))
        notes.append(
            {"line": L, "reason": f"已删除原手工目录（第 {L}–{chapter.span.start_line - 1} 行）并插入 \\tableofcontents"}
        )
    elif chapter is not None:
        L = chapter.span.start_line
        ops.append(PendingOp("insert_line", L - 1, new="\\tableofcontents"))
        ops.append(PendingOp("insert_line", L - 1, new=""))
        notes.append({"line": L, "reason": "未发现原手工目录，已在第一章前插入 \\tableofcontents"})
    else:
        notes.append({"line": 1, "reason": "未找到章标题边界，跳过目录处理（保留原目录）"})

    # 4) 章标题 \section*{N Title} → \chapter*{N Title} + 推进章计数器
    n_chapter = 0
    for s in sections:
        if not CHAPTER_RE.match(s.title) or TOC_ENTRY_SUFFIX_RE.search(s.title):
            continue
        if contents is not None and chapter is not None and s.span.start_line < chapter.span.start_line:
            continue  # 目录区内的条目（"1 Graphs 1" 类）已在删除范围
        L = s.span.start_line
        old = lines[L - 1]
        ops.append(PendingOp("replace_line", L, old=old, new=old.replace("\\section", "\\chapter", 1)))
        ops.append(PendingOp("insert_line", L, new="\\refstepcounter{chapter}"))
        n_chapter += 1
    if n_chapter:
        notes.append({"line": 1, "reason": f"章标题 {n_chapter} 处已转换为 \\chapter* 并推进章计数器"})
    return ops, notes

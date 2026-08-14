# -*- coding: utf-8 -*-
"""LaTeX 轻量结构解析器（M1 MVP，纯标准库）。

职责：把 .tex 源文本切成结构块（导言区 / 环境 / 段落 / 显示公式 / 保护区），
并记录每块的行号与字符偏移。不做排版语义，不要求文档可编译。

设计要点
--------
- 换行统一为 ``\\n`` 处理；原始换行风格记录在 ``Document.newline``，导出时还原；
- 等长屏蔽：注释、verbatim 类环境、``\\verb`` 的内容被替换为等长空格，
  因此屏蔽后文本的行号/偏移与原文完全一致；
- 一切正则匹配都在屏蔽文本上进行，注释与代码区不会误命中。

已知限制（MVP）
--------------
- 节标题/可选参数解析已升级为平衡括号扫描（`core/texparse.py`），支持嵌套花括号与
  数学区内的花括号（`\\section{A \\textit{b} for $K_{r,s}$}` 完整保留）；
- 环境名不支持花括号内的复杂嵌套；
- ``$$`` 显示公式不嵌套；``\\[``/``$$`` 内部出现闭合符会提前截断。
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from itertools import count
from typing import List, Optional, Tuple

PROTECTED_ENVS = {"verbatim", "verbatim*", "lstlisting", "minted", "comment"}
SECTION_LEVEL = {"chapter": 0, "section": 1, "subsection": 2, "subsubsection": 3}

ENV_RE = re.compile(r"\\(begin|end)\s*\{([^{}]*)\}")
INLINE_VERB_RE = re.compile(r"\\verb\*?([^a-zA-Z\s\\])")


@dataclass
class Span:
    """行号（1 基，含两端）与字符偏移（0 基，半开区间）。"""

    start_line: int
    end_line: int
    start_off: int
    end_off: int


@dataclass
class SectionNode:
    cmd: str
    title: str
    starred: bool
    level: int
    span: Span
    parent: Optional["SectionNode"] = None


@dataclass
class Block:
    id: int
    kind: str  # preamble | env | displaymath | para | verbatim
    name: str = ""  # 环境名（kind 为 env/verbatim 时）
    span: Span = None
    text: str = ""
    parent_id: Optional[int] = None
    in_env: Tuple[str, ...] = ()  # 祖先环境名（不含 document），由外向内
    section_path: Tuple[str, ...] = ()  # 所在章节标题链


@dataclass
class Document:
    text: str  # 规范化文本（换行统一为 \n）
    masked: str  # 等长屏蔽后文本
    newline: str  # 原始换行风格
    blocks: List[Block]
    env_ranges: List[Tuple]
    sections: List[SectionNode]
    display_spans: List[Tuple[int, int]]
    preamble_span: Optional[Span]
    unbalanced_begins: List[str]
    unbalanced_ends: List[str]
    line_starts: List[int] = field(default_factory=list)  # 缓存行首偏移

    # ---- 便捷查询 ----

    def block_at_line(self, line: int) -> Optional[Block]:
        for b in self.blocks:
            if b.span.start_line <= line <= b.span.end_line and b.kind in (
                "para",
                "env",
                "displaymath",
                "verbatim",
            ):
                return b
        return None

    def blocks_of_kind(self, kind: str) -> List[Block]:
        return [b for b in self.blocks if b.kind == kind]

    def ancestors_of(self, block: Block) -> Tuple[str, ...]:
        return block.in_env

    def is_in_protected(self, block: Block) -> bool:
        return bool(set(block.in_env) & PROTECTED_ENVS)


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def detect_newline(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\r" in text:
        return "\r"
    return "\n"


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def line_starts(text: str) -> List[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def offset_to_line(starts: List[int], off: int) -> int:
    """偏移 -> 1 基行号。"""
    return bisect_right(starts, off)


def line_span(starts: List[int], off_start: int, off_end: int) -> Tuple[int, int]:
    l1 = offset_to_line(starts, off_start)
    l2 = offset_to_line(starts, max(off_start, off_end - 1))
    return l1, l2


# ---------------------------------------------------------------------------
# 等长屏蔽
# ---------------------------------------------------------------------------


def mask_comments(text: str) -> str:
    """把未转义的 ``%`` 到行尾替换为空格（保留换行）。"""
    chars = list(text)
    n = len(text)
    i = 0
    while i < n:
        if chars[i] == "%":
            j = i - 1
            cnt = 0
            while j >= 0 and chars[j] == "\\":
                cnt += 1
                j -= 1
            if cnt % 2 == 0:  # 未被转义
                while i < n and chars[i] != "\n":
                    chars[i] = " "
                    i += 1
                continue
        i += 1
    return "".join(chars)


def find_env_ranges(text: str):
    """顺序扫描配对所有 ``\\begin/\\end``。

    返回 (ranges, unbalanced_begins, unbalanced_ends)，
    ranges 为 (name, begin_start, begin_end, end_start, end_end) 列表，按位置排序。
    """
    ranges = []
    stack = []  # (name, begin_start, begin_end)
    unbalanced_ends = []
    for m in ENV_RE.finditer(text):
        kind, name = m.group(1), m.group(2)
        if kind == "begin":
            stack.append((name, m.start(), m.end()))
        else:
            found = False
            for idx in range(len(stack) - 1, -1, -1):
                if stack[idx][0] == name:
                    _, bs, be = stack.pop(idx)
                    ranges.append((name, bs, be, m.start(), m.end()))
                    found = True
                    break
            if not found:
                unbalanced_ends.append(name)
    unbalanced_begins = [nm for nm, _, _ in stack]
    ranges.sort(key=lambda r: (r[1], r[3]))
    return ranges, unbalanced_begins, unbalanced_ends


def mask_protected(text: str, ranges: List[Tuple]) -> str:
    """把 verbatim 类环境内部替换为空格（保留换行与 begin/end 行）。"""
    out = list(text)
    for name, bs, be, es, ee in ranges:
        if name in PROTECTED_ENVS:
            for k in range(be, es):
                if out[k] != "\n":
                    out[k] = " "
    return "".join(out)


def mask_inline_verb(text: str) -> str:
    """把 ``\\verb|...|`` 的内容替换为空格。"""
    out = list(text)
    i = 0
    while True:
        m = INLINE_VERB_RE.search(text, i)
        if not m:
            break
        delim = m.group(1)
        start = m.end()  # 内容起始（定界符之后）
        j = text.find(delim, start)
        if j == -1:
            break
        for k in range(start, j):
            if out[k] != "\n":
                out[k] = " "
        i = j + 1
    return "".join(out)


def find_display_spans(masked: str) -> List[Tuple[int, int]]:
    """找 ``\\[ ... \\]`` 与 ``$$ ... $$`` 显示公式区间（半开偏移）。"""
    spans = []
    i, n = 0, len(masked)
    while i < n:
        if masked.startswith("\\[", i):
            j = masked.find("\\]", i + 2)
            if j < 0:
                break
            spans.append((i, j + 2))
            i = j + 2
        elif masked.startswith("$$", i):
            j = masked.find("$$", i + 2)
            if j < 0:
                break
            spans.append((i, j + 2))
            i = j + 2
        else:
            i += 1
    return spans


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------


def _build_sections(masked: str, starts: List[int]) -> List[SectionNode]:
    from .texparse import find_commands

    nodes = []
    stack = []
    for pc in find_commands(masked, tuple(SECTION_LEVEL.keys())):
        cmd = pc.name
        level = SECTION_LEVEL[cmd]
        l1, l2 = line_span(starts, pc.start, pc.end)
        node = SectionNode(
            cmd=cmd,
            title=pc.required[0].strip(),
            starred=pc.star,
            level=level,
            span=Span(l1, l2, pc.start, pc.end),
        )
        while stack and stack[-1].level >= level:
            stack.pop()
        node.parent = stack[-1] if stack else None
        stack.append(node)
        nodes.append(node)
    return nodes


def _sweep_blocks(
    text: str,
    masked: str,
    starts: List[int],
    env_ranges: List[Tuple],
    display_spans: List[Tuple[int, int]],
    preamble_span: Optional[Span],
) -> List[Block]:
    """逐行扫描，产出块列表（环境块、段落块、显示公式块、verbatim 块）。"""
    lines = text.split("\n")
    total = len(lines)
    ids = count(1)
    blocks: List[Block] = []

    # 环境事件按行号索引
    env_events = {}
    for idx, (name, bs, be, es, ee) in enumerate(env_ranges):
        bl = offset_to_line(starts, bs)
        el = offset_to_line(starts, es)
        env_events.setdefault(bl, []).append(("begin", idx))
        env_events.setdefault(el, []).append(("end", idx))

    # 显示公式区间转行号
    disp = [line_span(starts, s, e) for s, e in display_spans]
    disp_ptr = 0

    active_envs = []  # (name, idx)
    para_buf = []
    para_start = 0
    skip_until = 0
    last_disp_end = 0  # 最近一次进入的显示公式区间的结束行

    def mk_block(kind, name, l1, l2, parent_id=None) -> Block:
        return Block(
            id=next(ids),
            kind=kind,
            name=name,
            span=Span(l1, l2, starts[l1 - 1], starts[l2 - 1] + len(lines[l2 - 1])),
            text="\n".join(lines[l1 - 1 : l2]),
            parent_id=parent_id,
            in_env=tuple(n for n, _ in active_envs if n != "document"),
            section_path=(),
        )

    def flush_para(end_line: int):
        nonlocal para_buf, para_start
        if para_buf:
            blocks.append(mk_block("para", "", para_start, end_line))
        para_buf, para_start = [], 0

    if preamble_span is not None:
        blocks.append(
            Block(
                id=next(ids),
                kind="preamble",
                span=preamble_span,
                text="\n".join(lines[preamble_span.start_line - 1 : preamble_span.end_line]),
            )
        )

    for L in range(1, total + 1):
        if skip_until and L < skip_until:
            continue
        if preamble_span and preamble_span.start_line <= L <= preamble_span.end_line:
            continue

        had_env_event = False

        # 环境开始事件
        for kind, idx in env_events.get(L, []):
            if kind != "begin":
                continue
            had_env_event = True
            flush_para(L - 1)
            name, bs, be, es, ee = env_ranges[idx]
            bl, el = offset_to_line(starts, bs), offset_to_line(starts, es)
            active_envs.append((name, idx))
            if name in PROTECTED_ENVS:
                blocks.append(mk_block("verbatim", name, bl, el))
                skip_until = el
            else:
                # 普通环境：等结束事件时生成 env 块
                pass

        # 环境结束事件
        for kind, idx in env_events.get(L, []):
            if kind != "end":
                continue
            had_env_event = True
            flush_para(L - 1)
            name, bs, be, es, ee = env_ranges[idx]
            bl, el = offset_to_line(starts, bs), offset_to_line(starts, es)
            blocks.append(mk_block("env", name, bl, el))
            # 弹出到匹配项
            for k in range(len(active_envs) - 1, -1, -1):
                if active_envs[k][1] == idx:
                    active_envs.pop(k)
                    break

        # 显示公式
        if disp_ptr < len(disp) and L == disp[disp_ptr][0]:
            ds, de = disp[disp_ptr]
            flush_para(L - 1)
            blocks.append(mk_block("displaymath", "", ds, de))
            disp_ptr += 1
            last_disp_end = de
        if L <= last_disp_end:
            continue

        # 普通文本行
        if had_env_event:
            continue
        if not mlines_strip(masked, L, starts):
            flush_para(L - 1)
            continue
        if not para_buf:
            para_start = L
        para_buf.append(lines[L - 1])

    flush_para(total)
    blocks.sort(key=lambda b: b.span.start_off)
    return blocks


def mlines_strip(masked: str, L: int, starts: List[int]) -> bool:
    """第 L 行在屏蔽文本中是否含非空白字符。"""
    lo = starts[L - 1]
    if L - 1 < len(starts) - 1:
        hi = starts[L] - 1
    else:
        hi = len(masked)
    return any(not ch.isspace() for ch in masked[lo:hi])


def _assign_section_paths(blocks: List[Block], sections: List[SectionNode]):
    for b in blocks:
        line = b.span.start_line
        stack = []
        for s in sections:
            if s.span.start_line > line:
                break
            while stack and stack[-1].level >= s.level:
                stack.pop()
            stack.append(s)
        b.section_path = tuple(x.title for x in stack)


def parse_latex(text: str) -> Document:
    newline = detect_newline(text)
    text = normalize_newlines(text)
    t1 = mask_comments(text)
    env_ranges, ub, ue = find_env_ranges(t1)
    masked = mask_protected(t1, env_ranges)
    masked = mask_inline_verb(masked)
    display_spans = find_display_spans(masked)
    starts = line_starts(text)
    sections = _build_sections(masked, starts)

    doc_range = next((r for r in env_ranges if r[0] == "document"), None)
    preamble_span = None
    if doc_range is not None:
        dc = re.search(r"\\documentclass", masked)
        p_end_line = offset_to_line(starts, doc_range[1])
        p_start_line = offset_to_line(starts, dc.start()) if dc else 1
        end = p_end_line - 1
        while end >= p_start_line and not mlines_strip(masked, end, starts):
            end -= 1  # 裁掉 document 前的空白行
        if p_start_line <= end:
            lines = text.split("\n")
            preamble_span = Span(
                p_start_line,
                end,
                starts[p_start_line - 1],
                starts[end - 1] + len(lines[end - 1]),
            )

    blocks = _sweep_blocks(text, masked, starts, env_ranges, display_spans, preamble_span)
    _assign_section_paths(blocks, sections)

    return Document(
        text=text,
        masked=masked,
        newline=newline,
        blocks=blocks,
        env_ranges=env_ranges,
        sections=sections,
        display_spans=display_spans,
        preamble_span=preamble_span,
        unbalanced_begins=ub,
        unbalanced_ends=ue,
        line_starts=starts,
    )

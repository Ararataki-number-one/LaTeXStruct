# -*- coding: utf-8 -*-
"""目标式平衡括号解析（评审 P1：轻量 tokenizer + 平衡括号，非完整 TeX 引擎）。

解决 regex 方案的两类真实场景限制：
- ``\\section{A \\textit{very important} theorem}``（嵌套花括号截断）；
- ``\\begin{theorem}[Ramsey's theorem for $K_{r,s}$]``（可选参数含嵌套括号/数学）。

实现策略：
1. 命令定位用便宜正则（仅匹配 ``\\chapter|\\section|...`` 单词边界）；
2. 参数解析用**数学感知的括号平衡扫描器**——``$...$``/``$$...$$``/``\\(...\\)``/
   ``\\[...\\]`` 区域整体跳过，其内部花括号不计入深度；
3. 输入必须是"等长屏蔽后"文本（注释/verbatim 已空格化），保证偏移可回映射。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

CMD_FIND_RE = re.compile(r"\\(chapter|section|subsection|subsubsection)\b")


@dataclass
class ParsedCommand:
    name: str
    star: bool
    optional: Optional[str]  # [..] 参数原文（含括号本身）
    required: List[str]  # {..} 参数原文列表（不含花括号）
    start: int  # 反斜杠位置
    end: int  # 最后一个右花括号之后的位置


def _scan_balanced(text: str, open_pos: int, open_ch: str, close_ch: str) -> Optional[int]:
    """从 open_pos（指向开括号）扫描到匹配闭括号之后；数学区整体跳过。"""
    i = open_pos + 1
    depth = 1
    n = len(text)
    while i < n:
        if text.startswith("$$", i):
            j = text.find("$$", i + 2)
            i = j + 2 if j >= 0 else n
            continue
        if text[i] == "$":
            j = text.find("$", i + 1)
            i = j + 1 if j >= 0 else n
            continue
        if text.startswith("\\(", i):
            j = text.find("\\)", i + 2)
            i = j + 2 if j >= 0 else n
            continue
        if text.startswith("\\[", i):
            j = text.find("\\]", i + 2)
            i = j + 2 if j >= 0 else n
            continue
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def parse_command_args(text: str, name_start: int, name: str) -> Optional[ParsedCommand]:
    """从命令名结束位置开始解析 *、可选参数、必需参数；不平衡返回 None。"""
    i = name_start
    n = len(text)
    star = False
    while i < n and text[i].isspace():
        i += 1
    if i < n and text[i] == "*":
        star = True
        i += 1

    optional = None
    while i < n and text[i].isspace():
        i += 1
    if i < n and text[i] == "[":
        j = _scan_balanced(text, i, "[", "]")
        if j is None:
            return None
        optional = text[i:j]
        i = j

    required: List[str] = []
    while True:
        while i < n and text[i].isspace():
            i += 1
        if i < n and text[i] == "{":
            j = _scan_balanced(text, i, "{", "}")
            if j is None:
                return None
            required.append(text[i + 1 : j - 1])
            i = j
        else:
            break
    if not required:
        return None
    return ParsedCommand(name=name, star=star, optional=optional, required=required,
                         start=name_start - (len(name) + 1), end=i)


def find_commands(text: str, names) -> List[ParsedCommand]:
    """返回文本中所有指定节命令（按位置排序），解析失败的跳过。"""
    out: List[ParsedCommand] = []
    for m in CMD_FIND_RE.finditer(text):
        name = m.group(1)
        if name in names:
            pc = parse_command_args(text, m.end(), name)
            if pc is not None:
                out.append(pc)
    return out


def interior_section_command(interior: str) -> Optional[Tuple[str, bool, Optional[str]]]:
    """盒子内部仅含一个节标题命令（可带前导 \\relax）时，返回 (标题, starred, optional)。
    用于双语翻译框识别（替代单层花括号正则，支持嵌套标题）。"""
    text = interior.strip()
    if text.startswith("\\relax"):
        text = text[len("\\relax") :].lstrip()
    cmds = find_commands(text, ("chapter", "section", "subsection", "subsubsection"))
    if len(cmds) == 1:
        pc = cmds[0]
        if pc.start == 0 and pc.end >= len(text.rstrip()):
            return pc.required[0], pc.star, pc.optional
    return None

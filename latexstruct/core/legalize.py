# -*- coding: utf-8 -*-
"""AI 决策 span 合法化（实测驱动，v0.3.2）。

真实书稿 AI 实测发现：决策模型给出的 body_span 经常把图注/翻译框/后续叙述段错包进
定理范围（复查要花大量 token 纠正）。本模块在补丁应用前对 **source=="ai"** 的 wrap
决策做确定性收缩（复查 source=="review" 的修正结果不再动，规则模式决策不经过 AI 也不动）：

- 起点固定为候选标题段起点（不早于标题）；
- 终点收缩到"下一停点"之前（下一定理类标题/节标题/另一证明起始）；
- 段落原子性：终点吸附到所在块的块尾；
- 定理类（非 proof）：默认收缩到标题所在段（实测 10/10 的 wrong-range 都是多包，
  叙述段/图注不属于定理陈述；多段定理陈述由复查显式扩展，复查结果不受本模块影响）。
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from .parser import Block, Document
from .scanner import (
    BOX_ENVS,
    PROOF_RE,
    SECTION_START_RE,
    _first_nonempty_line,
    _match_title,
)


def _block_containing(doc: Document, line: int) -> Optional[Block]:
    for b in doc.blocks:
        if b.kind == "env" and b.name == "document":
            continue  # document 环境块横跨全文，不能作为吸附目标
        if b.kind in ("para", "env", "displaymath") and b.span.start_line <= line <= b.span.end_line:
            return b
    return None


def _next_stop_line(doc: Document, start_line: int) -> Optional[int]:
    """下一个"停点"段的行号：定理类标题 / 节标题 / 证明起始。"""
    for b in doc.blocks:
        if b.kind != "para" or b.span.start_line <= start_line:
            continue
        if set(b.in_env) & BOX_ENVS:
            continue
        first = _first_nonempty_line(b.text)
        if not first:
            continue
        if _match_title(first) or PROOF_RE.match(first) or SECTION_START_RE.match(first):
            return b.span.start_line
    return None


def legalize_wrap(doc: Document, d, cand) -> None:
    if d.action != "wrap" or not d.body_span:
        return
    bs, be = d.body_span
    start = cand.span.start_line
    if bs < start:
        bs = start
    if be < bs:
        be = cand.span.end_line

    # 停点收缩（定理类与 proof 都适用）
    stop = _next_stop_line(doc, start)
    if stop is not None and be >= stop:
        be = stop - 1
    if be < start:
        be = start

    if d.env != "proof":
        # 定理类：默认收缩到标题所在段（实测 AI 常把图注/叙述段/译文框多包进去）
        be = min(be, cand.span.end_line)
    else:
        # proof：终点吸附到所在块尾（段落原子性），且不落进盒内行开头
        blk = _block_containing(doc, be)
        if blk is not None:
            be = blk.span.end_line
        # 若终点落在盒环境块内部 → 收缩到盒前
        blk = _block_containing(doc, be)
        if blk is not None and blk.kind == "env" and blk.name in BOX_ENVS:
            be = blk.span.start_line - 1

    if be < cand.span.start_line:
        be = cand.span.start_line
    d.body_span = (bs, be)


def legalize_decisions(doc: Document, decisions, candidates_by_id: Dict) -> None:
    for d in decisions:
        if d.source != "ai":
            continue  # 规则决策与复查修正结果不受影响
        cand = candidates_by_id.get(d.candidate_id)
        if cand is None:
            continue
        legalize_wrap(doc, d, cand)

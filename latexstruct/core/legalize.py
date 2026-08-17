# -*- coding: utf-8 -*-
"""AI 决策 span 合法化。

真实书稿 AI 实测发现：决策模型给出的 body_span 经常把图注/翻译框/后续叙述段错包进
定理范围（复查要花大量 token 纠正）。本模块在补丁应用前对 **source=="ai"** 的 wrap
决策做确定性收缩；复查/缓存复用的 AI 决策也重新通过同一安全门，规则模式决策不动：

- 起点固定为候选标题段起点（不早于标题）；
- 终点收缩到"下一停点"之前（下一定理类标题/节标题/另一证明起始）；
- 段落原子性：终点吸附到所在块的块尾；
- 任何终点都吸附到完整段落/公式环境的末尾，绝不把 ``\\end{theorem}``
  或 ``\\end{proof}`` 插进尚未闭合的展示公式；
- proof 一旦出现明确的 ``\\square``/``\\qed``/“证毕”标记，就在该原子块结束，
  不吞入后续解释段落。

复查阶段只允许修改环境类型或撤销补丁，不再用结果文本行号改写源文本 span；
因此这里的所有坐标始终属于原始 ``Document``。
"""

from __future__ import annotations

import re
from typing import Dict, Optional

from .parser import Block, Document
from .scanner import (
    BOX_ENVS,
    MATH_ENVS,
    PROOF_RE,
    SECTION_START_RE,
    _first_nonempty_line,
    _match_title,
)


def _block_containing(doc: Document, line: int) -> Optional[Block]:
    matches = [
        b for b in doc.blocks
        if not (b.kind == "env" and b.name == "document")
        and b.kind in ("para", "env", "displaymath")
        and b.span.start_line <= line <= b.span.end_line
    ]
    if not matches:
        return None
    math_matches = [
        block for block in matches
        if block.kind == "displaymath"
        or (block.kind == "env" and block.name in MATH_ENVS | {"aligned", "alignedat", "gathered"})
    ]
    if math_matches:
        # 行落在嵌套数学结构时必须吸附到最外层数学块末尾。例如 equation 内
        # 还有 aligned/pmatrix，选择最短的 para 或内层 matrix 都仍可能把
        # theorem closer 放到 \end{equation}/\] 之前。
        return max(
            math_matches,
            key=lambda block: (
                block.span.end_line - block.span.start_line,
                -block.span.start_line,
            ),
        )
    # 嵌套环境中必须选最内层原子块；选到 document/外层 theorem 会把范围
    # 意外扩到很远；数学块已在上面单独按最外层处理。
    return min(
        matches,
        key=lambda block: (
            block.span.end_line - block.span.start_line,
            -block.span.start_line,
        ),
    )


_PROOF_END_RE = re.compile(
    r"(?:\\qedhere\b|\\qed\b|\\square\b|(?<![\w])□|证毕|"
    r"this\s+(?:completes|finishes)\s+the\s+proof)",
    re.I,
)


def _atomic_end(doc: Document, line: int) -> int:
    """把源行号吸附到完整的段落或嵌套环境末尾。"""
    end = max(1, line)
    while True:
        block = _block_containing(doc, end)
        expanded = block.span.end_line if block is not None else end
        if expanded <= end:
            return end
        end = expanded


def _proof_end_line(doc: Document, start: int, upper: int) -> Optional[int]:
    """返回安全证明区间内第一个明确结束标记所在原子块末行。"""
    lines = doc.masked.split("\n")
    upper = min(max(start, upper), len(lines))
    for line_no in range(start, upper + 1):
        active = lines[line_no - 1]
        if _PROOF_END_RE.search(active):
            return _atomic_end(doc, line_no)
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


_DOCUMENT_END_RE = re.compile(r"^\s*\\end\s*\{\s*document\s*\}\s*$", re.I)


def _proof_safe_end_line(doc: Document, start: int, requested_end: int) -> Optional[int]:
    """确定 proof 的完整、可证明终点；不能确定时返回 ``None``。

    模型给出的终点只是一项语义建议，不能证明 proof 已经完整。这里改用原文中
    的硬边界：优先取首个 ``\\qed``/``\\square``/“证毕”原子块；没有显式
    标记时，只能取下一可靠结构标题或 ``\\end{document}`` 之前的最后一块。
    对没有任何可靠右边界的截断片段，宁可不包裹，也不能生成半个 proof。
    """
    lines = doc.masked.split("\n")
    structural_stop = _next_stop_line(doc, start)
    document_stop = None
    for line_no in range(start + 1, len(lines) + 1):
        if _DOCUMENT_END_RE.match(lines[line_no - 1]):
            document_stop = line_no
            break
    stops = [item for item in (structural_stop, document_stop) if item is not None]
    stop = min(stops) if stops else None
    upper = (stop - 1) if stop is not None else len(lines)

    explicit = _proof_end_line(doc, start, upper)
    if explicit is not None and (stop is None or explicit < stop):
        return explicit
    if structural_stop is None and document_stop is None:
        return None

    end = stop - 1
    while end >= start and not lines[end - 1].strip():
        end -= 1
    if end < start:
        return None
    end = _atomic_end(doc, end)
    if end >= stop:
        return None

    if structural_stop is not None and structural_stop == stop:
        # 下一定理/证明/章节是可靠的语义边界，模型选短也必须扩到边界前。
        return end

    # 仅有文档终点时，尾部可能是 proof 之后的普通叙述。只有模型本身已经
    # 覆盖到最后一个原子块，才能把 \end{document} 当作 proof 右边界；否则
    # 无法区分“模型截断证明”和“后面是证明外正文”，一律不改。
    requested_atomic = _atomic_end(doc, max(start, requested_end))
    return end if requested_atomic == end else None


def legalize_wrap(doc: Document, d, cand) -> None:
    if hasattr(d, "_legalize_error"):
        delattr(d, "_legalize_error")
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

    # 定理类只允许越过候选标题段去接住 AI 明确命中的数学块。普通段落、
    # 翻译框或图注都不能仅因“位于下一标题之前”被吞进定理；这是比语义猜测
    # 更保守的边界。proof 仍可由模型选择多段范围，但终点必须保持原子性。
    if cand.kind == "theorem-like" and be > cand.span.end_line:
        requested_block = _block_containing(doc, be)
        requested_is_math = requested_block is not None and (
            requested_block.kind == "displaymath"
            or (
                requested_block.kind == "env"
                and requested_block.name
                in MATH_ENVS | {"aligned", "alignedat", "gathered"}
            )
        )
        if not requested_is_math:
            be = cand.span.end_line

    if d.env == "proof":
        safe_end = _proof_safe_end_line(doc, start, be)
        if safe_end is None:
            setattr(
                d,
                "_legalize_error",
                "无法用结束标记、下一结构标题或已覆盖的文档终点证明范围完整，"
                "已保守跳过，避免生成被截断的 proof",
            )
            return
        # proof 的完整性不能由模型选出的较短终点证明。确定性扩展到首个 QED
        # 或下一可靠结构边界，防止“实时预览正常、最终结果却截断证明”。
        be = safe_end
    else:
        # 尊重 AI 在源文本坐标系中选择的合法范围，但终点必须落在完整原子块之后。
        # 当 theorem 终点确实位于 equation/\\[...\\] 内时，吸附到外层数学块末尾，
        # 绝不把 closer 插入尚未闭合的公式。
        be = _atomic_end(doc, be)

    # 若终点落在翻译/题注盒内，宁可收缩到盒前，绝不吞入整个盒子。
    blk = _block_containing(doc, be)
    if blk is not None and blk.kind == "env" and blk.name in BOX_ENVS:
        be = blk.span.start_line - 1

    if stop is not None and be >= stop:
        be = stop - 1

    if be < cand.span.start_line:
        be = cand.span.start_line
    d.body_span = (bs, be)


def legalize_decisions(doc: Document, decisions, candidates_by_id: Dict) -> None:
    for d in decisions:
        if d.source not in {"ai", "review"}:
            continue  # 规则决策使用自身的确定性范围扩展；AI/复查/复用统一复验
        cand = candidates_by_id.get(d.candidate_id)
        if cand is None:
            continue
        legalize_wrap(doc, d, cand)

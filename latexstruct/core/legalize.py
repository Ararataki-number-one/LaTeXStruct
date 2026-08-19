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

from bisect import bisect_right
import re
from typing import Collection, Dict, Optional

from .parser import Block, Document
from .scanner import (
    BOX_ENVS,
    MATH_ENVS,
    PROOF_RE,
    SECTION_START_RE,
    THEOREM_LIKE_ENVS,
    _declared_theorem_envs,
    _first_nonempty_line,
    _match_title,
    _semantic_view,
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


_QED_COMMAND_RE = re.compile(r"\\qed(?:here)?\b", re.I)
_QED_SQUARE_RE = re.compile(
    r"(?:\\hfill\s*|^\s*|[.!?。；;：:]\s+)"
    r"(?:\$\$?|\\\(|\\\[)?\s*(?:\\square|\\Box|\\blacksquare|□|∎|■)"
    r"\s*(?:\$\$?|\\\)|\\\])?"
    r"\s*[.!?。；;：:]?\s*(?:%[^\n]*)?$",
    re.I,
)
# A terminal source QED must remain visible after structural wrapping.  This
# token regex is deliberately narrower than ``has_proof_end_marker``: prose
# such as "This completes the proof" is a reliable *boundary*, but still
# needs amsthm to typeset its normal QED symbol.
_EXPLICIT_QED_TOKEN_RE = re.compile(
    r"\\qed(?:here)?\b|\\(?:square|Box|blacksquare)(?![A-Za-z@])|[□∎■]",
    re.I,
)
_QED_STRUCTURAL_TRAILER_RE = re.compile(
    r"(?:"
    r"\s+"
    r"|[.!?。；;：:]"
    r"|\\(?:\)|\])"
    r"|\$\$?"
    r"|}"
    r"|\\\\(?:\[[^\]\n]*\])?"
    r"|\\end\s*\{[^{}\n]+\}"
    r")*\Z",
)
_PROOF_COMPLETION_RE = re.compile(
    r"(?:^|[.!?。；;：:]\s+|,\s+and\s+)"
    r"(?:"
    r"(?:this|that)\s+(?:completes|finishes)\s+the\s+proof(?!\s+of\b)"
    r"|(?:the|this|that|our)\s+proof\s+is\s+"
    r"(?:complete|completed|done|finished)"
    r")\s*[.!?。]?\s*(?:%[^\n]*)?$",
    re.I,
)
_CN_PROOF_END_RE = re.compile(r"(?:证毕|证明完毕)\s*[。.!]?\s*(?:%[^\n]*)?$")


def has_proof_end_marker(text: str) -> bool:
    """Return whether *text* contains an unambiguous terminal proof marker.

    Canonical natural-language endings are accepted only as a complete terminal
    sentence/clause.  Embedded, conditional, and local-claim phrases are not.
    """
    active = text or ""
    return bool(
        _QED_COMMAND_RE.search(active)
        or _QED_SQUARE_RE.search(active)
        or _PROOF_COMPLETION_RE.search(active)
        or _CN_PROOF_END_RE.search(active)
    )


def proof_body_has_terminal_explicit_qed(
    doc: Document,
    start_line: int,
    end_line: int,
) -> bool:
    """Return whether a proof body ends in a source-rendered QED marker.

    ``\\qed``/``\\qedhere`` and literal square glyphs count; a natural-language
    completion sentence does not.  Only whitespace, punctuation, math closers,
    row closers, and nested environment closers may follow the marker.  This
    distinction lets the patcher suppress an environment's *automatic* QED
    without deleting or rewriting any source/math token.
    """
    lines = doc.masked.split("\n")
    if not (1 <= start_line <= end_line <= len(lines)):
        return False
    active = "\n".join(lines[start_line - 1:end_line])
    matches = list(_EXPLICIT_QED_TOKEN_RE.finditer(active))
    if not matches:
        return False
    marker = matches[-1]
    if not _QED_STRUCTURAL_TRAILER_RE.fullmatch(active[marker.end():]):
        return False
    if _QED_COMMAND_RE.fullmatch(marker.group(0)):
        return True
    # A square-like command is also a legitimate mathematical operator.  Reuse
    # the strict boundary regex so only a standalone/punctuation-delimited QED
    # is accepted, not (for example) a terminal modal ``p \\Box`` formula.
    line_start = active.rfind("\n", 0, marker.start()) + 1
    line_end = active.find("\n", marker.end())
    if line_end < 0:
        line_end = len(active)
    return bool(_QED_SQUARE_RE.search(active[line_start:line_end]))


def _atomic_end(doc: Document, line: int, wrap_start: Optional[int] = None) -> int:
    """把源行号吸附到完整段落以及本次 wrap 内开启的环境末尾。"""
    end = max(1, line)
    while True:
        block = _block_containing(doc, end)
        expanded = block.span.end_line if block is not None else end
        if wrap_start is not None:
            enclosing = [
                candidate
                for candidate in doc.blocks
                if candidate.kind == "env"
                and candidate.name != "document"
                and candidate.span.start_line >= wrap_start
                and candidate.span.start_line <= end <= candidate.span.end_line
            ]
            if enclosing:
                expanded = max(expanded, max(item.span.end_line for item in enclosing))
        if expanded <= end:
            return end
        end = expanded


def _candidate_atom_has_body(doc: Document, cand) -> bool:
    """Return whether the scanner's title atom contains actual body text.

    ``title_remainder`` only describes text left on the *title line*.  A title
    such as ``Definition.`` followed by its statement on the next source line
    is still one parser paragraph/atomic block, so looking at that field alone
    incorrectly reports a title-only candidate.
    """
    if str(cand.payload.get("title_remainder", "")).strip():
        return True
    lines = doc.masked.split("\n")
    start = cand.span.start_line
    candidate_atomic_end = _atomic_end(
        doc, cand.span.end_line, wrap_start=start
    )
    return any(
        line.strip()
        for line in lines[start:min(candidate_atomic_end, len(lines))]
    )


def _pre_stop_atomic_end(
    doc: Document,
    start: int,
    stop: Optional[int],
) -> Optional[int]:
    """Last complete non-empty atom before a reliable structural stop."""
    if stop is None:
        return None
    lines = doc.masked.split("\n")
    last_line = min(stop - 1, len(lines))
    while last_line >= start and not lines[last_line - 1].strip():
        last_line -= 1
    if last_line < start:
        return None
    complete_end = _atomic_end(doc, last_line, wrap_start=start)
    return complete_end if complete_end < stop else None


def theorem_requires_boundary_singleton(
    doc: Document,
    cand,
    structured_envs: Optional[Collection[str]] = None,
) -> bool:
    """Whether a theorem-like candidate needs an isolated boundary decision."""
    if getattr(cand, "kind", "") != "theorem-like":
        return False
    start = cand.span.start_line
    candidate_atomic_end = _atomic_end(
        doc, cand.span.end_line, wrap_start=start
    )
    stop = _next_stop_line(doc, start, structured_envs)
    complete_end = _pre_stop_atomic_end(doc, start, stop)
    return complete_end is not None and complete_end > candidate_atomic_end


def _proof_end_line(doc: Document, start: int, upper: int) -> Optional[int]:
    """返回安全证明区间内第一个明确结束标记所在原子块末行。"""
    lines = doc.masked.split("\n")
    upper = min(max(start, upper), len(lines))
    for line_no in range(start, upper + 1):
        active = lines[line_no - 1]
        if has_proof_end_marker(active):
            return _atomic_end(doc, line_no, wrap_start=start)
    return None


def _reliable_stop_lines(
    doc: Document,
    structured_envs: Optional[Collection[str]] = None,
) -> tuple[int, ...]:
    """Return cached high-precision structural stop lines for *doc*."""
    supplied = frozenset(str(name).strip() for name in (structured_envs or ()) if name)
    cache = getattr(doc, "_latexstruct_reliable_stop_lines", None)
    if not isinstance(cache, dict):
        cache = {}
    if supplied in cache:
        return cache[supplied]
    declared = _declared_theorem_envs(doc.masked)
    known_structured_envs = (
        THEOREM_LIKE_ENVS
        | {"proof", "solution"}
        | {f"{name}*" for name in THEOREM_LIKE_ENVS | {"proof", "solution"}}
        | declared
        | {f"{name}*" for name in declared}
        | set(supplied)
        | {f"{name}*" for name in supplied if not name.endswith("*")}
    )
    stops = set()
    for b in doc.blocks:
        if set(b.in_env) & BOX_ENVS:
            continue
        if b.kind == "env" and b.name in known_structured_envs:
            stops.add(b.span.start_line)
            continue
        if b.kind != "para":
            continue
        first = _first_nonempty_line(b.text)
        if not first:
            continue
        semantic, _wrapper = _semantic_view(first)
        if (
            _match_title(first)
            or PROOF_RE.match(semantic)
            or SECTION_START_RE.match(first)
        ):
            stops.add(b.span.start_line)
    result = tuple(sorted(stops))
    cache[supplied] = result
    setattr(doc, "_latexstruct_reliable_stop_lines", cache)
    return result


def _next_stop_line(
    doc: Document,
    start_line: int,
    structured_envs: Optional[Collection[str]] = None,
) -> Optional[int]:
    """下一个可靠结构停点（预计算后用二分查找）。"""
    stops = _reliable_stop_lines(doc, structured_envs)
    index = bisect_right(stops, start_line)
    return stops[index] if index < len(stops) else None


def _proof_safe_end_line(
    doc: Document,
    start: int,
    requested_end: int,
    structured_envs: Optional[Collection[str]] = None,
) -> Optional[int]:
    """确定 proof 的完整、可证明终点；不能确定时返回 ``None``。

    明确 QED 是最强边界，即使模型漏选了后半段也可安全补到该标记。没有 QED
    时，模型范围必须已经到达下一可靠结构标题之前的最后一个原子块；否则
    中间段落可能是证明续文，也可能是证明后的讨论，程序不能擅自扩展，必须
    fail closed。模型越过下一结构标题时则安全收缩到标题之前。
    """
    lines = doc.masked.split("\n")
    stop = _next_stop_line(doc, start, structured_envs)
    upper = (stop - 1) if stop is not None else len(lines)

    explicit = _proof_end_line(doc, start, upper)
    if explicit is not None and (stop is None or explicit < stop):
        return explicit
    if stop is None:
        return None

    end = stop - 1
    while end >= start and not lines[end - 1].strip():
        end -= 1
    if end < start:
        return None
    end = _atomic_end(doc, end, wrap_start=start)
    if end >= stop:
        return None

    # 若模型越过了一个可靠结构停点，可以确定性地收缩回来；它不能成为把
    # 新定理/新章节吞入 proof 的理由。
    if requested_end >= stop:
        return end

    # 模型常把结构停点前的分隔空行也包含在 body_span 中。空行不属于任何
    # 语义原子块，直接拿它做比较会把“已经选到 proof 最后一段”的正确范围
    # 误判成截断。先归一到 requested_end 之前最后一个非空源行，再做原子块
    # 校验；这不会扩大模型选择的范围。
    normalized_requested_end = min(max(start, requested_end), stop - 1)
    while (
        normalized_requested_end >= start
        and not lines[normalized_requested_end - 1].strip()
    ):
        normalized_requested_end -= 1
    if normalized_requested_end < start:
        return None
    requested_atomic = _atomic_end(
        doc, normalized_requested_end, wrap_start=start
    )
    # 只有模型明确选择到可靠停点前的最后一个原子块时才接受。尤其不能把
    # requested_atomic 之后的普通讨论段自动扩进 proof。
    return end if requested_atomic == end else None


def _theorem_safe_end_line(
    doc: Document,
    cand,
    requested_end: int,
    structured_envs: Optional[Collection[str]] = None,
) -> Optional[int]:
    """Validate a theorem-like end without guessing across plain paragraphs.

    A title and its body in the same parser paragraph are a single atomic unit.
    Once an AI range leaves that paragraph, it is accepted only if it reaches the
    final non-empty atomic block immediately before a machine-verifiable structure
    stop. A shorter selection is a potentially truncated theorem; a selection that
    crosses the stop is an over-wrap. Both are left for manual review instead of
    being silently expanded or shortened.
    """
    start = cand.span.start_line
    lines = doc.masked.split("\n")
    candidate_atomic_end = _atomic_end(
        doc, cand.span.end_line, wrap_start=start
    )
    normalized_requested_end = max(start, requested_end)
    while (
        normalized_requested_end >= start
        and normalized_requested_end <= len(lines)
        and not lines[normalized_requested_end - 1].strip()
    ):
        normalized_requested_end -= 1
    if normalized_requested_end < start:
        return None
    requested_atomic = _atomic_end(
        doc, normalized_requested_end, wrap_start=start
    )
    stop = _next_stop_line(doc, start, structured_envs)
    complete_end = _pre_stop_atomic_end(doc, start, stop)
    if stop is not None and (
        complete_end is None
        or candidate_atomic_end >= stop
        or requested_atomic >= stop
    ):
        return None

    # A terminal square/QED in the candidate atom proves that atom complete,
    # but does not authorise silently shrinking an over-wide model selection.
    # The decision or reviewer must still select exactly that source atom.
    explicit_candidate_end = _theorem_end_line(doc, start, cand.span.end_line)
    if (
        explicit_candidate_end is not None
        and requested_atomic == explicit_candidate_end
    ):
        return explicit_candidate_end

    # A reliable successor makes every non-empty atom before it relevant to the
    # completeness proof.  In particular, do not accept a grammatically complete
    # first paragraph when another paragraph remains before the successor.  The
    # gate also must not silently extend the model's short selection: a corrected
    # full range has to come from a new decision/review response.
    if complete_end is not None and complete_end > candidate_atomic_end:
        return complete_end if requested_atomic == complete_end else None

    # No additional atom exists before the reliable stop (or no reliable stop is
    # available).  Snapping a line *within the same parser atom* to that atom's end
    # remains safe, provided the title atom really contains a statement body.
    if requested_atomic <= candidate_atomic_end:
        return (
            candidate_atomic_end
            if _candidate_atom_has_body(doc, cand)
            else None
        )
    return None


def _theorem_end_line(
    doc: Document,
    start: int,
    candidate_end: int,
) -> Optional[int]:
    """Return a hard terminal marker within the scanner's theorem atom.

    Publisher sources sometimes put an omitted-proof square directly at the
    end of a one-line proposition or theorem.  That is a stronger boundary than
    a much later result heading, so intervening prose must not make the complete
    one-line statement look truncated.  Deliberately inspect only the original
    candidate atom: searching later atoms could mistake an unrecognised proof's
    QED for the theorem boundary and silently swallow that proof.
    """
    candidate_atomic_end = _atomic_end(doc, candidate_end, wrap_start=start)
    lines = doc.masked.split("\n")
    active = "\n".join(lines[start - 1:candidate_atomic_end])
    return candidate_atomic_end if has_proof_end_marker(active) else None


def legalize_wrap(
    doc: Document,
    d,
    cand,
    structured_envs: Optional[Collection[str]] = None,
) -> None:
    if hasattr(d, "_legalize_error"):
        delattr(d, "_legalize_error")
    if d.action != "wrap" or not d.body_span:
        return
    _requested_start, be = d.body_span
    start = cand.span.start_line
    # 候选标题是 wrap 的唯一合法起点。parse_decisions 通常已经保证这一点，
    # 缓存/复查决策仍需在这里统一复验。
    bs = start
    if be < start:
        be = cand.span.end_line

    requested_end = be

    # proof 与 theorem-like 都必须经过可验证的边界门。过去 theorem-like 会把
    # 越过停点的范围静默缩回标题段，也会接受停点前漏掉最后一段的范围；两种
    # 情况都让预览看似正常、实际正文却被截断。现在统一 fail closed。
    stop = _next_stop_line(doc, start, structured_envs)
    if be < start:
        be = start

    if d.env == "proof":
        safe_end = _proof_safe_end_line(
            doc, start, requested_end, structured_envs
        )
        if safe_end is None:
            setattr(
                d,
                "_legalize_error",
                "无法用结束标记或下一可靠结构标题证明范围完整，"
                "已保守跳过，避免生成被截断的 proof",
            )
            return
        # proof 的完整性不能由模型选出的较短终点证明。确定性扩展到首个 QED
        # 或下一可靠结构边界，防止“实时预览正常、最终结果却截断证明”。
        be = safe_end
    else:
        safe_end = _theorem_safe_end_line(
            doc, cand, requested_end, structured_envs
        )
        if safe_end is None:
            setattr(
                d,
                "_legalize_error",
                "定理类范围没有到达可验证的完整原子边界，或跨越了下一结构；"
                "已保守跳过，避免漏段或吞入后续叙述",
            )
            return
        be = safe_end

    # proof 的 QED 可以合法位于盒内，此时 _atomic_end 已把 closer 放到盒后。
    # theorem-like 的盒子通常是翻译/题注；静默缩到盒前会制造截断环境，必须
    # 撤销整项并交人工确认。
    blk = _block_containing(doc, be)
    if (
        blk is not None
        and blk.kind == "env"
        and blk.name in BOX_ENVS
        and d.env != "proof"
    ):
        setattr(d, "_legalize_error", "定理类范围触及翻译或题注盒，已保守跳过")
        return

    if stop is not None and be >= stop:
        setattr(d, "_legalize_error", "结构范围跨越下一可靠停点，已保守跳过")
        return

    if be < cand.span.start_line:
        be = cand.span.start_line
    d.body_span = (bs, be)


def legalize_decisions(
    doc: Document,
    decisions,
    candidates_by_id: Dict,
    structured_envs: Optional[Collection[str]] = None,
) -> None:
    for d in decisions:
        if d.source not in {"ai", "review"}:
            continue  # 规则决策使用自身的确定性范围扩展；AI/复查/复用统一复验
        cand = candidates_by_id.get(d.candidate_id)
        if cand is None:
            continue
        legalize_wrap(doc, d, cand, structured_envs)

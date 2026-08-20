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


_DETERMINISTIC_STATEMENT_PUNCTUATION_RE = re.compile(
    r"[.!?。？！]\s*(?:[}\])]|\\(?:textit|textbf|emph)\s*)*\s*$"
)
_DETERMINISTIC_STATEMENT_CLOSER_RE = re.compile(
    r"(?:"
    r"\\\]"
    r"|\\end\s*\{(?:equation\*?|align\*?|alignat\*?|flalign\*?|"
    r"gather\*?|multline\*?|eqnarray\*?|itemize|enumerate|description|cases)\}"
    r")\s*(?:%[^\n]*)?$"
)
_DETERMINISTIC_STATEMENT_CONTINUATION_RE = re.compile(
    r"^(?:"
    r"as\s+(?:\$|\\\()"
    r"|for\s+(?:all|every|each|any|some|no|sufficiently\b|infinitely\b)"
    r"|then\b"
    r"|or\b"
    r"|where\b"
    r"|whenever\b"
    r"|provided(?:\s+that)?\b"
    r"|subject\s+to\b"
    r"|such\s+that\b"
    r"|with\s+probability\b"
    r"|independent\s+sets?\b"
    r")",
    re.I,
)
_DETERMINISTIC_STATEMENT_BODY_OPEN_RE = re.compile(
    r"^(?:"
    r"(?:every|each|any|no)\b"
    r"|there\s+(?:exists?|are)\b"
    r"|\$"
    r"|\\\("
    r"|\\\["
    r"|\\begin\b"
    r")",
    re.I,
)
_DETERMINISTIC_STATEMENT_CONDITIONAL_OPEN_RE = re.compile(
    r"^(?:let|suppose|assume|given|if|whenever)\b",
    re.I,
)
_DETERMINISTIC_STATEMENT_MATH_EVIDENCE_RE = re.compile(
    r"(?:"
    r"\$[^$\n]+\$"
    r"|\\\([^\n]*\\\)"
    r"|\\\[[^\n]*\\\]"
    r"|\\begin\s*\{(?:equation\*?|align\*?|gather\*?|multline\*?|cases)\}"
    r"|(?<![<>=])(?:=|<=|>=|<|>)(?![<>=])"
    r"|[≤≥≠∈∉⊂⊆⊃⊇≈≡]"
    r")",
)
_DETERMINISTIC_STATEMENT_STRUCTURAL_ENVS = {
    "equation", "equation*", "align", "align*", "alignat", "alignat*",
    "flalign", "flalign*", "gather", "gather*", "multline", "multline*",
    "eqnarray", "eqnarray*", "itemize", "enumerate", "description", "cases",
}
_DETERMINISTIC_PROOF_NATURAL_CLOSER_RE = re.compile(
    r"(?:^|\n\s*|[.!?。；;：:]\s+)"
    r"(?:"
    r"as\s+(?:required|claimed|desired|needed)"
    r"|which\s+(?:proves|establishes|completes)\s+"
    r"(?:the\s+)?(?:claim|result|proof|theorem|lemma)"
    r")\s*[.!?。]?\s*(?:%[^\n]*)?$",
    re.I,
)


def _next_top_level_content_block(doc: Document, end_line: int) -> Optional[Block]:
    """Return the first source atom after *end_line*, excluding outer wrappers."""
    candidates = [
        block
        for block in doc.blocks
        if block.span.start_line > end_line
        and not (block.kind == "env" and block.name == "document")
        and not block.in_env
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda block: (block.span.start_line, block.span.end_line))


def _deterministic_statement_is_closed(doc: Document, start: int, end: int) -> bool:
    """Prove a formal statement has a local source-level closing boundary.

    This is deliberately narrower than ordinary AI legalization.  OCR formal
    labels are locked only when a second, non-model gate can see either terminal
    sentence punctuation or a complete display/list closer at the rule-selected
    boundary.  The check never derives or rewrites mathematical content.
    """
    lines = doc.masked.split("\n")
    if not (1 <= start <= end <= len(lines)):
        return False
    active = "\n".join(lines[start - 1:end]).rstrip()
    if not active:
        return False
    return bool(
        _DETERMINISTIC_STATEMENT_PUNCTUATION_RE.search(active)
        or _DETERMINISTIC_STATEMENT_CLOSER_RE.search(active)
    )


def _deterministic_statement_body_opens_formally(text: str) -> bool:
    """Validate the first prose body after an otherwise title-only atom."""
    stripped = text.lstrip()
    conditional = _DETERMINISTIC_STATEMENT_CONDITIONAL_OPEN_RE.match(stripped)
    if conditional:
        return bool(_DETERMINISTIC_STATEMENT_MATH_EVIDENCE_RE.search(stripped))
    return bool(
        _DETERMINISTIC_STATEMENT_BODY_OPEN_RE.match(stripped)
        or _DETERMINISTIC_STATEMENT_CONTINUATION_RE.match(stripped)
    )


def _deterministic_statement_extension_is_supported(doc: Document, cand, end: int) -> bool:
    """Reject rule-only lowercase paragraph expansion outside the title atom.

    Rule scanning deliberately treats a lowercase paragraph as a possible
    continuation.  That is useful recall evidence, but it is not strong enough
    to create an immutable OCR anchor: a normal discussion paragraph can have
    exactly the same shape.  Cross-atom deterministic statements therefore
    admit only complete display/list atoms plus narrowly grammatical formal
    continuations.  Every prose continuation must carry its own narrow formal
    connector; an unstyled continuation additionally requires a preceding
    display/list.  Uncertain multi-paragraph prose stays on the AI/manual path.
    """
    start = cand.span.start_line
    candidate_atomic_end = _atomic_end(doc, cand.span.end_line, wrap_start=start)
    if end <= candidate_atomic_end:
        return True

    body_seen = _candidate_atom_has_body(doc, cand)
    structural_seen = False
    cursor = candidate_atomic_end
    extension_blocks = sorted(
        (
            block for block in doc.blocks
            if block.span.start_line > candidate_atomic_end
            and block.span.start_line <= end
            and not (block.kind == "env" and block.name == "document")
        ),
        key=lambda block: (
            block.span.start_line,
            -(block.span.end_line - block.span.start_line),
        ),
    )
    for block in extension_blocks:
        # An outer display/list atom consumes its nested parser blocks.
        if block.span.start_line <= cursor:
            continue
        if block.span.end_line > end:
            return False
        if block.kind == "displaymath" or (
            block.kind == "env"
            and block.name in _DETERMINISTIC_STATEMENT_STRUCTURAL_ENVS
        ):
            structural_seen = True
            body_seen = True
            cursor = block.span.end_line
            continue
        if block.kind != "para" or block.in_env:
            return False
        if _is_ocr_page_separator_text(block.text):
            cursor = block.span.end_line
            continue

        first = _first_nonempty_line(block.text)
        if not first:
            cursor = block.span.end_line
            continue
        semantic, wrapper = _semantic_view(first)
        formal_connector = bool(
            _DETERMINISTIC_STATEMENT_CONTINUATION_RE.match(semantic.lstrip())
        )
        if not body_seen:
            # A title-only atom may take exactly its first source paragraph as
            # the statement body, but only when that paragraph opens with
            # formal mathematical grammar.  This restores common
            # ``Theorem 1.`` / ``Every graph ...`` layout without reviving the
            # unconditional lowercase/styled expansion that caused over-wraps.
            if not _deterministic_statement_body_opens_formally(semantic):
                return False
            body_seen = True
            cursor = block.span.end_line
            continue
        # Every cross-atom prose paragraph must carry its own formal grammar
        # evidence.  Typography is not semantic evidence, and a preceding
        # display/list proves only that atom complete; neither may authorise an
        # arbitrary historical or explanatory paragraph that follows it.
        if not formal_connector:
            return False
        if wrapper is not None:
            cursor = block.span.end_line
            continue
        if not structural_seen:
            return False
        cursor = block.span.end_line
    return cursor >= end


def _is_ocr_page_separator_text(text: str) -> bool:
    """Recognise the isolated page commands inserted by OCR page merging."""
    active = "\n".join(
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("%")
    ).strip()
    return active in (r"\clearpage", r"\newpage")


def _deterministic_proof_is_closed(
    doc: Document,
    start: int,
    end: int,
    structured_envs: Optional[Collection[str]] = None,
) -> bool:
    """Require a source QED, or a natural closer backed by a reliable stop."""
    if proof_body_has_terminal_explicit_qed(doc, start, end):
        return True
    stop = _next_stop_line(doc, start, structured_envs)
    if stop is None or end >= stop:
        return False
    lines = doc.masked.split("\n")
    if not (1 <= start <= end <= len(lines)):
        return False
    active = "\n".join(lines[start - 1:end]).rstrip()
    return bool(
        _PROOF_COMPLETION_RE.search(active)
        or _CN_PROOF_END_RE.search(active)
        or _DETERMINISTIC_PROOF_NATURAL_CLOSER_RE.search(active)
    )


def legalize_deterministic_wrap(
    doc: Document,
    d,
    cand,
    structured_envs: Optional[Collection[str]] = None,
) -> None:
    """Validate a rule-selected OCR formal span with an independent hard gate.

    Proofs reuse the established QED/next-structure legalizer.  Numbered
    theorem-like entries additionally require an exact keyword-derived
    environment, an atomic rule boundary, a locally closed statement, and no
    unconsumed lowercase/styled/display continuation.  Failure leaves the item
    unlocked so the normal AI path can decide it; no partial wrap is emitted.
    """
    if hasattr(d, "_legalize_error"):
        delattr(d, "_legalize_error")
    if d.action != "wrap" or not d.body_span:
        setattr(d, "_legalize_error", "确定性结构项缺少可验证的 wrap 范围")
        return
    if getattr(cand, "kind", "") == "proof":
        if d.env != "proof":
            setattr(d, "_legalize_error", "证明锚点的目标环境不是 proof")
            return
        legalize_wrap(doc, d, cand, structured_envs)
        if hasattr(d, "_legalize_error"):
            return
        if not d.body_span or not _deterministic_proof_is_closed(
            doc, d.body_span[0], d.body_span[1], structured_envs
        ):
            setattr(
                d,
                "_legalize_error",
                "无显式 QED 的证明缺少可靠结构停点和终结语证据，未进入确定性锁定",
            )
        return
    if getattr(cand, "kind", "") != "theorem-like":
        setattr(d, "_legalize_error", "仅定理类或证明候选可成为确定性语义锚点")
        return
    expected_env = str(getattr(cand, "env_hint", "") or "")
    if not expected_env or d.env != expected_env:
        setattr(d, "_legalize_error", "目标环境与显式标题关键词不一致")
        return
    if not str(getattr(cand, "payload", {}).get("number", "") or "").strip():
        setattr(d, "_legalize_error", "无显式编号的定理类标题不进入确定性锁定路径")
        return

    start, end = d.body_span
    if start != cand.span.start_line or end < cand.span.end_line:
        setattr(d, "_legalize_error", "确定性范围未完整覆盖标题原子")
        return
    atomic_end = _atomic_end(doc, end, wrap_start=start)
    if atomic_end != end:
        setattr(d, "_legalize_error", "确定性终点未落在完整段落、公式或列表边界")
        return
    stop = _next_stop_line(doc, start, structured_envs)
    if stop is not None and end >= stop:
        setattr(d, "_legalize_error", "确定性范围跨越下一可靠结构标题")
        return
    candidate_atomic_end = _atomic_end(
        doc, cand.span.end_line, wrap_start=cand.span.start_line
    )
    if not _candidate_atom_has_body(doc, cand) and end <= candidate_atomic_end:
        setattr(d, "_legalize_error", "标题原子没有可验证正文")
        return
    if not _deterministic_statement_extension_is_supported(doc, cand, end):
        setattr(d, "_legalize_error", "普通小写叙述段不能作为定理跨原子扩展的锁定证据")
        return
    if not _deterministic_statement_is_closed(doc, start, end):
        setattr(d, "_legalize_error", "定理陈述缺少局部可证明的句末或完整公式/列表边界")
        return

    next_block = _next_top_level_content_block(doc, end)
    if next_block is not None:
        if next_block.kind == "displaymath":
            setattr(d, "_legalize_error", "规则终点之后仍有未包含的展示公式")
            return
        if next_block.kind == "env" and next_block.name in MATH_ENVS:
            setattr(d, "_legalize_error", "规则终点之后仍有未包含的数学环境")
            return
        if next_block.kind == "para":
            first = _first_nonempty_line(next_block.text)
            semantic, wrapper = _semantic_view(first)
            stripped = semantic.lstrip()
            is_new_structure = bool(
                _match_title(first)
                or PROOF_RE.match(semantic)
                or SECTION_START_RE.match(first)
            )
            if not is_new_structure and (
                wrapper is not None
                or stripped[:1].islower()
                or stripped.startswith(("\\(", "$", "\\[", "\\begin"))
            ):
                setattr(d, "_legalize_error", "规则终点之后仍有语法承接段，未锁定该范围")
                return
    d.body_span = (start, end)


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

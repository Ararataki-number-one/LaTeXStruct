#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed evaluation of structural edits made to a LaTeX document.

The evaluator is deliberately independent of LaTeXStruct's production parser.
It compares formal environments against line-bounded truth, checks that prose
was conserved, and verifies that an outline and a table of contents survived.
It never treats compilation success or a visually plausible PDF as accuracy.

Truth manifest example::

    {
      "schema": "latexstruct-tex-structure-truth-v1",
      "items": [
        {"kind": "theorem", "id": "1.1", "start_line": 20, "end_line": 24},
        {"kind": "proof", "id": "P1.1", "start_line": 26, "end_line": 30},
        {
          "kind": "remark",
          "id": "remark-after-1.1",
          "heading_label": "Remark",
          "start_line": 32,
          "end_line": 34
        }
      ]
    }

Without a manifest, simple formal and proof headings are discovered
automatically.  That mode is diagnostic only: release evidence must use a
reviewed manifest so that a detector cannot silently define its own ground
truth or infer statement boundaries from blank lines.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


TRUTH_SCHEMA = "latexstruct-tex-structure-truth-v1"
FORMAL_KINDS = (
    "theorem",
    "lemma",
    "proposition",
    "corollary",
    "conjecture",
    "claim",
    "fact",
    "definition",
    "remark",
    "observation",
    "note",
    "example",
    "problem",
    "question",
)
ALL_KINDS = FORMAL_KINDS + ("proof",)
KIND_PATTERN = "|".join(FORMAL_KINDS)

FORMAL_HEADING_RE = re.compile(
    rf"\\textbf\s*\{{\s*(?P<kind>{KIND_PATTERN})\s+"
    r"(?P<id>\d+(?:\.\d+)*)(?:\.)?[^{}]*\}",
    re.IGNORECASE,
)
PLAIN_FORMAL_HEADING_RE = re.compile(
    rf"(?m)^\s*(?P<kind>{KIND_PATTERN})\s+"
    r"(?P<id>\d+(?:\.\d+)*)(?:\.(?!\d)|(?=\s+\())\s*"
    r"\s*",
    re.IGNORECASE,
)
PROOF_HEADING_RE = re.compile(
    r"\\textit\s*\{\s*(?:proof|sketch\s+of\s+the\s+proof|proof\s+of\b)[^{}]*\}",
    re.IGNORECASE,
)
PLAIN_PROOF_HEADING_RE = re.compile(
    r"(?m)^\s*(?:Proof(?:\s+of\s+[^\n]*?)?|Sketch\s+of\s+the\s+proof)"
    r"\.(?!\d)\s*"
)
ENV_BEGIN_RE = re.compile(
    rf"\\begin\{{(?P<kind>{'|'.join(ALL_KINDS)})(?P<star>\*)?\}}",
    re.IGNORECASE,
)
STRUCTURAL_COMMAND_RE = re.compile(
    r"\\(?:part|chapter|section|subsection|subsubsection)\*?\s*\{"
)
OUTLINE_COMMAND_RE = re.compile(
    r"\\(?P<command>part|chapter|section|subsection|subsubsection)"
    r"(?P<star>\*)?\s*\{",
    re.IGNORECASE,
)
INLINE_OUTLINE_RE = re.compile(
    r"\\textbf\s*\{\s*(?P<number>\d+(?:\.\d+)*)\.\s*(?P<title>[^{}]+)\}",
    re.IGNORECASE,
)
PLAIN_OUTLINE_RE = re.compile(
    r"(?m)^\s*(?:(?P<number>\d+)\.\s+)?(?P<title>[A-Z][A-Z\s.'’\\\-–—]+)\s*$"
)
PLAIN_OUTLINE_STRUCTURAL_RE = re.compile(
    r"(?mi)^\s*(?:\d+\.\s+[A-Z][A-Z\s.'’\\\-–—]+|REFERENCES)\s*$"
)
TOKEN_RE = re.compile(r"\\[A-Za-z@]+|\\[^\s]|[^\W_]+|_|[^\s]", re.UNICODE)
FORMAL_LABEL_RE = re.compile(
    rf"^(?P<kind>{KIND_PATTERN})(?:\s+(?P<number>\d+(?:\.\d+)*))?"
    r"(?P<tail>(?:\s+\([^\n]*\))?\.?)\s*$",
    re.IGNORECASE,
)
PROOF_LABEL_RE = re.compile(
    r"^(?:proof(?:\s+of\s+.+?)?|sketch\s+of\s+the\s+proof)\.?\s*$",
    re.IGNORECASE,
)
PLAIN_FORMAL_PREFIX_RE = re.compile(
    rf"^(?P<label>(?P<kind>{KIND_PATTERN})"
    r"(?:\s+(?P<number>\d+(?:\.\d+)*))?"
    r"(?:\s+\([^\n]*?\))?\.)(?=\s|$)",
    re.IGNORECASE,
)
PLAIN_NUMBERED_FORMAL_PREFIX_RE = re.compile(
    rf"^(?P<label>(?P<kind>{KIND_PATTERN})\s+"
    r"(?P<number>\d+(?:\.\d+)*))(?=\s+\(|\s*$)",
    re.IGNORECASE,
)
PLAIN_PROOF_PREFIX_RE = re.compile(
    r"^(?P<label>(?:Proof(?:\s+of\s+[^\n]*?)?|Sketch\s+of\s+the\s+proof)\.)"
    r"(?=\s|$)",
    re.IGNORECASE,
)
EQUATION_NUMBER_PATTERNS = (
    re.compile(
        r"\\text[ \t]*\{[ \t]*\([ \t]*"
        r"(?P<label>[0-9]{1,4}[A-Za-z]?)[ \t]*\)[ \t]*\}"
        r"[ \t]*\\qquad(?![A-Za-z@])"
    ),
    re.compile(
        r"\\qquad(?![A-Za-z@])[ \t]*\([ \t]*"
        r"(?P<label>[0-9]{1,4}[A-Za-z]?)[ \t]*\)"
    ),
    re.compile(
        r"\\tag[ \t]*\{[ \t]*"
        r"(?P<label>[0-9]{1,4}[A-Za-z]?)[ \t]*\}"
    ),
)
DISPLAY_EQUATION_BLOCK_PATTERNS = (
    re.compile(r"\\\[(?P<body>.*?)\\\]", re.DOTALL),
    re.compile(
        r"\\begin\{(?P<environment>"
        r"equation\*?|align\*?|alignat\*?|flalign\*?|gather\*?|multline\*?"
        r")\}(?P<body>.*?)\\end\{(?P=environment)\}",
        re.DOTALL,
    ),
)
BIBITEM_NUMBER_RE = re.compile(
    r"(?m)^[ \t]*\\bibitem(?![A-Za-z@])[ \t]*"
    r"(?:\[(?P<display>[^\]\r\n]*)\][ \t]*)?"
    r"\{ref(?P<number>[1-9][0-9]*)\}[ \t]*"
)
PRINTED_REFERENCE_NUMBER_RE = re.compile(
    r"(?m)^[ \t]*(?:\\noindent[ \t]*)?"
    r"\[(?P<number>[1-9][0-9]*)\][ \t]*"
    r"(?:\\quad(?![A-Za-z@])[ \t]*)?"
)

PRESENTATION_ONE_ARG = {
    "emph",
    "mbox",
    "textbf",
    "textit",
    "textnormal",
    "textrm",
    "textsc",
    "textsf",
    "textsl",
    "texttt",
    "textup",
    "underline",
}
PRESENTATION_TWO_ARG = {"colorbox", "href", "textcolor"}
PRESENTATION_DECLARATIONS = {
    "bf",
    "bfseries",
    "em",
    "it",
    "itshape",
    "mdseries",
    "normalfont",
    "rmfamily",
    "scshape",
    "sffamily",
    "slshape",
    "ttfamily",
    "upshape",
}


@dataclass(frozen=True)
class TruthItem:
    kind: str
    item_id: str
    heading_label: str
    heading_number: str
    start_line: int
    end_line: int
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class CandidateEnvironment:
    kind: str
    item_id: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class SourceHeading:
    kind: str
    number: str
    label: str
    start_offset: int
    end_offset: int
    line: int


@dataclass(frozen=True)
class TruthHeading:
    level: int
    title: str
    title_key: str
    start_line: int
    end_line: int


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normalise_text_for_hash(text: str) -> str:
    """Canonicalise decoded text only; never claim this is a file-byte hash."""
    return text.replace("\r\n", "\n").replace("\r", "\n").lstrip("\ufeff")


def _normalised_text_sha256(text: str) -> str:
    return _sha256_text(_normalise_text_for_hash(text))


def _strip_comments(text: str) -> str:
    cleaned = []
    for line in text.splitlines():
        cut = len(line)
        for index, char in enumerate(line):
            if char != "%":
                continue
            slash_count = 0
            cursor = index - 1
            while cursor >= 0 and line[cursor] == "\\":
                slash_count += 1
                cursor -= 1
            if slash_count % 2 == 0:
                cut = index
                break
        cleaned.append(line[:cut])
    return "\n".join(cleaned)


def _document_body(text: str) -> str:
    match = re.search(r"\\begin\{document\}", text)
    if not match:
        return text
    end = re.search(r"\\end\{document\}", text[match.end():])
    if not end:
        return text[match.end():]
    return text[match.end():match.end() + end.start()]


def _balanced_group_end(text: str, opening_brace: int) -> int | None:
    depth = 0
    index = opening_brace
    while index < len(text):
        char = text[index]
        if char in "{}":
            slash_count = 0
            cursor = index - 1
            while cursor >= 0 and text[cursor] == "\\":
                slash_count += 1
                cursor -= 1
            if slash_count % 2:
                index += 1
                continue
            depth += 1 if char == "{" else -1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _skip_space(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _command_name(text: str, index: int) -> tuple[str, int] | None:
    match = re.match(r"\\([A-Za-z@]+)\*?", text[index:])
    if match is None:
        return None
    return match.group(1).casefold(), index + match.end()


def _required_group(text: str, index: int) -> tuple[int, int] | None:
    opening = _skip_space(text, index)
    if opening >= len(text) or text[opening] != "{":
        return None
    end = _balanced_group_end(text, opening)
    if end is None:
        return None
    return opening, end


def _leading_styled_span(line: str) -> tuple[int, int] | None:
    """Return one complete leading presentation atom, if present."""
    start = _skip_space(line, 0)
    if start >= len(line):
        return None
    if line[start] == "{":
        end = _balanced_group_end(line, start)
        if end is None:
            return None
        inner = line[start + 1:end - 1].lstrip()
        command = _command_name(inner, 0) if inner.startswith("\\") else None
        if command is None or command[0] not in PRESENTATION_DECLARATIONS | {"color"}:
            return None
        return start, end
    if line[start] != "\\":
        return None
    command = _command_name(line, start)
    if command is None:
        return None
    name, cursor = command
    if name in PRESENTATION_ONE_ARG:
        group = _required_group(line, cursor)
        return (start, group[1]) if group else None
    if name in PRESENTATION_TWO_ARG:
        first = _required_group(line, cursor)
        if first is None:
            return None
        second = _required_group(line, first[1])
        return (start, second[1]) if second else None
    return None


def _flatten_presentation(text: str) -> str:
    """Remove visual wrappers while retaining their visible heading text."""
    output: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "~":
            output.append(" ")
            index += 1
            continue
        if char in "{}":
            index += 1
            continue
        if char != "\\":
            output.append(char)
            index += 1
            continue
        command = _command_name(text, index)
        if command is None:
            index += 1
            continue
        name, cursor = command
        if name in PRESENTATION_DECLARATIONS:
            index = cursor
            continue
        if name == "color":
            group = _required_group(text, cursor)
            index = group[1] if group else cursor
            continue
        if name in PRESENTATION_ONE_ARG:
            group = _required_group(text, cursor)
            if group is None:
                index = cursor
                continue
            output.append(_flatten_presentation(text[group[0] + 1:group[1] - 1]))
            index = group[1]
            continue
        if name in PRESENTATION_TWO_ARG:
            first = _required_group(text, cursor)
            second = _required_group(text, first[1]) if first else None
            if first is None or second is None:
                index = cursor
                continue
            # textcolor/colorbox hide their colour argument; href hides its URL.
            output.append(_flatten_presentation(text[second[0] + 1:second[1] - 1]))
            index = second[1]
            continue
        # Unknown control words are formatting for the purposes of a heading
        # label.  Preserve separation so adjacent words cannot accidentally join.
        output.append(" ")
        index = cursor
    return re.sub(r"\s+", " ", "".join(output)).strip()


def _canonical_heading_label(value: str) -> str:
    visible = _flatten_presentation(value).casefold().rstrip(" .")
    return " ".join(re.findall(r"[^\W_]+|\d+(?:\.\d+)*", visible, re.UNICODE))


def _parse_heading_label(value: str) -> tuple[str, str, str] | None:
    visible = re.sub(r"\s+", " ", _flatten_presentation(value)).strip()
    formal = FORMAL_LABEL_RE.fullmatch(visible)
    if formal:
        number = (formal.group("number") or "").rstrip(".")
        tail = formal.group("tail") or ""
        if not number and not tail.rstrip().endswith("."):
            return None
        return formal.group("kind").casefold(), number, visible.rstrip(" .")
    if PROOF_LABEL_RE.fullmatch(visible):
        return "proof", "", visible.rstrip(" .")
    return None


def _find_source_headings(text: str) -> list[SourceHeading]:
    """Find line-anchored source headings, including nested visual wrappers."""
    result: list[SourceHeading] = []
    offset = 0
    for line_number, line_with_end in enumerate(text.splitlines(keepends=True), start=1):
        line = line_with_end.rstrip("\r\n")
        styled = _leading_styled_span(line)
        if styled is not None:
            start, end = styled
            parsed = _parse_heading_label(line[start:end])
            if parsed is not None:
                kind, number, label = parsed
                result.append(SourceHeading(
                    kind=kind,
                    number=number,
                    label=label,
                    start_offset=offset + start,
                    end_offset=offset + end,
                    line=line_number,
                ))
                offset += len(line_with_end)
                continue

        stripped_start = _skip_space(line, 0)
        fragment = line[stripped_start:]
        match = (
            PLAIN_FORMAL_PREFIX_RE.match(fragment)
            or PLAIN_NUMBERED_FORMAL_PREFIX_RE.match(fragment)
            or PLAIN_PROOF_PREFIX_RE.match(fragment)
        )
        if match is not None:
            parsed = _parse_heading_label(match.group("label"))
            if parsed is not None:
                kind, number, label = parsed
                result.append(SourceHeading(
                    kind=kind,
                    number=number,
                    label=label,
                    start_offset=offset + stripped_start,
                    end_offset=offset + stripped_start + match.end("label"),
                    line=line_number,
                ))
        offset += len(line_with_end)
    return result


def _remove_source_headings(text: str) -> str:
    chars = list(text)
    for heading in _find_source_headings(text):
        chars[heading.start_offset:heading.end_offset] = (
            " " * (heading.end_offset - heading.start_offset)
        )
    return "".join(chars)


def _remove_balanced_commands(text: str, pattern: re.Pattern[str]) -> str:
    output: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(text, cursor)
        if not match:
            output.append(text[cursor:])
            break
        opening = text.find("{", match.start(), match.end())
        end = _balanced_group_end(text, opening)
        if end is None:
            output.append(text[cursor:])
            break
        output.append(text[cursor:match.start()])
        output.append(" ")
        cursor = end
    return "".join(output)


def _remove_formal_markup(text: str) -> str:
    text = _remove_source_headings(text)
    text = FORMAL_HEADING_RE.sub(" ", text)
    text = PLAIN_FORMAL_HEADING_RE.sub(" ", text)
    text = PROOF_HEADING_RE.sub(" ", text)
    text = PLAIN_PROOF_HEADING_RE.sub(" ", text)
    text = re.sub(
        rf"\\(?:begin|end)\{{(?:{'|'.join(ALL_KINDS)})\*?\}}"
        r"(?:\s*\[[^\]\n]*\])?",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\\ifcsname\s+qedsymbol\\endcsname\s*"
        r"\\let\\qedsymbol\\empty\\fi",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    return text


def _normalise_fragment(text: str, *, document_scope: bool = False) -> tuple[str, ...]:
    if document_scope:
        text = _document_body(text)
    text = _strip_comments(text)
    text = _remove_formal_markup(text)
    # Evidence-gated semantic IR may move a printed equation number from the
    # left or right edge of a display into an AMS ``\tag``.  Canonicalize the
    # complete display and place a common numbered token at its end.  Binding
    # that token to its own display catches not only wrong or swapped numbers,
    # but also a label moved onto the wrong equation.
    def replace_equation_block(match: re.Match[str]) -> str:
        body = match.group("body")
        body_source = body
        hits = []
        for pattern in EQUATION_NUMBER_PATTERNS:
            hits.extend(
                (number.start(), number.group("label"))
                for number in pattern.finditer(body_source)
            )
            body = pattern.sub(" ", body)
        markers = "".join(
            rf" \LATEXSTRUCTSemanticEquationNumber{{{label}}} "
            for _offset, label in sorted(hits)
        )
        return body + markers

    for pattern in DISPLAY_EQUATION_BLOCK_PATTERNS:
        text = pattern.sub(replace_equation_block, text)
    text = re.sub(
        r"\\(?:begin|end)\{equation\*?\}|\\\[|\\\]",
        " ",
        text,
    )
    text = re.sub(
        r"\\begin\{thebibliography\}\s*\{[^{}\r\n]*\}"
        r"|\\end\{thebibliography\}",
        " ",
        text,
    )
    # Numbered reference prefixes and refN bibitems are likewise two renderings
    # of one source label.  Retain their ordered numbers as common tokens.  A
    # non-matching optional display label is deliberately left as an additional
    # token so that the evaluator fails closed instead of blessing it.
    def replace_bibitem(match: re.Match[str]) -> str:
        number = match.group("number")
        display = match.group("display")
        if display is not None and display.strip() != number:
            return (
                rf" \LATEXSTRUCTSemanticReferenceNumber{{{number}}} "
                f" LATEXSTRUCTINVALIDBIBLABEL {display} "
            )
        return rf" \LATEXSTRUCTSemanticReferenceNumber{{{number}}} "

    text = BIBITEM_NUMBER_RE.sub(replace_bibitem, text)

    def replace_printed_reference(match: re.Match[str]) -> str:
        return (
            rf" \LATEXSTRUCTSemanticReferenceNumber"
            rf"{{{match.group('number')}}} "
        )

    text = PRINTED_REFERENCE_NUMBER_RE.sub(replace_printed_reference, text)
    text = INLINE_OUTLINE_RE.sub(" ", text)
    text = PLAIN_OUTLINE_STRUCTURAL_RE.sub(" ", text)
    text = _remove_balanced_commands(text, STRUCTURAL_COMMAND_RE)
    text = re.sub(
        r"\\(?:tableofcontents|maketitle|frontmatter|mainmatter|backmatter)\b",
        " ",
        text,
    )
    # FaithfulBook inserts these zero-argument layout controls in the document
    # body.  They affect navigation/pagination only and must not be counted as
    # source prose added by the structural transformation.
    text = re.sub(
        r"\\(?:LSFirstPageEmpty|LSMainMatter|LSChapterContents)\b",
        " ",
        text,
    )
    text = re.sub(
        r"\\(?:clearpage|cleardoublepage|newpage|pagebreak)\b"
        r"(?:[ \t]*\[[^\]\r\n]*\])?",
        " ",
        text,
    )
    text = re.sub(r"\\(?:label|hypertarget)\s*\{[^{}]*\}", " ", text)
    text = re.sub(r"\\(?:begin|end)\{center\}", " ", text)
    text = re.sub(
        r"\\addcontentsline\s*\{[^{}]*\}\s*\{[^{}]*\}\s*\{[^{}]*\}",
        " ",
        text,
    )
    # A full stop is sometimes outside the bold formal-heading group.  It is
    # heading punctuation, not statement content.
    text = re.sub(r"(?m)^\s*[.:]\s*", " ", text)
    return tuple(TOKEN_RE.findall(text))


def _normalise_item(text: str) -> tuple[str, ...]:
    return _normalise_fragment(text)


def _validate_truth_items(raw_items: object, lines: Sequence[str]) -> list[TruthItem]:
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("truth manifest items must be a non-empty array")
    result: list[TruthItem] = []
    seen: set[tuple[str, str]] = set()
    occupied: list[tuple[int, int, str]] = []
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, dict):
            raise ValueError(f"truth item {index} must be an object")
        kind = str(raw.get("kind", "")).strip().lower()
        item_id = str(raw.get("id", "")).strip()
        raw_heading_label = raw.get("heading_label")
        if raw_heading_label is not None and not isinstance(raw_heading_label, str):
            raise ValueError(f"truth item {index} heading_label must be a string")
        heading_label = str(raw_heading_label or "").strip()
        start = raw.get("start_line")
        end = raw.get("end_line")
        if kind not in ALL_KINDS or not item_id:
            raise ValueError(f"truth item {index} has invalid kind or id")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end > len(lines)
        ):
            raise ValueError(f"truth item {kind}:{item_id} has invalid line bounds")
        key = (kind, item_id.casefold())
        if key in seen:
            raise ValueError(f"duplicate truth key: {kind}:{item_id}")
        for other_start, other_end, other_key in occupied:
            if start <= other_end and other_start <= end:
                raise ValueError(
                    f"overlapping truth bounds: {kind}:{item_id} and {other_key}"
                )
        source = "\n".join(lines[start - 1:end])
        headings = _find_source_headings(source)
        if not headings:
            noun = "proof" if kind == "proof" else "formal"
            raise ValueError(f"truth item {kind}:{item_id} has no {noun} heading")
        if len(headings) != 1:
            raise ValueError(f"truth item {kind}:{item_id} contains multiple headings")
        header = headings[0]
        if header.kind != kind:
            raise ValueError(f"truth heading does not match {kind}:{item_id}")
        if heading_label:
            if _canonical_heading_label(heading_label) != _canonical_heading_label(header.label):
                raise ValueError(f"truth heading_label does not match {kind}:{item_id}")
        elif kind != "proof" and header.number:
            # Preserve the concise v1 manifest form for numbered formal items.
            if header.number.rstrip(".") != item_id.rstrip("."):
                raise ValueError(f"truth heading does not match {kind}:{item_id}")
        heading_label = heading_label or header.label
        tokens = _normalise_item(source)
        if not tokens:
            raise ValueError(f"truth item {kind}:{item_id} has an empty body")
        seen.add(key)
        occupied.append((start, end, f"{kind}:{item_id}"))
        result.append(TruthItem(
            kind=kind,
            item_id=item_id,
            heading_label=heading_label,
            heading_number=header.number,
            start_line=start,
            end_line=end,
            tokens=tokens,
        ))
    return result


def _infer_truth_items(text: str) -> list[TruthItem]:
    lines = text.splitlines()
    raw: list[dict[str, object]] = []
    for heading in _find_source_headings(text):
        line_number = heading.line
        end = line_number
        while end < len(lines) and lines[end].strip():
            end += 1
        item_id = (
            heading.number
            if heading.number
            else f"{'P' if heading.kind == 'proof' else heading.kind}@L{line_number}"
        )
        raw.append({
            "kind": heading.kind,
            "id": item_id,
            "heading_label": heading.label,
            "start_line": line_number,
            "end_line": end,
        })
    if not raw:
        raise ValueError("no formal truth items were discovered")
    return _validate_truth_items(raw, lines)


def load_truth(text: str, manifest: dict[str, object] | None) -> list[TruthItem]:
    if manifest is None:
        return _infer_truth_items(text)
    if not isinstance(manifest, dict) or manifest.get("schema") != TRUTH_SCHEMA:
        raise ValueError(f"truth manifest schema must be {TRUTH_SCHEMA!r}")
    return _validate_truth_items(manifest.get("items"), text.splitlines())


def _validate_truth_headings(
    raw_headings: object, lines: Sequence[str]
) -> list[TruthHeading]:
    if not isinstance(raw_headings, list):
        raise ValueError("truth manifest headings must be an array")
    result: list[TruthHeading] = []
    for index, raw in enumerate(raw_headings):
        if not isinstance(raw, dict):
            raise ValueError(f"truth heading {index} must be an object")
        level = raw.get("level")
        title = raw.get("title")
        start = raw.get("start_line")
        end = raw.get("end_line")
        if isinstance(level, bool) or not isinstance(level, int) or level < 0:
            raise ValueError(f"truth heading {index} has invalid level")
        if not isinstance(title, str) or not title.strip():
            raise ValueError(f"truth heading {index} has invalid title")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end > len(lines)
        ):
            raise ValueError(f"truth heading {index} has invalid line bounds")
        expected_key = _outline_title(title)
        source = "\n".join(lines[start - 1:end])
        source_key = _outline_title(source)
        if not expected_key or source_key != expected_key:
            raise ValueError(f"truth heading {index} title does not match source lines")
        result.append(TruthHeading(
            level=level,
            title=title.strip(),
            title_key=expected_key,
            start_line=start,
            end_line=end,
        ))
    return result


def load_truth_headings(
    text: str, manifest: dict[str, object] | None
) -> tuple[list[TruthHeading] | None, bool]:
    """Return reviewed headings and whether the manifest explicitly supplied them."""
    if manifest is None or "headings" not in manifest:
        return None, False
    return _validate_truth_headings(manifest.get("headings"), text.splitlines()), True


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _id_from_title(kind: str, title: str, body: str) -> str:
    if kind == "proof":
        return ""
    number = re.search(r"(?<!\d)(\d+(?:\.\d+)+|\d+)(?!\d)", title)
    if number:
        return number.group(1).rstrip(".")
    heading = next((
        value for value in _find_source_headings(body)
        if value.kind == kind and value.number
    ), None)
    if heading is not None:
        return heading.number.rstrip(".")
    label = re.search(
        rf"\\label\s*\{{(?:{kind[:3]}|{kind})[:._-]?(\d+(?:\.\d+)*)\}}",
        body,
        flags=re.IGNORECASE,
    )
    return label.group(1) if label else ""


def extract_candidate_environments(text: str) -> list[CandidateEnvironment]:
    environments: list[CandidateEnvironment] = []
    cursor = 0
    while True:
        begin = ENV_BEGIN_RE.search(text, cursor)
        if not begin:
            break
        kind = begin.group("kind").casefold()
        env_name = kind + ("*" if begin.group("star") else "")
        end_re = re.compile(rf"\\end\{{{re.escape(env_name)}\}}", re.IGNORECASE)
        end = end_re.search(text, begin.end())
        if not end:
            # An unbalanced candidate is a prediction with a body extending to
            # EOF.  Keeping it makes the scorer fail closed instead of hiding it.
            body_start = begin.end()
            body_end = len(text)
            end_offset = len(text)
        else:
            body_start = begin.end()
            body_end = end.start()
            end_offset = end.end()
        title = ""
        title_match = re.match(r"\s*\[([^\]\n]*)\]", text[body_start:body_end])
        if title_match:
            title = title_match.group(1)
            body_start += title_match.end()
        body = text[body_start:body_end]
        environments.append(CandidateEnvironment(
            kind=kind,
            item_id=_id_from_title(kind, title, body),
            start_line=_line_number(text, begin.start()),
            end_line=_line_number(text, end_offset),
            start_offset=begin.start(),
            end_offset=end_offset,
            tokens=_normalise_item(body),
        ))
        cursor = max(end_offset, begin.end())
    return environments


def _is_contiguous(needle: Sequence[str], haystack: Sequence[str]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    width = len(needle)
    return any(tuple(haystack[index:index + width]) == tuple(needle)
               for index in range(len(haystack) - width + 1))


def _outline_title(title: str) -> str:
    title = re.sub(r"\\(?:begin|end)\{center\}", " ", title, flags=re.IGNORECASE)
    title = _flatten_presentation(title)
    title = re.sub(r"^\s*\d+(?:\.\d+)*\.?\s*", "", title)
    title = title.rstrip(" .")
    tokens = re.findall(r"[^\W_]+", title.casefold(), flags=re.UNICODE)
    return "".join(tokens)


def extract_outline(text: str) -> list[dict[str, object]]:
    body = _strip_comments(_document_body(text))
    command_nodes: list[tuple[int, str, int]] = []
    ranks = {"part": 0, "chapter": 1, "section": 2, "subsection": 3,
             "subsubsection": 4}
    for match in OUTLINE_COMMAND_RE.finditer(body):
        opening = body.find("{", match.start(), match.end())
        end = _balanced_group_end(body, opening)
        if end is None:
            continue
        title = body[opening + 1:end - 1]
        command_nodes.append((match.start(), title, ranks[match.group("command").casefold()]))
    min_rank = min((rank for _, _, rank in command_nodes), default=2)
    nodes: list[dict[str, object]] = [
        {
            "level": rank - min_rank,
            "title": _outline_title(title),
            "line": _line_number(body, offset),
        }
        for offset, title, rank in command_nodes
        if _outline_title(title)
    ]
    for match in INLINE_OUTLINE_RE.finditer(body):
        number = match.group("number")
        title = _outline_title(match.group("title"))
        if title:
            nodes.append({
                "level": number.count("."),
                "title": title,
                "line": _line_number(body, match.start()),
            })
    occupied_lines = {int(item["line"]) for item in nodes}
    for match in PLAIN_OUTLINE_RE.finditer(body):
        line = _line_number(body, match.start())
        title_text = match.group("title").strip()
        number = match.group("number")
        if line in occupied_lines or (number is None and title_text.casefold() != "references"):
            continue
        title = _outline_title(title_text)
        if title:
            nodes.append({"level": 0, "title": title, "line": line})
    bibliography = re.search(r"\\begin\{thebibliography\}\s*\{", body)
    if bibliography and not any(item["title"] == "references" for item in nodes):
        nodes.append({
            "level": 0,
            "title": "references",
            "line": _line_number(body, bibliography.start()),
        })
    nodes.sort(key=lambda item: int(item["line"]))
    return nodes


def _masked_outside_environments(
    text: str, environments: Iterable[CandidateEnvironment]
) -> str:
    chars = list(text)
    for environment in environments:
        chars[environment.start_offset:environment.end_offset] = (
            " " * (environment.end_offset - environment.start_offset)
        )
    return "".join(chars)


def _masked_truth_heading_lines(text: str, headings: Sequence[TruthHeading]) -> str:
    if not headings:
        return text
    chars = list(text)
    line_offsets: list[tuple[int, int]] = []
    cursor = 0
    for line in text.splitlines(keepends=True):
        line_offsets.append((cursor, cursor + len(line.rstrip("\r\n"))))
        cursor += len(line)
    for heading in headings:
        for line_number in range(heading.start_line, heading.end_line + 1):
            start, end = line_offsets[line_number - 1]
            chars[start:end] = " " * (end - start)
    return "".join(chars)


def _line_token_deficits(original: str, candidate: str) -> tuple[list[int], list[int]]:
    def document_lines(text: str) -> list[tuple[int, str]]:
        lines = text.splitlines()
        start = next(
            (index for index, line in enumerate(lines)
             if re.search(r"\\begin\{document\}", line)),
            -1,
        )
        end = next(
            (index for index, line in enumerate(lines[start + 1:], start=start + 1)
             if re.search(r"\\end\{document\}", line)),
            len(lines),
        )
        return [(index + 1, lines[index]) for index in range(start + 1, end)]

    original_lines = document_lines(original)
    candidate_lines = document_lines(candidate)

    def line_tokens(line: str) -> tuple[str, ...]:
        return _normalise_fragment(line)

    original_units = [
        (line_number, tokens)
        for line_number, line in original_lines
        if (tokens := line_tokens(line))
    ]
    candidate_units = [
        (line_number, tokens)
        for line_number, line in candidate_lines
        if (tokens := line_tokens(line))
    ]
    matcher = difflib.SequenceMatcher(
        a=[tokens for _, tokens in original_units],
        b=[tokens for _, tokens in candidate_units],
        autojunk=False,
    )
    missing: list[int] = []
    excess: list[int] = []
    for operation, left_start, left_end, right_start, right_end in matcher.get_opcodes():
        if operation in {"delete", "replace"}:
            missing.extend(line for line, _ in original_units[left_start:left_end])
        if operation in {"insert", "replace"}:
            excess.extend(line for line, _ in candidate_units[right_start:right_end])
    return missing, excess


def _first_difference(left: Sequence[str], right: Sequence[str]) -> int | None:
    for index, (left_token, right_token) in enumerate(zip(left, right)):
        if left_token != right_token:
            return index
    return None if len(left) == len(right) else min(len(left), len(right))


def evaluate_tex_structure(
    original: str,
    candidate: str,
    *,
    manifest: dict[str, object] | None = None,
    threshold: float = 0.95,
    require_toc: bool = True,
    original_binary_sha256: str | None = None,
    candidate_binary_sha256: str | None = None,
) -> dict[str, object]:
    """Return a content-free, JSON-serialisable accuracy report."""
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between zero and one")
    for name, value in (
        ("original_binary_sha256", original_binary_sha256),
        ("candidate_binary_sha256", candidate_binary_sha256),
    ):
        if value is not None and re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ValueError(f"{name} must be a 64-character hexadecimal digest")
    original_binary_digest = (
        original_binary_sha256.casefold()
        if original_binary_sha256 is not None
        else _sha256_bytes(original.encode("utf-8"))
    )
    candidate_binary_digest = (
        candidate_binary_sha256.casefold()
        if candidate_binary_sha256 is not None
        else _sha256_bytes(candidate.encode("utf-8"))
    )
    original_text_digest = _normalised_text_sha256(original)
    candidate_text_digest = _normalised_text_sha256(candidate)
    truth = load_truth(original, manifest)
    reviewed_headings, headings_explicit = load_truth_headings(original, manifest)
    predicted = extract_candidate_environments(candidate)

    used_predictions: set[int] = set()
    exact_matches: list[dict[str, object]] = []
    missing: list[str] = []
    boundary_errors: list[dict[str, object]] = []
    duplicates: list[dict[str, object]] = []

    def same_structural_key(expected: TruthItem, item: CandidateEnvironment) -> bool:
        if item.kind != expected.kind:
            return False
        # Proofs and unnumbered formal items have no stable identifier in the
        # rendered LaTeX environment.  Their reviewed body tokens are the key.
        if expected.kind == "proof" or not expected.heading_number:
            return True
        return item.item_id.rstrip(".") == expected.heading_number.rstrip(".")

    matched_prediction_for_truth: dict[int, int] = {}
    unresolved_truth: list[int] = []
    # Match every reviewed item by exact body tokens before diagnosing any
    # partial boundary.  This prevents one proof from stealing another proof's
    # exact candidate merely because both use the same environment name.
    for truth_index, expected in enumerate(truth):
        exact = [
            (index, item) for index, item in enumerate(predicted)
            if index not in used_predictions
            and same_structural_key(expected, item)
            and item.tokens == expected.tokens
        ]
        if not exact:
            unresolved_truth.append(truth_index)
            continue
        chosen_index, chosen = exact[0]
        used_predictions.add(chosen_index)
        matched_prediction_for_truth[truth_index] = chosen_index
        exact_matches.append({
            "kind": expected.kind,
            "id": expected.item_id,
            "candidate_start_line": chosen.start_line,
            "candidate_end_line": chosen.end_line,
        })

    for truth_index in unresolved_truth:
        expected = truth[truth_index]
        missing.append(f"{expected.kind}:{expected.item_id}")
        candidates = [
            (index, item) for index, item in enumerate(predicted)
            if index not in used_predictions and same_structural_key(expected, item)
        ]
        if expected.kind == "proof" or not expected.heading_number:
            candidates = [
                (index, item) for index, item in candidates
                if _is_contiguous(item.tokens, expected.tokens)
                or _is_contiguous(expected.tokens, item.tokens)
            ]
        if not candidates:
            continue
        index, closest = min(
            candidates,
            key=lambda pair: abs(len(pair[1].tokens) - len(expected.tokens)),
        )
        used_predictions.add(index)
        if _is_contiguous(expected.tokens, closest.tokens):
            error = "overwrapped"
        elif _is_contiguous(closest.tokens, expected.tokens):
            error = "underwrapped"
        else:
            error = "content_mismatch"
        boundary_errors.append({
            "kind": expected.kind,
            "id": expected.item_id,
            "error": error,
            "candidate_start_line": closest.start_line,
            "candidate_end_line": closest.end_line,
        })

    duplicate_predictions: dict[int, list[int]] = {}
    for prediction_index, item in enumerate(predicted):
        if prediction_index in used_predictions:
            continue
        matching_truth = next((
            truth_index for truth_index, expected in enumerate(truth)
            if same_structural_key(expected, item) and item.tokens == expected.tokens
        ), None)
        if matching_truth is not None:
            duplicate_predictions.setdefault(matching_truth, []).append(prediction_index)
    for truth_index, prediction_indexes in duplicate_predictions.items():
        expected = truth[truth_index]
        primary = matched_prediction_for_truth.get(truth_index)
        all_indexes = ([primary] if primary is not None else []) + prediction_indexes
        duplicates.append({
            "kind": expected.kind,
            "id": expected.item_id,
            "candidate_lines": [predicted[index].start_line for index in all_indexes],
        })

    unmatched = [
        {
            "kind": item.kind,
            "id": item.item_id or None,
            "start_line": item.start_line,
            "end_line": item.end_line,
        }
        for index, item in enumerate(predicted)
        if index not in used_predictions
    ]
    true_positive = len(exact_matches)
    expected_count = len(truth)
    predicted_count = len(predicted)
    precision = true_positive / predicted_count if predicted_count else 0.0
    recall = true_positive / expected_count if expected_count else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    outside = _masked_outside_environments(candidate, predicted)
    residual = [
        {
            "kind": heading.kind,
            "id": heading.number or None,
            "line": heading.line,
        }
        for heading in _find_source_headings(outside)
    ]

    original_body_source = (
        _masked_truth_heading_lines(original, reviewed_headings)
        if reviewed_headings is not None
        else original
    )
    original_tokens = _normalise_fragment(original_body_source, document_scope=True)
    candidate_tokens = _normalise_fragment(candidate, document_scope=True)
    original_counter = Counter(original_tokens)
    candidate_counter = Counter(candidate_tokens)
    missing_token_count = sum((original_counter - candidate_counter).values())
    excess_token_count = sum((candidate_counter - original_counter).values())
    token_conserved = original_tokens == candidate_tokens
    missing_lines, excess_lines = (
        ([], [])
        if token_conserved
        else _line_token_deficits(original_body_source, candidate)
    )

    if reviewed_headings is None:
        expected_outline = extract_outline(original)
    else:
        expected_outline = [
            {
                "level": heading.level,
                "title": heading.title_key,
                "line": heading.start_line,
            }
            for heading in reviewed_headings
        ]
    candidate_outline = extract_outline(candidate)
    expected_outline_counts = Counter(
        (item["level"], item["title"]) for item in expected_outline
    )
    candidate_outline_counts = Counter(
        (item["level"], item["title"]) for item in candidate_outline
    )
    outline_matched = sum((expected_outline_counts & candidate_outline_counts).values())
    outline_total = sum(expected_outline_counts.values())
    outline_coverage = outline_matched / outline_total if outline_total else 1.0
    missing_outline = [
        {"level": level, "title_hash": _sha256_text(str(title))[:16]}
        for (level, title), count in (expected_outline_counts - candidate_outline_counts).items()
        for _ in range(count)
    ]
    unexpected_outline = [
        {"level": level, "title_hash": _sha256_text(str(title))[:16]}
        for (level, title), count in (candidate_outline_counts - expected_outline_counts).items()
        for _ in range(count)
    ]
    toc_present = bool(re.search(
        r"\\tableofcontents\b", _strip_comments(_document_body(candidate))
    ))

    blockers = {
        "missing": bool(missing),
        "duplicate": bool(duplicates),
        "boundary_error": bool(boundary_errors),
        "unmatched_environment": bool(unmatched),
        "residual_formal_heading": bool(residual),
        "body_token_change": not token_conserved,
        "outline_incomplete": outline_coverage < 1.0 or bool(unexpected_outline),
        "toc_missing": require_toc and not toc_present,
    }
    score_passed = f1 >= threshold
    passed = score_passed and not any(blockers.values())
    return {
        "schema": "latexstruct-tex-structure-accuracy-report-v1",
        "passed": passed,
        "threshold": threshold,
        "score_passed": score_passed,
        "inputs": {
            "original": {
                "binary_sha256": original_binary_digest,
                "normalized_text_sha256": original_text_digest,
            },
            "candidate": {
                "binary_sha256": candidate_binary_digest,
                "normalized_text_sha256": candidate_text_digest,
            },
            "original_binary_sha256": original_binary_digest,
            "candidate_binary_sha256": candidate_binary_digest,
            "original_normalized_text_sha256": original_text_digest,
            "candidate_normalized_text_sha256": candidate_text_digest,
            # Deprecated v1 aliases retained for report consumers.  They have
            # always represented decoded text, never arbitrary file bytes.
            "original_sha256": original_text_digest,
            "candidate_sha256": candidate_text_digest,
            "binary_sha256_source": (
                "file-bytes"
                if original_binary_sha256 is not None and candidate_binary_sha256 is not None
                else "utf8-serialization"
            ),
            "truth_mode": "manifest" if manifest is not None else "auto-discovery",
            "outline_truth_mode": "manifest" if headings_explicit else "auto-discovery",
            "release_evidence_eligible": manifest is not None and headings_explicit,
        },
        "exact_structure": {
            "true_positive": true_positive,
            "predicted": predicted_count,
            "expected": expected_count,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "matches": exact_matches,
            "missing": missing,
            "duplicates": duplicates,
            "boundary_errors": boundary_errors,
            "unmatched_environments": unmatched,
        },
        "residual_formal_headings": residual,
        "body_token_conservation": {
            "conserved": token_conserved,
            "original_token_count": len(original_tokens),
            "candidate_token_count": len(candidate_tokens),
            "missing_token_count": missing_token_count,
            "excess_token_count": excess_token_count,
            "first_difference_index": _first_difference(original_tokens, candidate_tokens),
            "missing_original_lines": missing_lines,
            "excess_candidate_lines": excess_lines,
        },
        "document_structure": {
            "toc_required": require_toc,
            "toc_present": toc_present,
            "outline_truth_mode": "manifest" if headings_explicit else "auto-discovery",
            "expected_outline_nodes": outline_total,
            "candidate_outline_nodes": sum(candidate_outline_counts.values()),
            "matched_outline_nodes": outline_matched,
            "outline_coverage": outline_coverage,
            "missing_outline_nodes": missing_outline,
            "unexpected_outline_nodes": unexpected_outline,
        },
        "blockers": blockers,
    }


def _load_manifest(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("truth manifest must be a JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path, help="original LaTeX file")
    parser.add_argument("candidate", type=Path, help="structured candidate LaTeX file")
    parser.add_argument("--truth", type=Path, help="reviewed JSON truth manifest")
    parser.add_argument("--threshold", type=float, default=0.95)
    parser.add_argument("--no-require-toc", action="store_true")
    parser.add_argument("--json-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    original_bytes = args.original.read_bytes()
    candidate_bytes = args.candidate.read_bytes()
    report = evaluate_tex_structure(
        original_bytes.decode("utf-8-sig"),
        candidate_bytes.decode("utf-8-sig"),
        manifest=_load_manifest(args.truth),
        threshold=args.threshold,
        require_toc=not args.no_require_toc,
        original_binary_sha256=_sha256_bytes(original_bytes),
        candidate_binary_sha256=_sha256_bytes(candidate_bytes),
    )
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

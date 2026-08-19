# -*- coding: utf-8 -*-
"""Fail-closed OCR typography and soft-line-break evidence.

This module is deliberately independent from the OCR job runner.  It extracts
JSON-serialisable evidence from a PDF ``rawdict`` payload, validates an active
LaTeX fragment against that evidence, and produces bounded retry data.  It does
not edit LaTeX, call a model, or mutate a job.

The PDF text layer is untrusted.  It can nominate exact glyph occurrences and
their geometry, but its text is never interpreted as an instruction and is
never copied to retry data unless it passes a narrow printable-text allowlist.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .invariants import math_tokens
from .parser import PROTECTED_ENVS, find_env_ranges, mask_comments, parse_latex

SCHEMA_VERSION = 1
MATH_SENTINEL = "\ufff0"

_MATH_FONT_RE = re.compile(
    r"(?:math|cmmi|cmsy|cmex|msam|msbm|symbol|stix.*math)", re.I,
)
_ITALIC_FONT_RE = re.compile(
    r"(?:italic|oblique|slant|(?:^|[-_])it(?:[-_]|\d|$)|cmti)",
    re.I,
)
_SMALL_CAPS_FONT_RE = re.compile(
    r"(?:small.?caps?|cmcsc|(?:^|[-_])sc(?:[-_]|\d|$))", re.I,
)
_BOLD_FONT_RE = re.compile(r"(?:bold|cmbx|(?:^|[-_])(?:bd|bf)(?:[-_]|\d|$))", re.I)
_MONO_FONT_RE = re.compile(r"(?:mono|courier|cmtt|typewriter)", re.I)
_EXERCISE_NUMBER_RE = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")
_LINE_END_FRAGMENT_RE = re.compile(r"([A-Za-z]{2,})-$")
_LINE_START_FRAGMENT_RE = re.compile(r"^([a-z]{2,})")
_WORD_RE = re.compile(r"(?<![A-Za-z])([A-Za-z]{3,})(?![A-Za-z-])")
_HYPHENATED_WORD_RE = re.compile(
    r"(?<![A-Za-z])([A-Za-z]{2,}(?:-[A-Za-z]{2,})+)(?![A-Za-z])",
)
_STYLE_COMMANDS = {"emph": "italic", "textit": "italic", "textsc": "smallcaps"}
_INVISIBLE_COMMANDS = {
    "begin", "end", "centering", "clearpage", "hfill", "noindent", "newpage",
    "pagebreak", "quad", "qquad", "vfill", "vspace", "hspace", "includegraphics",
}
_TEXT_ARGUMENT_COMMANDS = {
    "mbox", "operatorname", "text", "textbf", "textrm", "textnormal", "textsuperscript",
}
_SAFE_FEEDBACK_PUNCTUATION = frozenset(" .,:;!?()[]'\"\u2019/-\u2013\u2014+&")
_PDF_SPACING_DIACRITICS = {
    "\u00b4": "\u0301",  # TeX/PDF text layers commonly emit acute before its base.
    "\u02dd": "\u030b",  # Likewise for Hungarian double acute (for example Erd\H{o}s).
}
_LATEX_SYMBOL_ACCENTS = {"'": "\u0301"}
_LATEX_NAMED_ACCENTS = {"H": "\u030b"}
_ACTIVE_CONTROL_RE = re.compile(r"\\([A-Za-z@]+|.)", re.S)
_INLINE_VERB_CAPTURE_RE = re.compile(r"\\verb\*?([^A-Za-z\s\\])([\s\S]*?)\1")


@dataclass(frozen=True)
class _VisibleUnit:
    kind: str
    text: str
    source_start: int
    source_end: int
    styles: tuple[str, ...] = ()


def _finite_bbox(value) -> list[float] | None:
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return None
    try:
        result = [float(item) for item in value]
    except (TypeError, ValueError):
        return None
    if not all(math.isfinite(item) for item in result):
        return None
    if result[2] < result[0] or result[3] < result[1]:
        return None
    return result


def _union_bbox(values: Iterable[Sequence[float]]) -> list[float] | None:
    boxes = [list(value) for value in values if _finite_bbox(value) is not None]
    if not boxes:
        return None
    return [
        min(box[0] for box in boxes), min(box[1] for box in boxes),
        max(box[2] for box in boxes), max(box[3] for box in boxes),
    ]


def _normalized_bbox(bbox: Sequence[float], width: float, height: float) -> list[float]:
    return [
        round(float(bbox[0]) / width, 6), round(float(bbox[1]) / height, 6),
        round(float(bbox[2]) / width, 6), round(float(bbox[3]) / height, 6),
    ]


def _font_name(value: object) -> str:
    name = str(value or "").strip()
    return name.split("+", 1)[-1]


def _font_class(font: str, flags: int = 0) -> str:
    name = _font_name(font)
    if _MATH_FONT_RE.search(name):
        return "math_italic" if (_ITALIC_FONT_RE.search(name) or "cmmi" in name.lower()) else "math"
    if _SMALL_CAPS_FONT_RE.search(name):
        return "small_caps_text"
    if flags & 2 or _ITALIC_FONT_RE.search(name):
        return "text_italic"
    if flags & 16 or _BOLD_FONT_RE.search(name):
        return "bold_text"
    if flags & 8 or _MONO_FONT_RE.search(name):
        return "monospace_text"
    return "roman_text"


def _span_text(span: Mapping) -> str:
    chars = span.get("chars")
    if isinstance(chars, list):
        value = "".join(
            str(character.get("c") or "")
            for character in chars
            if isinstance(character, Mapping)
        )
    else:
        value = str(span.get("text") or "")
    value = unicodedata.normalize("NFC", value).replace("\x00", "")
    return "".join(" " if character in "\r\n\t" else character for character in value)


def _span_bbox(span: Mapping) -> list[float] | None:
    bbox = _finite_bbox(span.get("bbox"))
    if bbox is not None:
        return bbox
    chars = span.get("chars")
    if not isinstance(chars, list):
        return None
    return _union_bbox(
        character.get("bbox")
        for character in chars
        if isinstance(character, Mapping)
    )


def _compose_pdf_spacing_diacritics(value: object) -> str:
    """Compose the two spacing accents observed in the source's TeX text layer.

    A spacing mark is accepted only immediately before an alphabetic base.  A
    stray mark survives this function and is subsequently rejected by the
    evidence-text allowlist.
    """
    source = str(value or "")
    result: list[str] = []
    index = 0
    while index < len(source):
        combining = _PDF_SPACING_DIACRITICS.get(source[index])
        if combining and index + 1 < len(source) and source[index + 1].isalpha():
            result.extend((source[index + 1], combining))
            index += 2
            continue
        result.append(source[index])
        index += 1
    return unicodedata.normalize("NFC", "".join(result))


def _safe_evidence_text(value: object, *, limit: int = 160) -> str:
    text = _compose_pdf_spacing_diacritics(value).strip()
    if not text or len(text) > limit or any(character in "\\{}%#$^_~`" for character in text):
        return ""
    for character in text:
        if character.isalnum() or character.isspace() or character in _SAFE_FEEDBACK_PUNCTUATION:
            continue
        category = unicodedata.category(character)
        if category.startswith(("L", "M")):
            continue
        return ""
    return " ".join(text.split())


def _canonical_text(value: object, *, casefold: bool = True) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = " ".join(text.split())
    return text.casefold() if casefold else text


def _looks_like_acronym(value: str) -> bool:
    letters = [character for character in value if character.isalpha()]
    return 2 <= len(letters) <= 8 and all(character.isupper() for character in letters)


def build_document_lexicon(text: str) -> dict[str, int]:
    """Count intact plain and hyphenated words in deterministic document text."""
    normalized = unicodedata.normalize("NFKC", str(text or ""))
    counts: Counter[str] = Counter()
    for match in _HYPHENATED_WORD_RE.finditer(normalized):
        counts[match.group(1).casefold()] += 1
    for match in _WORD_RE.finditer(normalized):
        counts[match.group(1).casefold()] += 1
    return dict(sorted(counts.items()))


def merge_document_lexicons(*lexicons: Mapping[str, int]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for lexicon in lexicons:
        for word, raw_count in (lexicon or {}).items():
            try:
                count = int(raw_count)
            except (TypeError, ValueError):
                continue
            if count > 0 and re.fullmatch(r"[A-Za-z]{2,}(?:-[A-Za-z]{2,})*", str(word)):
                counts[str(word).casefold()] += count
    return dict(sorted(counts.items()))


def classify_soft_line_break(
    left_fragment: str,
    right_fragment: str,
    document_lexicon: Mapping[str, int] | None = None,
    *,
    minimum_count: int = 2,
) -> dict:
    """Return JOIN/KEEP/AMBIGUOUS from positive, document-local lexical evidence."""
    left = str(left_fragment or "")
    right = str(right_fragment or "")
    if not re.fullmatch(r"[A-Za-z]{2,}", left) or not re.fullmatch(r"[a-z]{2,}", right):
        return {"decision": "ambiguous", "joined_count": 0, "hyphenated_count": 0}
    joined = (left + right).casefold()
    hyphenated = (left + "-" + right).casefold()
    counts = document_lexicon or {}
    try:
        joined_count = max(0, int(counts.get(joined, 0)))
        hyphenated_count = max(0, int(counts.get(hyphenated, 0)))
    except (TypeError, ValueError):
        joined_count = hyphenated_count = 0
    if joined_count >= minimum_count and hyphenated_count == 0:
        decision = "join"
    elif hyphenated_count >= minimum_count and joined_count == 0:
        decision = "keep"
    else:
        decision = "ambiguous"
    return {
        "decision": decision,
        "joined_count": joined_count,
        "hyphenated_count": hyphenated_count,
    }


def _rawdict_lines(payload: Mapping) -> tuple[list[dict], float, float]:
    try:
        width = float(payload.get("width") or 0.0)
        height = float(payload.get("height") or 0.0)
    except (TypeError, ValueError):
        return [], 0.0, 0.0
    if not math.isfinite(width) or not math.isfinite(height) or width <= 0 or height <= 0:
        return [], 0.0, 0.0
    result = []
    for block_index, block in enumerate(payload.get("blocks") or []):
        if not isinstance(block, Mapping) or int(block.get("type") or 0) != 0:
            continue
        for line_index, line in enumerate(block.get("lines") or []):
            if not isinstance(line, Mapping):
                continue
            direction = line.get("dir") or (1.0, 0.0)
            try:
                horizontal = abs(float(direction[1])) <= 0.05 and float(direction[0]) > 0.0
            except (TypeError, ValueError, IndexError):
                horizontal = False
            if not horizontal:
                continue
            spans = []
            for span_index, span in enumerate(line.get("spans") or []):
                if not isinstance(span, Mapping):
                    continue
                text = _span_text(span)
                bbox = _span_bbox(span)
                if not text or bbox is None:
                    continue
                try:
                    flags = int(span.get("flags") or 0)
                    size = float(span.get("size") or max(1.0, bbox[3] - bbox[1]))
                except (TypeError, ValueError):
                    flags, size = 0, max(1.0, bbox[3] - bbox[1])
                font = _font_name(span.get("font"))
                spans.append({
                    "index": span_index,
                    "text": text,
                    "bbox": bbox,
                    "font": font,
                    "flags": flags,
                    "size": size,
                    "font_class": _font_class(font, flags),
                })
            if not spans:
                continue
            bbox = _finite_bbox(line.get("bbox")) or _union_bbox(span["bbox"] for span in spans)
            if bbox is None:
                continue
            result.append({
                "block_index": block_index,
                "line_index": line_index,
                "line_id": f"b{block_index}-l{line_index}",
                "bbox": bbox,
                "spans": spans,
                "text": "".join(span["text"] for span in spans),
            })
    return result, width, height


def _percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    position = max(0.0, min(1.0, fraction)) * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _body_lines(lines: Sequence[dict], height: float) -> list[dict]:
    return [
        line for line in lines
        if line["bbox"][1] >= 0.075 * height and line["bbox"][3] <= 0.94 * height
    ]


def _adjacent_spans(left: Mapping, right: Mapping) -> bool:
    size = max(1.0, float(left.get("size") or 0), float(right.get("size") or 0))
    gap = float(right["bbox"][0]) - float(left["bbox"][2])
    overlap = min(left["bbox"][3], right["bbox"][3]) - max(
        left["bbox"][1], right["bbox"][1],
    )
    min_height = min(
        left["bbox"][3] - left["bbox"][1], right["bbox"][3] - right["bbox"][1],
    )
    return -0.15 * size <= gap <= max(1.5, 0.35 * size) and overlap >= 0.55 * min_height


def _merge_style_spans(spans: Sequence[dict], font_class: str) -> list[dict]:
    groups: list[list[dict]] = []
    for span in spans:
        if span["font_class"] != font_class:
            continue
        if groups and _adjacent_spans(groups[-1][-1], span):
            groups[-1].append(span)
        else:
            groups.append([span])
    result = []
    for group in groups:
        result.append({
            "first_index": group[0]["index"],
            "last_index": group[-1]["index"],
            "text": "".join(item["text"] for item in group),
            "bbox": _union_bbox(item["bbox"] for item in group),
            "font_names": sorted({item["font"] for item in group}),
            "size_pt": round(sum(item["size"] for item in group) / len(group), 4),
            "font_class": font_class,
        })
    return result


def _line_match_parts(line: Mapping, first_index: int, last_index: int) -> tuple[str, str]:
    before, after = [], []
    before_math = after_math = False
    for span in line["spans"]:
        target = before if span["index"] < first_index else after if span["index"] > last_index else None
        if target is None:
            continue
        is_math = span["font_class"].startswith("math")
        if is_math:
            already = before_math if target is before else after_math
            if not already:
                target.append(MATH_SENTINEL)
            if target is before:
                before_math = True
            else:
                after_math = True
        else:
            target.append(span["text"])
            if target is before:
                before_math = False
            else:
                after_math = False
    return _canonical_text("".join(before))[-48:], _canonical_text("".join(after))[:48]


def extract_rawdict_ocr_style_evidence(
    payload: Mapping,
    page_no: int,
    *,
    document_lexicon: Mapping[str, int] | None = None,
) -> dict:
    """Extract occurrence-level, JSON-safe evidence from one PyMuPDF rawdict page."""
    lines, width, height = _rawdict_lines(payload)
    if not lines:
        return {
            "schema_version": SCHEMA_VERSION, "page": int(page_no),
            "page_size_points": [], "column_bbox_normalized": [],
            "style_runs": [], "soft_line_breaks": [],
        }
    body = _body_lines(lines, height)
    if not body:
        # A sparse header/footer-only page provides no trustworthy body
        # geometry.  Returning no evidence is safer than promoting furniture.
        return {
            "schema_version": SCHEMA_VERSION, "page": int(page_no),
            "page_size_points": [round(width, 4), round(height, 4)],
            "column_bbox_normalized": [],
            "style_runs": [], "soft_line_breaks": [],
        }
    column_left = _percentile([line["bbox"][0] for line in body], 0.10)
    column_right = _percentile([line["bbox"][2] for line in body], 0.90)
    column_top = min(line["bbox"][1] for line in body)
    column_bottom = max(line["bbox"][3] for line in body)

    style_runs = []
    for line in body:
        spans = line["spans"]
        bold_numbers = [
            span for span in spans
            if span["font_class"] == "bold_text" and _EXERCISE_NUMBER_RE.search(span["text"])
        ]
        line_text = line["text"].strip()
        exercise_title_line = bool(
            bold_numbers
            and len(line_text) <= 100
            and not line_text.endswith((".", "?", "!", ":", ";"))
        )
        parenthesized_credit = (
            len(line_text) <= 100
            and line_text.startswith("(") and line_text.endswith(")")
            and line["bbox"][2] >= column_right - max(3.0, 0.8 * max(
                span["size"] for span in spans
            ))
        )
        for font_class, style in (
            ("text_italic", "italic"), ("small_caps_text", "smallcaps"),
        ):
            for group in _merge_style_spans(spans, font_class):
                text = group["text"]
                safe_text = _safe_evidence_text(text)
                first_position = next(
                    (index for index, span in enumerate(spans) if span["index"] == group["first_index"]),
                    -1,
                )
                left_neighbor = spans[first_position - 1] if first_position > 0 else None
                math_suffix = bool(
                    style == "italic"
                    and safe_text.startswith("-")
                    and left_neighbor
                    and left_neighbor["font_class"].startswith("math")
                    and _adjacent_spans(left_neighbor, {
                        "bbox": group["bbox"], "size": group["size_pt"],
                    })
                )
                if style == "smallcaps" and exercise_title_line:
                    role = "exercise_title"
                elif style == "smallcaps" and parenthesized_credit:
                    role = "credit"
                elif math_suffix:
                    role = "math_compound_suffix"
                else:
                    role = "other"
                context_before, context_after = _line_match_parts(
                    line, group["first_index"], group["last_index"],
                )
                if role == "credit":
                    # Parentheses are sometimes encoded in the small-caps font
                    # although delimiters are not part of the credited name.
                    if safe_text.startswith("("):
                        safe_text = safe_text[1:].lstrip()
                        context_before += "("
                    if safe_text.endswith(")"):
                        safe_text = safe_text[:-1].rstrip()
                        context_after = ")" + context_after
                actionable = bool(
                    safe_text
                    and (
                        style == "italic" and math_suffix
                        or style == "smallcaps"
                        and role in {"exercise_title", "credit"}
                        and not _looks_like_acronym(safe_text)
                    )
                )
                record = {
                    "evidence_id": (
                        f"p{int(page_no)}-{line['line_id']}-s{group['first_index']}-{style}"
                    ),
                    "kind": "style_run",
                    "style": style,
                    "role": role,
                    "source_text": safe_text,
                    "safe_for_feedback": bool(safe_text),
                    "actionable": actionable,
                    "line_id": line["line_id"],
                    "bbox_normalized": _normalized_bbox(group["bbox"], width, height),
                    "font": {
                        "names": group["font_names"],
                        "size_pt": group["size_pt"],
                        "class": group["font_class"],
                    },
                    "context_before": context_before,
                    "context_after": context_after,
                    "source": "pdf_rawdict_font_geometry",
                }
                if left_neighbor and left_neighbor["font_class"].startswith("math"):
                    record["left_neighbor"] = {
                        "source_text": _safe_evidence_text(left_neighbor["text"], limit=40),
                        "font_class": left_neighbor["font_class"],
                        "bbox_normalized": _normalized_bbox(
                            left_neighbor["bbox"], width, height,
                        ),
                    }
                if bold_numbers and role == "exercise_title":
                    number = _EXERCISE_NUMBER_RE.search(bold_numbers[0]["text"])
                    record["exercise_number"] = number.group(1) if number else ""
                style_runs.append(record)

    soft_breaks = []
    by_block: dict[int, list[dict]] = {}
    for line in body:
        by_block.setdefault(line["block_index"], []).append(line)
    line_groups = list(by_block.values())
    raw_order = sorted(body, key=lambda line: (line["block_index"], line["line_index"]))
    for left_line, right_line in zip(raw_order, raw_order[1:]):
        # PyMuPDF sometimes starts a new text block for an indented continuation
        # line.  Only bridge immediately adjacent blocks; all font, baseline,
        # margin and lexical gates below still have to agree.
        if right_line["block_index"] == left_line["block_index"] + 1:
            line_groups.append([left_line, right_line])
    for block_lines in line_groups:
        block_lines.sort(key=lambda line: (line["bbox"][1], line["bbox"][0]))
        for left_line, right_line in zip(block_lines, block_lines[1:]):
            left_match = _LINE_END_FRAGMENT_RE.search(left_line["text"].rstrip())
            right_match = _LINE_START_FRAGMENT_RE.match(right_line["text"].lstrip())
            if not left_match or not right_match:
                continue
            left_span = next(
                (span for span in reversed(left_line["spans"]) if span["text"].strip()), None,
            )
            right_span = next(
                (span for span in right_line["spans"] if span["text"].strip()), None,
            )
            if not left_span or not right_span:
                continue
            if (
                left_span["font_class"].startswith("math")
                or right_span["font_class"].startswith("math")
                or "monospace" in left_span["font_class"]
                or "monospace" in right_span["font_class"]
            ):
                continue
            left_font = _font_name(left_span["font"]).casefold()
            right_font = _font_name(right_span["font"]).casefold()
            size = max(1.0, left_span["size"], right_span["size"])
            top_gap = right_line["bbox"][1] - left_line["bbox"][1]
            if (
                left_font != right_font
                or abs(left_span["size"] - right_span["size"]) > 0.03 * size
                or not 0.80 * size <= top_gap <= 1.45 * size
                or left_line["bbox"][2] < column_right - max(2.0, 0.60 * size)
                or right_line["bbox"][0] > column_left + max(12.0, 2.50 * size)
            ):
                continue
            left_fragment, right_fragment = left_match.group(1), right_match.group(1)
            lexical = classify_soft_line_break(
                left_fragment, right_fragment, document_lexicon,
            )
            joined = left_fragment + right_fragment
            hyphenated = left_fragment + "-" + right_fragment
            safe = bool(_safe_evidence_text(joined) and _safe_evidence_text(hyphenated))
            soft_breaks.append({
                "evidence_id": (
                    f"p{int(page_no)}-{left_line['line_id']}-{right_line['line_id']}-break"
                ),
                "kind": "soft_line_break",
                "decision": lexical["decision"],
                "left_fragment": left_fragment if safe else "",
                "right_fragment": right_fragment if safe else "",
                "joined_text": joined if safe else "",
                "hyphenated_text": hyphenated if safe else "",
                "safe_for_feedback": safe,
                "actionable": safe and lexical["decision"] in {"join", "keep"},
                "lexical_counts": {
                    "joined": lexical["joined_count"],
                    "hyphenated": lexical["hyphenated_count"],
                },
                "left_line_bbox_normalized": _normalized_bbox(
                    left_line["bbox"], width, height,
                ),
                "right_line_bbox_normalized": _normalized_bbox(
                    right_line["bbox"], width, height,
                ),
                "font": {"name": left_span["font"], "size_pt": round(size, 4)},
                "context_before": _canonical_text(
                    left_line["text"][:left_match.start(1)],
                )[-48:],
                "context_after": _canonical_text(
                    right_line["text"][right_match.end(1):],
                )[:48],
                "source": "pdf_rawdict_geometry_plus_document_lexicon",
            })

    return {
        "schema_version": SCHEMA_VERSION,
        "page": int(page_no),
        "page_size_points": [round(width, 4), round(height, 4)],
        "column_bbox_normalized": _normalized_bbox(
            [column_left, column_top, column_right, column_bottom], width, height,
        ),
        "style_runs": style_runs,
        "soft_line_breaks": soft_breaks,
    }


def pdf_document_lexicon(pdf_path: str | Path) -> dict[str, int]:
    """Build a document-local lexicon using PyMuPDF when it is available."""
    import fitz  # PyMuPDF; optional runtime dependency

    document = fitz.open(str(pdf_path))
    try:
        counts: Counter[str] = Counter()
        for page in document:
            try:
                text = page.get_text("text", sort=True)
            except TypeError:
                text = page.get_text("text")
            counts.update(build_document_lexicon(text))
        return dict(sorted(counts.items()))
    finally:
        document.close()


def extract_pdf_ocr_style_evidence(
    pdf_path: str | Path,
    page_no: int,
    *,
    document_lexicon: Mapping[str, int] | None = None,
) -> dict:
    """Extract one page from a PDF without coupling it to an OCR job."""
    import fitz  # PyMuPDF; optional runtime dependency

    document = fitz.open(str(pdf_path))
    try:
        if page_no < 1 or page_no > int(document.page_count):
            raise ValueError(f"PDF page must be between 1 and {document.page_count}")
        page = document[page_no - 1]
        try:
            payload = page.get_text("rawdict", sort=True)
        except TypeError:
            payload = page.get_text("rawdict")
        return extract_rawdict_ocr_style_evidence(
            payload, page_no, document_lexicon=document_lexicon,
        )
    finally:
        document.close()


def _balanced_group_end(text: str, open_offset: int, end: int) -> int | None:
    if open_offset >= end or text[open_offset] != "{":
        return None
    depth = 0
    index = open_offset
    while index < end:
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _balanced_optional_end(text: str, open_offset: int, end: int) -> int | None:
    if open_offset >= end or text[open_offset] != "[":
        return None
    square_depth = 0
    brace_depth = 0
    index = open_offset
    while index < end:
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == "{":
            brace_depth += 1
        elif character == "}" and brace_depth:
            brace_depth -= 1
        elif not brace_depth and character == "[":
            square_depth += 1
        elif not brace_depth and character == "]":
            square_depth -= 1
            if square_depth == 0:
                return index
        index += 1
    return None


def _command_group(text: str, command_end: int, end: int) -> tuple[int, int] | None:
    index = command_end
    if index < end and text[index] == "*":
        index += 1
    while index < end and text[index].isspace():
        index += 1
    while index < end and text[index] == "[":
        close = _balanced_optional_end(text, index, end)
        if close is None:
            return None
        index = close + 1
        while index < end and text[index].isspace():
            index += 1
    if index >= end or text[index] != "{":
        return None
    close = _balanced_group_end(text, index, end)
    return (index, close) if close is not None else None


def _latex_accented_character(
    text: str,
    argument_start: int,
    end: int,
    combining: str,
) -> tuple[str, int] | None:
    index = argument_start
    while index < end and text[index].isspace():
        index += 1
    if index >= end:
        return None
    if text[index] == "{":
        close = _balanced_group_end(text, index, end)
        if close is None:
            return None
        base = text[index + 1:close]
        source_end = close + 1
    else:
        base = text[index]
        source_end = index + 1
    if len(base) != 1 or not base.isalpha():
        return None
    return unicodedata.normalize("NFC", base + combining), source_end


def latex_visible_units(tex: str) -> list[dict]:
    """Return active text/math units with source offsets and presentation styles."""
    document = parse_latex(str(tex or ""))
    text, masked = document.text, document.masked
    units: list[_VisibleUnit] = []

    def active(offset: int) -> bool:
        return not (masked[offset] == " " and not text[offset].isspace())

    def scan(start: int, end: int, styles: tuple[str, ...] = ()) -> None:
        index = start
        while index < end:
            if not active(index):
                index += 1
                continue
            if text.startswith("\\(", index):
                close = masked.find("\\)", index + 2, end)
                if close < 0:
                    close = end - 2
                units.append(_VisibleUnit(
                    "math", text[index + 2:close], index, min(end, close + 2), styles,
                ))
                index = min(end, close + 2)
                continue
            if text.startswith("\\[", index):
                close = masked.find("\\]", index + 2, end)
                if close < 0:
                    close = end - 2
                units.append(_VisibleUnit(
                    "math", text[index + 2:close], index, min(end, close + 2), styles,
                ))
                index = min(end, close + 2)
                continue
            if text.startswith("$$", index):
                close = masked.find("$$", index + 2, end)
                if close < 0:
                    close = end - 2
                units.append(_VisibleUnit(
                    "math", text[index + 2:close], index, min(end, close + 2), styles,
                ))
                index = min(end, close + 2)
                continue
            if text[index] == "$" and (index == 0 or text[index - 1] != "\\"):
                close = index + 1
                while close < end:
                    if text[close] == "$" and text[close - 1] != "\\":
                        break
                    close += 1
                units.append(_VisibleUnit(
                    "math", text[index + 1:close], index, min(end, close + 1), styles,
                ))
                index = min(end, close + 1)
                continue
            if text[index] == "\\":
                command_match = re.match(r"\\([A-Za-z@]+)", text[index:end])
                if command_match:
                    command = command_match.group(1)
                    command_end = index + command_match.end()
                    accent = _LATEX_NAMED_ACCENTS.get(command)
                    if accent:
                        composed = _latex_accented_character(
                            text, command_end, end, accent,
                        )
                        if composed:
                            units.append(_VisibleUnit(
                                "text", composed[0], index, composed[1], styles,
                            ))
                            index = composed[1]
                            continue
                    group = _command_group(text, command_end, end)
                    if command in _STYLE_COMMANDS and group:
                        scan(group[0] + 1, group[1], (*styles, _STYLE_COMMANDS[command]))
                        index = group[1] + 1
                        continue
                    if command in _TEXT_ARGUMENT_COMMANDS and group:
                        scan(group[0] + 1, group[1], styles)
                        index = group[1] + 1
                        continue
                    if command in _INVISIBLE_COMMANDS:
                        if command in {"includegraphics", "begin", "end", "vspace", "hspace"} and group:
                            index = group[1] + 1
                        else:
                            index = command_end
                        continue
                    if group:
                        scan(group[0] + 1, group[1], styles)
                        index = group[1] + 1
                        continue
                    index = command_end
                    continue
                if index + 1 < end:
                    escaped = text[index + 1]
                    accent = _LATEX_SYMBOL_ACCENTS.get(escaped)
                    if accent:
                        composed = _latex_accented_character(
                            text, index + 2, end, accent,
                        )
                        if composed:
                            units.append(_VisibleUnit(
                                "text", composed[0], index, composed[1], styles,
                            ))
                            index = composed[1]
                            continue
                    if escaped in "%&#_{}$":
                        units.append(_VisibleUnit("text", escaped, index, index + 2, styles))
                    elif escaped.isspace():
                        units.append(_VisibleUnit("text", " ", index, index + 2, styles))
                    index += 2
                    continue
            if text[index] in "{}":
                index += 1
                continue
            units.append(_VisibleUnit("text", text[index], index, index + 1, styles))
            index += 1

    scan(0, len(text))
    return [
        {
            "kind": unit.kind, "text": unit.text,
            "source_start": unit.source_start, "source_end": unit.source_end,
            "styles": list(unit.styles),
        }
        for unit in units
    ]


def _canonical_visible(
    units: Sequence[Mapping], *, casefold: bool = True,
) -> tuple[str, list[Mapping]]:
    output: list[str] = []
    mapping: list[Mapping] = []
    previous_space = False
    for unit in units:
        if unit.get("kind") == "math":
            if not output or output[-1] != MATH_SENTINEL:
                output.append(MATH_SENTINEL)
                mapping.append(unit)
            previous_space = False
            continue
        normalized = unicodedata.normalize("NFKC", str(unit.get("text") or ""))
        if casefold:
            normalized = normalized.casefold()
        for character in normalized:
            if character.isspace():
                if output and not previous_space:
                    output.append(" ")
                    mapping.append(unit)
                previous_space = True
            else:
                output.append(character)
                mapping.append(unit)
                previous_space = False
    while output and output[-1] == " ":
        output.pop()
        mapping.pop()
    return "".join(output), mapping


def latex_visible_text(
    tex: str,
    *,
    include_math_placeholders: bool = True,
    casefold: bool = False,
) -> str:
    visible, _ = _canonical_visible(latex_visible_units(tex), casefold=casefold)
    return visible if include_math_placeholders else visible.replace(MATH_SENTINEL, "")


def _all_occurrences(haystack: str, needle: str) -> list[tuple[int, int]]:
    if not needle:
        return []
    result = []
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return result
        result.append((index, index + len(needle)))
        start = index + 1


def _context_matches(value: str, start: int, end: int, record: Mapping) -> bool:
    def normalized(part: object) -> str:
        result = _canonical_text(part)
        return re.sub(rf"\s*{re.escape(MATH_SENTINEL)}\s*", MATH_SENTINEL, result)

    before = normalized(record.get("context_before") or "")
    after = normalized(record.get("context_after") or "")
    visible_before = normalized(value[:start])
    visible_after = normalized(value[end:])
    return (not before or visible_before.endswith(before)) and (
        not after or visible_after.startswith(after)
    )


def _contextual_occurrences(
    value: str,
    occurrences: Sequence[tuple[int, int]],
    record: Mapping,
) -> list[tuple[int, int]]:
    contextual = [
        item for item in occurrences
        if _context_matches(value, item[0], item[1], record)
    ]
    return contextual


def _visible_slice_text(mapping: Sequence[Mapping]) -> str:
    seen = set()
    result = []
    for unit in mapping:
        key = (unit.get("source_start"), unit.get("source_end"))
        if key in seen:
            continue
        seen.add(key)
        if unit.get("kind") == "text":
            result.append(str(unit.get("text") or ""))
    return unicodedata.normalize("NFC", "".join(result))


def validate_ocr_style_tex(tex: str, evidence: Mapping) -> dict:
    """Validate one OCR page without changing it or trusting evidence text as code."""
    units = latex_visible_units(tex)
    visible, mapping = _canonical_visible(units)
    issues = []

    for record in evidence.get("style_runs") or []:
        if not isinstance(record, Mapping) or not record.get("actionable"):
            continue
        source_text = _safe_evidence_text(record.get("source_text"))
        if not source_text:
            continue
        target = _canonical_text(source_text)
        occurrences = _contextual_occurrences(
            visible, _all_occurrences(visible, target), record,
        )
        base_issue = {
            "evidence_id": str(record.get("evidence_id") or "")[:120],
            "kind": "style_run",
            "style": str(record.get("style") or ""),
            "role": str(record.get("role") or ""),
            "bbox_normalized": list(record.get("bbox_normalized") or [])[:4],
        }
        if len(occurrences) != 1:
            issues.append({
                **base_issue,
                "status": "ambiguous_alignment" if occurrences else "missing_alignment",
                "retry_required": False,
                "needs_review": True,
                "occurrence_count": len(occurrences),
            })
            continue
        start, end = occurrences[0]
        expected_neighbor = _canonical_text(
            (record.get("left_neighbor") or {}).get("source_text")
            if isinstance(record.get("left_neighbor"), Mapping) else "",
        )
        requires_math_neighbor = bool(
            record.get("role") == "math_compound_suffix" or record.get("left_neighbor")
        )
        left_unit = mapping[start - 1] if start > 0 else {}
        actual_neighbor = _canonical_text(left_unit.get("text") or "")
        math_neighbor_ok = bool(
            not requires_math_neighbor
            or (
                left_unit.get("kind") == "math"
                and (not expected_neighbor or actual_neighbor == expected_neighbor)
            )
        )
        if not math_neighbor_ok:
            issues.append({
                **base_issue,
                "status": "math_neighbor_mismatch",
                "retry_required": False,
                "needs_review": True,
                "occurrence_count": 1,
            })
            continue
        target_units = [
            unit for unit in mapping[start:end]
            if unit.get("kind") == "text" and str(unit.get("text") or "").strip()
        ]
        expected_style = str(record.get("style") or "")
        style_ok = bool(target_units) and all(
            expected_style in (unit.get("styles") or []) for unit in target_units
        )
        math_crossed = False
        if requires_math_neighbor:
            math_crossed = expected_style in (left_unit.get("styles") or [])
        raw_text = _visible_slice_text(mapping[start:end])
        case_ok = unicodedata.normalize("NFC", raw_text) == source_text
        if not style_ok or math_crossed or not case_ok:
            issues.append({
                **base_issue,
                "status": (
                    "style_crosses_math" if math_crossed else
                    "case_pattern_mismatch" if style_ok and not case_ok else
                    "missing_style"
                ),
                "retry_required": True,
                "needs_review": False,
                "target_text": source_text,
            })

    for record in evidence.get("soft_line_breaks") or []:
        if not isinstance(record, Mapping):
            continue
        decision = str(record.get("decision") or "ambiguous")
        left = _safe_evidence_text(record.get("left_fragment"), limit=40)
        right = _safe_evidence_text(record.get("right_fragment"), limit=40)
        if not left or not right:
            continue
        left_key, right_key = _canonical_text(left), _canonical_text(right)
        split_re = re.compile(
            rf"(?<![a-z]){re.escape(left_key)}-\s*{re.escape(right_key)}(?![a-z])",
        )
        raw_split_occurrences = [
            match.span() for match in split_re.finditer(visible)
        ]
        split_occurrences = _contextual_occurrences(
            visible, raw_split_occurrences, record,
        )
        joined_occurrences = _contextual_occurrences(
            visible, _all_occurrences(visible, left_key + right_key), record,
        )
        hyphenated_occurrences = _contextual_occurrences(
            visible, _all_occurrences(visible, left_key + "-" + right_key), record,
        )
        split_count = len(split_occurrences)
        joined_count = len(joined_occurrences)
        hyphenated_count = len(hyphenated_occurrences)
        base_issue = {
            "evidence_id": str(record.get("evidence_id") or "")[:120],
            "kind": "soft_line_break",
            "decision": decision,
            "left_line_bbox_normalized": list(
                record.get("left_line_bbox_normalized") or []
            )[:4],
            "right_line_bbox_normalized": list(
                record.get("right_line_bbox_normalized") or []
            )[:4],
        }
        if decision == "ambiguous":
            issues.append({
                **base_issue, "status": "ambiguous_lexical_evidence",
                "retry_required": False, "needs_review": True,
            })
        elif decision == "join" and split_count:
            issues.append({
                **base_issue, "status": "soft_break_not_joined",
                "retry_required": split_count == 1,
                "needs_review": split_count != 1,
                "occurrence_count": split_count,
                "left_fragment": left, "right_fragment": right,
                "joined_text": left + right,
            })
        elif decision == "join" and joined_count != 1:
            issues.append({
                **base_issue, "status": "joined_word_alignment_ambiguous",
                "retry_required": False, "needs_review": True,
                "occurrence_count": joined_count,
            })
        elif decision == "keep" and hyphenated_count != 1:
            issues.append({
                **base_issue, "status": "lexical_hyphen_not_preserved",
                "retry_required": False,
                "needs_review": True,
                "occurrence_count": joined_count,
                "left_fragment": left, "right_fragment": right,
                "hyphenated_text": left + "-" + right,
            })

    return {
        "schema_version": SCHEMA_VERSION,
        "page": int(evidence.get("page") or 0),
        "ok": not issues,
        "retry_required": any(item.get("retry_required") for item in issues),
        "needs_review": any(item.get("needs_review") for item in issues),
        "issues": issues,
    }


def build_ocr_style_retry_feedback(validation: Mapping) -> dict:
    """Return bounded static actions; never return arbitrary PDF context or LaTeX."""
    actions = []
    for issue in validation.get("issues") or []:
        if not isinstance(issue, Mapping) or not issue.get("retry_required"):
            continue
        action = {
            "evidence_id": str(issue.get("evidence_id") or "")[:120],
            "action": "",
        }
        if issue.get("kind") == "soft_line_break":
            if issue.get("decision") == "join":
                action["action"] = "join_discretionary_line_break"
            else:
                action["action"] = "preserve_lexical_hyphen"
            action["left_line_bbox_normalized"] = list(
                issue.get("left_line_bbox_normalized") or []
            )[:4]
            action["right_line_bbox_normalized"] = list(
                issue.get("right_line_bbox_normalized") or []
            )[:4]
        elif issue.get("kind") == "style_run":
            style = str(issue.get("style") or "")
            if style not in {"italic", "smallcaps"}:
                continue
            action["action"] = "apply_text_style_without_crossing_math"
            action["style"] = style
            action["role"] = str(issue.get("role") or "")[:40]
            action["bbox_normalized"] = list(issue.get("bbox_normalized") or [])[:4]
        if action["action"]:
            actions.append(action)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "ocr_style_retry",
        "page": int(validation.get("page") or 0),
        "policy": (
            "Reinspect the page pixels and correct only these bounded typography or line-break "
            "occurrences. Preserve every mathematical token and all other visible text."
        ),
        "actions": actions[:32],
    }


def _normalize_allowed_breaks(value: str, evidence: Mapping) -> str:
    result = value
    for record in evidence.get("soft_line_breaks") or []:
        if (
            not isinstance(record, Mapping)
            or record.get("decision") != "join"
            or not record.get("actionable")
            or not record.get("safe_for_feedback")
        ):
            continue
        left = _canonical_text(record.get("left_fragment") or "")
        right = _canonical_text(record.get("right_fragment") or "")
        if left and right:
            pattern = re.compile(
                rf"(?<![a-z]){re.escape(left)}-\s*{re.escape(right)}(?![a-z])",
            )
            matches = _contextual_occurrences(
                result, [match.span() for match in pattern.finditer(result)], record,
            )
            if len(matches) == 1:
                start, end = matches[0]
                result = result[:start] + left + right + result[end:]
    return result


def _normalize_allowed_case_patterns(value: str, evidence: Mapping) -> str:
    result = value
    for record in evidence.get("style_runs") or []:
        if not isinstance(record, Mapping) or not record.get("actionable"):
            continue
        if record.get("style") != "smallcaps":
            continue
        target = _safe_evidence_text(record.get("source_text"))
        if not target:
            continue
        pattern = re.compile(re.escape(unicodedata.normalize("NFKC", target)), re.I)
        matches = [
            match for match in pattern.finditer(result)
            if _context_matches(result.casefold(), match.start(), match.end(), record)
        ]
        if len(matches) != 1:
            continue
        match = matches[0]
        result = result[:match.start()] + target.casefold() + result[match.end():]
    return result


def _ordered_math_payloads(tex: str) -> tuple[str, ...]:
    return tuple(
        _canonical_text(unit.get("text") or "", casefold=False)
        for unit in latex_visible_units(tex)
        if unit.get("kind") == "math"
    )


def _active_control_fingerprint(tex: str) -> tuple[str, ...]:
    masked = parse_latex(str(tex or "")).masked
    ignored = {
        *_STYLE_COMMANDS,
        *_LATEX_NAMED_ACCENTS,
        *_LATEX_SYMBOL_ACCENTS,
    }
    return tuple(
        match.group(1)
        for match in _ACTIVE_CONTROL_RE.finditer(masked)
        if match.group(1) not in ignored
    )


def _protected_fingerprint(tex: str) -> tuple[str, ...]:
    source = str(tex or "")
    active = mask_comments(source)
    ranges, _, _ = find_env_ranges(active)
    records = [
        f"env:{name}:{source[begin:end]}"
        for name, begin, _body_start, _body_end, end in sorted(
            ranges, key=lambda item: item[1],
        )
        if name in PROTECTED_ENVS
    ]
    records.extend(
        f"verb:{source[match.start():match.end()]}"
        for match in _INLINE_VERB_CAPTURE_RE.finditer(active)
    )
    return tuple(records)


def _style_command_occurrences(tex: str) -> Counter[tuple[str, str]]:
    source = str(tex or "")
    masked = parse_latex(source).masked
    result: Counter[tuple[str, str]] = Counter()
    for match in _ACTIVE_CONTROL_RE.finditer(masked):
        command = match.group(1)
        style = _STYLE_COMMANDS.get(command)
        if not style:
            continue
        group = _command_group(source, match.end(), len(source))
        if group is None:
            continue
        visible = latex_visible_text(
            source[group[0] + 1:group[1]], casefold=True,
        )
        target = _canonical_text(visible)
        if target:
            result[(style, target)] += 1
    return result


def _allowed_style_command_changes(
    before: str,
    evidence: Mapping,
) -> tuple[Counter[tuple[str, str]], Counter[tuple[str, str]]]:
    additions: Counter[tuple[str, str]] = Counter()
    removals: Counter[tuple[str, str]] = Counter()
    validation = validate_ocr_style_tex(before, evidence)
    for issue in validation.get("issues") or []:
        if not isinstance(issue, Mapping) or issue.get("kind") != "style_run":
            continue
        if not issue.get("retry_required"):
            continue
        style = str(issue.get("style") or "")
        target = _canonical_text(_safe_evidence_text(issue.get("target_text")))
        if style not in {"italic", "smallcaps"} or not target:
            continue
        status = str(issue.get("status") or "")
        if status in {"missing_style", "style_crosses_math"}:
            additions[(style, target)] += 1
        if status == "style_crosses_math":
            removals[(style, MATH_SENTINEL + target)] += 1
    return additions, removals


def validate_controlled_ocr_style_revision(
    before: str,
    after: str,
    evidence: Mapping,
) -> dict:
    """Allow only evidenced style/break fixes and preserve active TeX semantics."""
    before_math, after_math = math_tokens(before), math_tokens(after)
    before_math_order = _ordered_math_payloads(before)
    after_math_order = _ordered_math_payloads(after)
    before_visible = _normalize_allowed_breaks(
        latex_visible_text(before, casefold=False), evidence,
    )
    after_visible = _normalize_allowed_breaks(
        latex_visible_text(after, casefold=False), evidence,
    )
    before_visible = _normalize_allowed_case_patterns(before_visible, evidence)
    after_visible = _normalize_allowed_case_patterns(after_visible, evidence)
    before_controls = _active_control_fingerprint(before)
    after_controls = _active_control_fingerprint(after)
    before_protected = _protected_fingerprint(before)
    after_protected = _protected_fingerprint(after)
    before_styles = _style_command_occurrences(before)
    after_styles = _style_command_occurrences(after)
    added_styles = after_styles - before_styles
    removed_styles = before_styles - after_styles
    allowed_additions, allowed_removals = _allowed_style_command_changes(before, evidence)
    style_changes_allowed = not (
        added_styles - allowed_additions or removed_styles - allowed_removals
    )
    after_validation = validate_ocr_style_tex(after, evidence)
    retry_issue_resolved = not bool(after_validation.get("retry_required"))
    math_equal = before_math == after_math and before_math_order == after_math_order
    visible_equal = before_visible == after_visible
    controls_equal = before_controls == after_controls
    protected_equal = before_protected == after_protected
    return {
        "ok": bool(
            math_equal
            and visible_equal
            and controls_equal
            and protected_equal
            and style_changes_allowed
            and retry_issue_resolved
        ),
        "math_equal": math_equal,
        "math_multiset_equal": before_math == after_math,
        "math_order_equal": before_math_order == after_math_order,
        "before_math_count": len(before_math),
        "after_math_count": len(after_math),
        "visible_text_equal": visible_equal,
        "active_controls_equal": controls_equal,
        "protected_regions_equal": protected_equal,
        "style_changes_allowed": style_changes_allowed,
        "retry_issue_resolved": retry_issue_resolved,
        "before_visible_sha256": hashlib.sha256(before_visible.encode("utf-8")).hexdigest(),
        "after_visible_sha256": hashlib.sha256(after_visible.encode("utf-8")).hexdigest(),
    }

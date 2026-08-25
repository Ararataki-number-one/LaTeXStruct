"""Deterministic PyMuPDF object-layer extraction for OCR candidates.

The source PDF remains authoritative.  The candidates produced here are
plain, conservatively escaped visible text plus stable object evidence; they
are not visually verified OCR and they intentionally contain no inferred
``chapter``, ``section``, theorem, lemma, or proof environments.
"""

from __future__ import annotations

import hashlib
import json
import re
import statistics
import unicodedata
from collections.abc import Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from typing import Any

from .ocr_classifier import classify_page_features
from .ocr_scheduler import (
    DEFAULT_OBJECT_EXTRACTION_WORKERS,
    MAX_OBJECT_EXTRACTION_WORKERS,
    MIN_OBJECT_EXTRACTION_WORKERS,
)
from .ocr_native_figures import (
    NATIVE_FIGURE_SOURCE,
    native_figure_latex,
    native_figure_path,
)
from .ocr_schema import PageBlock, PageBlockType, PageClassification, PageFeatures


_CAPTION_RE = re.compile(r"^\s*(?:fig(?:ure)?\.?|table|图|表)\s*\d*", re.IGNORECASE)
_BIBLIOGRAPHY_RE = re.compile(
    r"^\s*(?:\[\s*\d+\s*\]\s+|\d+\s*\)\s+|"
    r"\d+\s*\.\s+(?=(?:[A-Z]\.\s+|[A-Z][\w'’.-]+,\s)))"
)
_LIST_RE = re.compile(r"^\s*(?:[•◦▪‣]|[-–—]\s+|(?:\d+|[A-Za-z])[.)]\s+)")
_NUMBERED_SUBHEADING_RE = re.compile(r"^\s*\d+(?:\.\d+)+\.\s+\S")
_NUMBERED_HEADING_RE = re.compile(r"^\s*\d+\.\s+[^\n]{1,120}$")
_PRINTED_PAGE_NUMBER_RE = re.compile(
    r"(?:[1-9][0-9]{0,5}|[ivxlcdm]{2,12})",
    re.IGNORECASE,
)
_MATH_ASCII = frozenset("=+-*/<>^_|∑∏∫√∞≈≠≤≥±×÷∈∉⊂⊆⊃⊇∪∩→←↔⇒⇔∀∃∂∇")
_MATH_FONT_MARKERS = ("math", "cmmi", "cmsy", "cmex", "symbol", "euclid", "mt extra")
_SMALL_CAP_FONT_MARKERS = ("smallcap", "small cap", "cmcsc", "cmsc")
_MATH_REGION_POLICY_VERSION = "latexstruct-object-math-region-v1"
_VECTOR_FIGURE_POLICY_VERSION = "latexstruct-vector-figure-region-v1"
_FIGURE_CAPTION_RE = re.compile(
    r"^\s*(?:fig(?:ure)?\.?|图)\s*\d+",
    re.IGNORECASE,
)
_FORMAL_DISPLAY_PREFIX_RE = re.compile(
    r"^\s*(?:theorem|lemma|proposition|corollary|definition|conjecture|"
    r"claim|observation|fact|problem|question)"
    r"(?:\s+(?:[A-Z]|[0-9]+(?:\.[0-9]+)*))?\s*[.:]?\s*$",
    re.IGNORECASE,
)
_FORMAL_DISPLAY_SPLIT_POLICY_VERSION = "latexstruct-formal-display-split-v1"
_PROSE_WORD_RE = re.compile(r"[A-Za-z\u00c0-\u024f]{3,}")
_TEX_ESCAPES = {
    "\\": r"\textbackslash{}",
    "{": r"\{",
    "}": r"\}",
    "$": r"\$",
    "&": r"\&",
    "%": r"\%",
    "#": r"\#",
    "_": r"\_",
    "^": r"\textasciicircum{}",
    "~": r"\textasciitilde{}",
}

# PyMuPDF documents are deliberately never shared between threads.  The
# object-layer stage uses isolated worker processes, each of which owns one
# read-only document handle.  Six workers matches the recommended scheduler
# profile while the hard ceiling keeps both PDF handles and copied source
# buffers bounded.
DEFAULT_EXTRACTION_WORKERS = DEFAULT_OBJECT_EXTRACTION_WORKERS
MAX_EXTRACTION_WORKERS = MAX_OBJECT_EXTRACTION_WORKERS
_WORKER_DOCUMENT: Any | None = None
_WORKER_SOURCE_PDF_SHA256 = ""


def _pymupdf():
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError as exc:  # pragma: no cover - packaged runtime includes it
            raise RuntimeError("PyMuPDF is required for OCR page extraction") from exc
    return pymupdf


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def _hash_object(value: object) -> str:
    return _sha256(_canonical_bytes(value))


def _round(value: object) -> float:
    return round(float(value), 6)


def _bbox(value: Sequence[object]) -> tuple[float, float, float, float]:
    if len(value) != 4:
        return (0.0, 0.0, 0.0, 0.0)
    return tuple(_round(item) for item in value)  # type: ignore[return-value]


def _clipped_bbox(
    value: Sequence[object],
    width: float,
    height: float,
) -> tuple[float, float, float, float]:
    x0, y0, x1, y1 = _bbox(value)
    return (
        max(0.0, min(width, x0)),
        max(0.0, min(height, y0)),
        max(0.0, min(width, x1)),
        max(0.0, min(height, y1)),
    )


def _block_text(block: Mapping[str, Any]) -> str:
    lines: list[str] = []
    for line in block.get("lines") or ():
        spans = line.get("spans") or () if isinstance(line, Mapping) else ()
        text = "".join(str(span.get("text") or "") for span in spans if isinstance(span, Mapping))
        lines.append(text.rstrip())
    return "\n".join(lines).strip()


def _spans(block: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for line in block.get("lines") or ():
        if not isinstance(line, Mapping):
            continue
        result.extend(span for span in (line.get("spans") or ()) if isinstance(span, Mapping))
    return result


def _raw_line_text(line: Mapping[str, Any]) -> str:
    return "".join(
        str(span.get("text") or "")
        for span in (line.get("spans") or ())
        if isinstance(span, Mapping)
    ).strip()


def _raw_line_spans(line: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        span
        for span in (line.get("spans") or ())
        if isinstance(span, Mapping)
    ]


def _formal_display_split_is_supported(
    raw_blocks: Sequence[object],
    source_index: int,
) -> bool:
    """Recognize one formal-prefix line immediately joined to display math."""

    raw_block = raw_blocks[source_index]
    if not isinstance(raw_block, Mapping):
        return False
    lines = tuple(
        line
        for line in (raw_block.get("lines") or ())
        if isinstance(line, Mapping)
    )
    if len(lines) < 2:
        return False
    first_text = _raw_line_text(lines[0])
    first_spans = _raw_line_spans(lines[0])
    if (
        _FORMAL_DISPLAY_PREFIX_RE.fullmatch(first_text) is None
        or not first_spans
        or not any(int(span.get("flags") or 0) & 16 for span in first_spans)
    ):
        return False
    remainder_lines = lines[1:]
    remainder_text = "\n".join(_raw_line_text(line) for line in remainder_lines).strip()
    remainder_spans = [span for line in remainder_lines for span in _raw_line_spans(line)]
    remainder_score = _math_likelihood(remainder_text, remainder_spans)
    if not remainder_text or len(remainder_text) > 48 or remainder_score < 0.22:
        return False

    scores = [remainder_score]
    current_bbox = _bbox(raw_block.get("bbox") or ())
    region_bottom = current_bbox[3]
    maximum_bottom = current_bbox[3] + 54.0
    for candidate in raw_blocks[source_index + 1 : source_index + 8]:
        if not isinstance(candidate, Mapping) or int(candidate.get("type") or 0) != 0:
            continue
        candidate_bbox = _bbox(candidate.get("bbox") or ())
        if candidate_bbox[1] > region_bottom + 24.0 or candidate_bbox[1] > maximum_bottom:
            break
        text = _block_text(candidate)
        spans = _spans(candidate)
        score = _math_likelihood(text, spans)
        if score < 0.16 and len(text.strip()) > 48:
            break
        scores.append(score)
        region_bottom = max(region_bottom, candidate_bbox[3])
    return (
        len(scores) >= 4
        and sum(score >= 0.25 for score in scores) >= 4
        and max(scores) >= 0.50
    )


def _split_text_entry_at_first_line(
    entry: Mapping[str, Any],
    raw_block: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create two hash-bound fragments without interpreting the formula."""

    lines = tuple(
        line
        for line in (raw_block.get("lines") or ())
        if isinstance(line, Mapping)
    )
    fragments: list[dict[str, Any]] = []
    parent_evidence = entry["evidence"]
    parent_hash = _hash_object(parent_evidence)
    for fragment_index, fragment_lines in enumerate((lines[:1], lines[1:]), start=1):
        spans = [span for line in fragment_lines for span in _raw_line_spans(line)]
        text = "\n".join(_raw_line_text(line) for line in fragment_lines).strip()
        line_boxes = [_bbox(line.get("bbox") or ()) for line in fragment_lines]
        bbox = (
            min(box[0] for box in line_boxes),
            min(box[1] for box in line_boxes),
            max(box[2] for box in line_boxes),
            max(box[3] for box in line_boxes),
        )
        fonts = tuple(sorted({str(span.get("font") or "") for span in spans}))
        sizes = [
            float(span.get("size") or 0.0)
            for span in spans
            if float(span.get("size") or 0.0) > 0.0
        ]
        flags = [int(span.get("flags") or 0) for span in spans]
        colors = [int(span.get("color") or 0) for span in spans]
        evidence = {
            "kind": "formal_display_fragment",
            "policy_version": _FORMAL_DISPLAY_SPLIT_POLICY_VERSION,
            "fragment": "formal_prefix" if fragment_index == 1 else "display_math",
            "bbox": list(bbox),
            "text": text,
            "parent_source_object_hash": parent_hash,
            "parent_source_object": parent_evidence,
            "source_line_indices": (
                [0] if fragment_index == 1 else list(range(1, len(lines)))
            ),
        }
        fragments.append({
            "kind": "text",
            "source_index": int(entry["source_index"]),
            "source_fragment_order": fragment_index,
            "bbox": bbox,
            "text": text,
            "fonts": fonts,
            "font_size": statistics.median(sizes or [0.0]),
            "bold": any(flag & 16 for flag in flags),
            "italic": any(flag & 2 for flag in flags),
            "line_count": len(fragment_lines),
            "span_count": len(spans),
            "color": colors[0] if colors and len(set(colors)) == 1 else -1,
            "math_likelihood": _math_likelihood(text, spans),
            "block_type_override": (
                PageBlockType.HEADING_TEXT
                if fragment_index == 1
                else PageBlockType.DISPLAY_MATH
            ),
            "evidence": evidence,
        })
    return fragments[0], fragments[1]


def _is_garbled(character: str) -> bool:
    if character == "\ufffd":
        return True
    category = unicodedata.category(character)
    return category in {"Cc", "Cs", "Co", "Cn"} and character not in "\t\r\n"


def _is_math_character(character: str) -> bool:
    codepoint = ord(character)
    return (
        character in _MATH_ASCII
        or unicodedata.category(character) == "Sm"
        or 0x0370 <= codepoint <= 0x03FF
        or 0x1D400 <= codepoint <= 0x1D7FF
    )


def _math_likelihood(
    text: str,
    spans: Sequence[Mapping[str, Any]],
) -> float:
    characters = [character for character in text if not character.isspace()]
    if not characters:
        return 0.0
    math_count = sum(_is_math_character(character) for character in characters)
    digit_count = sum(character.isdigit() for character in characters)
    span_character_count = 0
    math_font_character_count = 0
    for span in spans:
        span_characters = [
            character
            for character in str(span.get("text") or "")
            if not character.isspace()
        ]
        span_character_count += len(span_characters)
        font = str(span.get("font") or "").casefold()
        if any(marker in font for marker in _MATH_FONT_MARKERS):
            math_font_character_count += len(span_characters)

    # A font name is useful evidence only in proportion to the visible
    # characters it actually covers.  A one-character CMMI span inside a prose
    # paragraph must not promote the entire PDF text block to mathematics.
    coverage_denominator = max(len(characters), span_character_count, 1)
    math_font_coverage = min(
        1.0,
        math_font_character_count / coverage_denominator,
    )
    density = math_count / len(characters)
    if math_count and digit_count:
        density += min(0.15, digit_count / len(characters) * 0.25)
    density += 0.55 * math_font_coverage
    return round(min(1.0, density), 6)


def _latex_visible_text(text: str) -> str:
    """Escape visible text without inventing any semantic environment."""
    return "".join(_TEX_ESCAPES.get(character, character) for character in text)


def _rectangle_union_area(
    rectangles: Sequence[tuple[float, float, float, float]],
) -> float:
    valid = [item for item in rectangles if item[2] > item[0] and item[3] > item[1]]
    xs = sorted({coordinate for item in valid for coordinate in (item[0], item[2])})
    area = 0.0
    for left, right in zip(xs, xs[1:]):
        if right <= left:
            continue
        intervals = sorted(
            (item[1], item[3])
            for item in valid
            if item[0] < right and item[2] > left
        )
        covered = 0.0
        start: float | None = None
        end: float | None = None
        for low, high in intervals:
            if start is None:
                start, end = low, high
            elif low > end:
                covered += end - start
                start, end = low, high
            else:
                end = max(end, high)
        if start is not None and end is not None:
            covered += end - start
        area += (right - left) * covered
    return area


def _double_column_likelihood(
    text_entries: Sequence[Mapping[str, Any]],
    width: float,
) -> float:
    substantial = [
        entry
        for entry in text_entries
        if len(str(entry["text"]).strip()) >= 8
        and float(entry["bbox"][2]) - float(entry["bbox"][0]) <= width * 0.68
    ]
    left = [entry for entry in substantial if (entry["bbox"][0] + entry["bbox"][2]) / 2 < width / 2]
    right = [entry for entry in substantial if (entry["bbox"][0] + entry["bbox"][2]) / 2 >= width / 2]
    if not left or not right:
        return 0.0
    balance = min(len(left), len(right)) / max(len(left), len(right))
    overlapping = 0
    possible = 0
    for first in left:
        for second in right:
            possible += 1
            overlap = min(first["bbox"][3], second["bbox"][3]) - max(
                first["bbox"][1], second["bbox"][1]
            )
            if overlap > 0:
                overlapping += 1
    overlap_ratio = overlapping / possible if possible else 0.0
    side_gap = min(float(item["bbox"][0]) for item in right) - max(
        float(item["bbox"][2]) for item in left
    )
    gap_signal = max(0.0, min(1.0, side_gap / max(width * 0.08, 1.0)))
    return round(min(1.0, 0.35 * balance + 0.45 * overlap_ratio + 0.20 * gap_signal), 6)


def _reading_order_confidence(
    text_entries: Sequence[Mapping[str, Any]],
    double_column_likelihood: float,
) -> float:
    if not text_entries:
        return 0.0
    if len(text_entries) == 1:
        return 1.0
    if double_column_likelihood >= 0.55:
        return round(min(0.92, 0.62 + 0.30 * double_column_likelihood), 6)
    ambiguous_pairs = 0
    pairs = 0
    for index, first in enumerate(text_entries):
        for second in text_entries[index + 1 :]:
            pairs += 1
            vertical_overlap = min(first["bbox"][3], second["bbox"][3]) - max(
                first["bbox"][1], second["bbox"][1]
            )
            horizontal_gap = max(
                float(second["bbox"][0]) - float(first["bbox"][2]),
                float(first["bbox"][0]) - float(second["bbox"][2]),
                0.0,
            )
            if vertical_overlap > 0 and horizontal_gap > 0:
                ambiguous_pairs += 1
    ambiguity = ambiguous_pairs / pairs if pairs else 0.0
    return round(max(0.35, 0.96 - 0.55 * ambiguity), 6)


def _ordered_entries(
    entries: Sequence[dict[str, Any]],
    width: float,
    double_column_likelihood: float,
) -> list[dict[str, Any]]:
    if double_column_likelihood >= 0.55:
        return sorted(
            entries,
            key=lambda item: (
                0 if (item["bbox"][0] + item["bbox"][2]) / 2 < width / 2 else 1,
                item["bbox"][1],
                item["bbox"][0],
                item["source_index"],
            ),
        )
    return sorted(
        entries,
        key=lambda item: (
            item["bbox"][1],
            item["bbox"][0],
            item["source_index"],
        ),
    )


def _axis_overlap(first0: float, first1: float, second0: float, second1: float) -> float:
    return max(0.0, min(first1, second1) - max(first0, second0))


def _axis_gap(first0: float, first1: float, second0: float, second1: float) -> float:
    return max(second0 - first1, first0 - second1, 0.0)


def _math_region_column(
    entry: Mapping[str, Any],
    *,
    page_width: float,
    double_column_likelihood: float,
) -> int:
    """Return a conservative physical column, with zero meaning spanning/unknown."""
    if double_column_likelihood < 0.55:
        return 0
    x0, _y0, x1, _y1 = entry["bbox"]
    if x1 <= page_width * 0.52:
        return -1
    if x0 >= page_width * 0.48:
        return 1
    return 0


def _math_extender_only(entry: Mapping[str, Any]) -> bool:
    characters = [
        character
        for character in str(entry.get("text") or "")
        if not character.isspace()
    ]
    return (
        bool(characters)
        and any("cmex" in str(font).casefold() for font in entry.get("fonts") or ())
        and all(
            ord(character) < 32
            or unicodedata.category(character) in {"Co", "Cs", "Cn"}
            for character in characters
        )
    )


def _math_region_entries_are_adjacent(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
    *,
    page_width: float,
    median_font_size: float,
    double_column_likelihood: float,
) -> bool:
    """Test whether two source objects belong to one bounded visual math region.

    This is deliberately geometric. It does not concatenate symbols into a
    mathematical interpretation. The limits admit overlapping super/subscript
    and fraction objects while keeping separate rows and physical columns apart.
    """
    first_math = float(first.get("math_likelihood") or 0.0) >= 0.16
    second_math = float(second.get("math_likelihood") or 0.0) >= 0.16
    if not (first_math or second_math):
        return False
    first_column = _math_region_column(
        first,
        page_width=page_width,
        double_column_likelihood=double_column_likelihood,
    )
    second_column = _math_region_column(
        second,
        page_width=page_width,
        double_column_likelihood=double_column_likelihood,
    )
    if first_column and second_column and first_column != second_column:
        return False

    first_x0, first_y0, first_x1, first_y1 = first["bbox"]
    second_x0, second_y0, second_x1, second_y1 = second["bbox"]
    first_width = max(0.0, first_x1 - first_x0)
    second_width = max(0.0, second_x1 - second_x0)
    first_height = max(0.0, first_y1 - first_y0)
    second_height = max(0.0, second_y1 - second_y0)
    if min(first_width, second_width, first_height, second_height) <= 0:
        return False
    horizontal_overlap = _axis_overlap(first_x0, first_x1, second_x0, second_x1)
    vertical_overlap = _axis_overlap(first_y0, first_y1, second_y0, second_y1)
    horizontal_gap = _axis_gap(first_x0, first_x1, second_x0, second_x1)
    vertical_gap = _axis_gap(first_y0, first_y1, second_y0, second_y1)
    local_font_size = max(
        1.0,
        float(median_font_size or 0.0),
        float(first.get("font_size") or 0.0),
        float(second.get("font_size") or 0.0),
    )

    if first_math and second_math:
        first_mixed = _looks_like_mixed_text_math(str(first.get("text") or ""))
        second_mixed = _looks_like_mixed_text_math(str(second.get("text") or ""))
        same_formula_band = (
            vertical_overlap >= min(first_height, second_height) * 0.12
            and horizontal_gap <= local_font_size * 3.5
        )
        script_signal = (
            min(
                float(first.get("font_size") or local_font_size),
                float(second.get("font_size") or local_font_size),
            )
            <= max(1.0, median_font_size * 0.72)
        )
        extender_signal = any(
            marker in str(font).casefold()
            for entry in (first, second)
            for font in (entry.get("fonts") or ())
            for marker in ("cmex", "cmmi6", "cmsy6", "cmr6")
        )
        script_or_extender = script_signal or extender_signal
        extender_only = _math_extender_only(first) and _math_extender_only(second)
        center_distance = abs(
            (first_x0 + first_x1) / 2.0 - (second_x0 + second_x1) / 2.0
        )
        stacked_alignment = (
            horizontal_overlap >= min(first_width, second_width) * 0.20
            and (
                script_signal
                or center_distance
                <= max(local_font_size, min(first_width, second_width) * 0.25)
            )
        )
        stacked_formula_piece = (
            script_or_extender
            and not (first_mixed or second_mixed)
            and stacked_alignment
            and vertical_gap > 0.0
            and vertical_gap <= local_font_size * 0.38
        )
        extended_stacked_piece = (
            (script_signal or extender_only)
            and not (first_mixed or second_mixed)
            and stacked_alignment
            and vertical_gap > 0.0
            and vertical_gap <= local_font_size * 0.85
        )
        return same_formula_band or stacked_formula_piece or extended_stacked_piece

    # A low-math object is admitted only when it physically intersects the
    # math object (embedded prose/punctuation), or is a very short continuation
    # on the same baseline. It therefore cannot bridge separate display rows.
    nonmath = second if first_math else first
    nonmath_text = str(nonmath.get("text") or "").strip()
    embedded = horizontal_overlap > 0.0 and vertical_overlap > 0.0
    short_baseline_continuation = (
        len(nonmath_text) <= 12
        and vertical_overlap >= min(first_height, second_height) * 0.30
        and horizontal_gap <= local_font_size * 0.45
    )
    return embedded or short_baseline_continuation


def _looks_like_mixed_text_math(text: str) -> bool:
    stripped = str(text or "").strip()
    return len(stripped) >= 20 and len(_PROSE_WORD_RE.findall(stripped)) >= 2


def _is_prose_entry(entry: Mapping[str, Any]) -> bool:
    return _looks_like_mixed_text_math(str(entry.get("text") or ""))


def _coalesced_math_entry(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    children = sorted(
        entries,
        key=lambda item: (
            item["bbox"][1],
            item["bbox"][0],
            item["source_index"],
        ),
    )
    bbox = (
        min(item["bbox"][0] for item in children),
        min(item["bbox"][1] for item in children),
        max(item["bbox"][2] for item in children),
        max(item["bbox"][3] for item in children),
    )
    source_evidence = [item["evidence"] for item in children]
    source_hashes = [_hash_object(item) for item in source_evidence]
    evidence = {
        "kind": "coalesced_math_region",
        "policy_version": _MATH_REGION_POLICY_VERSION,
        "bbox": list(bbox),
        "source_indices": [int(item["source_index"]) for item in children],
        "source_object_hashes": source_hashes,
        "source_objects": source_evidence,
    }
    font_names = tuple(
        sorted({str(font) for item in children for font in item.get("fonts") or ()})
    )
    font_sizes = [
        float(item.get("font_size") or 0.0)
        for item in children
        if float(item.get("font_size") or 0.0) > 0.0
    ]
    colors = {int(item.get("color") or 0) for item in children}
    block_type = (
        PageBlockType.MIXED_TEXT_MATH
        if any(_is_prose_entry(item) for item in children)
        else PageBlockType.DISPLAY_MATH
    )
    return {
        "kind": "text",
        "source_index": min(int(item["source_index"]) for item in children),
        "bbox": bbox,
        # Keep every source fragment as a separate visual proposal. The host
        # does not guess operators, braces, or mathematical reading order.
        "text": "\n".join(
            str(item.get("text") or "")
            for item in children
            if str(item.get("text") or "")
        ),
        "fonts": font_names,
        "font_size": statistics.median(font_sizes or [0.0]),
        "bold": any(bool(item.get("bold")) for item in children),
        "italic": any(bool(item.get("italic")) for item in children),
        "line_count": sum(int(item.get("line_count") or 0) for item in children),
        "span_count": sum(int(item.get("span_count") or 0) for item in children),
        "color": next(iter(colors)) if len(colors) == 1 else -1,
        "math_likelihood": max(
            float(item.get("math_likelihood") or 0.0) for item in children
        ),
        "block_type_override": block_type,
        "source_object_count": len(children),
        "evidence": evidence,
    }


def _coalesce_math_regions(
    text_entries: Sequence[dict[str, Any]],
    *,
    page_width: float,
    median_font_size: float,
    double_column_likelihood: float,
) -> list[dict[str, Any]]:
    """Coalesce fragmented source objects into stable, patchable visual regions."""
    entries = list(text_entries)
    parents = list(range(len(entries)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(first: int, second: int) -> None:
        first_root = find(first)
        second_root = find(second)
        if first_root == second_root:
            return
        if first_root < second_root:
            parents[second_root] = first_root
        else:
            parents[first_root] = second_root

    for first_index, first in enumerate(entries):
        for second_index in range(first_index + 1, len(entries)):
            if _math_region_entries_are_adjacent(
                first,
                entries[second_index],
                page_width=page_width,
                median_font_size=median_font_size,
                double_column_likelihood=double_column_likelihood,
            ):
                union(first_index, second_index)

    components: dict[int, list[dict[str, Any]]] = {}
    for index, entry in enumerate(entries):
        components.setdefault(find(index), []).append(entry)
    result = [
        _coalesced_math_entry(component) if len(component) > 1 else component[0]
        for _root, component in sorted(components.items())
    ]
    return sorted(result, key=lambda item: int(item["source_index"]))


def _is_isolated_printed_page_number(
    entry: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    *,
    page_width: float,
    page_height: float,
    median_font_size: float,
) -> bool:
    """Identify a printed folio without treating body digits as footnotes.

    The decision deliberately combines content, typography, edge geometry,
    conventional folio placement, and isolation.  A bare superscript marker
    next to real footnote text therefore remains a footnote candidate, while an
    isolated small page number remains source evidence but is not body content.
    """
    if entry.get("kind") != "text" or entry.get("block_type_override") is not None:
        return False
    text = str(entry.get("text") or "").strip()
    if _PRINTED_PAGE_NUMBER_RE.fullmatch(text) is None:
        return False
    if (
        int(entry.get("line_count") or 0) != 1
        or int(entry.get("span_count") or 0) != 1
        or median_font_size <= 0
    ):
        return False
    x0, y0, x1, y1 = entry["bbox"]
    width = max(0.0, float(x1) - float(x0))
    height = max(0.0, float(y1) - float(y0))
    if (
        width <= 0
        or height <= 0
        or width > page_width * 0.10
        or height > page_height * 0.05
    ):
        return False
    at_top = float(y1) <= page_height * 0.12
    at_bottom = float(y0) >= page_height * 0.88
    if not (at_top or at_bottom):
        return False
    center_ratio = ((float(x0) + float(x1)) / 2.0) / page_width
    centered = 0.40 <= center_ratio <= 0.60
    if not (
        centered
        or center_ratio <= 0.18
        or center_ratio >= 0.82
    ):
        return False
    # A centered one-token folio is already strongly identified by the narrow
    # edge geometry.  Outer-corner folios need the additional small-type and
    # isolation evidence because a real footnote marker often sits near a text
    # margin.
    if centered:
        return True
    if float(entry.get("font_size") or 0.0) > median_font_size * 0.90:
        return False

    isolation_limit = max(height * 2.2, median_font_size * 1.8)
    for peer in entries:
        if peer is entry or peer.get("kind") != "text":
            continue
        if not str(peer.get("text") or "").strip():
            continue
        peer_x0, peer_y0, peer_x1, peer_y1 = peer["bbox"]
        peer_at_same_edge = (
            at_top and float(peer_y1) <= page_height * 0.16
        ) or (
            at_bottom and float(peer_y0) >= page_height * 0.84
        )
        if not peer_at_same_edge:
            continue
        vertical_gap = max(
            float(peer_y0) - float(y1),
            float(y0) - float(peer_y1),
            0.0,
        )
        vertical_overlap = min(float(y1), float(peer_y1)) - max(
            float(y0), float(peer_y0)
        )
        horizontal_gap = max(
            float(peer_x0) - float(x1),
            float(x0) - float(peer_x1),
            0.0,
        )
        if vertical_overlap > 0 or (
            vertical_gap <= isolation_limit
            and horizontal_gap <= page_width * 0.65
        ):
            return False
    return True


def _block_type(
    entry: Mapping[str, Any],
    *,
    page_height: float,
    median_font_size: float,
    printed_page_number: bool = False,
) -> PageBlockType:
    if entry["kind"] == "image":
        return PageBlockType.FIGURE
    override = entry.get("block_type_override")
    if override is not None:
        return PageBlockType(override)
    text = str(entry["text"] or "")
    stripped = text.strip()
    if not stripped:
        return PageBlockType.UNKNOWN
    if printed_page_number:
        return PageBlockType.PRINTED_PAGE_NUMBER
    size = float(entry["font_size"] or 0.0)
    fonts = tuple(str(item).casefold() for item in (entry.get("fonts") or ()))
    heading_style = (
        median_font_size > 0
        and (
            size >= median_font_size * 1.28
            or bool(entry["bold"])
            or any(
                marker in font
                for font in fonts
                for marker in _SMALL_CAP_FONT_MARKERS
            )
        )
    )
    if _CAPTION_RE.match(stripped):
        return PageBlockType.CAPTION
    # Numbered section headings must be recognized before list/reference
    # prefixes.  Hierarchical numbers are section-like by construction; a
    # top-level dotted number additionally needs heading typography.
    if _NUMBERED_SUBHEADING_RE.match(stripped) or (
        _NUMBERED_HEADING_RE.match(stripped) and heading_style
    ):
        return PageBlockType.HEADING_TEXT
    if _BIBLIOGRAPHY_RE.match(stripped):
        return PageBlockType.BIBLIOGRAPHY_ITEM
    if (
        entry["bbox"][1] >= page_height * 0.80
        and median_font_size > 0
        and size <= median_font_size * 0.82
    ):
        return PageBlockType.FOOTNOTE
    if _LIST_RE.match(stripped):
        return PageBlockType.LIST_ITEM
    if len(stripped) <= 160 and median_font_size > 0 and (
        size >= median_font_size * 1.28
        or bool(entry["bold"]) and len(stripped) <= 90
    ):
        return PageBlockType.HEADING_TEXT
    likelihood = float(entry["math_likelihood"])
    if likelihood >= 0.55:
        return PageBlockType.DISPLAY_MATH
    if likelihood >= 0.16:
        if _looks_like_mixed_text_math(stripped):
            return PageBlockType.MIXED_TEXT_MATH
        return PageBlockType.INLINE_MATH
    return PageBlockType.TEXT


def _rect_area(value: Sequence[object]) -> float:
    x0, y0, x1, y1 = _bbox(value)
    return max(0.0, x1 - x0) * max(0.0, y1 - y0)


def _rect_intersection_area(
    first: Sequence[object],
    second: Sequence[object],
) -> float:
    first_x0, first_y0, first_x1, first_y1 = _bbox(first)
    second_x0, second_y0, second_x1, second_y1 = _bbox(second)
    return max(0.0, min(first_x1, second_x1) - max(first_x0, second_x0)) * max(
        0.0,
        min(first_y1, second_y1) - max(first_y0, second_y0),
    )


def _canonical_drawing_geometry(value: object) -> object:
    """Convert PyMuPDF geometry into a stable JSON-compatible projection."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return _round(value)
    if all(hasattr(value, name) for name in ("x0", "y0", "x1", "y1")):
        return [
            _round(getattr(value, "x0")),
            _round(getattr(value, "y0")),
            _round(getattr(value, "x1")),
            _round(getattr(value, "y1")),
        ]
    if all(hasattr(value, name) for name in ("x", "y")):
        return [_round(getattr(value, "x")), _round(getattr(value, "y"))]
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_drawing_geometry(item)
            for key, item in sorted(value.items(), key=lambda row: str(row[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [_canonical_drawing_geometry(item) for item in value]
    return str(value)


def _drawing_evidence(index: int, drawing: Mapping[str, Any]) -> dict[str, object]:
    color = drawing.get("color")
    fill = drawing.get("fill")
    width = drawing.get("width")
    return {
        "source_drawing_index": index,
        "rect": list(_bbox(drawing.get("rect") or ())),
        "type": str(drawing.get("type") or ""),
        "close_path": bool(drawing.get("closePath")),
        "color": _canonical_drawing_geometry(color),
        "fill": _canonical_drawing_geometry(fill),
        "width": _round(width) if isinstance(width, (int, float)) else None,
        "dashes": str(drawing.get("dashes") or ""),
        "line_cap": _canonical_drawing_geometry(drawing.get("lineCap")),
        "line_join": _canonical_drawing_geometry(drawing.get("lineJoin")),
        "items": _canonical_drawing_geometry(tuple(drawing.get("items") or ())),
    }


def _drawing_belongs_to_cluster(
    drawing_bbox: Sequence[object],
    cluster_bbox: Sequence[object],
) -> bool:
    drawing = _bbox(drawing_bbox)
    cluster = _bbox(cluster_bbox)
    drawing_area = _rect_area(drawing)
    if drawing_area > 0:
        return _rect_intersection_area(drawing, cluster) / drawing_area >= 0.80
    tolerance = 1.5
    return (
        drawing[0] >= cluster[0] - tolerance
        and drawing[1] >= cluster[1] - tolerance
        and drawing[2] <= cluster[2] + tolerance
        and drawing[3] <= cluster[3] + tolerance
    )


def _adjacent_figure_caption(
    cluster_bbox: Sequence[object],
    text_entries: Sequence[Mapping[str, Any]],
    *,
    page_height: float,
) -> bool:
    cluster_x0, _cluster_y0, cluster_x1, cluster_y1 = _bbox(cluster_bbox)
    cluster_width = max(0.0, cluster_x1 - cluster_x0)
    for entry in text_entries:
        text = str(entry.get("text") or "").strip()
        if _FIGURE_CAPTION_RE.match(text) is None:
            continue
        x0, y0, x1, _y1 = _bbox(entry.get("bbox") or ())
        gap = y0 - cluster_y1
        horizontal_overlap = max(0.0, min(cluster_x1, x1) - max(cluster_x0, x0))
        if (
            -2.0 <= gap <= max(28.0, page_height * 0.06)
            and horizontal_overlap >= min(cluster_width, max(0.0, x1 - x0)) * 0.25
        ):
            return True
    return False


def _bounded_local_figure_bbox(
    bbox: Sequence[object],
    *,
    page_width: float,
    page_height: float,
) -> bool:
    x0, y0, x1, y1 = _bbox(bbox)
    width = max(0.0, x1 - x0)
    height = max(0.0, y1 - y0)
    page_area = max(1.0, page_width * page_height)
    area_ratio = width * height / page_area
    return (
        width >= 36.0
        and height >= 24.0
        and width / page_width >= 0.06
        and height / page_height >= 0.025
        and width / page_width <= 0.94
        and height / page_height <= 0.78
        and 0.002 <= area_ratio <= 0.72
    )


def _vector_figure_entries(
    page: Any,
    *,
    page_width: float,
    page_height: float,
    text_entries: Sequence[dict[str, Any]],
    image_entries: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], set[int]]:
    """Return conservative vector figures and absorbed in-figure text ids.

    PyMuPDF's drawing clusters are only candidates.  A cluster must be a
    bounded local region with multiple connected drawing objects and either
    strong filled/coloured complexity or a nearby printed Figure caption.
    Tables, formula rules, page borders, and isolated decoration therefore do
    not become figures merely because they contain vector paths.
    """

    try:
        raw_drawings = tuple(page.get_drawings() or ())
        raw_clusters = tuple(page.cluster_drawings() or ())
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return [], set()
    drawings = tuple(
        (index, drawing)
        for index, drawing in enumerate(raw_drawings)
        if isinstance(drawing, Mapping) and drawing.get("rect") is not None
    )
    if not drawings or not raw_clusters:
        return [], set()

    figure_entries: list[dict[str, Any]] = []
    absorbed_source_indices: set[int] = set()
    for cluster_index, raw_cluster in enumerate(raw_clusters):
        cluster = _clipped_bbox(tuple(raw_cluster), page_width, page_height)
        if not _bounded_local_figure_bbox(
            cluster,
            page_width=page_width,
            page_height=page_height,
        ):
            continue
        members = tuple(
            (index, drawing)
            for index, drawing in drawings
            if _drawing_belongs_to_cluster(drawing.get("rect") or (), cluster)
        )
        if len(members) < 4:
            continue
        # Do not duplicate an embedded raster object that already owns the
        # same local region.
        cluster_area = _rect_area(cluster)
        if any(
            _rect_intersection_area(cluster, image.get("bbox") or ())
            / max(1.0, min(cluster_area, _rect_area(image.get("bbox") or ())))
            >= 0.85
            for image in image_entries
        ):
            continue

        filled = sum(member.get("fill") is not None for _index, member in members)
        coloured = {
            tuple(round(float(channel), 4) for channel in color)
            for _index, member in members
            for color in (member.get("fill"), member.get("color"))
            if isinstance(color, Sequence)
            and not isinstance(color, (str, bytes, bytearray))
            and len(color) in {1, 3, 4}
            and any(abs(float(channel)) > 1e-6 for channel in color)
        }
        item_kinds = {
            str(item[0])
            for _index, member in members
            for item in (member.get("items") or ())
            if isinstance(item, Sequence) and item
        }
        caption_adjacent = _adjacent_figure_caption(
            cluster,
            text_entries,
            page_height=page_height,
        )
        strong_complexity = (
            len(members) >= 8
            and (filled >= 2 or len(coloured) >= 2)
            and len(item_kinds) >= 1
        )
        if not (caption_adjacent or strong_complexity):
            continue
        if caption_adjacent and filled < 1 and len(members) < 6:
            continue

        padding = max(2.0, min(6.0, min(page_width, page_height) * 0.006))
        absorption_region = (
            max(0.0, cluster[0] - padding),
            max(0.0, cluster[1] - padding),
            min(page_width, cluster[2] + padding),
            min(page_height, cluster[3] + padding),
        )
        absorbed: list[dict[str, Any]] = []
        for entry in text_entries:
            text = str(entry.get("text") or "").strip()
            if not text or _FIGURE_CAPTION_RE.match(text):
                continue
            entry_bbox = entry.get("bbox") or ()
            entry_area = _rect_area(entry_bbox)
            overlap = _rect_intersection_area(entry_bbox, absorption_region)
            if (
                entry_area > 0
                and overlap / entry_area >= 0.80
                and entry_area <= cluster_area * 0.35
                and len(text) <= 96
                and int(entry.get("line_count") or 0) <= 6
            ):
                absorbed.append(entry)
        absorbed_indices = {int(entry["source_index"]) for entry in absorbed}
        if absorbed_indices & absorbed_source_indices:
            # Overlapping accepted clusters would duplicate labels and object
            # hashes.  Reject the later candidate instead of guessing.
            continue
        absorbed_source_indices.update(absorbed_indices)
        content_boxes = [cluster, *(entry["bbox"] for entry in absorbed)]
        content_bbox = (
            min(box[0] for box in content_boxes),
            min(box[1] for box in content_boxes),
            max(box[2] for box in content_boxes),
            max(box[3] for box in content_boxes),
        )
        padded = (
            max(0.0, content_bbox[0] - padding),
            max(0.0, content_bbox[1] - padding),
            min(page_width, content_bbox[2] + padding),
            min(page_height, content_bbox[3] + padding),
        )
        evidence = {
            "kind": "vector_drawing_figure",
            "policy_version": _VECTOR_FIGURE_POLICY_VERSION,
            "source_cluster_index": cluster_index,
            "bbox": list(padded),
            "drawing_objects": [
                _drawing_evidence(index, drawing) for index, drawing in members
            ],
            "absorbed_text_objects": [entry["evidence"] for entry in absorbed],
            "caption_adjacent": caption_adjacent,
        }
        figure_entries.append({
            "kind": "vector_figure",
            "source_index": 2_000_000 + cluster_index,
            "bbox": padded,
            "text": "",
            "fonts": (),
            "font_size": 0.0,
            "bold": False,
            "italic": False,
            "line_count": 0,
            "span_count": 0,
            "color": 0,
            "math_likelihood": 0.0,
            "block_type_override": PageBlockType.FIGURE,
            "source_object_count": len(members) + len(absorbed),
            "host_figure": True,
            "host_figure_source": NATIVE_FIGURE_SOURCE,
            "evidence": evidence,
        })
    return figure_entries, absorbed_source_indices


def _image_entries(page: Any, width: float, height: float) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        infos = page.get_image_info(hashes=True, xrefs=True)
    except (AttributeError, RuntimeError, ValueError):
        infos = []
    for index, info in enumerate(infos):
        bbox = _clipped_bbox(info.get("bbox") or (), width, height)
        raw_digest = info.get("digest") or b""
        digest = raw_digest.hex() if isinstance(raw_digest, bytes) else str(raw_digest)
        evidence = {
            "kind": "image",
            "bbox": list(bbox),
            "xref": int(info.get("xref") or 0),
            "pixel_width": int(info.get("width") or 0),
            "pixel_height": int(info.get("height") or 0),
            "digest": digest,
        }
        result.append({
            "kind": "image",
            "source_index": 1_000_000 + index,
            "bbox": bbox,
            "text": "",
            "fonts": (),
            "font_size": 0.0,
            "bold": False,
            "italic": False,
            "line_count": 0,
            "span_count": 0,
            "color": 0,
            "math_likelihood": 0.0,
            "host_figure": _bounded_local_figure_bbox(
                bbox,
                page_width=width,
                page_height=height,
            ),
            "host_figure_source": NATIVE_FIGURE_SOURCE,
            "evidence": evidence,
        })
    return result


def _extract_open_page(
    page: Any,
    *,
    source_pdf_sha256: str,
    source_page_number: int,
    selected_index: int,
) -> PageClassification:
    width = _round(page.rect.width)
    height = _round(page.rect.height)
    page_id = f"ocr-page-{selected_index:06d}"
    try:
        text_dict = page.get_text("dict", sort=False)
    except (RuntimeError, ValueError) as exc:
        raise ValueError(f"cannot extract PDF text objects from page {source_page_number}") from exc

    text_entries: list[dict[str, Any]] = []
    all_font_sizes: list[float] = []
    all_characters: list[str] = []
    font_character_total = 0
    font_character_healthy = 0
    in_bounds_text_area = 0.0
    raw_text_area = 0.0
    horizontal_spans = 0
    total_spans = 0
    source_text_layer_evidence: list[dict[str, object]] = []
    raw_blocks = tuple(text_dict.get("blocks") or ())
    for source_index, raw_block in enumerate(raw_blocks):
        if not isinstance(raw_block, Mapping) or int(raw_block.get("type") or 0) != 0:
            continue
        text = _block_text(raw_block)
        spans = _spans(raw_block)
        fonts = tuple(sorted({str(span.get("font") or "") for span in spans}))
        sizes = [float(span.get("size") or 0.0) for span in spans if float(span.get("size") or 0.0) > 0]
        weighted_size_values: list[float] = []
        for span in spans:
            span_text = str(span.get("text") or "")
            span_size = float(span.get("size") or 0.0)
            font = str(span.get("font") or "").casefold()
            all_characters.extend(span_text)
            weighted_size_values.extend([span_size] * max(1, len(span_text.strip())))
            character_count = len(span_text)
            font_character_total += character_count
            font_is_healthy = bool(font) and ".notdef" not in font and "unknown" not in font
            font_character_healthy += sum(
                font_is_healthy and not _is_garbled(character)
                for character in span_text
            )
            total_spans += 1
        for line in raw_block.get("lines") or ():
            direction = line.get("dir") or (1.0, 0.0) if isinstance(line, Mapping) else (1.0, 0.0)
            try:
                if abs(float(direction[1])) <= 0.15:
                    horizontal_spans += len(line.get("spans") or ())
            except (IndexError, TypeError, ValueError):
                pass
        all_font_sizes.extend(weighted_size_values)
        raw_bbox = _bbox(raw_block.get("bbox") or ())
        bbox = _clipped_bbox(raw_bbox, width, height)
        raw_area = max(0.0, raw_bbox[2] - raw_bbox[0]) * max(0.0, raw_bbox[3] - raw_bbox[1])
        clipped_area = max(0.0, bbox[2] - bbox[0]) * max(0.0, bbox[3] - bbox[1])
        raw_text_area += raw_area
        in_bounds_text_area += clipped_area
        flags = [int(span.get("flags") or 0) for span in spans]
        colors = [int(span.get("color") or 0) for span in spans]
        math_likelihood = _math_likelihood(text, spans)
        evidence = {
            "kind": "text",
            "source_block_number": int(raw_block.get("number") or source_index),
            "bbox": list(bbox),
            "text": text,
            "fonts": list(fonts),
            "font_sizes": [round(item, 4) for item in sizes],
            "flags": flags,
            "colors": colors,
            "line_count": len(raw_block.get("lines") or ()),
        }
        source_text_layer_evidence.append(evidence)
        entry = {
            "kind": "text",
            "source_index": source_index,
            "bbox": bbox,
            "text": text,
            "fonts": fonts,
            "font_size": statistics.median(weighted_size_values or sizes or [0.0]),
            "bold": any(flag & 16 for flag in flags),
            "italic": any(flag & 2 for flag in flags),
            "line_count": len(raw_block.get("lines") or ()),
            "span_count": len(spans),
            "color": colors[0] if colors and len(set(colors)) == 1 else -1,
            "math_likelihood": math_likelihood,
            "evidence": evidence,
        }
        if _formal_display_split_is_supported(raw_blocks, source_index):
            text_entries.extend(_split_text_entry_at_first_line(entry, raw_block))
        else:
            text_entries.append(entry)

    images = _image_entries(page, width, height)
    vector_figures, absorbed_text_indices = _vector_figure_entries(
        page,
        page_width=width,
        page_height=height,
        text_entries=text_entries,
        image_entries=images,
    )
    if absorbed_text_indices:
        text_entries = [
            entry
            for entry in text_entries
            if int(entry["source_index"]) not in absorbed_text_indices
        ]
    figure_entries = [*images, *vector_figures]
    image_rectangles = [entry["bbox"] for entry in figure_entries]
    page_area = width * height
    image_area = _rectangle_union_area(image_rectangles)
    image_coverage = min(1.0, image_area / page_area) if page_area else 0.0
    maximum_image_ratio = max(
        (
            (entry["bbox"][2] - entry["bbox"][0])
            * (entry["bbox"][3] - entry["bbox"][1])
            / page_area
            for entry in figure_entries
        ),
        default=0.0,
    )

    characters = [character for character in all_characters if not character.isspace()]
    character_count = len(characters)
    printable_ratio = (
        sum(character.isprintable() for character in characters) / character_count
        if character_count
        else 0.0
    )
    replacement_ratio = characters.count("\ufffd") / character_count if character_count else 0.0
    garbled_ratio = (
        sum(_is_garbled(character) for character in characters) / character_count
        if character_count
        else 0.0
    )
    font_health = (
        font_character_healthy / font_character_total if font_character_total else 0.0
    )
    math_density = (
        sum(_is_math_character(character) for character in characters) / character_count
        if character_count
        else 0.0
    )
    double_column = _double_column_likelihood(text_entries, width)
    reading_confidence = _reading_order_confidence(text_entries, double_column)
    bbox_confidence = min(1.0, in_bounds_text_area / raw_text_area) if raw_text_area else 0.0
    direction_confidence = horizontal_spans / total_spans if total_spans else 0.0
    alignment_confidence = (
        round(0.75 * bbox_confidence + 0.25 * direction_confidence, 6)
        if total_spans
        else 0.0
    )
    median_font_size = statistics.median(all_font_sizes) if all_font_sizes else 0.0
    region_entries = _coalesce_math_regions(
        text_entries,
        page_width=width,
        median_font_size=median_font_size,
        double_column_likelihood=double_column,
    )
    formula_regions = sum(
        float(entry["math_likelihood"]) >= 0.35 for entry in region_entries
    )
    features = PageFeatures(
        page_width=width,
        page_height=height,
        rotation=int(page.rotation or 0),
        has_text_objects=bool(text_entries),
        text_character_count=character_count,
        printable_character_ratio=round(printable_ratio, 6),
        unicode_replacement_ratio=round(replacement_ratio, 6),
        garbled_character_ratio=round(garbled_ratio, 6),
        font_mapping_health=round(font_health, 6),
        text_block_count=len(text_entries),
        image_count=len(figure_entries),
        image_coverage_ratio=round(image_coverage, 6),
        single_full_page_image=(
            len(figure_entries) == 1 and maximum_image_ratio >= 0.85
        ),
        math_symbol_density=round(math_density, 6),
        formula_region_count=formula_regions,
        double_column_likelihood=double_column,
        text_pixel_alignment_confidence=alignment_confidence,
        reading_order_confidence=reading_confidence,
    )

    ordered = _ordered_entries(
        [*region_entries, *figure_entries],
        width,
        double_column,
    )
    blocks: list[PageBlock] = []
    page_evidence_blocks: list[dict[str, Any]] = []
    host_figure_index = 0
    for reading_order, entry in enumerate(ordered, 1):
        object_hash = _hash_object(entry["evidence"])
        block_id = f"{page_id}-block-{reading_order:04d}-{object_hash[:12]}"
        block_kind = _block_type(
            entry,
            page_height=height,
            median_font_size=median_font_size,
            printed_page_number=_is_isolated_printed_page_number(
                entry,
                region_entries,
                page_width=width,
                page_height=height,
                median_font_size=median_font_size,
            ),
        )
        style = {
            "font_names": "|".join(entry["fonts"]),
            "font_size": round(float(entry["font_size"]), 4),
            "bold": bool(entry["bold"]),
            "italic": bool(entry["italic"]),
            "line_count": int(entry["line_count"]),
            "span_count": int(entry["span_count"]),
            "color": int(entry["color"]),
            "source_object_count": int(entry.get("source_object_count") or 1),
        }
        if bool(entry.get("host_figure")):
            host_figure_index += 1
            figure_path = native_figure_path(source_page_number, host_figure_index)
            style.update({
                "host_figure_index": host_figure_index,
                "host_figure_path": figure_path,
                "host_figure_source": str(
                    entry.get("host_figure_source") or NATIVE_FIGURE_SOURCE
                ),
            })
            candidate_latex = native_figure_latex(
                figure_path,
                bbox=entry["bbox"],
                page_width=width,
            )
        else:
            candidate_latex = (
                _latex_visible_text(str(entry["text"]))
                if entry["kind"] == "text"
                else ""
            )
        blocks.append(PageBlock(
            block_id=block_id,
            block_type=block_kind,
            bbox=entry["bbox"],
            reading_order=reading_order,
            plain_text=str(entry["text"]),
            style_features=style,  # type: ignore[arg-type]
            math_likelihood=float(entry["math_likelihood"]),
            source_object_hash=object_hash,
            candidate_latex=candidate_latex,
        ))
        page_evidence_blocks.append(entry["evidence"])

    text_layer_payload = source_text_layer_evidence
    text_layer_sha256 = _hash_object(text_layer_payload)
    page_object_hash = _hash_object({
        "source_pdf_sha256": source_pdf_sha256,
        "source_page_number": source_page_number,
        "page_xref": int(getattr(page, "xref", 0) or 0),
        "width": width,
        "height": height,
        "rotation": int(page.rotation or 0),
        "objects": page_evidence_blocks,
    })
    candidate_tex = "\n\n".join(
        block.candidate_latex for block in blocks if block.candidate_latex
    )
    return PageClassification(
        page_id=page_id,
        source_page_number=source_page_number,
        selected_index=selected_index,
        strategy=classify_page_features(features, source_type="pdf"),
        features=features,
        blocks=tuple(blocks),
        source_page_object_hash=page_object_hash,
        source_text_layer_sha256=text_layer_sha256,
        candidate_tex=candidate_tex,
    )


def _extraction_worker_count(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("extraction_workers must be an integer")
    if value != 1 and value < MIN_OBJECT_EXTRACTION_WORKERS:
        raise ValueError(
            "extraction_workers must be 1 for serial extraction or between "
            f"{MIN_OBJECT_EXTRACTION_WORKERS} and {MAX_EXTRACTION_WORKERS}"
        )
    if value > MAX_EXTRACTION_WORKERS:
        raise ValueError(
            "extraction_workers must be 1 for serial extraction or between "
            f"{MIN_OBJECT_EXTRACTION_WORKERS} and {MAX_EXTRACTION_WORKERS}"
        )
    return value


def _open_pdf(payload: bytes) -> Any:
    pymupdf = _pymupdf()
    try:
        document = pymupdf.open(stream=payload, filetype="pdf")
    except (RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("input is not a readable PDF") from exc
    if bool(getattr(document, "needs_pass", False)):
        document.close()
        raise ValueError("encrypted PDF requires a password before OCR extraction")
    return document


def _initialize_extraction_worker(payload: bytes, source_pdf_sha256: str) -> None:
    """Open one private read-only document in an isolated worker process."""

    global _WORKER_DOCUMENT, _WORKER_SOURCE_PDF_SHA256
    if _WORKER_DOCUMENT is not None:
        try:
            _WORKER_DOCUMENT.close()
        except Exception:  # pragma: no cover - defensive process teardown only
            pass
    _WORKER_DOCUMENT = _open_pdf(bytes(payload))
    _WORKER_SOURCE_PDF_SHA256 = str(source_pdf_sha256)


def _extract_worker_page(
    task: tuple[int, int],
) -> tuple[int, PageClassification]:
    """Extract one page from process-local state and retain its output slot."""

    selected_index, source_page_number = task
    document = _WORKER_DOCUMENT
    if document is None or not _WORKER_SOURCE_PDF_SHA256:
        raise RuntimeError("OCR extraction worker was not initialized")
    page = _extract_open_page(
        document.load_page(source_page_number - 1),
        source_pdf_sha256=_WORKER_SOURCE_PDF_SHA256,
        source_page_number=source_page_number,
        selected_index=selected_index,
    )
    return selected_index, page


def _extract_pages_serial(
    payload: bytes,
    *,
    source_pdf_sha256: str,
    page_numbers: Sequence[int],
) -> tuple[PageClassification, ...]:
    document = _open_pdf(payload)
    try:
        return tuple(
            _extract_open_page(
                document.load_page(source_page_number - 1),
                source_pdf_sha256=source_pdf_sha256,
                source_page_number=source_page_number,
                selected_index=selected_index,
            )
            for selected_index, source_page_number in enumerate(page_numbers, 1)
        )
    finally:
        document.close()


def _extract_pages_parallel(
    payload: bytes,
    *,
    source_pdf_sha256: str,
    page_numbers: Sequence[int],
    extraction_workers: int,
) -> tuple[PageClassification, ...]:
    """Run a fail-closed process pool with at most one queued task per worker."""

    tasks = tuple(enumerate(page_numbers, 1))
    worker_count = min(extraction_workers, len(tasks))
    results: list[PageClassification | None] = [None] * len(tasks)
    executor = ProcessPoolExecutor(
        max_workers=worker_count,
        initializer=_initialize_extraction_worker,
        initargs=(payload, source_pdf_sha256),
    )
    pending: dict[Future[tuple[int, PageClassification]], tuple[int, int]] = {}
    next_task = 0
    failed = True
    try:
        while next_task < len(tasks) and len(pending) < worker_count:
            task = tasks[next_task]
            pending[executor.submit(_extract_worker_page, task)] = task
            next_task += 1
        while pending:
            completed, _not_done = wait(tuple(pending), return_when=FIRST_COMPLETED)
            finished: list[tuple[int, PageClassification]] = []
            for future in sorted(completed, key=lambda item: pending[item][0]):
                expected_index, expected_source_page = pending.pop(future)
                returned_index, page = future.result()
                if returned_index != expected_index:
                    raise RuntimeError("OCR extraction worker returned the wrong output slot")
                if (
                    page.selected_index != expected_index
                    or page.page_id != f"ocr-page-{expected_index:06d}"
                    or page.source_page_number != expected_source_page
                ):
                    raise RuntimeError("OCR extraction worker returned mismatched page identity")
                if results[expected_index - 1] is not None:
                    raise RuntimeError("OCR extraction worker returned a duplicate page")
                finished.append((expected_index, page))
            # Resolve and validate the entire completed set before scheduling
            # replacements.  A single failed future therefore closes the pool
            # without starting work beyond the already-bounded in-flight set.
            for expected_index, page in finished:
                results[expected_index - 1] = page
            for _finished_page in finished:
                if next_task < len(tasks):
                    task = tasks[next_task]
                    pending[executor.submit(_extract_worker_page, task)] = task
                    next_task += 1
        if any(page is None for page in results):
            raise RuntimeError("OCR extraction pool completed with missing pages")
        failed = False
    finally:
        if failed:
            for future in pending:
                future.cancel()
        executor.shutdown(wait=True, cancel_futures=failed)
    return tuple(page for page in results if page is not None)


def extract_pdf_pages(
    pdf_bytes: bytes,
    selected_pages: Sequence[int] | None = None,
    *,
    extraction_workers: int = DEFAULT_EXTRACTION_WORKERS,
) -> tuple[PageClassification, ...]:
    """Extract selected PDF pages in stable order with bounded local workers.

    The recommended/default path uses six isolated processes because PyMuPDF
    document handles are not thread-safe.  ``extraction_workers=1`` is the
    deterministic serial reference and low-resource fallback; every other
    value is hard-bounded at eight.
    """
    payload = bytes(pdf_bytes)
    if not payload:
        raise ValueError("PDF input is empty")
    workers = _extraction_worker_count(extraction_workers)
    document = _open_pdf(payload)
    try:
        page_numbers = tuple(
            range(1, document.page_count + 1) if selected_pages is None else selected_pages
        )
        if not page_numbers:
            raise ValueError("selected_pages cannot be empty")
        if len(page_numbers) != len(set(page_numbers)):
            raise ValueError("selected_pages must be unique")
        if any(
            not isinstance(number, int) or isinstance(number, bool)
            or number < 1
            or number > document.page_count
            for number in page_numbers
        ):
            raise ValueError("selected_pages contains an out-of-range page")
    finally:
        document.close()
    source_hash = _sha256(payload)
    if workers == 1 or len(page_numbers) == 1:
        return _extract_pages_serial(
            payload,
            source_pdf_sha256=source_hash,
            page_numbers=page_numbers,
        )
    return _extract_pages_parallel(
        payload,
        source_pdf_sha256=source_hash,
        page_numbers=page_numbers,
        extraction_workers=workers,
    )


def extract_pdf_page(
    pdf_bytes: bytes,
    source_page_number: int,
    *,
    selected_index: int = 1,
) -> PageClassification:
    """Extract one page while retaining its frozen selected-page identity."""
    if selected_index < 1:
        raise ValueError("selected_index must be positive")
    pages = extract_pdf_pages(pdf_bytes, (source_page_number,), extraction_workers=1)
    page = pages[0]
    if selected_index == 1:
        return page
    # Re-extracting with a different selected index is intentional: both the
    # page_id and every block_id must be bound to that immutable index.
    payload = bytes(pdf_bytes)
    pymupdf = _pymupdf()
    document = pymupdf.open(stream=payload, filetype="pdf")
    try:
        return _extract_open_page(
            document.load_page(source_page_number - 1),
            source_pdf_sha256=_sha256(payload),
            source_page_number=source_page_number,
            selected_index=selected_index,
        )
    finally:
        document.close()


def extract_image_page(
    image_bytes: bytes,
    *,
    source_page_number: int = 1,
    selected_index: int = 1,
) -> PageClassification:
    """Bind one original image to the scanned-page path as ``IMAGE_ONLY``."""
    payload = bytes(image_bytes)
    if not payload:
        raise ValueError("image input is empty")
    if source_page_number < 1 or selected_index < 1:
        raise ValueError("page numbers and selected indexes must be positive")
    pymupdf = _pymupdf()
    try:
        pixmap = pymupdf.Pixmap(payload)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("input is not a readable image") from exc
    try:
        width = float(pixmap.width)
        height = float(pixmap.height)
    finally:
        pixmap = None
    page_id = f"ocr-page-{selected_index:06d}"
    source_hash = _sha256(payload)
    object_hash = _hash_object({
        "kind": "original-image",
        "source_sha256": source_hash,
        "width": width,
        "height": height,
    })
    block = PageBlock(
        block_id=f"{page_id}-block-0001-{object_hash[:12]}",
        block_type=PageBlockType.FIGURE,
        bbox=(0.0, 0.0, width, height),
        reading_order=1,
        plain_text="",
        style_features={
            "font_names": "",
            "font_size": 0.0,
            "bold": False,
            "italic": False,
            "line_count": 0,
            "span_count": 0,
            "color": 0,
        },  # type: ignore[arg-type]
        math_likelihood=0.0,
        source_object_hash=object_hash,
        candidate_latex="",
    )
    features = PageFeatures(
        page_width=width,
        page_height=height,
        rotation=0,
        has_text_objects=False,
        text_character_count=0,
        printable_character_ratio=0.0,
        unicode_replacement_ratio=0.0,
        garbled_character_ratio=0.0,
        font_mapping_health=0.0,
        text_block_count=0,
        image_count=1,
        image_coverage_ratio=1.0,
        single_full_page_image=True,
        math_symbol_density=0.0,
        formula_region_count=0,
        double_column_likelihood=0.0,
        text_pixel_alignment_confidence=0.0,
        reading_order_confidence=0.0,
    )
    return PageClassification(
        page_id=page_id,
        source_page_number=source_page_number,
        selected_index=selected_index,
        strategy=classify_page_features(features, source_type="image"),
        features=features,
        blocks=(block,),
        source_page_object_hash=source_hash,
        source_text_layer_sha256=_sha256(b""),
        candidate_tex="",
    )


__all__ = [
    "DEFAULT_EXTRACTION_WORKERS",
    "MAX_EXTRACTION_WORKERS",
    "extract_image_page",
    "extract_pdf_page",
    "extract_pdf_pages",
]

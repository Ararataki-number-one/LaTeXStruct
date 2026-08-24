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
from .ocr_schema import PageBlock, PageBlockType, PageClassification, PageFeatures


_CAPTION_RE = re.compile(r"^\s*(?:fig(?:ure)?\.?|table|图|表)\s*\d*", re.IGNORECASE)
_BIBLIOGRAPHY_RE = re.compile(r"^\s*(?:\[\s*\d+\s*\]|\d+\s*[.)]\s+)")
_LIST_RE = re.compile(r"^\s*(?:[•◦▪‣]|[-–—]\s+|(?:\d+|[A-Za-z])[.)]\s+)")
_MATH_ASCII = frozenset("=+-*/<>^_|∑∏∫√∞≈≠≤≥±×÷∈∉⊂⊆⊃⊇∪∩→←↔⇒⇔∀∃∂∇")
_MATH_FONT_MARKERS = ("math", "cmmi", "cmsy", "cmex", "symbol", "euclid", "mt extra")
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


def _math_likelihood(text: str, fonts: Sequence[str]) -> float:
    characters = [character for character in text if not character.isspace()]
    if not characters:
        return 0.0
    math_count = sum(_is_math_character(character) for character in characters)
    digit_count = sum(character.isdigit() for character in characters)
    font_signal = any(
        marker in font.casefold()
        for font in fonts
        for marker in _MATH_FONT_MARKERS
    )
    density = math_count / len(characters)
    if math_count and digit_count:
        density += min(0.15, digit_count / len(characters) * 0.25)
    if font_signal:
        density += 0.35
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


def _block_type(
    entry: Mapping[str, Any],
    *,
    page_height: float,
    median_font_size: float,
) -> PageBlockType:
    if entry["kind"] == "image":
        return PageBlockType.FIGURE
    text = str(entry["text"] or "")
    stripped = text.strip()
    if not stripped:
        return PageBlockType.UNKNOWN
    size = float(entry["font_size"] or 0.0)
    if _CAPTION_RE.match(stripped):
        return PageBlockType.CAPTION
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
        return PageBlockType.INLINE_MATH
    return PageBlockType.TEXT


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
    for source_index, raw_block in enumerate(text_dict.get("blocks") or ()):
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
        math_likelihood = _math_likelihood(text, fonts)
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
        text_entries.append({
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
        })

    images = _image_entries(page, width, height)
    image_rectangles = [entry["bbox"] for entry in images]
    page_area = width * height
    image_area = _rectangle_union_area(image_rectangles)
    image_coverage = min(1.0, image_area / page_area) if page_area else 0.0
    maximum_image_ratio = max(
        (
            (entry["bbox"][2] - entry["bbox"][0])
            * (entry["bbox"][3] - entry["bbox"][1])
            / page_area
            for entry in images
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
    formula_regions = sum(
        float(entry["math_likelihood"]) >= 0.35 for entry in text_entries
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
        image_count=len(images),
        image_coverage_ratio=round(image_coverage, 6),
        single_full_page_image=len(images) == 1 and maximum_image_ratio >= 0.85,
        math_symbol_density=round(math_density, 6),
        formula_region_count=formula_regions,
        double_column_likelihood=double_column,
        text_pixel_alignment_confidence=alignment_confidence,
        reading_order_confidence=reading_confidence,
    )

    ordered = _ordered_entries([*text_entries, *images], width, double_column)
    blocks: list[PageBlock] = []
    page_evidence_blocks: list[dict[str, Any]] = []
    for reading_order, entry in enumerate(ordered, 1):
        object_hash = _hash_object(entry["evidence"])
        block_id = f"{page_id}-block-{reading_order:04d}-{object_hash[:12]}"
        block_kind = _block_type(
            entry,
            page_height=height,
            median_font_size=median_font_size,
        )
        style = {
            "font_names": "|".join(entry["fonts"]),
            "font_size": round(float(entry["font_size"]), 4),
            "bold": bool(entry["bold"]),
            "italic": bool(entry["italic"]),
            "line_count": int(entry["line_count"]),
            "span_count": int(entry["span_count"]),
            "color": int(entry["color"]),
        }
        candidate_latex = (
            _latex_visible_text(str(entry["text"])) if entry["kind"] == "text" else ""
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

    text_layer_payload = [entry["evidence"] for entry in text_entries]
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

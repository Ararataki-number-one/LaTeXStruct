# -*- coding: utf-8 -*-
"""Fail-closed, offline PDF fidelity gate for a source range and a generated PDF.

This tool measures *mechanical* fidelity that can be established without a model:
page mapping and geometry, normalized extracted-text similarity, chapter-title
coverage, figure-caption / visual-region preservation, generated-font embedding,
and searchability.  Optional sampled rendering adds global SSIM and text-block
(``版心``) estimates.

It deliberately does **not** claim mathematical-semantic accuracy, editorial
correctness, or "98% accuracy".  Those remain explicit unverified items even when
the mechanical 80/100 gate passes.

Exit codes are suitable for a release gate::

    0  mechanical fidelity score >= 80 and every hard gate passed
    1  evaluation completed, but the quality gate failed
    2  evaluation could not be completed (a fail-closed report is still written)

Example for the first seventeen chapters of the Bondy source PDF::

    python tools/evaluate_pdf_fidelity.py source.pdf generated.pdf \
        --source-start 3 --source-end 473 --expected-chapter-count 17 \
        --render-samples 34 --json-out fidelity.json --markdown-out fidelity.md

    python tools/evaluate_pdf_fidelity.py source.pdf source.pdf \
        --manifest benchmark/bondy_first17_fidelity_manifest.json --self-compare

The normal application dependency ``PyMuPDF`` is preferred.  ``pypdf`` is an
accepted fallback, which keeps the evaluator usable in document-tooling runtimes.
No network access and no AI/model invocation are performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence


SCHEMA_VERSION = 1
GATE_NAME = "mechanical_pdf_fidelity_80"
GATE_THRESHOLD = 80.0
TOOL_VERSION = "1.0"

CATEGORY_WEIGHTS = {
    "pagination_geometry": 15.0,
    "text_fidelity": 35.0,
    "chapter_structure": 15.0,
    "figures": 10.0,
    "fonts_searchability": 10.0,
    "rendered_layout": 15.0,
}

CHAPTER_EN_RE = re.compile(
    r"^\s*(?:chapter|chap\.?)[\s\u00a0]+([0-9ivxlcdm]+)\b[\s:.-]*(.*?)\s*$",
    re.IGNORECASE,
)
CHAPTER_ZH_RE = re.compile(r"^\s*第\s*([0-9一二三四五六七八九十百]+)\s*章\s*(.*?)\s*$")
CHAPTER_NUMERIC_RE = re.compile(r"^\s*([1-9][0-9]?)\s+([^\d\s].{1,100}?)\s*$")
# A caption is intentionally stricter than a textual figure reference.  Bondy's
# real captions are extracted as ``Fig. 1.23. Caption text``.  Lines beginning
# ``Figure 1.23`` are prose references, while ``Figure 1.23a`` / ``Fig. 1.23a``
# denote subfigures and must not become additional top-level figure labels.
# Requiring the abbreviated marker, exactly two numeric components, and the
# terminal full stop makes the 17-chapter source inventory reproducibly 195.
CAPTION_RE = re.compile(
    r"(?im)^\s*Fig\.\s*([0-9]+\.[0-9]+)\.\s*(?=\S)"
)
CAPTION_ZH_RE = re.compile(
    r"(?m)^\s*图\s*([0-9]+\.[0-9]+)[.。]\s*(?=\S)"
)
CAPTION_DETECTION_RULE = "line-start Fig. x.y. (two numeric components; terminal period required)"

MANDATORY_UNVERIFIED = {
    "page_inspection",
    "text_extraction",
    "chapter_detection",
    "font_inspection",
}


class EvaluationError(RuntimeError):
    """An operational error that must make the release gate fail closed."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and strictly normalize a release-gate expectation manifest.

    Supported manifests may put source fields at top level or below ``source``.
    Chapter expectations use either ``chapters`` objects, or parallel
    ``chapter_ranges`` / ``figure_label_counts`` arrays.  Unknown fields are
    retained in ``raw`` but never interpreted as instructions.
    """

    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"cannot read fidelity manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvaluationError("fidelity manifest root must be a JSON object")
    source = value.get("source") if isinstance(value.get("source"), dict) else {}
    source_range = source.get("range", value.get("source_range"))
    if source_range is None and value.get("selected_start_page") is not None:
        source_range = [value.get("selected_start_page"), value.get("selected_end_page")]
    if source_range is not None:
        if (
            not isinstance(source_range, list)
            or len(source_range) != 2
            or any(not isinstance(item, int) for item in source_range)
            or source_range[0] <= 0
            or source_range[0] > source_range[1]
        ):
            raise EvaluationError("manifest source range must be [positive_start, inclusive_end]")
        source_range = [int(source_range[0]), int(source_range[1])]
    source_size_mm = source.get("page_size_mm", value.get("source_page_size_mm"))
    if source_size_mm is None and value.get("page_width_mm") is not None:
        source_size_mm = [value.get("page_width_mm"), value.get("page_height_mm")]
    if source_size_mm is not None:
        if (
            not isinstance(source_size_mm, list)
            or len(source_size_mm) != 2
            or any(not isinstance(item, (int, float)) or item <= 0 for item in source_size_mm)
        ):
            raise EvaluationError("manifest source page size must be [width_mm, height_mm]")
        source_size_mm = [float(source_size_mm[0]), float(source_size_mm[1])]
    source_sha256 = str(source.get("sha256", value.get("source_sha256", ""))).strip().upper()
    if source_sha256 and not re.fullmatch(r"[0-9A-F]{64}", source_sha256):
        raise EvaluationError("manifest source SHA-256 must contain exactly 64 hexadecimal characters")

    chapters_raw = value.get("chapters")
    chapters: list[dict[str, Any]] = []
    if chapters_raw is not None:
        if not isinstance(chapters_raw, list):
            raise EvaluationError("manifest chapters must be a JSON list")
        for index, item in enumerate(chapters_raw, start=1):
            if not isinstance(item, dict):
                raise EvaluationError(f"manifest chapter {index} must be an object")
            title = str(item.get("title", "")).strip()
            start = item.get("source_start", item.get("start", item.get("start_page")))
            end = item.get("source_end", item.get("end", item.get("end_page")))
            figure_count = item.get(
                "figure_label_count", item.get("figure_count", item.get("figure_labels"))
            )
            if start is None or end is None or int(start) <= 0 or int(start) > int(end):
                raise EvaluationError(f"manifest chapter {index} needs a valid inclusive source span")
            if figure_count is not None and int(figure_count) < 0:
                raise EvaluationError(f"manifest chapter {index} figure count cannot be negative")
            number = int(item.get("number", index))
            search_title = title
            if title and not (
                CHAPTER_EN_RE.match(title)
                or CHAPTER_ZH_RE.match(title)
                or re.match(r"^\s*[0-9]+(?:\s|[.:])", title)
            ):
                search_title = f"{number} {title}"
            chapters.append(
                {
                    "number": number,
                    "title": search_title,
                    "display_title": title or search_title,
                    "source_start": int(start),
                    "source_end": int(end),
                    "figure_label_count": int(figure_count) if figure_count is not None else None,
                }
            )
    else:
        ranges = value.get("chapter_ranges", [])
        counts = value.get("figure_label_counts", [])
        titles = value.get("chapter_titles", [])
        if ranges and not isinstance(ranges, list):
            raise EvaluationError("manifest chapter_ranges must be a list")
        if counts and (not isinstance(counts, list) or len(counts) != len(ranges)):
            raise EvaluationError("manifest figure_label_counts must align with chapter_ranges")
        if titles and (not isinstance(titles, list) or len(titles) != len(ranges)):
            raise EvaluationError("manifest chapter_titles must align with chapter_ranges")
        for index, span in enumerate(ranges, start=1):
            if (
                not isinstance(span, list)
                or len(span) != 2
                or any(not isinstance(item, int) for item in span)
                or span[0] <= 0
                or span[0] > span[1]
            ):
                raise EvaluationError(f"manifest chapter range {index} is invalid")
            chapters.append(
                {
                    "number": index,
                    "title": str(titles[index - 1]).strip() if titles else "",
                    "source_start": int(span[0]),
                    "source_end": int(span[1]),
                    "figure_label_count": int(counts[index - 1]) if counts else None,
                }
            )
    if chapters:
        for previous, current in zip(chapters, chapters[1:]):
            if current["source_start"] != previous["source_end"] + 1:
                raise EvaluationError("manifest chapter spans must be ordered, contiguous, and non-overlapping")
    declared_hard_gates = value.get("hard_gates") if isinstance(value.get("hard_gates"), dict) else {}
    expected_chapter_count = value.get("expected_chapter_count", declared_hard_gates.get("chapter_count"))
    if expected_chapter_count is None and chapters:
        expected_chapter_count = len(chapters)
    if expected_chapter_count is not None and int(expected_chapter_count) <= 0:
        raise EvaluationError("manifest expected_chapter_count must be positive")
    total_figures = value.get(
        "expected_total_figure_labels", declared_hard_gates.get("expected_figure_labels")
    )
    if total_figures is None and chapters and all(item["figure_label_count"] is not None for item in chapters):
        total_figures = sum(int(item["figure_label_count"]) for item in chapters)
    if total_figures is not None and int(total_figures) < 0:
        raise EvaluationError("manifest expected_total_figure_labels cannot be negative")
    normalized_text_threshold = float(declared_hard_gates.get("normalized_text_accuracy", 0.80))
    if not 0.0 <= normalized_text_threshold <= 1.0:
        raise EvaluationError("manifest normalized_text_accuracy must be between 0 and 1")
    representative_pages = value.get("representative_source_pages", [])
    if not isinstance(representative_pages, list) or any(
        not isinstance(item, int) or item <= 0 for item in representative_pages
    ):
        raise EvaluationError("manifest representative_source_pages must contain positive integers")
    return {
        "path": str(path.resolve()),
        "source_sha256": source_sha256 or None,
        "source_range": source_range,
        "source_page_size_mm": source_size_mm,
        "page_size_tolerance_mm": float(value.get("page_size_tolerance_mm", 0.5)),
        "expected_chapter_count": int(expected_chapter_count) if expected_chapter_count is not None else None,
        "chapters": chapters,
        "expected_total_figure_labels": int(total_figures) if total_figures is not None else None,
        "normalized_text_threshold": normalized_text_threshold,
        "declared_hard_gates": declared_hard_gates,
        "representative_source_pages": list(representative_pages),
        "raw": value,
    }


@dataclass
class PageInfo:
    number: int
    width_pt: float
    height_pt: float
    text: str
    text_error: str = ""
    image_count: int = 0
    form_count: int = 0
    vector_count: int = 0
    fonts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def visual_complexity(self) -> int:
        return self.image_count * 20 + self.form_count * 10 + min(self.vector_count, 200)

    @property
    def visual_present(self) -> bool:
        return self.image_count > 0 or self.form_count > 0 or self.vector_count >= 6


@dataclass
class GrayImage:
    width: int
    height: int
    pixels: bytes


def _round(value: float, digits: int = 4) -> float:
    return round(float(value), digits)


def _mean(values: Iterable[float], default: float = 0.0) -> float:
    materialized = list(values)
    return float(statistics.fmean(materialized)) if materialized else float(default)


def normalize_text(text: str) -> str:
    """Normalize text for comparison without erasing mathematical symbols."""

    value = unicodedata.normalize("NFKC", str(text or "")).casefold()
    # Soft hyphens and extraction-only control characters are never meaningful.
    value = value.replace("\u00ad", "")
    return "".join(
        char for char in value if unicodedata.category(char)[:1] in {"L", "N", "S"}
    )


def _tokenize(text: str) -> list[str]:
    value = unicodedata.normalize("NFKC", str(text or "")).casefold()
    return re.findall(r"[\w]+|[^\w\s]", value, flags=re.UNICODE)


def _counter_f1(left: Sequence[str], right: Sequence[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    a, b = Counter(left), Counter(right)
    common = sum((a & b).values())
    precision = common / len(right)
    recall = common / len(left)
    return (2.0 * precision * recall / (precision + recall)) if precision + recall else 0.0


def normalized_text_similarity(source: str, generated: str) -> dict[str, float]:
    """Return a bounded character/order + token-presence similarity."""

    a, b = normalize_text(source), normalize_text(generated)
    if not a and not b:
        sequence = token = 1.0
    elif not a or not b:
        sequence = token = 0.0
    else:
        sequence = SequenceMatcher(None, a, b).ratio()
        token = _counter_f1(_tokenize(source), _tokenize(generated))
    combined = 0.75 * sequence + 0.25 * token
    return {
        "combined": _round(combined),
        "character_sequence": _round(sequence),
        "token_multiset_f1": _round(token),
    }


def _caption_keys(text: str) -> list[str]:
    keys = {f"figure:{match.group(1).casefold()}" for match in CAPTION_RE.finditer(text or "")}
    keys.update(f"figure:{match.group(1).casefold()}" for match in CAPTION_ZH_RE.finditer(text or ""))
    return sorted(keys)


def _page_size_similarity(source: PageInfo, generated: PageInfo) -> float:
    def ratio(a: float, b: float) -> float:
        return min(a, b) / max(a, b) if a > 0 and b > 0 else 0.0

    return (ratio(source.width_pt, generated.width_pt) + ratio(source.height_pt, generated.height_pt)) / 2.0


def _font_key(record: dict[str, Any]) -> str:
    return "|".join(
        str(record.get(key, "")) for key in ("object", "basefont", "subtype", "encoding")
    )


class _PypdfDocument:
    backend_name = "pypdf"

    def __init__(self, path: Path):
        try:
            from pypdf import PdfReader
            from pypdf.generic import ContentStream, IndirectObject
        except ImportError as exc:  # pragma: no cover - selected only without dependency
            raise EvaluationError("pypdf is not installed") from exc
        self._ContentStream = ContentStream
        self._IndirectObject = IndirectObject
        self.path = path
        try:
            self.reader = PdfReader(str(path), strict=False)
            self.page_count = len(self.reader.pages)
        except Exception as exc:
            raise EvaluationError(f"cannot open PDF with pypdf: {path}: {exc}") from exc
        self._font_cache: dict[str, dict[str, Any]] = {}

    def close(self) -> None:
        stream = getattr(self.reader, "stream", None)
        close = getattr(stream, "close", None)
        if callable(close):
            close()

    def _resolve(self, value: Any) -> Any:
        if isinstance(value, self._IndirectObject):
            return value.get_object()
        return value

    def _object_key(self, value: Any) -> str:
        if isinstance(value, self._IndirectObject):
            return f"{value.idnum}:{value.generation}"
        return f"direct:{id(value)}"

    def _font_record(self, raw: Any) -> dict[str, Any]:
        key = self._object_key(raw)
        if key in self._font_cache:
            return dict(self._font_cache[key])
        font = self._resolve(raw) or {}
        descendants = self._resolve(font.get("/DescendantFonts", [])) or []
        embedded = False
        descriptor = self._resolve(font.get("/FontDescriptor")) if hasattr(font, "get") else None
        if descriptor:
            embedded = any(descriptor.get(name) is not None for name in ("/FontFile", "/FontFile2", "/FontFile3"))
        child_names: list[str] = []
        for child_raw in descendants:
            child = self._resolve(child_raw) or {}
            child_names.append(str(child.get("/BaseFont", "")))
            child_descriptor = self._resolve(child.get("/FontDescriptor"))
            if child_descriptor and any(
                child_descriptor.get(name) is not None
                for name in ("/FontFile", "/FontFile2", "/FontFile3")
            ):
                embedded = True
        record = {
            "object": key,
            "basefont": str(font.get("/BaseFont", "")),
            "subtype": str(font.get("/Subtype", "")),
            "encoding": str(font.get("/Encoding", "")),
            "descendant_fonts": child_names,
            "embedded": bool(embedded),
        }
        self._font_cache[key] = dict(record)
        return record

    def _inspect_resources(
        self, raw_resources: Any, visited: Optional[set[str]] = None
    ) -> tuple[int, int, list[dict[str, Any]]]:
        visited = visited or set()
        resources = self._resolve(raw_resources) or {}
        images = forms = 0
        fonts: list[dict[str, Any]] = []
        raw_fonts = self._resolve(resources.get("/Font", {})) or {}
        for raw_font in raw_fonts.values():
            fonts.append(self._font_record(raw_font))
        xobjects = self._resolve(resources.get("/XObject", {})) or {}
        for raw_xobject in xobjects.values():
            key = self._object_key(raw_xobject)
            if key in visited:
                continue
            visited.add(key)
            xobject = self._resolve(raw_xobject) or {}
            subtype = str(xobject.get("/Subtype", ""))
            if subtype == "/Image":
                images += 1
            elif subtype == "/Form":
                forms += 1
                nested_images, nested_forms, nested_fonts = self._inspect_resources(
                    xobject.get("/Resources", {}), visited
                )
                images += nested_images
                forms += nested_forms
                fonts.extend(nested_fonts)
        unique_fonts = {_font_key(item): item for item in fonts}
        return images, forms, list(unique_fonts.values())

    def inspect_page(self, index: int) -> PageInfo:
        page = self.reader.pages[index]
        rotation = int(page.get("/Rotate", 0) or 0) % 360
        width = float(page.mediabox.width)
        height = float(page.mediabox.height)
        if rotation in {90, 270}:
            width, height = height, width
        text_error = ""
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            text = ""
            text_error = f"{type(exc).__name__}: {exc}"
        try:
            images, forms, fonts = self._inspect_resources(page.get("/Resources", {}))
        except Exception as exc:
            images, forms, fonts = 0, 0, []
            text_error = "; ".join(filter(None, [text_error, f"resource inspection: {exc}"]))
        vectors = 0
        try:
            contents = page.get_contents()
            if contents is not None:
                stream = self._ContentStream(contents, self.reader)
                vector_operators = {b"m", b"l", b"c", b"v", b"y", b"re", b"S", b"s", b"f", b"f*", b"B", b"B*"}
                vectors = sum(1 for _operands, operator in stream.operations if operator in vector_operators)
        except Exception:
            # Text, image and font inspection can still be complete.  Vector-region
            # detection is a conservative enhancement and stays at zero on failure.
            vectors = 0
        return PageInfo(
            number=index + 1,
            width_pt=width,
            height_pt=height,
            text=text,
            text_error=text_error,
            image_count=images,
            form_count=forms,
            vector_count=vectors,
            fonts=fonts,
        )

    def outline(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []

        def walk(items: Any, level: int = 0) -> None:
            if not isinstance(items, list):
                return
            for item in items:
                if isinstance(item, list):
                    walk(item, level + 1)
                    continue
                title = str(getattr(item, "title", "") or "").strip()
                if not title:
                    continue
                try:
                    page = self.reader.get_destination_page_number(item) + 1
                except Exception:
                    page = None
                records.append({"title": title, "page": page, "level": level})

        try:
            walk(self.reader.outline)
        except Exception:
            return []
        return records


class _PyMuPDFDocument:
    backend_name = "pymupdf"

    def __init__(self, path: Path):
        module = _load_pymupdf()
        if module is None:  # pragma: no cover - selected only without dependency
            raise EvaluationError("PyMuPDF is not installed")
        self.fitz = module
        self.path = path
        try:
            self.document = module.open(str(path))
            self.page_count = int(self.document.page_count)
        except Exception as exc:
            raise EvaluationError(f"cannot open PDF with PyMuPDF: {path}: {exc}") from exc
        self._font_cache: dict[int, dict[str, Any]] = {}

    def close(self) -> None:
        self.document.close()

    def _font_record(self, item: Sequence[Any]) -> dict[str, Any]:
        xref = int(item[0]) if item and item[0] else 0
        if xref in self._font_cache:
            return dict(self._font_cache[xref])
        embedded = False
        if xref > 0:
            try:
                extracted = self.document.extract_font(xref)
                embedded = bool(extracted and len(extracted) >= 4 and extracted[3])
            except Exception:
                embedded = False
        record = {
            "object": f"xref:{xref}",
            "basefont": str(item[3] if len(item) > 3 else ""),
            "subtype": str(item[2] if len(item) > 2 else ""),
            "encoding": str(item[5] if len(item) > 5 else ""),
            "descendant_fonts": [],
            "embedded": embedded,
        }
        self._font_cache[xref] = dict(record)
        return record

    def inspect_page(self, index: int) -> PageInfo:
        page = self.document.load_page(index)
        text_error = ""
        try:
            try:
                text = page.get_text("text", sort=True) or ""
            except TypeError:  # older supported PyMuPDF
                text = page.get_text("text") or ""
        except Exception as exc:
            text = ""
            text_error = f"{type(exc).__name__}: {exc}"
        try:
            images = len({int(item[0]) for item in page.get_images(full=True)})
        except Exception:
            images = 0
        try:
            forms = len(page.get_xobjects())
        except Exception:
            forms = 0
        try:
            vectors = len(page.get_drawings())
        except Exception:
            vectors = 0
        try:
            fonts = [self._font_record(item) for item in page.get_fonts(full=True)]
        except Exception as exc:
            fonts = []
            text_error = "; ".join(filter(None, [text_error, f"font inspection: {exc}"]))
        rect = page.rect
        return PageInfo(
            number=index + 1,
            width_pt=float(rect.width),
            height_pt=float(rect.height),
            text=text,
            text_error=text_error,
            image_count=images,
            form_count=forms,
            vector_count=vectors,
            fonts=fonts,
        )

    def outline(self) -> list[dict[str, Any]]:
        records = []
        try:
            toc = self.document.get_toc(simple=True)
        except Exception:
            return records
        for item in toc:
            if len(item) >= 3:
                records.append(
                    {"title": str(item[1]).strip(), "page": int(item[2]), "level": int(item[0]) - 1}
                )
        return records


def _load_pymupdf() -> Any:
    try:
        import pymupdf

        return pymupdf
    except ImportError:
        try:
            import fitz

            if hasattr(fitz, "open"):
                return fitz
        except ImportError:
            pass
    return None


def open_pdf(path: Path, backend: str = "auto") -> Any:
    if not path.is_file():
        raise EvaluationError(f"PDF does not exist: {path}")
    if path.suffix.casefold() != ".pdf":
        raise EvaluationError(f"input is not named as a PDF: {path}")
    errors: list[str] = []
    candidates = [backend] if backend != "auto" else ["pymupdf", "pypdf"]
    for name in candidates:
        try:
            if name == "pymupdf":
                return _PyMuPDFDocument(path)
            if name == "pypdf":
                return _PypdfDocument(path)
            raise EvaluationError(f"unsupported PDF backend: {name}")
        except EvaluationError as exc:
            errors.append(str(exc))
    raise EvaluationError("; ".join(errors) or "no usable PDF backend")


def _is_chapter_title(title: str, *, outline_level: Optional[int] = None) -> bool:
    if CHAPTER_EN_RE.match(title) or CHAPTER_ZH_RE.match(title):
        return True
    # Numeric chapter titles are accepted only from shallow outline entries.  This
    # recognizes Bondy's "1 Graphs" ... "17 Edge Colourings" without treating
    # section headings such as "1.2 Walks" as chapters.
    return outline_level is not None and outline_level <= 1 and bool(CHAPTER_NUMERIC_RE.match(title))


def _detect_chapters(
    document: Any,
    pages: Sequence[PageInfo],
    start_page: int,
    end_page: int,
) -> list[dict[str, Any]]:
    chapters: list[dict[str, Any]] = []
    for item in document.outline():
        page = item.get("page")
        title = str(item.get("title", "")).strip()
        if (
            isinstance(page, int)
            and start_page <= page <= end_page
            and _is_chapter_title(title, outline_level=item.get("level"))
        ):
            chapters.append({"title": title, "source_page": page, "method": "pdf_outline"})
    if not chapters:
        # Fail-safe fallback: explicit "Chapter N" / "第N章" headings, plus a
        # numeric heading only when it appears among the first eight non-empty lines.
        for page in pages:
            lines = [line.strip() for line in page.text.splitlines() if line.strip()][:8]
            for line in lines:
                if CHAPTER_EN_RE.match(line) or CHAPTER_ZH_RE.match(line):
                    chapters.append(
                        {"title": line[:160], "source_page": page.number, "method": "page_heading"}
                    )
                    break
    deduplicated: dict[str, dict[str, Any]] = {}
    for chapter in sorted(chapters, key=lambda item: (item["source_page"], item["title"])):
        key = normalize_text(chapter["title"])
        deduplicated.setdefault(key, chapter)
    return list(deduplicated.values())


def _load_expected_titles(path: Optional[Path], inline: Sequence[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if path is not None:
        try:
            raw = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise EvaluationError(f"cannot read chapter title file: {path}: {exc}") from exc
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = [line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        if isinstance(value, dict):
            value = value.get("chapters")
        if not isinstance(value, list):
            raise EvaluationError("chapter title file must be a JSON list, {chapters: [...]}, or one title per line")
        for item in value:
            if isinstance(item, str):
                records.append({"title": item.strip(), "source_page": None, "method": "user_file"})
            elif isinstance(item, dict) and str(item.get("title", "")).strip():
                page = item.get("source_page")
                records.append(
                    {
                        "title": str(item["title"]).strip(),
                        "source_page": int(page) if page is not None else None,
                        "method": "user_file",
                    }
                )
            else:
                raise EvaluationError("every chapter title entry must be a string or an object with title")
    records.extend(
        {"title": str(title).strip(), "source_page": None, "method": "command_line"}
        for title in inline
        if str(title).strip()
    )
    return records


def _find_title_pages(title: str, pages: Sequence[PageInfo]) -> list[int]:
    needle = normalize_text(title)
    if not needle:
        return []
    return [page.number for page in pages if needle in normalize_text(page.text)]


def _inspect_range(
    document: Any,
    start: int,
    end: int,
    *,
    label: str,
    progress: bool,
) -> list[PageInfo]:
    pages: list[PageInfo] = []
    total = end - start + 1
    for ordinal, page_number in enumerate(range(start, end + 1), start=1):
        try:
            page = document.inspect_page(page_number - 1)
        except Exception as exc:
            raise EvaluationError(f"{label} page {page_number} inspection failed: {exc}") from exc
        pages.append(page)
        if progress and (ordinal == 1 or ordinal % 25 == 0 or ordinal == total):
            print(f"[{label}] inspected {ordinal}/{total} pages", file=sys.stderr, flush=True)
    return pages


def _font_inventory(pages: Sequence[PageInfo]) -> list[dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for page in pages:
        for raw in page.fonts:
            key = _font_key(raw)
            record = inventory.setdefault(key, {**raw, "pages": []})
            record["pages"].append(page.number)
    return [
        {**record, "pages": sorted(set(record["pages"])), "page_use_count": len(set(record["pages"]))}
        for _key, record in sorted(inventory.items())
    ]


def _searchable(source: PageInfo, generated: PageInfo) -> bool:
    source_length = len(normalize_text(source.text))
    generated_length = len(normalize_text(generated.text))
    if source_length == 0:
        return generated_length == 0
    required = min(20, max(1, math.ceil(source_length * 0.1)))
    return generated_length >= required


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return float(ordered[index])


def _build_chapter_diagnostics(
    chapters: list[dict[str, Any]],
    source_pages: Sequence[PageInfo],
    generated_pages: Sequence[PageInfo],
    page_results: Sequence[dict[str, Any]],
    source_start: int,
    source_end: int,
    generated_start: int,
) -> list[dict[str, Any]]:
    for chapter in chapters:
        if chapter.get("source_page") is None:
            found = _find_title_pages(chapter["title"], source_pages)
            chapter["source_page"] = found[0] if found else None
            chapter["source_title_pages"] = found
        else:
            chapter["source_title_pages"] = _find_title_pages(chapter["title"], source_pages)
        chapter["generated_title_pages"] = _find_title_pages(chapter["title"], generated_pages)
        chapter["title_preserved"] = bool(chapter["generated_title_pages"])

    ordered = sorted(
        [item for item in chapters if isinstance(item.get("source_page"), int)],
        key=lambda item: item["source_page"],
    )
    diagnostics: list[dict[str, Any]] = []
    by_source_page = {item["source_page"]: item for item in page_results if item.get("source_page")}
    for index, chapter in enumerate(ordered):
        chapter_start = max(source_start, int(chapter["source_page"]))
        next_start = int(ordered[index + 1]["source_page"]) if index + 1 < len(ordered) else source_end + 1
        expected_end = chapter.get("source_end")
        chapter_end = min(source_end, int(expected_end) if expected_end is not None else next_start - 1)
        results = [by_source_page[number] for number in range(chapter_start, chapter_end + 1) if number in by_source_page]
        similarities = [
            float(item["text_similarity"]["combined"])
            for item in results
            if item.get("text_similarity", {}).get("status") == "verified"
        ]
        missing_captions = sorted(
            {key for item in results for key in item.get("missing_caption_keys", [])}
        )
        source_caption_keys = sorted(
            {key for item in results for key in item.get("source_caption_keys", [])}
        )
        generated_caption_keys = sorted(
            {key for item in results for key in item.get("generated_caption_keys", [])}
        )
        low_pages = [
            {
                "source_page": item["source_page"],
                "generated_page": item.get("generated_page"),
                "similarity": item.get("text_similarity", {}).get("combined"),
            }
            for item in results
            if item.get("text_similarity", {}).get("status") == "verified"
            and float(item["text_similarity"]["combined"]) < 0.80
        ]
        expected_generated_start = generated_start + chapter_start - source_start
        expected_generated_end = generated_start + chapter_end - source_start
        issues = []
        if not chapter.get("title_preserved"):
            issues.append("chapter_title_missing")
        if low_pages:
            issues.append("low_text_similarity_pages")
        if missing_captions:
            issues.append("missing_figure_captions")
        expected_figures = chapter.get("figure_label_count")
        if expected_figures is not None and len(source_caption_keys) != int(expected_figures):
            issues.append("source_figure_count_manifest_mismatch")
        if expected_figures is not None and len(
            set(source_caption_keys) & set(generated_caption_keys)
        ) != int(expected_figures):
            issues.append("generated_figure_count_manifest_mismatch")
        diagnostics.append(
            {
                **chapter,
                "source_span": [chapter_start, chapter_end],
                "expected_generated_span": [expected_generated_start, expected_generated_end],
                "compared_pages": len(results),
                "mean_text_similarity": _round(_mean(similarities)) if similarities else None,
                "minimum_text_similarity": _round(min(similarities)) if similarities else None,
                "searchable_page_ratio": _round(
                    _mean(1.0 if item.get("generated_searchable") else 0.0 for item in results)
                ) if results else None,
                "low_similarity_pages": low_pages,
                "missing_caption_keys": missing_captions,
                "source_figure_label_count": len(source_caption_keys),
                "generated_matching_figure_label_count": len(
                    set(source_caption_keys) & set(generated_caption_keys)
                ),
                "expected_figure_label_count": expected_figures,
                "issues": issues,
            }
        )
    # Preserve user-supplied entries that could not be located in the source.  They
    # are not silently discarded: chapter coverage and its hard gate will fail.
    located_ids = {id(item) for item in ordered}
    for chapter in chapters:
        if id(chapter) not in located_ids:
            diagnostics.append(
                {
                    **chapter,
                    "source_span": None,
                    "expected_generated_span": None,
                    "compared_pages": 0,
                    "mean_text_similarity": None,
                    "minimum_text_similarity": None,
                    "searchable_page_ratio": None,
                    "low_similarity_pages": [],
                    "missing_caption_keys": [],
                    "source_figure_label_count": None,
                    "generated_matching_figure_label_count": None,
                    "expected_figure_label_count": chapter.get("figure_label_count"),
                    "issues": ["chapter_title_not_located_in_source"],
                }
            )
    return diagnostics


def _even_sample_indices(total: int, count: int, preferred: Sequence[int] = ()) -> list[int]:
    if total <= 0 or count <= 0:
        return []
    count = min(total, count)
    selected = {index for index in preferred if 0 <= index < total}
    if len(selected) > count:
        selected = set(sorted(selected)[:count])
    if len(selected) < count:
        if count == 1:
            candidates = [total // 2]
        else:
            candidates = [round(index * (total - 1) / (count - 1)) for index in range(count)]
        selected.update(candidates)
    if len(selected) < count:
        selected.update(index for index in range(total) if index not in selected)
    return sorted(selected)[:count]


def _read_pgm(path: Path) -> GrayImage:
    data = path.read_bytes()
    position = 0

    def token() -> bytes:
        nonlocal position
        while position < len(data):
            if data[position : position + 1] == b"#":
                newline = data.find(b"\n", position)
                position = len(data) if newline < 0 else newline + 1
            elif data[position] in b" \t\r\n":
                position += 1
            else:
                break
        start = position
        while position < len(data) and data[position] not in b" \t\r\n#":
            position += 1
        return data[start:position]

    if token() != b"P5":
        raise EvaluationError(f"renderer did not produce binary PGM: {path}")
    width, height, maximum = int(token()), int(token()), int(token())
    while position < len(data) and data[position] in b" \t\r\n":
        position += 1
    expected = width * height
    if maximum <= 0 or maximum > 255 or len(data) - position < expected:
        raise EvaluationError(f"unsupported or truncated PGM: {path}")
    pixels = data[position : position + expected]
    if maximum != 255:
        pixels = bytes(round(value * 255 / maximum) for value in pixels)
    return GrayImage(width, height, pixels)


class _Renderer:
    def __init__(self, source_path: Path, generated_path: Path, dpi: int):
        self.dpi = dpi
        self.fitz = _load_pymupdf()
        self.documents: dict[Path, Any] = {}
        # Prefer a native executable.  On Windows a PATH shim may be a ``.cmd``
        # wrapper whose nested relative-path assumptions fail under subprocess.
        self.pdftoppm = None if self.fitz is not None else (
            shutil.which("pdftoppm.exe") or shutil.which("pdftoppm")
        )
        if self.fitz is not None:
            self.documents[source_path] = self.fitz.open(str(source_path))
            self.documents[generated_path] = self.fitz.open(str(generated_path))
        elif not self.pdftoppm:
            raise EvaluationError("sample rendering requested, but neither PyMuPDF nor pdftoppm is available")

    @property
    def backend(self) -> str:
        return "pymupdf" if self.fitz is not None else "pdftoppm"

    def close(self) -> None:
        for document in self.documents.values():
            document.close()

    def render(self, path: Path, page_number: int, temp_dir: Path) -> GrayImage:
        if self.fitz is not None:
            document = self.documents[path]
            page = document.load_page(page_number - 1)
            pixmap = page.get_pixmap(
                matrix=self.fitz.Matrix(self.dpi / 72.0, self.dpi / 72.0),
                colorspace=self.fitz.csGRAY,
                alpha=False,
            )
            pixels = bytes(pixmap.samples)
            if getattr(pixmap, "stride", pixmap.width) != pixmap.width:
                stride = int(pixmap.stride)
                pixels = b"".join(
                    pixels[row * stride : row * stride + pixmap.width]
                    for row in range(pixmap.height)
                )
            return GrayImage(int(pixmap.width), int(pixmap.height), pixels)
        prefix = temp_dir / f"render-{path.stem}-{page_number}"
        command = [
            str(self.pdftoppm),
            "-f", str(page_number),
            "-l", str(page_number),
            "-r", str(self.dpi),
            "-gray",
            "-singlefile",
            str(path),
            str(prefix),
        ]
        completed = subprocess.run(command, capture_output=True, check=False, timeout=120)
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()[:500]
            raise EvaluationError(f"pdftoppm failed for page {page_number}: {detail}")
        return _read_pgm(prefix.with_suffix(".pgm"))


def _resize_gray(image: GrayImage, width: int, height: int) -> bytes:
    try:
        from PIL import Image

        resampling = getattr(Image, "Resampling", Image).LANCZOS
        rendered = Image.frombytes("L", (image.width, image.height), image.pixels)
        return rendered.resize((width, height), resampling).tobytes()
    except ImportError:
        # Dependency-free nearest-neighbour fallback.  Render width defaults to a
        # conservative 384px, so this remains bounded for release-gate sampling.
        output = bytearray(width * height)
        for y in range(height):
            source_y = min(image.height - 1, int(y * image.height / height))
            source_row = source_y * image.width
            target_row = y * width
            for x in range(width):
                source_x = min(image.width - 1, int(x * image.width / width))
                output[target_row + x] = image.pixels[source_row + source_x]
        return bytes(output)


def global_ssim(left: bytes, right: bytes) -> float:
    """Global grayscale SSIM (reported as global, not windowed SSIM)."""

    if len(left) != len(right) or not left:
        return 0.0
    count = len(left)
    mean_left = sum(left) / count
    mean_right = sum(right) / count
    if count > 1:
        variance_left = sum((value - mean_left) ** 2 for value in left) / (count - 1)
        variance_right = sum((value - mean_right) ** 2 for value in right) / (count - 1)
        covariance = sum(
            (a - mean_left) * (b - mean_right) for a, b in zip(left, right)
        ) / (count - 1)
    else:
        variance_left = variance_right = covariance = 0.0
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    denominator = (mean_left**2 + mean_right**2 + c1) * (
        variance_left + variance_right + c2
    )
    if denominator == 0:
        return 1.0
    return max(0.0, min(1.0, ((2 * mean_left * mean_right + c1) * (2 * covariance + c2)) / denominator))


def content_box(image: bytes, width: int, height: int, threshold: int = 245) -> Optional[list[float]]:
    min_x, min_y, max_x, max_y = width, height, -1, -1
    for index, value in enumerate(image):
        if value >= threshold:
            continue
        y, x = divmod(index, width)
        min_x, min_y = min(min_x, x), min(min_y, y)
        max_x, max_y = max(max_x, x), max(max_y, y)
    if max_x < 0:
        return None
    return [
        min_x / width,
        min_y / height,
        (max_x + 1) / width,
        (max_y + 1) / height,
    ]


def content_box_similarity(left: Optional[Sequence[float]], right: Optional[Sequence[float]]) -> float:
    if left is None and right is None:
        return 1.0
    if left is None or right is None:
        return 0.0
    mean_boundary_error = sum(abs(a - b) for a, b in zip(left, right)) / 4.0
    return max(0.0, min(1.0, 1.0 - 2.0 * mean_boundary_error))


def _render_samples(
    source_path: Path,
    generated_path: Path,
    source_start: int,
    generated_start: int,
    page_count: int,
    sample_count: int,
    explicit_source_pages: Sequence[int],
    chapter_source_pages: Sequence[int],
    dpi: int,
    render_width: int,
) -> dict[str, Any]:
    if sample_count <= 0 and not explicit_source_pages:
        return {
            "status": "not_run",
            "reason": "render sampling was not requested",
            "backend": None,
            "samples": [],
            "mean_global_ssim": None,
            "mean_content_box_similarity": None,
        }
    if explicit_source_pages:
        invalid = [page for page in explicit_source_pages if not source_start <= page < source_start + page_count]
        if invalid:
            raise EvaluationError(f"sample source pages outside compared range: {invalid}")
        indices = sorted({page - source_start for page in explicit_source_pages})
    else:
        preferred = [page - source_start for page in chapter_source_pages]
        indices = _even_sample_indices(page_count, sample_count, preferred)
    renderer = _Renderer(source_path, generated_path, dpi)
    samples: list[dict[str, Any]] = []
    failures: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="latexstruct-pdf-fidelity-") as temp:
            temp_dir = Path(temp)
            for index in indices:
                source_page = source_start + index
                generated_page = generated_start + index
                try:
                    source_image = renderer.render(source_path, source_page, temp_dir)
                    generated_image = renderer.render(generated_path, generated_page, temp_dir)
                    source_aspect = source_image.height / max(1, source_image.width)
                    generated_aspect = generated_image.height / max(1, generated_image.width)
                    target_height = max(64, round(render_width * (source_aspect + generated_aspect) / 2.0))
                    source_pixels = _resize_gray(source_image, render_width, target_height)
                    generated_pixels = _resize_gray(generated_image, render_width, target_height)
                    source_box = content_box(source_pixels, render_width, target_height)
                    generated_box = content_box(generated_pixels, render_width, target_height)
                    samples.append(
                        {
                            "source_page": source_page,
                            "generated_page": generated_page,
                            "global_ssim": _round(global_ssim(source_pixels, generated_pixels)),
                            "source_content_box": [_round(value) for value in source_box] if source_box else None,
                            "generated_content_box": [_round(value) for value in generated_box] if generated_box else None,
                            "content_box_similarity": _round(content_box_similarity(source_box, generated_box)),
                        }
                    )
                except Exception as exc:
                    failures.append(f"source {source_page} / generated {generated_page}: {exc}")
    finally:
        renderer.close()
    if failures or len(samples) != len(indices):
        return {
            "status": "unverified",
            "reason": "one or more requested render samples failed",
            "backend": renderer.backend,
            "requested_samples": len(indices),
            "successful_samples": len(samples),
            "failures": failures,
            "samples": samples,
            "mean_global_ssim": None,
            "mean_content_box_similarity": None,
        }
    return {
        "status": "verified",
        "reason": None,
        "backend": renderer.backend,
        "dpi": dpi,
        "comparison_width_px": render_width,
        "requested_samples": len(indices),
        "successful_samples": len(samples),
        "failures": [],
        "samples": samples,
        "mean_global_ssim": _round(_mean(item["global_ssim"] for item in samples)),
        "mean_content_box_similarity": _round(
            _mean(item["content_box_similarity"] for item in samples)
        ),
    }


def _category(
    category_id: str,
    score: float,
    status: str,
    metrics: dict[str, Any],
    explanation: str,
) -> dict[str, Any]:
    weight = CATEGORY_WEIGHTS[category_id]
    return {
        "id": category_id,
        "weight": weight,
        "score": _round(max(0.0, min(weight, score)), 2),
        "status": status,
        "metrics": metrics,
        "explanation": explanation,
    }


def evaluate_pdf_fidelity(
    source_path: Path | str,
    generated_path: Path | str,
    *,
    source_start: int = 1,
    source_end: Optional[int] = None,
    generated_start: Optional[int] = None,
    generated_end: Optional[int] = None,
    self_compare: bool = False,
    expected_chapter_count: Optional[int] = None,
    expected_chapters: Optional[Sequence[dict[str, Any] | str]] = None,
    manifest: Optional[dict[str, Any]] = None,
    render_samples: int = 0,
    sample_source_pages: Sequence[int] = (),
    render_dpi: int = 96,
    render_width: int = 384,
    backend: str = "auto",
    progress: bool = False,
) -> dict[str, Any]:
    """Evaluate a source page range against a generated PDF.

    Page numbers are physical, one-based and inclusive.  For different files, an
    omitted generated range means the whole generated PDF.  When both paths resolve
    to the same PDF, an entirely omitted generated range automatically mirrors the
    selected source range; ``self_compare=True`` makes that intent explicit and
    rejects conflicting ranges.  Extra or missing output pages are otherwise not
    hidden.
    """

    source_path = Path(source_path).expanduser().resolve()
    generated_path = Path(generated_path).expanduser().resolve()
    source_document = generated_document = None
    try:
        source_document = open_pdf(source_path, backend)
        selected_backend = source_document.backend_name
        generated_document = open_pdf(generated_path, selected_backend)
        source_end = int(source_end if source_end is not None else source_document.page_count)
        source_start = int(source_start)
        same_pdf = source_path == generated_path
        if self_compare:
            if not same_pdf:
                raise EvaluationError("self-compare requires source_pdf and generated_pdf to resolve to the same file")
            if generated_start is not None and int(generated_start) != source_start:
                raise EvaluationError("self-compare generated start must equal the selected source start")
            if generated_end is not None and int(generated_end) != source_end:
                raise EvaluationError("self-compare generated end must equal the selected source end")
            generated_start, generated_end = source_start, source_end
            range_alignment_mode = "explicit_self_compare"
        elif generated_start is None and generated_end is None and same_pdf:
            generated_start, generated_end = source_start, source_end
            range_alignment_mode = "automatic_same_pdf_source_range"
        else:
            generated_start = int(generated_start if generated_start is not None else 1)
            generated_end = int(
                generated_end if generated_end is not None else generated_document.page_count
            )
            range_alignment_mode = "explicit_or_generated_file_range"
        if not 1 <= source_start <= source_end <= source_document.page_count:
            raise EvaluationError(
                f"invalid source range {source_start}-{source_end}; PDF has {source_document.page_count} pages"
            )
        if not 1 <= generated_start <= generated_end <= generated_document.page_count:
            raise EvaluationError(
                f"invalid generated range {generated_start}-{generated_end}; PDF has {generated_document.page_count} pages"
            )
        if not 0 <= render_samples <= 1000:
            raise EvaluationError("--render-samples must be between 0 and 1000")
        if not 36 <= render_dpi <= 600:
            raise EvaluationError("--render-dpi must be between 36 and 600")
        if not 64 <= render_width <= 2048:
            raise EvaluationError("--render-width must be between 64 and 2048")

        source_pages = _inspect_range(
            source_document, source_start, source_end, label="source", progress=progress
        )
        generated_pages = _inspect_range(
            generated_document, generated_start, generated_end, label="generated", progress=progress
        )
        source_count, generated_count = len(source_pages), len(generated_pages)
        aligned_count = min(source_count, generated_count)
        page_results: list[dict[str, Any]] = []
        all_source_caption_keys: set[str] = set()
        all_generated_caption_keys: set[str] = set()
        aligned_caption_hits = aligned_caption_total = 0
        visual_ratios: list[float] = []
        text_similarities: list[float] = []
        size_similarities: list[float] = []
        expected_text_pages = searchable_pages = 0
        text_errors: list[str] = []

        for index in range(aligned_count):
            source, generated = source_pages[index], generated_pages[index]
            source_normalized = normalize_text(source.text)
            generated_normalized = normalize_text(generated.text)
            source_captions = _caption_keys(source.text)
            generated_captions = _caption_keys(generated.text)
            all_source_caption_keys.update(source_captions)
            all_generated_caption_keys.update(generated_captions)
            missing_caption_keys = sorted(set(source_captions) - set(generated_captions))
            aligned_caption_total += len(source_captions)
            aligned_caption_hits += len(source_captions) - len(missing_caption_keys)
            if source.text_error:
                text_errors.append(f"source page {source.number}: {source.text_error}")
            if generated.text_error:
                text_errors.append(f"generated page {generated.number}: {generated.text_error}")
            if source_normalized:
                expected_text_pages += 1
                searchable_pages += int(_searchable(source, generated))
                similarity = normalized_text_similarity(source.text, generated.text)
                similarity["status"] = "verified" if not source.text_error and not generated.text_error else "unverified"
                if similarity["status"] == "verified":
                    text_similarities.append(float(similarity["combined"]))
            else:
                similarity = {
                    "status": "not_applicable",
                    "combined": None,
                    "character_sequence": None,
                    "token_multiset_f1": None,
                    "reason": "source page has no extractable normalized text",
                }
            size_similarity = _page_size_similarity(source, generated)
            size_similarities.append(size_similarity)
            if source.visual_present:
                if source.visual_complexity > 0:
                    visual_ratios.append(min(1.0, generated.visual_complexity / source.visual_complexity))
                else:
                    visual_ratios.append(float(generated.visual_present))
            page_results.append(
                {
                    "status": "compared",
                    "source_page": source.number,
                    "generated_page": generated.number,
                    "source_size_pt": [_round(source.width_pt, 2), _round(source.height_pt, 2)],
                    "generated_size_pt": [_round(generated.width_pt, 2), _round(generated.height_pt, 2)],
                    "size_similarity": _round(size_similarity),
                    "source_normalized_characters": len(source_normalized),
                    "generated_normalized_characters": len(generated_normalized),
                    "generated_searchable": _searchable(source, generated),
                    "text_similarity": similarity,
                    "source_caption_keys": source_captions,
                    "generated_caption_keys": generated_captions,
                    "missing_caption_keys": missing_caption_keys,
                    "source_visual": {
                        "images": source.image_count,
                        "forms": source.form_count,
                        "vectors": source.vector_count,
                        "complexity": source.visual_complexity,
                        "present": source.visual_present,
                    },
                    "generated_visual": {
                        "images": generated.image_count,
                        "forms": generated.form_count,
                        "vectors": generated.vector_count,
                        "complexity": generated.visual_complexity,
                        "present": generated.visual_present,
                    },
                }
            )

        for source in source_pages[aligned_count:]:
            all_source_caption_keys.update(_caption_keys(source.text))
            page_results.append(
                {"status": "missing_generated_page", "source_page": source.number, "generated_page": None}
            )
        for generated in generated_pages[aligned_count:]:
            all_generated_caption_keys.update(_caption_keys(generated.text))
            page_results.append(
                {"status": "extra_generated_page", "source_page": None, "generated_page": generated.number}
            )

        manifest = manifest or {}
        if expected_chapter_count is None and manifest.get("expected_chapter_count") is not None:
            expected_chapter_count = int(manifest["expected_chapter_count"])
        supplied_chapters: list[dict[str, Any]] = []
        for item in expected_chapters or []:
            if isinstance(item, str):
                supplied_chapters.append(
                    {"title": item.strip(), "source_page": None, "method": "caller"}
                )
            elif isinstance(item, dict) and str(item.get("title", "")).strip():
                supplied_chapters.append(
                    {
                        "title": str(item["title"]).strip(),
                        "source_page": int(item["source_page"]) if item.get("source_page") is not None else None,
                        "method": str(item.get("method", "caller")),
                    }
                )
            else:
                raise EvaluationError("invalid expected_chapters entry")
        detected_chapters = _detect_chapters(source_document, source_pages, source_start, source_end)
        manifest_chapters = []
        if manifest.get("chapters"):
            by_start = {int(item["source_page"]): item for item in detected_chapters}
            for item in manifest["chapters"]:
                source_page = int(item["source_start"])
                detected = by_start.get(source_page, {})
                title = str(item.get("title") or detected.get("title") or "").strip()
                manifest_chapters.append(
                    {
                        "title": title,
                        "display_title": str(item.get("display_title") or title),
                        "source_page": source_page,
                        "source_end": int(item["source_end"]),
                        "figure_label_count": item.get("figure_label_count"),
                        "number": item.get("number"),
                        "method": "fidelity_manifest",
                    }
                )
        chapters = manifest_chapters or supplied_chapters or detected_chapters
        chapter_diagnostics = _build_chapter_diagnostics(
            chapters,
            source_pages,
            generated_pages,
            page_results,
            source_start,
            source_end,
            generated_start,
        )
        chapter_count = len(chapter_diagnostics)
        preserved_chapters = sum(bool(item.get("title_preserved")) for item in chapter_diagnostics)
        chapter_coverage = preserved_chapters / chapter_count if chapter_count else 0.0

        source_fonts = _font_inventory(source_pages)
        generated_fonts = _font_inventory(generated_pages)
        embedded_fonts = sum(bool(record["embedded"]) for record in generated_fonts)
        embedded_ratio = embedded_fonts / len(generated_fonts) if generated_fonts else 0.0

        render = _render_samples(
            source_path,
            generated_path,
            source_start,
            generated_start,
            aligned_count,
            render_samples,
            sample_source_pages,
            [int(item["source_page"]) for item in chapter_diagnostics if item.get("source_page")],
            render_dpi,
            render_width,
        )

        page_count_ratio = min(source_count, generated_count) / max(source_count, generated_count)
        mean_size = _mean(size_similarities)
        mean_text = _mean(text_similarities)
        p10_text = _percentile(text_similarities, 0.10)
        search_ratio = searchable_pages / expected_text_pages if expected_text_pages else 0.0
        global_caption_coverage = (
            len(all_source_caption_keys & all_generated_caption_keys) / len(all_source_caption_keys)
            if all_source_caption_keys
            else 1.0
        )
        aligned_caption_coverage = (
            aligned_caption_hits / aligned_caption_total if aligned_caption_total else 1.0
        )
        caption_coverage = min(global_caption_coverage, aligned_caption_coverage)
        visual_coverage = _mean(visual_ratios, default=1.0)

        categories = [
            _category(
                "pagination_geometry",
                8.0 * page_count_ratio + 7.0 * mean_size,
                "verified",
                {
                    "source_pages": source_count,
                    "generated_pages": generated_count,
                    "exact_page_count": source_count == generated_count,
                    "page_count_ratio": _round(page_count_ratio),
                    "mean_size_similarity": _round(mean_size),
                    "minimum_size_similarity": _round(min(size_similarities)) if size_similarities else None,
                },
                "8 points for page-count alignment and 7 for physical page-size similarity.",
            ),
            _category(
                "text_fidelity",
                30.0 * mean_text + 5.0 * search_ratio,
                "unverified" if text_errors or not text_similarities else "verified",
                {
                    "mean_normalized_similarity": _round(mean_text),
                    "required_mean_normalized_similarity": _round(
                        float(manifest.get("normalized_text_threshold", 0.80))
                    ),
                    "p10_normalized_similarity": _round(p10_text),
                    "verified_text_pages": len(text_similarities),
                    "source_text_pages": expected_text_pages,
                    "generated_searchable_ratio": _round(search_ratio),
                    "extraction_errors": text_errors,
                },
                "30 points for normalized page text and 5 for searchable aligned pages; this is not semantic verification.",
            ),
            _category(
                "chapter_structure",
                15.0 * chapter_coverage,
                "unverified" if chapter_count == 0 else "verified",
                {
                    "detected_or_supplied_chapters": chapter_count,
                    "expected_chapter_count": expected_chapter_count,
                    "preserved_titles": preserved_chapters,
                    "title_coverage": _round(chapter_coverage),
                },
                "15 points for preserving every detected or explicitly supplied chapter title.",
            ),
            _category(
                "figures",
                5.0 * caption_coverage + 5.0 * visual_coverage,
                "not_applicable" if not all_source_caption_keys and not visual_ratios else "verified",
                {
                    "source_caption_keys": sorted(all_source_caption_keys),
                    "missing_caption_keys": sorted(all_source_caption_keys - all_generated_caption_keys),
                    "caption_detection_rule": CAPTION_DETECTION_RULE,
                    "global_caption_coverage": _round(global_caption_coverage),
                    "aligned_caption_coverage": _round(aligned_caption_coverage),
                    "visual_region_pages": len(visual_ratios),
                    "visual_region_presence_ratio": _round(visual_coverage),
                    "visual_detection_note": "Raster images, form XObjects, and substantial vector drawing operators are conservative region proxies.",
                },
                "5 points for caption keys and 5 for page-aligned image/form/vector-region evidence.",
            ),
            _category(
                "fonts_searchability",
                7.0 * embedded_ratio + 3.0 * search_ratio,
                "unverified" if not generated_fonts else "verified",
                {
                    "generated_fonts": len(generated_fonts),
                    "embedded_fonts": embedded_fonts,
                    "embedded_font_ratio": _round(embedded_ratio),
                    "generated_searchable_ratio": _round(search_ratio),
                    "source_font_inventory": source_fonts,
                    "generated_font_inventory": generated_fonts,
                },
                "7 points for generated font embedding and 3 for searchable expected text pages.",
            ),
            _category(
                "rendered_layout",
                (
                    10.0 * float(render["mean_global_ssim"])
                    + 5.0 * float(render["mean_content_box_similarity"])
                    if render["status"] == "verified"
                    else 0.0
                ),
                render["status"],
                {
                    "mean_global_ssim": render.get("mean_global_ssim"),
                    "mean_content_box_similarity": render.get("mean_content_box_similarity"),
                    "sample_count": len(render.get("samples", [])),
                    "renderer": render.get("backend"),
                },
                "Optional: 10 points for sampled global grayscale SSIM and 5 for normalized content-box similarity.",
            ),
        ]
        score = _round(sum(item["score"] for item in categories), 2)

        hard_gates: list[dict[str, Any]] = []

        def gate(gate_id: str, passed: bool, observed: Any, requirement: str) -> None:
            hard_gates.append(
                {"id": gate_id, "passed": bool(passed), "observed": observed, "requirement": requirement}
            )

        gate("score_threshold", score >= GATE_THRESHOLD, score, f">= {GATE_THRESHOLD:.0f}/100")
        gate("exact_page_count", source_count == generated_count, f"{source_count}/{generated_count}", "equal selected page counts")
        gate("page_size", mean_size >= 0.95, _round(mean_size), ">= 0.95 mean dimension similarity")
        gate("complete_page_inspection", aligned_count == source_count == generated_count, aligned_count, "every selected page aligned and inspected")
        gate("text_extraction", not text_errors and bool(text_similarities), len(text_errors), "no extraction errors and at least one text-bearing page")
        required_mean_text = float(manifest.get("normalized_text_threshold", 0.80))
        gate(
            "mean_text_fidelity",
            mean_text >= required_mean_text,
            _round(mean_text),
            f">= {required_mean_text:.2f} normalized similarity",
        )
        gate("low_tail_text_fidelity", p10_text >= 0.55, _round(p10_text), ">= 0.55 tenth-percentile page similarity")
        gate("searchability", search_ratio >= 0.95, _round(search_ratio), ">= 0.95 of source text pages searchable")
        gate("chapter_detection", chapter_count > 0, chapter_count, "> 0 chapters detected or supplied")
        if expected_chapter_count is not None:
            gate("expected_chapter_count", chapter_count == expected_chapter_count, chapter_count, f"exactly {expected_chapter_count} chapters")
        gate("chapter_title_coverage", chapter_coverage >= 1.0, _round(chapter_coverage), "all chapter titles preserved")
        gate("figure_caption_coverage", caption_coverage >= 0.90, _round(caption_coverage), ">= 0.90 when source captions exist")
        gate("visual_region_presence", visual_coverage >= 0.90, _round(visual_coverage), ">= 0.90 when source visual regions exist")
        gate("font_inspection", bool(generated_fonts), len(generated_fonts), "> 0 used generated fonts inspected")
        gate("font_embedding", embedded_ratio >= 0.95, _round(embedded_ratio), ">= 0.95 of used generated fonts embedded")
        if render_samples > 0 or sample_source_pages:
            gate(
                "requested_render_sampling",
                render["status"] == "verified",
                render["status"],
                "every explicitly requested render sample completed",
            )

        manifest_summary: dict[str, Any] = {
            "path": manifest.get("path"),
            "source_sha256_expected": manifest.get("source_sha256"),
            "source_sha256_observed": None,
            "source_page_size_mm_expected": manifest.get("source_page_size_mm"),
            "source_page_size_mm_observed": None,
            "unsupported_declared_hard_gates": [],
        }
        if manifest.get("source_sha256"):
            observed_sha256 = _sha256(source_path)
            manifest_summary["source_sha256_observed"] = observed_sha256
            gate(
                "manifest_source_sha256",
                observed_sha256 == manifest["source_sha256"],
                observed_sha256,
                f"exactly {manifest['source_sha256']}",
            )
        if manifest.get("source_range"):
            gate(
                "manifest_source_range",
                [source_start, source_end] == list(manifest["source_range"]),
                [source_start, source_end],
                f"exactly {manifest['source_range']}",
            )
        if manifest.get("source_page_size_mm"):
            factor = 25.4 / 72.0
            observed_width = _mean(page.width_pt * factor for page in source_pages)
            observed_height = _mean(page.height_pt * factor for page in source_pages)
            expected_width, expected_height = manifest["source_page_size_mm"]
            tolerance = float(manifest.get("page_size_tolerance_mm", 0.5))
            errors_mm = [
                max(
                    abs(page.width_pt * factor - expected_width),
                    abs(page.height_pt * factor - expected_height),
                )
                for page in source_pages
            ]
            manifest_summary["source_page_size_mm_observed"] = [
                _round(observed_width, 3),
                _round(observed_height, 3),
            ]
            manifest_summary["source_page_size_max_error_mm"] = _round(max(errors_mm), 3)
            gate(
                "manifest_source_page_size",
                max(errors_mm) <= tolerance,
                manifest_summary["source_page_size_mm_observed"],
                f"{expected_width} x {expected_height} mm within {tolerance} mm on every selected page",
            )
        if manifest.get("chapters"):
            expected_spans = [
                [int(item["source_start"]), int(item["source_end"])]
                for item in manifest["chapters"]
            ]
            observed_spans = [item.get("source_span") for item in chapter_diagnostics]
            gate(
                "manifest_chapter_spans",
                observed_spans == expected_spans,
                observed_spans,
                f"exactly {expected_spans}",
            )
            expected_counts = [item.get("figure_label_count") for item in manifest["chapters"]]
            if all(item is not None for item in expected_counts):
                observed_source_counts = [
                    item.get("source_figure_label_count") for item in chapter_diagnostics
                ]
                observed_generated_counts = [
                    item.get("generated_matching_figure_label_count") for item in chapter_diagnostics
                ]
                gate(
                    "manifest_source_figure_counts_by_chapter",
                    observed_source_counts == expected_counts,
                    observed_source_counts,
                    f"exactly {expected_counts}",
                )
                gate(
                    "manifest_generated_figure_counts_by_chapter",
                    observed_generated_counts == expected_counts,
                    observed_generated_counts,
                    f"exactly {expected_counts}",
                )
        if manifest.get("expected_total_figure_labels") is not None:
            expected_total = int(manifest["expected_total_figure_labels"])
            gate(
                "manifest_source_total_figure_labels",
                len(all_source_caption_keys) == expected_total,
                len(all_source_caption_keys),
                f"exactly {expected_total}",
            )
            gate(
                "manifest_generated_total_figure_labels",
                len(all_source_caption_keys & all_generated_caption_keys) == expected_total,
                len(all_source_caption_keys & all_generated_caption_keys),
                f"exactly {expected_total} source labels preserved",
            )

        supported_declared_gates = {
            "chapter_count",
            "normalized_text_accuracy",
            "expected_figure_labels",
            "missing_figures",
            "searchable_text",
            "fonts_embedded",
        }
        for name, requested in manifest.get("declared_hard_gates", {}).items():
            if name in supported_declared_gates:
                continue
            manifest_summary["unsupported_declared_hard_gates"].append(name)
            gate(
                f"manifest_external:{name}",
                False,
                "unverified",
                f"requires external evidence for declared requirement {requested!r}",
            )

        failed_hard_gates = [item["id"] for item in hard_gates if not item["passed"]]
        decision = "pass" if not failed_hard_gates else "fail"
        unverified_items = [
            {
                "id": "mathematical_semantic_accuracy",
                "status": "unverified",
                "reason": "Text extraction similarity cannot establish that formulae, proofs, definitions, references, or symbols are mathematically correct.",
                "verification_needed": "Expert mathematical review and/or source-aware formula-level validation.",
            },
            {
                "id": "editorial_publication_readiness",
                "status": "unverified",
                "reason": "A mechanical PDF fidelity gate is not a substitute for copy-editing, typography review, rights clearance, or prepress approval.",
                "verification_needed": "Human editorial, typography, accessibility, legal, and prepress sign-off.",
            },
        ]
        if render["status"] != "verified":
            unverified_items.append(
                {
                    "id": "sampled_visual_similarity",
                    "status": render["status"],
                    "reason": render.get("reason") or "render sampling unavailable",
                    "verification_needed": "Run with --render-samples or --sample-pages and an available renderer.",
                }
            )
        for name in manifest_summary["unsupported_declared_hard_gates"]:
            unverified_items.append(
                {
                    "id": f"manifest_hard_gate:{name}",
                    "status": "unverified",
                    "reason": "The supplied manifest declares a hard gate outside this PDF evaluator's evidence scope.",
                    "verification_needed": "Attach independently reproducible evidence or use the responsible compile/semantic/reference checker; do not infer a pass here.",
                }
            )

        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "evaluate_pdf_fidelity", "version": TOOL_VERSION, "offline": True, "model_invoked": False},
            "gate": {
                "name": GATE_NAME,
                "threshold": GATE_THRESHOLD,
                "score": score,
                "maximum_score": 100.0,
                "decision": decision,
                "exit_code": 0 if decision == "pass" else 1,
                "failed_hard_gates": failed_hard_gates,
                "scope": "mechanical PDF fidelity only",
                "publication_readiness": "not_established",
                "mathematical_semantic_accuracy": "unverified",
            },
            "inputs": {
                "source_pdf": str(source_path),
                "generated_pdf": str(generated_path),
                "source_pdf_pages": source_document.page_count,
                "generated_pdf_pages": generated_document.page_count,
                "source_range": [source_start, source_end],
                "generated_range": [generated_start, generated_end],
                "range_alignment_mode": range_alignment_mode,
                "backend": selected_backend,
                "manifest": manifest.get("path"),
            },
            "framework": {
                "weights": CATEGORY_WEIGHTS,
                "hard_gates": hard_gates,
                "scoring_note": "Scores measure reproducible proxies. Hard gates prevent a high aggregate from hiding critical omissions.",
            },
            "categories": categories,
            "chapter_diagnostics": chapter_diagnostics,
            "page_diagnostics": page_results,
            "render_sampling": render,
            "manifest_evidence": manifest_summary,
            "unverified_items": unverified_items,
            "warnings": [
                "Passing this gate must not be reported as 98% mathematical accuracy or as publication equivalence.",
                "Normalized extracted-text similarity may miss visually substituted glyphs or semantically wrong equations.",
            ],
            "errors": [],
        }
    finally:
        if generated_document is not None:
            generated_document.close()
        if source_document is not None:
            source_document.close()


def failure_report(
    source_path: Path | str,
    generated_path: Path | str,
    message: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "evaluate_pdf_fidelity", "version": TOOL_VERSION, "offline": True, "model_invoked": False},
        "gate": {
            "name": GATE_NAME,
            "threshold": GATE_THRESHOLD,
            "score": 0.0,
            "maximum_score": 100.0,
            "decision": "error",
            "exit_code": 2,
            "failed_hard_gates": ["evaluation_completed"],
            "scope": "mechanical PDF fidelity only",
            "publication_readiness": "not_established",
            "mathematical_semantic_accuracy": "unverified",
        },
        "inputs": {
            "source_pdf": str(Path(source_path).expanduser()),
            "generated_pdf": str(Path(generated_path).expanduser()),
        },
        "framework": {"weights": CATEGORY_WEIGHTS, "hard_gates": []},
        "categories": [],
        "chapter_diagnostics": [],
        "page_diagnostics": [],
        "render_sampling": {"status": "unverified", "samples": []},
        "unverified_items": [
            {
                "id": "all_quality_metrics",
                "status": "unverified",
                "reason": "The evaluator did not complete.",
                "verification_needed": "Resolve the operational error and rerun the evaluator.",
            },
            {
                "id": "mathematical_semantic_accuracy",
                "status": "unverified",
                "reason": "This tool never establishes mathematical semantic correctness.",
                "verification_needed": "Expert mathematical validation.",
            },
        ],
        "warnings": ["Fail-closed: no quality claim is emitted after an operational error."],
        "errors": [str(message)],
    }


def report_markdown(report: dict[str, Any]) -> str:
    gate = report["gate"]
    lines = [
        "# PDF fidelity release-gate report",
        "",
        f"- Decision: **{str(gate['decision']).upper()}**",
        f"- Mechanical score: **{gate['score']}/{gate['maximum_score']}** (threshold {gate['threshold']})",
        f"- Gate: `{gate['name']}`",
        f"- Mathematical semantic accuracy: **{gate['mathematical_semantic_accuracy']}**",
        f"- Publication readiness: **{gate['publication_readiness']}**",
        "",
        "> This report measures mechanical PDF fidelity only. It must not be described as 98% mathematical accuracy or publication equivalence.",
        "",
        "## Inputs",
        "",
        f"- Source: `{report['inputs'].get('source_pdf', '')}`",
        f"- Generated: `{report['inputs'].get('generated_pdf', '')}`",
    ]
    if "source_range" in report["inputs"]:
        lines.extend(
            [
                f"- Source physical pages: `{report['inputs']['source_range'][0]}-{report['inputs']['source_range'][1]}`",
                f"- Generated physical pages: `{report['inputs']['generated_range'][0]}-{report['inputs']['generated_range'][1]}`",
                f"- PDF backend: `{report['inputs']['backend']}`",
            ]
        )
    if report.get("errors"):
        lines.extend(["", "## Operational errors", ""])
        lines.extend(f"- {error}" for error in report["errors"])

    lines.extend(["", "## Weighted score", "", "| Category | Weight | Score | Status |", "|---|---:|---:|---|"])
    for category in report.get("categories", []):
        lines.append(
            f"| {category['id']} | {category['weight']:.0f} | {category['score']:.2f} | {category['status']} |"
        )

    lines.extend(["", "## Hard gates", "", "| Gate | Result | Observed | Requirement |", "|---|---|---|---|"])
    for item in report.get("framework", {}).get("hard_gates", []):
        observed = str(item.get("observed", "")).replace("|", "\\|")
        requirement = str(item.get("requirement", "")).replace("|", "\\|")
        lines.append(
            f"| {item['id']} | {'PASS' if item['passed'] else 'FAIL'} | {observed} | {requirement} |"
        )

    chapters = report.get("chapter_diagnostics", [])
    lines.extend(
        [
            "",
            "## Chapter diagnostics",
            "",
            "| Chapter | Source span | Generated span | Title | Mean text | Figures source/matched/expected | Low pages | Issues |",
            "|---|---:|---:|---|---:|---:|---:|---|",
        ]
    )
    for item in chapters:
        source_span = "-" if not item.get("source_span") else f"{item['source_span'][0]}-{item['source_span'][1]}"
        generated_span = "-" if not item.get("expected_generated_span") else f"{item['expected_generated_span'][0]}-{item['expected_generated_span'][1]}"
        title = str(item.get("title", "")).replace("|", "\\|")
        mean_text = "-" if item.get("mean_text_similarity") is None else f"{item['mean_text_similarity']:.4f}"
        figure_counts = "/".join(
            "-" if value is None else str(value)
            for value in (
                item.get("source_figure_label_count"),
                item.get("generated_matching_figure_label_count"),
                item.get("expected_figure_label_count"),
            )
        )
        issues = ", ".join(item.get("issues", [])) or "-"
        lines.append(
            f"| {title} | {source_span} | {generated_span} | {'OK' if item.get('title_preserved') else 'MISSING'} | {mean_text} | {figure_counts} | {len(item.get('low_similarity_pages', []))} | {issues} |"
        )
    if not chapters:
        lines.append("| *(none detected or supplied)* | - | - | MISSING | - | -/-/- | 0 | chapter_detection_unverified |")

    samples = report.get("render_sampling", {}).get("samples", [])
    lines.extend(
        [
            "",
            "## Rendered sample diagnostics",
            "",
            f"Status: `{report.get('render_sampling', {}).get('status', 'unverified')}`",
            "",
            "| Source page | Generated page | Global SSIM | Content-box similarity |",
            "|---:|---:|---:|---:|",
        ]
    )
    for item in samples:
        lines.append(
            f"| {item['source_page']} | {item['generated_page']} | {item['global_ssim']:.4f} | {item['content_box_similarity']:.4f} |"
        )
    if not samples:
        lines.append("| - | - | - | - |")

    page_diagnostics = report.get("page_diagnostics", [])
    worst = sorted(
        [
            item for item in page_diagnostics
            if item.get("text_similarity", {}).get("status") == "verified"
        ],
        key=lambda item: item["text_similarity"]["combined"],
    )[:25]
    lines.extend(
        [
            "",
            "## Lowest-scoring pages (up to 25)",
            "",
            "| Source | Generated | Text similarity | Size similarity | Missing captions |",
            "|---:|---:|---:|---:|---|",
        ]
    )
    for item in worst:
        captions = ", ".join(item.get("missing_caption_keys", [])) or "-"
        lines.append(
            f"| {item['source_page']} | {item['generated_page']} | {item['text_similarity']['combined']:.4f} | {item['size_similarity']:.4f} | {captions} |"
        )
    if not worst:
        lines.append("| - | - | - | - | no verified page text comparisons |")

    lines.extend(["", "## Explicitly unverified", ""])
    for item in report.get("unverified_items", []):
        lines.append(
            f"- **{item['id']}** (`{item['status']}`): {item['reason']} Required: {item['verification_needed']}"
        )
    if report.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in report["warnings"])
    lines.append("")
    return "\n".join(lines)


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(data, encoding="utf-8", newline="\n")
    temporary.replace(path)


def write_reports(report: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    json_path, markdown_path = json_path.resolve(), markdown_path.resolve()
    if json_path == markdown_path:
        raise EvaluationError("JSON and Markdown output paths must differ")
    _atomic_write(json_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(markdown_path, report_markdown(report))


def _parse_page_list(value: str) -> list[int]:
    if not str(value or "").strip():
        return []
    pages: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            left, right = item.split("-", 1)
            start, end = int(left), int(right)
            if start > end:
                raise argparse.ArgumentTypeError(f"invalid descending page range: {item}")
            pages.update(range(start, end + 1))
        else:
            pages.add(int(item))
    if any(page <= 0 for page in pages):
        raise argparse.ArgumentTypeError("sample pages must be positive physical page numbers")
    return sorted(pages)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline, fail-closed 80/100 mechanical PDF fidelity release gate."
    )
    parser.add_argument("source_pdf", type=Path)
    parser.add_argument("generated_pdf", type=Path)
    parser.add_argument("--manifest", type=Path, help="strict JSON source/chapter/figure expectation manifest")
    parser.add_argument("--source-start", type=int, help="1-based inclusive physical source page; manifest range is used when omitted")
    parser.add_argument("--source-end", type=int, help="1-based inclusive physical source page")
    parser.add_argument(
        "--generated-start",
        type=int,
        help="1-based inclusive generated page; default is 1, except same-file auto-alignment",
    )
    parser.add_argument("--generated-end", type=int, help="1-based inclusive generated page; default is the file end")
    parser.add_argument(
        "--self-compare",
        action="store_true",
        help="require identical PDF paths and mirror the selected source range on the generated side",
    )
    parser.add_argument("--expected-chapter-count", type=int)
    parser.add_argument("--chapter-title", action="append", default=[], help="explicit expected title; repeatable")
    parser.add_argument("--chapter-title-file", type=Path, help="UTF-8 JSON or one-title-per-line file")
    parser.add_argument("--render-samples", type=int, default=0, help="even/chapter-start visual samples; 0 disables")
    parser.add_argument("--sample-pages", type=_parse_page_list, default=[], help="explicit physical source pages, e.g. 3,12,49")
    parser.add_argument("--render-dpi", type=int, default=96)
    parser.add_argument("--render-width", type=int, default=384)
    parser.add_argument("--backend", choices=("auto", "pymupdf", "pypdf"), default="auto")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--quiet", action="store_true", help="suppress page-inspection progress")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    generated = args.generated_pdf.expanduser()
    json_path = args.json_out or generated.with_suffix(".fidelity.json")
    markdown_path = args.markdown_out or generated.with_suffix(".fidelity.md")
    try:
        manifest = load_manifest(args.manifest) if args.manifest else {}
        supplied = _load_expected_titles(args.chapter_title_file, args.chapter_title)
        source_start = args.source_start
        source_end = args.source_end
        if source_start is None:
            source_start = int(manifest.get("source_range", [1, None])[0]) if manifest.get("source_range") else 1
        if source_end is None and manifest.get("source_range"):
            source_end = int(manifest["source_range"][1])
        expected_chapter_count = args.expected_chapter_count
        if expected_chapter_count is None and manifest.get("expected_chapter_count") is not None:
            expected_chapter_count = int(manifest["expected_chapter_count"])
        report = evaluate_pdf_fidelity(
            args.source_pdf,
            args.generated_pdf,
            source_start=source_start,
            source_end=source_end,
            generated_start=args.generated_start,
            generated_end=args.generated_end,
            self_compare=args.self_compare,
            expected_chapter_count=expected_chapter_count,
            expected_chapters=supplied,
            manifest=manifest,
            render_samples=args.render_samples,
            sample_source_pages=args.sample_pages,
            render_dpi=args.render_dpi,
            render_width=args.render_width,
            backend=args.backend,
            progress=not args.quiet,
        )
        exit_code = int(report["gate"]["exit_code"])
    except Exception as exc:
        report = failure_report(args.source_pdf, args.generated_pdf, str(exc))
        exit_code = 2
    try:
        write_reports(report, json_path, markdown_path)
    except Exception as exc:
        print(f"failed to write fidelity reports: {exc}", file=sys.stderr)
        return 2
    print(
        f"{report['gate']['decision'].upper()} score={report['gate']['score']}/100 "
        f"json={json_path} markdown={markdown_path}",
        file=sys.stderr,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

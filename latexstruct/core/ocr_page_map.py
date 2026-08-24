# -*- coding: utf-8 -*-
r"""Stable OCR page anchors and baseline-PDF page mapping.

Only host-owned comments in frozen raw OCR are authoritative.  This module
creates a separate syntax candidate containing invisible ``\hypertarget``
anchors, then resolves the corresponding PDF named destinations with PyMuPDF.
It never mutates or rewrites the raw OCR string and never guesses a mapping for
legacy input without host markers.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Mapping, Sequence


OCR_PAGE_MAP_SCHEMA = "latexstruct-ocr-page-map-v1"

_PAGE_ID_RE = re.compile(r"^ocr-page-(?P<index>[0-9]{6})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HOST_MARKER_PREFIX = "% LaTeXStruct-Page:"
_HOST_MARKER_RE = re.compile(
    r"^[ \t]*% LaTeXStruct-Page: "
    r"page_id=(?P<page_id>ocr-page-[0-9]{6}) "
    r"source_page=(?P<source_page>[1-9][0-9]*)[ \t]*$"
)
_RESERVED_TARGET_RE = re.compile(
    r"\\hypertarget\s*\{\s*(ocr-page-[0-9]{6})\s*\}\s*\{",
    re.I,
)


class OcrPageMapError(ValueError):
    """Raised when host markers or compiled named destinations are unsafe."""


def _fail(message: str) -> None:
    raise OcrPageMapError(message)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(str(value).encode("utf-8"))


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class OcrPageAnchor:
    """One stable host marker extracted from frozen raw OCR."""

    page_id: str
    source_page: int
    task_index: int
    tex_marker: str

    def __post_init__(self) -> None:
        match = _PAGE_ID_RE.fullmatch(str(self.page_id or ""))
        if match is None or int(match.group("index")) != self.task_index:
            raise ValueError("page anchor page_id must encode task_index")
        if (
            not isinstance(self.task_index, int)
            or isinstance(self.task_index, bool)
            or self.task_index < 1
            or not isinstance(self.source_page, int)
            or isinstance(self.source_page, bool)
            or self.source_page < 1
        ):
            raise ValueError("page anchor indices must be positive integers")
        expected = (
            f"% LaTeXStruct-Page: page_id={self.page_id} "
            f"source_page={self.source_page}"
        )
        if self.tex_marker != expected:
            raise ValueError("page anchor tex_marker is not the canonical host comment")

    @property
    def hypertarget(self) -> str:
        return f"\\hypertarget{{{self.page_id}}}{{}}"


@dataclass(frozen=True, slots=True)
class OcrPageAnchorInjection:
    """A syntax-only candidate plus hashes proving raw remained distinct."""

    syntax_tex: str
    anchors: tuple[OcrPageAnchor, ...]
    raw_tex_sha256: str
    syntax_tex_sha256: str

    def __post_init__(self) -> None:
        if not _SHA256_RE.fullmatch(str(self.raw_tex_sha256 or "")):
            raise ValueError("raw_tex_sha256 is invalid")
        if self.syntax_tex_sha256 != _sha256_text(self.syntax_tex):
            raise ValueError("syntax_tex_sha256 does not match syntax_tex")
        object.__setattr__(self, "anchors", tuple(self.anchors))


@dataclass(frozen=True, slots=True)
class OcrPdfPageMapEntry:
    page_id: str
    source_page: int
    task_index: int
    tex_marker: str
    baseline_pdf_pages: tuple[int, ...]

    def __post_init__(self) -> None:
        OcrPageAnchor(
            page_id=self.page_id,
            source_page=self.source_page,
            task_index=self.task_index,
            tex_marker=self.tex_marker,
        )
        pages = tuple(self.baseline_pdf_pages)
        if (
            not pages
            or len(pages) != len(set(pages))
            or tuple(sorted(pages)) != pages
            or any(
                not isinstance(page, int) or isinstance(page, bool) or page < 1
                for page in pages
            )
        ):
            raise ValueError("baseline_pdf_pages must be ordered unique positive integers")
        object.__setattr__(self, "baseline_pdf_pages", pages)

    def to_dict(self) -> dict[str, object]:
        return {
            "page_id": self.page_id,
            "source_page": self.source_page,
            "task_index": self.task_index,
            "tex_marker": self.tex_marker,
            "baseline_pdf_pages": list(self.baseline_pdf_pages),
        }


@dataclass(frozen=True, slots=True)
class OcrPdfPageMap:
    """Hash-bound map resolved from one exact compiled PDF."""

    baseline_pdf_sha256: str
    baseline_pdf_page_count: int
    entries: tuple[OcrPdfPageMapEntry, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", str(self.baseline_pdf_sha256 or "")):
            raise ValueError("baseline_pdf_sha256 is invalid")
        if (
            not isinstance(self.baseline_pdf_page_count, int)
            or isinstance(self.baseline_pdf_page_count, bool)
            or self.baseline_pdf_page_count < 1
        ):
            raise ValueError("baseline_pdf_page_count must be positive")
        entries = tuple(self.entries)
        if not entries:
            raise ValueError("compiled page map cannot be empty")
        if [entry.task_index for entry in entries] != list(range(1, len(entries) + 1)):
            raise ValueError("compiled page map task indices must be contiguous")
        if len({entry.page_id for entry in entries}) != len(entries):
            raise ValueError("compiled page map page_id values must be unique")
        if len({entry.source_page for entry in entries}) != len(entries):
            raise ValueError("compiled page map source pages must be unique")
        if any(
            page > self.baseline_pdf_page_count
            for entry in entries
            for page in entry.baseline_pdf_pages
        ):
            raise ValueError("compiled page map references a PDF page out of range")
        object.__setattr__(self, "entries", entries)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": OCR_PAGE_MAP_SCHEMA,
            "baseline_pdf_sha256": self.baseline_pdf_sha256,
            "baseline_pdf_page_count": self.baseline_pdf_page_count,
            "pages": [entry.to_dict() for entry in self.entries],
        }

    def to_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_dict())


def extract_page_anchors(
    raw_tex: str,
    *,
    expected_selected_pages: Sequence[int] | None = None,
) -> tuple[OcrPageAnchor, ...]:
    """Extract and strictly validate host page comments in textual order."""
    source = str(raw_tex or "")
    reserved_targets = _RESERVED_TARGET_RE.findall(source)
    if reserved_targets:
        _fail("raw OCR already contains a reserved LaTeXStruct hypertarget")
    anchors: list[OcrPageAnchor] = []
    seen_ids: set[str] = set()
    seen_sources: set[int] = set()
    for line in source.splitlines():
        if _HOST_MARKER_PREFIX not in line:
            continue
        match = _HOST_MARKER_RE.fullmatch(line)
        if match is None:
            _fail("raw OCR contains a malformed LaTeXStruct page marker")
        page_id = match.group("page_id")
        source_page = int(match.group("source_page"))
        id_match = _PAGE_ID_RE.fullmatch(page_id)
        assert id_match is not None
        task_index = int(id_match.group("index"))
        if page_id in seen_ids or source_page in seen_sources:
            _fail("raw OCR contains duplicate page_id or source_page markers")
        expected_task = len(anchors) + 1
        if task_index != expected_task:
            _fail("raw OCR page_id markers are missing or out of task order")
        if anchors and source_page <= anchors[-1].source_page:
            _fail("raw OCR source_page markers are not strictly increasing")
        marker = (
            f"% LaTeXStruct-Page: page_id={page_id} "
            f"source_page={source_page}"
        )
        anchors.append(OcrPageAnchor(page_id, source_page, task_index, marker))
        seen_ids.add(page_id)
        seen_sources.add(source_page)
    if expected_selected_pages is not None:
        selected = tuple(expected_selected_pages)
        if any(
            not isinstance(page, int) or isinstance(page, bool) or page < 1
            for page in selected
        ) or tuple(sorted(set(selected))) != selected:
            _fail("expected selected pages must be unique ordered positive integers")
        # No markers means a legacy input: preserve compatibility, but return no
        # anchors and therefore no page map.  A partially marked input is never
        # treated as legacy and must match the frozen selection exactly.
        if anchors and tuple(anchor.source_page for anchor in anchors) != selected:
            _fail("raw OCR page markers are missing or outside selected_pages")
    return tuple(anchors)


def inject_page_anchors(
    raw_tex: str,
    *,
    expected_selected_pages: Sequence[int] | None = None,
) -> OcrPageAnchorInjection:
    """Return a separate syntax candidate with invisible page hypertargets.

    Input strings are immutable, and this function never writes any file.  With
    legacy input containing no host comments, ``syntax_tex`` is byte-for-byte
    identical to the input and ``anchors`` is empty.
    """
    source = str(raw_tex or "")
    anchors = extract_page_anchors(
        source,
        expected_selected_pages=expected_selected_pages,
    )
    if not anchors:
        return OcrPageAnchorInjection(
            syntax_tex=source,
            anchors=(),
            raw_tex_sha256=_sha256_text(source),
            syntax_tex_sha256=_sha256_text(source),
        )
    anchor_by_marker = {anchor.tex_marker: anchor for anchor in anchors}
    output: list[str] = []
    injected: set[str] = set()
    for line in source.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        match = _HOST_MARKER_RE.fullmatch(body)
        if match is None:
            output.append(line)
            continue
        canonical_marker = (
            f"% LaTeXStruct-Page: page_id={match.group('page_id')} "
            f"source_page={int(match.group('source_page'))}"
        )
        anchor = anchor_by_marker[canonical_marker]
        line_ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        if line_ending:
            output.append(line)
            output.append(anchor.hypertarget + line_ending)
        else:
            output.append(line + "\n" + anchor.hypertarget)
        injected.add(anchor.page_id)
    if injected != {anchor.page_id for anchor in anchors}:
        _fail("not every host page marker received a syntax anchor")
    syntax = "".join(output)
    return OcrPageAnchorInjection(
        syntax_tex=syntax,
        anchors=anchors,
        raw_tex_sha256=_sha256_text(source),
        syntax_tex_sha256=_sha256_text(syntax),
    )


def _pdf_named_destinations(
    pdf_bytes: bytes,
) -> tuple[int, Mapping[str, object], tuple[float, ...]]:
    data = bytes(pdf_bytes or b"")
    if not data.startswith(b"%PDF-"):
        _fail("baseline PDF lacks the PDF magic header")
    try:
        import pymupdf

        with pymupdf.open(stream=data, filetype="pdf") as document:
            page_count = int(document.page_count)
            names = document.resolve_names()
            page_heights = tuple(float(document[index].rect.height) for index in range(page_count))
    except Exception as exc:
        raise OcrPageMapError("baseline PDF cannot be opened or resolve named destinations") from exc
    if page_count < 1 or not isinstance(names, Mapping):
        _fail("baseline PDF has invalid pages or named destinations")
    if any(not math.isfinite(height) or height <= 0 for height in page_heights):
        _fail("baseline PDF has invalid page geometry")
    return page_count, names, page_heights


def build_pdf_page_map(
    pdf_bytes: bytes,
    anchors: Sequence[OcrPageAnchor],
) -> OcrPdfPageMap:
    """Resolve an exact compiled PDF into a strict 1-based page map."""
    expected = tuple(anchors)
    if not expected:
        _fail("cannot create a compiled page map without host page anchors")
    for index, anchor in enumerate(expected, start=1):
        if anchor.task_index != index:
            _fail("page anchors are missing, duplicated, or out of task order")
    if len({anchor.page_id for anchor in expected}) != len(expected) or len(
        {anchor.source_page for anchor in expected}
    ) != len(expected):
        _fail("page anchors contain duplicate identities")
    page_count, names, page_heights = _pdf_named_destinations(bytes(pdf_bytes))
    expected_ids = {anchor.page_id for anchor in expected}
    observed_ids = {
        str(name) for name in names if _PAGE_ID_RE.fullmatch(str(name))
    }
    missing = sorted(expected_ids - observed_ids)
    extra = sorted(observed_ids - expected_ids)
    if missing or extra:
        _fail(f"compiled PDF page destinations mismatch; missing={missing}, extra={extra}")
    starts: list[int] = []
    vertical_ratios: list[float] = []
    for anchor in expected:
        destination = names.get(anchor.page_id)
        if not isinstance(destination, Mapping):
            _fail(f"compiled PDF destination is invalid: {anchor.page_id}")
        page = destination.get("page")
        if not isinstance(page, int) or isinstance(page, bool) or not 0 <= page < page_count:
            _fail(f"compiled PDF destination is out of range: {anchor.page_id}")
        point = destination.get("to")
        if (
            not isinstance(point, (tuple, list))
            or len(point) != 2
            or isinstance(point[1], bool)
            or not isinstance(point[1], (int, float))
            or not math.isfinite(float(point[1]))
        ):
            _fail(f"compiled PDF destination lacks a finite target point: {anchor.page_id}")
        starts.append(page)
        vertical_ratios.append(float(point[1]) / page_heights[page])
    if starts != sorted(starts):
        _fail("compiled PDF page destinations are out of source order")
    entries: list[OcrPdfPageMapEntry] = []
    top_anchor_ratio = max(vertical_ratios)
    for index, (anchor, start) in enumerate(zip(expected, starts, strict=True)):
        if index + 1 < len(starts):
            next_start = starts[index + 1]
            if next_start == start:
                end = start
            else:
                # If the next anchor begins below the run's observed top anchor
                # position, the preceding source segment can occupy the same
                # boundary page.  Retain that overlap; otherwise the interval
                # ends on the preceding PDF page.
                next_starts_below_top = vertical_ratios[index + 1] < top_anchor_ratio - 0.005
                end = next_start if next_starts_below_top else next_start - 1
                end = max(start, end)
        else:
            end = page_count - 1
        pages = tuple(range(start + 1, end + 2))
        entries.append(OcrPdfPageMapEntry(
            page_id=anchor.page_id,
            source_page=anchor.source_page,
            task_index=anchor.task_index,
            tex_marker=anchor.tex_marker,
            baseline_pdf_pages=pages,
        ))
    return OcrPdfPageMap(
        baseline_pdf_sha256=_sha256_bytes(bytes(pdf_bytes)),
        baseline_pdf_page_count=page_count,
        entries=tuple(entries),
    )


def verify_page_map_json(
    page_map_json: bytes,
    pdf_bytes: bytes,
    anchors: Sequence[OcrPageAnchor],
) -> OcrPdfPageMap:
    """Recompute a page map and require exact canonical JSON bytes."""
    recomputed = build_pdf_page_map(pdf_bytes, anchors)
    if bytes(page_map_json or b"") != recomputed.to_json_bytes():
        _fail("page_map.json differs from the recomputed PDF named destinations")
    return recomputed


__all__ = [
    "OCR_PAGE_MAP_SCHEMA",
    "OcrPageAnchor",
    "OcrPageAnchorInjection",
    "OcrPageMapError",
    "OcrPdfPageMap",
    "OcrPdfPageMapEntry",
    "build_pdf_page_map",
    "extract_page_anchors",
    "inject_page_anchors",
    "verify_page_map_json",
]

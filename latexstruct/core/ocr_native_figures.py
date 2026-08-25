"""Host-owned native PDF figure transport.

The object extractor, rather than a model, owns the identity and crop of a
native raster or vector figure.  This module turns those frozen block facts
into the existing four-field OCR transport contract.  It never accepts image
bytes from a model and it fails closed if the final candidate TeX adds,
removes, duplicates, or reorders an ``includegraphics`` reference.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence

from .ocr_schema import PageBlock, PageBlockType, PageClassification


NATIVE_FIGURE_SOURCE = "host_native_pdf_object"
_TARGET_TEXT_BLOCK_PAGE_RATIO = 125.0 / 155.0
_FIGURE_WIDTH_MIN = 0.25
_FIGURE_WIDTH_MAX = 1.0
_FIGURE_HEIGHT_MAX = 0.72
_INCLUDEGRAPHICS_RE = re.compile(
    r"\\includegraphics(?:\s*\[[^\]\r\n]*\])?\s*\{([^{}\r\n]+)\}",
    re.IGNORECASE,
)
_NATIVE_FIGURE_PATH_RE = re.compile(
    r"^figures/page_(?P<page>[0-9]{4,})_figure_(?P<index>[0-9]{2,})\.png$"
)


class OcrNativeFigureError(ValueError):
    """Native figure evidence and the final candidate are not identical."""


def native_figure_path(source_page: int, index: int) -> str:
    if (
        not isinstance(source_page, int)
        or isinstance(source_page, bool)
        or source_page < 1
        or not isinstance(index, int)
        or isinstance(index, bool)
        or index < 1
    ):
        raise OcrNativeFigureError("native figure page/index must be positive integers")
    return f"figures/page_{source_page:04d}_figure_{index:02d}.png"


def _figure_width_ratio(
    bbox: tuple[float, float, float, float],
    page_width: float,
) -> float:
    if not math.isfinite(float(page_width)) or page_width <= 0:
        raise OcrNativeFigureError("native figure page width is invalid")
    width = max(0.0, float(bbox[2]) - float(bbox[0]))
    page_ratio = width / float(page_width)
    body_ratio = page_ratio / _TARGET_TEXT_BLOCK_PAGE_RATIO
    return round(
        min(_FIGURE_WIDTH_MAX, max(_FIGURE_WIDTH_MIN, body_ratio)),
        2,
    )


def native_figure_latex(
    path: str,
    *,
    bbox: tuple[float, float, float, float],
    page_width: float,
) -> str:
    """Return the deterministic bounded TeX projection for one native figure."""

    normalized_path = str(path or "").replace("\\", "/").strip()
    if _NATIVE_FIGURE_PATH_RE.fullmatch(normalized_path) is None:
        raise OcrNativeFigureError("native figure path is not canonical")
    width_ratio = _figure_width_ratio(bbox, page_width)
    return (
        rf"\includegraphics[width={width_ratio:.2f}\linewidth,"
        rf"height={_FIGURE_HEIGHT_MAX:.2f}\textheight,keepaspectratio]"
        rf"{{{normalized_path}}}"
    )


def _style(block: PageBlock) -> Mapping[str, object]:
    return dict(block.style_features)


def _host_figure_blocks(
    classification: PageClassification,
) -> tuple[tuple[PageBlock, str], ...]:
    rows: list[tuple[PageBlock, str]] = []
    for block in classification.blocks:
        if block.block_type is not PageBlockType.FIGURE:
            continue
        style = _style(block)
        path = str(style.get("host_figure_path") or "").replace("\\", "/").strip()
        if not path:
            # A full-page scan/background may still be represented as FIGURE,
            # but it is not a native local object and must not be materialized.
            continue
        rows.append((block, path))
    return tuple(rows)


def _pixel_bbox(
    bbox: tuple[float, float, float, float],
    *,
    page_width: float,
    page_height: float,
    image_width: int,
    image_height: int,
) -> tuple[list[float], list[int]]:
    if page_width <= 0 or page_height <= 0:
        raise OcrNativeFigureError("native figure page dimensions are invalid")
    x0, y0, x1, y1 = (float(value) for value in bbox)
    normalized = [
        max(0.0, min(1.0, x0 / page_width)),
        max(0.0, min(1.0, y0 / page_height)),
        max(0.0, min(1.0, x1 / page_width)),
        max(0.0, min(1.0, y1 / page_height)),
    ]
    if not (
        normalized[0] < normalized[2]
        and normalized[1] < normalized[3]
        and all(math.isfinite(value) for value in normalized)
    ):
        raise OcrNativeFigureError("native figure bbox is empty or outside the page")
    rounded = [round(value, 6) for value in normalized]
    pixels = [
        max(0, min(image_width - 1, math.floor(normalized[0] * image_width))),
        max(0, min(image_height - 1, math.floor(normalized[1] * image_height))),
        max(1, min(image_width, math.ceil(normalized[2] * image_width))),
        max(1, min(image_height, math.ceil(normalized[3] * image_height))),
    ]
    if pixels[0] >= pixels[2] or pixels[1] >= pixels[3]:
        raise OcrNativeFigureError("native figure pixel bbox is empty")
    return rounded, pixels


def build_host_native_figure_transport(
    classification: PageClassification,
    *,
    candidate_tex: str,
    image_size_pixels: Sequence[int],
    unresolved_regions: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    """Bind native figure blocks to final TeX and persisted page-render pixels.

    The returned object is suitable for ``validate_ocr_batch_response``.  The
    caller must persist this host-produced transport in the terminal envelope;
    provider output is not accepted as a substitute for these records.
    """

    if not isinstance(classification, PageClassification):
        raise OcrNativeFigureError("native figure transport requires a page classification")
    size = tuple(image_size_pixels)
    if (
        len(size) != 2
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            for value in size
        )
    ):
        raise OcrNativeFigureError("native figure render size is invalid")
    image_width, image_height = size
    blocks = _host_figure_blocks(classification)
    expected_paths = [
        native_figure_path(classification.source_page_number, index)
        for index in range(1, len(blocks) + 1)
    ]
    actual_paths = [
        match.group(1).replace("\\", "/").strip()
        for match in _INCLUDEGRAPHICS_RE.finditer(str(candidate_tex or ""))
    ]
    if actual_paths != expected_paths:
        raise OcrNativeFigureError(
            "final candidate includegraphics references differ from host native figures"
        )

    figures: list[dict[str, object]] = []
    for index, ((block, path), expected_path) in enumerate(
        zip(blocks, expected_paths, strict=True),
        start=1,
    ):
        if path != expected_path:
            raise OcrNativeFigureError("native figure block paths are not contiguous")
        style = _style(block)
        if (
            style.get("host_figure_index") != index
            or style.get("host_figure_source") != NATIVE_FIGURE_SOURCE
        ):
            raise OcrNativeFigureError("native figure block ownership is invalid")
        normalized, pixels = _pixel_bbox(
            block.bbox,
            page_width=float(classification.features.page_width),
            page_height=float(classification.features.page_height),
            image_width=image_width,
            image_height=image_height,
        )
        figures.append({
            "path": path,
            "index": index,
            "bbox_normalized": normalized,
            "bbox_pixels": pixels,
            "source": NATIVE_FIGURE_SOURCE,
            "source_object_hash": block.source_object_hash,
        })

    return {
        "page_id": classification.page_id,
        "latex": str(candidate_tex),
        "figures": figures,
        "unresolved_regions": [dict(item) for item in unresolved_regions],
    }


__all__ = [
    "NATIVE_FIGURE_SOURCE",
    "OcrNativeFigureError",
    "build_host_native_figure_transport",
    "native_figure_latex",
    "native_figure_path",
]

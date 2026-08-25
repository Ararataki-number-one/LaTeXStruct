"""Deterministic native PDF figure extraction and transport closure."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pymupdf
import pytest

from latexstruct.core import ocr_extraction
from latexstruct.core.analysis_inventory import (
    AnalysisNativeSourceBlock,
    InventoryStatus,
    build_analysis_inventory_bundle,
    build_host_inventory_authorizations,
    coerce_analysis_native_source_blocks,
)
from latexstruct.core.ocr_block_inventory import (
    build_ocr_block_inventory,
    parse_ocr_block_inventory,
)
from latexstruct.core.ocr_extraction import extract_pdf_pages
from latexstruct.core.ocr_native_figures import (
    NATIVE_FIGURE_SOURCE,
    OcrNativeFigureError,
    build_host_native_figure_transport,
)
from latexstruct.core.ocr_runtime import (
    OcrBatchValidationError,
    _crop_ocr_figure_png,
    validate_ocr_batch_response,
)
from latexstruct.core.ocr_pipeline import SourceClassification
from latexstruct.core.ocr_schema import DocumentStrategy, PageBlockType


REAL_37_SHA256 = "29074289719d99d7fc89f528cc0b140c27be679ea5d2477fe517eff741e7757c"


def _pdf(builder) -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=400, height=600)
        builder(page)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _graph_page(page) -> None:
    nodes = ((120, 120), (200, 90), (280, 120), (160, 200), (240, 200))
    edges = ((0, 1), (1, 2), (0, 3), (1, 3), (1, 4), (2, 4), (3, 4))
    for first, second in edges:
        page.draw_line(nodes[first], nodes[second], color=(0, 0, 0), width=2)
    for index, center in enumerate(nodes):
        page.draw_circle(
            center,
            12,
            color=(0, 0, 0),
            fill=(0.2 + 0.1 * index, 0.5, 0.8 - 0.1 * index),
            width=1.5,
        )
        page.insert_text(
            (center[0] - 4, center[1] + 4),
            chr(65 + index),
            fontsize=9,
        )
    page.insert_text((105, 230), "Figure 1. Synthetic graph.", fontsize=10)
    page.insert_text(
        (40, 280),
        "Ordinary body text stays outside the diagram.",
        fontsize=11,
    )


def _table_and_rules_page(page) -> None:
    for y in range(100, 221, 20):
        page.draw_line((80, y), (320, y), color=(0, 0, 0), width=1)
    for x in range(80, 321, 40):
        page.draw_line((x, 100), (x, 220), color=(0, 0, 0), width=1)
    page.insert_text((110, 245), "Table 1. Synthetic values.", fontsize=10)
    # Isolated formula-like rules are deliberately outside the table cluster.
    page.draw_line((90, 330), (150, 330), color=(0, 0, 0), width=0.8)
    page.draw_line((230, 330), (290, 330), color=(0, 0, 0), width=0.8)
    page.insert_text((40, 380), "Ordinary body text remains.", fontsize=11)


def _host_figures(page):
    return tuple(
        block for block in page.blocks
        if block.block_type is PageBlockType.FIGURE
        and dict(block.style_features).get("host_figure_path")
    )


def _intersection_ratio(first, second) -> float:
    x0 = max(first[0], second[0])
    y0 = max(first[1], second[1])
    x1 = min(first[2], second[2])
    y1 = min(first[3], second[3])
    intersection = max(0.0, x1 - x0) * max(0.0, y1 - y0)
    area = max(0.0, second[2] - second[0]) * max(0.0, second[3] - second[1])
    return intersection / area if area else 0.0


def test_vector_graph_is_one_host_figure_and_absorbs_only_internal_labels() -> None:
    payload = _pdf(_graph_page)
    first = extract_pdf_pages(payload, extraction_workers=1)[0]
    second = extract_pdf_pages(payload, extraction_workers=1)[0]

    figures = _host_figures(first)
    assert len(figures) == 1
    figure = figures[0]
    assert figure.plain_text == ""
    assert dict(figure.style_features) == {
        **dict(figure.style_features),
        "host_figure_index": 1,
        "host_figure_path": "figures/page_0001_figure_01.png",
        "host_figure_source": NATIVE_FIGURE_SOURCE,
    }
    assert "height=0.72\\textheight,keepaspectratio" in figure.candidate_latex
    assert first.to_dict() == second.to_dict()
    visible_text = [block.plain_text for block in first.blocks if block.plain_text]
    assert "Figure 1. Synthetic graph." in visible_text
    assert "Ordinary body text stays outside the diagram." in visible_text
    assert not ({"A", "B", "C", "D", "E"} & set(visible_text))


def test_table_grid_and_isolated_rules_are_not_promoted_to_figure() -> None:
    page = extract_pdf_pages(_pdf(_table_and_rules_page), extraction_workers=1)[0]

    assert _host_figures(page) == ()
    assert any(
        block.block_type is PageBlockType.CAPTION
        and block.plain_text == "Table 1. Synthetic values."
        for block in page.blocks
    )


def _raw_line(text: str, y: float, *, flags: int = 0, font: str = "CMMI12"):
    bbox = [100.0, y, 300.0, y + 10.0]
    return {
        "bbox": bbox,
        "spans": [{
            "text": text,
            "bbox": bbox,
            "font": font,
            "size": 12.0,
            "flags": flags,
            "color": 0,
        }],
    }


def test_formal_prefix_display_split_requires_dense_adjacent_math() -> None:
    first = {
        "type": 0,
        "bbox": [100.0, 100.0, 300.0, 122.0],
        "lines": [
            _raw_line("Theorem 1.2.", 100.0, flags=16, font="CMBX12"),
            _raw_line("x + y = z", 112.0),
        ],
    }
    following = [
        {
            "type": 0,
            "bbox": [100.0, y, 300.0, y + 10.0],
            "lines": [_raw_line(text, y)],
        }
        for text, y in (("a + b = c", 124.0), ("p ≤ q", 136.0), ("R(3, k) ≥ n", 148.0))
    ]
    raw_blocks = [first, *following]
    entry = {
        "kind": "text",
        "source_index": 0,
        "bbox": (100.0, 100.0, 300.0, 122.0),
        "text": "Theorem 1.2.\nx + y = z",
        "fonts": ("CMBX12", "CMMI12"),
        "font_size": 12.0,
        "bold": True,
        "italic": False,
        "line_count": 2,
        "span_count": 2,
        "color": 0,
        "math_likelihood": 0.5,
        "evidence": {"kind": "text", "source_block_number": 0},
    }

    assert ocr_extraction._formal_display_split_is_supported(raw_blocks, 0)
    formal, display = ocr_extraction._split_text_entry_at_first_line(entry, first)
    assert formal["text"] == "Theorem 1.2."
    assert formal["block_type_override"] is PageBlockType.HEADING_TEXT
    assert display["text"] == "x + y = z"
    assert display["block_type_override"] is PageBlockType.DISPLAY_MATH

    prose = dict(first)
    prose["lines"] = [
        _raw_line(
            "Theorem 1.2. This sentence is ordinary prose.",
            100.0,
            flags=16,
            font="CMBX12",
        ),
        _raw_line("x + y = z", 112.0),
    ]
    assert not ocr_extraction._formal_display_split_is_supported(
        [prose, *following],
        0,
    )
    assert not ocr_extraction._formal_display_split_is_supported(raw_blocks[:3], 0)


def test_native_transport_is_exact_host_owned_and_runtime_validated() -> None:
    page = extract_pdf_pages(_pdf(_graph_page), extraction_workers=1)[0]
    transport = build_host_native_figure_transport(
        page,
        candidate_tex=page.candidate_tex,
        image_size_pixels=(800, 1200),
    )

    validated = validate_ocr_batch_response(
        {"pages": [transport]},
        [page.page_id],
        page_context_by_page_id={page.page_id: {
            "source_page": 1,
            "image_size_pixels": (800, 1200),
        }},
    )[0]
    assert validated.figures[0]["source"] == NATIVE_FIGURE_SOURCE
    assert validated.figures[0]["source_object_hash"] == _host_figures(page)[0].source_object_hash
    assert tuple(validated.figures[0]["bbox_pixels"]) == tuple(
        transport["figures"][0]["bbox_pixels"]
    )

    spoofed_figure = dict(transport["figures"][0])
    spoofed_figure["source_object_hash"] = "A" * 64
    with pytest.raises(OcrBatchValidationError, match="source object hash"):
        validate_ocr_batch_response(
            {"pages": [{**transport, "figures": [spoofed_figure]}]},
            [page.page_id],
            page_context_by_page_id={page.page_id: {
                "source_page": 1,
                "image_size_pixels": (800, 1200),
            }},
        )

    with pytest.raises(OcrNativeFigureError, match="differ"):
        build_host_native_figure_transport(
            page,
            candidate_tex="Ordinary text without the host figure.",
            image_size_pixels=(800, 1200),
        )
    with pytest.raises(OcrNativeFigureError, match="differ"):
        build_host_native_figure_transport(
            page,
            candidate_tex=(
                page.candidate_tex
                + "\n\\includegraphics{figures/page_0001_figure_02.png}"
            ),
            image_size_pixels=(800, 1200),
        )


def test_block_projection_retains_textless_figure_identity_and_geometry() -> None:
    payload = _pdf(_graph_page)
    page = extract_pdf_pages(payload, extraction_workers=1)[0]
    source = SourceClassification(
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_type="pdf",
        document_strategy=DocumentStrategy.BORN_DIGITAL_FAST,
        pages=(page,),
    )
    artifact = build_ocr_block_inventory(
        run_id="c" * 32,
        source_classification=source,
        selected_pages=(1,),
    )
    inventory = parse_ocr_block_inventory(
        artifact,
        expected_run_id="c" * 32,
        expected_source_sha256=source.source_sha256,
        expected_selected_pages=(1,),
        expected_snapshot_pages=source.snapshot_contract_pages(),
    )
    projected = [
        row for row in inventory.native_source_block_projection()
        if row["block_type"] == "FIGURE"
    ]

    assert len(projected) == 1
    assert projected[0]["plain_text"] == ""
    assert projected[0]["object_path"] == "figures/page_0001_figure_01.png"
    assert projected[0]["reading_order"] == 1
    assert projected[0]["bbox"] == list(_host_figures(page)[0].bbox)
    typed = coerce_analysis_native_source_blocks(projected)
    assert typed[0].object_path == projected[0]["object_path"]
    assert typed[0].source_sha256 == _host_figures(page)[0].source_object_hash


def _tex(body: str, *, source_page: int = 23) -> str:
    return "\n".join((
        r"\documentclass{book}",
        r"\usepackage{graphicx}",
        r"\begin{document}",
        "% LaTeXStruct-Page: "
        f"page_id=ocr-page-000001 source_page={source_page}",
        body,
        r"\end{document}",
    ))


def _native_object(*, object_path: str) -> AnalysisNativeSourceBlock:
    return AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=23,
        block_id="ocr-page-000001-block-0001-0123456789ab",
        block_type="FIGURE",
        reading_order=1,
        plain_text="",
        bbox=(190.0, 68.0, 422.0, 244.0),
        object_path=object_path,
        source_sha256="a" * 64,
    )


def test_analysis_inventory_binds_textless_object_by_path_not_page_count() -> None:
    path = "figures/page_0023_figure_01.png"
    block = _native_object(object_path=path)
    source = _tex(rf"\includegraphics{{{path}}}")
    authorizations = build_host_inventory_authorizations(
        (block,),
        ocr_manifest_sha256="b" * 64,
        generated_toc_required=False,
    )

    present = build_analysis_inventory_bundle(
        source,
        source,
        {23: (23,)},
        native_source_blocks=(block,),
        authorizations=authorizations,
    ).category("figure")
    unrelated = build_analysis_inventory_bundle(
        source,
        _tex(r"\includegraphics{figures/page_0023_figure_99.png}"),
        {23: (23,)},
        native_source_blocks=(block,),
        authorizations=authorizations,
    ).category("figure")

    assert present.status is InventoryStatus.PASS
    assert present.baseline_total == present.current_total == 1
    assert present.baseline_items[0].semantic_sha256 == present.current_items[0].semantic_sha256
    assert present.baseline_items[0].source_sha256 == "a" * 64
    assert unrelated.status is InventoryStatus.FAILED
    assert any("0 exact TeX object references" in error for error in unrelated.scan_errors)


def test_textless_object_without_materialization_path_is_failed_not_na() -> None:
    block = _native_object(object_path="")
    category = build_analysis_inventory_bundle(
        _tex("Plain text."),
        _tex("Plain text."),
        {23: (23,)},
        native_source_blocks=(block,),
    ).category("figure")

    assert category.status is InventoryStatus.FAILED
    assert category.scanner_executed is True
    assert any("lacks a host object path" in error for error in category.scan_errors)


@pytest.mark.skipif(
    not os.environ.get("LATEXSTRUCT_REAL_37_PDF"),
    reason="set LATEXSTRUCT_REAL_37_PDF for the authorized local 37-page probe",
)
def test_authorized_real_37_vector_figures_and_formal_split() -> None:
    source_path = Path(os.environ["LATEXSTRUCT_REAL_37_PDF"])
    payload = source_path.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == REAL_37_SHA256
    pages = extract_pdf_pages(payload, extraction_workers=1)

    figure_pages = [
        page.source_page_number for page in pages if _host_figures(page)
    ]
    assert figure_pages == [23, 27]
    document = pymupdf.open(stream=payload, filetype="pdf")
    try:
        for source_page in figure_pages:
            classification = pages[source_page - 1]
            figures = _host_figures(classification)
            assert len(figures) == 1
            figure = figures[0]
            captions = [
                block for block in classification.blocks
                if block.block_type is PageBlockType.CAPTION
            ]
            assert len(captions) == 1
            assert captions[0].plain_text.startswith("Figure ")
            assert all(
                _intersection_ratio(figure.bbox, block.bbox) < 0.50
                for block in classification.blocks
                if block is not figure
            )

            matrix = pymupdf.Matrix(2.5, 2.5)
            page_pixmap = document[source_page - 1].get_pixmap(
                matrix=matrix,
                alpha=False,
            )
            page_png = page_pixmap.tobytes("png")
            image_size = (page_pixmap.width, page_pixmap.height)
            transport = build_host_native_figure_transport(
                classification,
                # Production binds the helper to the cleaned terminal TeX,
                # not the raw PDF glyph projection (which may contain C0
                # extraction sentinels in unrelated equations).
                candidate_tex=figure.candidate_latex,
                image_size_pixels=image_size,
            )
            validated = validate_ocr_batch_response(
                {"pages": [transport]},
                [classification.page_id],
                page_context_by_page_id={classification.page_id: {
                    "source_page": source_page,
                    "image_size_pixels": image_size,
                }},
            )[0]
            crop_bytes, crop_size = _crop_ocr_figure_png(
                page_png,
                tuple(validated.figures[0]["bbox_pixels"]),
                image_size,
            )
            assert crop_bytes.startswith(b"\x89PNG\r\n\x1a\n")
            assert crop_size[0] > 500 and crop_size[1] > 400
            assert crop_size[0] < image_size[0] and crop_size[1] < image_size[1]
            crop = pymupdf.Pixmap(crop_bytes)
            channels = crop.n
            samples = crop.samples
            nonwhite = sum(
                any(samples[offset + channel] < 235 for channel in range(min(3, channels)))
                for offset in range(0, len(samples), channels)
            )
            assert nonwhite / (crop.width * crop.height) > 0.005
    finally:
        document.close()

    page_two = pages[1]
    theorem_blocks = [
        block for block in page_two.blocks
        if block.block_type is PageBlockType.HEADING_TEXT
        and block.plain_text == "Theorem 1.2."
    ]
    following_math = [
        block for block in page_two.blocks
        if block.block_type is PageBlockType.DISPLAY_MATH
        and "R(3, k)" in block.plain_text
        and "log k" in block.plain_text
    ]
    assert len(theorem_blocks) == len(following_math) == 1
    assert "Theorem 1.2." not in following_math[0].plain_text

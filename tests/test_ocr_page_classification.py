from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pymupdf
import pytest

from latexstruct.core import ocr_extraction
from latexstruct.core.ocr_classifier import (
    classify_document,
    classify_page,
    classify_page_features,
)
from latexstruct.core.ocr_extraction import extract_image_page, extract_pdf_pages
from latexstruct.core.ocr_schema import (
    DocumentStrategy,
    PageBlockType,
    PageCandidate,
    PageFeatures,
    PageStrategy,
)


def _png(width: int = 80, height: int = 120, color: int = 0xD0D0D0) -> bytes:
    pixmap = pymupdf.Pixmap(
        pymupdf.csRGB,
        pymupdf.IRect(0, 0, width, height),
        False,
    )
    pixmap.clear_with(color)
    return pixmap.tobytes("png")


def _pdf(*page_builders) -> bytes:
    document = pymupdf.open()
    try:
        for builder in page_builders:
            page = document.new_page(width=400, height=600)
            builder(page)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _clean_page(page) -> None:
    page.insert_textbox(
        (40, 40, 360, 520),
        "Recent results in Ramsey theory\n"
        "Let G be a finite graph and let x + y = z.\n"
        "The visible text layer remains source evidence.",
        fontsize=11,
    )


def _scanned_page(page) -> None:
    page.insert_image(page.rect, stream=_png(400, 600), keep_proportion=False)


def _hybrid_page(page) -> None:
    page.insert_textbox(
        (30, 30, 370, 170),
        "This paragraph is a healthy searchable text layer with enough content.",
        fontsize=11,
    )
    page.insert_image((30, 190, 370, 570), stream=_png(340, 380), keep_proportion=False)


def _features(**overrides) -> PageFeatures:
    values = {
        "page_width": 400.0,
        "page_height": 600.0,
        "rotation": 0,
        "has_text_objects": True,
        "text_character_count": 120,
        "printable_character_ratio": 1.0,
        "unicode_replacement_ratio": 0.0,
        "garbled_character_ratio": 0.0,
        "font_mapping_health": 1.0,
        "text_block_count": 3,
        "image_count": 0,
        "image_coverage_ratio": 0.0,
        "single_full_page_image": False,
        "math_symbol_density": 0.08,
        "formula_region_count": 1,
        "double_column_likelihood": 0.0,
        "text_pixel_alignment_confidence": 1.0,
        "reading_order_confidence": 0.95,
    }
    values.update(overrides)
    return PageFeatures(**values)


def _raw_text_entry(
    source_index: int,
    bbox: tuple[float, float, float, float],
    text: str,
    *,
    math_likelihood: float,
    font_size: float = 12.0,
    fonts: tuple[str, ...] = ("CMR12",),
) -> dict[str, object]:
    evidence = {
        "kind": "text",
        "source_block_number": source_index,
        "bbox": list(bbox),
        "text": text,
        "fonts": list(fonts),
        "font_sizes": [font_size],
        "flags": [0],
        "colors": [0],
        "line_count": 1,
    }
    return {
        "kind": "text",
        "source_index": source_index,
        "bbox": bbox,
        "text": text,
        "fonts": fonts,
        "font_size": font_size,
        "bold": False,
        "italic": False,
        "line_count": 1,
        "span_count": 1,
        "color": 0,
        "math_likelihood": math_likelihood,
        "evidence": evidence,
    }


def _canonical_pages(pages) -> bytes:
    return (
        json.dumps(
            [page.to_dict() for page in pages],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def test_born_digital_page_extracts_host_features_and_plain_candidate():
    page = extract_pdf_pages(_pdf(_clean_page))[0]

    assert page.strategy is PageStrategy.BORN_DIGITAL_CLEAN
    assert page.page_id == "ocr-page-000001"
    assert page.features.page_width == 400.0
    assert page.features.page_height == 600.0
    assert page.features.rotation == 0
    assert page.features.has_text_objects is True
    assert page.features.printable_character_ratio == 1.0
    assert page.features.font_mapping_health == 1.0
    assert page.features.text_block_count >= 1
    assert page.features.image_coverage_ratio == 0.0
    assert page.candidate_tex.startswith("Recent results")
    assert isinstance(page.candidate, PageCandidate)
    assert page.candidate.blocks == page.blocks
    assert classify_page(page.candidate) == page
    assert all(len(block.source_object_hash) == 64 for block in page.blocks)


def test_math_font_signal_is_weighted_by_covered_characters():
    prose_prefix = "For every finite graph, the vertex "
    prose_suffix = " belongs to the selected independent set."
    prose = prose_prefix + "x" + prose_suffix
    prose_spans = (
        {"text": prose_prefix, "font": "CMR12"},
        {"text": "x", "font": "CMMI12"},
        {"text": prose_suffix, "font": "CMR12"},
    )
    formula = "x + y = z"
    formula_spans = (
        {"text": "x", "font": "CMMI12"},
        {"text": " + ", "font": "CMSY10"},
        {"text": "y", "font": "CMMI12"},
        {"text": " = ", "font": "CMSY10"},
        {"text": "z", "font": "CMMI12"},
    )

    assert ocr_extraction._math_likelihood(prose, prose_spans) < 0.16
    assert ocr_extraction._math_likelihood(formula, formula_spans) >= 0.55


def test_numbered_heading_is_not_misclassified_as_bibliography_or_list():
    common = {
        "kind": "text",
        "bbox": (40.0, 40.0, 360.0, 70.0),
        "font_size": 12.0,
        "bold": False,
        "fonts": ("CMR12", "CMCSC10"),
        "math_likelihood": 0.0,
    }
    heading = {**common, "text": "1. Introduction"}
    subsection = {
        **common,
        "text": "1.2. Ramsey numbers. This paragraph continues the section.",
        "fonts": ("CMR12", "CMBX12"),
    }
    bibliography = {
        **common,
        "text": "[1] P. Erdős, Some remarks on Ramsey theory.",
        "fonts": ("CMR12",),
    }
    dotted_bibliography = {
        **common,
        "text": "1. P. Erdős, Some remarks on Ramsey theory.",
        "fonts": ("CMR12",),
    }
    numbered_list = {
        **common,
        "text": "1. Choose a vertex and remove its neighbourhood.",
        "fonts": ("CMR12",),
    }

    assert ocr_extraction._block_type(
        heading, page_height=600.0, median_font_size=12.0
    ) is PageBlockType.HEADING_TEXT
    assert ocr_extraction._block_type(
        subsection, page_height=600.0, median_font_size=12.0
    ) is PageBlockType.HEADING_TEXT
    assert ocr_extraction._block_type(
        bibliography, page_height=600.0, median_font_size=12.0
    ) is PageBlockType.BIBLIOGRAPHY_ITEM
    assert ocr_extraction._block_type(
        dotted_bibliography, page_height=600.0, median_font_size=12.0
    ) is PageBlockType.BIBLIOGRAPHY_ITEM
    assert ocr_extraction._block_type(
        numbered_list, page_height=600.0, median_font_size=12.0
    ) is PageBlockType.LIST_ITEM


def test_isolated_edge_folio_is_distinct_from_body_digits_and_footnotes():
    body = _raw_text_entry(
        1,
        (40.0, 40.0, 360.0, 500.0),
        "A body paragraph contains the number 17 without making it a folio.",
        math_likelihood=0.0,
        font_size=11.0,
    )
    folio = _raw_text_entry(
        2,
        (195.0, 552.0, 205.0, 560.0),
        "17",
        math_likelihood=0.0,
        font_size=8.0,
    )
    assert ocr_extraction._is_isolated_printed_page_number(
        folio,
        (body, folio),
        page_width=400.0,
        page_height=600.0,
        median_font_size=11.0,
    ) is True
    assert ocr_extraction._block_type(
        folio,
        page_height=600.0,
        median_font_size=11.0,
        printed_page_number=True,
    ) is PageBlockType.PRINTED_PAGE_NUMBER

    interior = dict(folio, bbox=(195.0, 300.0, 205.0, 308.0))
    assert ocr_extraction._is_isolated_printed_page_number(
        interior,
        (body, interior),
        page_width=400.0,
        page_height=600.0,
        median_font_size=11.0,
    ) is False

    marker = dict(folio, bbox=(42.0, 540.0, 47.0, 548.0), text="1")
    footnote_text = _raw_text_entry(
        3,
        (50.0, 538.0, 330.0, 550.0),
        "Publisher footnote text remains source content.",
        math_likelihood=0.0,
        font_size=8.0,
    )
    assert ocr_extraction._is_isolated_printed_page_number(
        marker,
        (body, marker, footnote_text),
        page_width=400.0,
        page_height=600.0,
        median_font_size=11.0,
    ) is False
    assert ocr_extraction._block_type(
        footnote_text,
        page_height=600.0,
        median_font_size=11.0,
    ) is PageBlockType.FOOTNOTE


def test_real_extraction_keeps_printed_folio_out_of_footnote_type():
    def page_with_folio(page) -> None:
        page.insert_textbox(
            (40, 40, 360, 500),
            "A sufficiently long searchable paragraph establishes the body font size.",
            fontsize=11,
        )
        page.insert_text((195, 570), "17", fontsize=8)

    extracted = extract_pdf_pages(_pdf(page_with_folio))[0]
    folios = [
        block for block in extracted.blocks
        if block.block_type is PageBlockType.PRINTED_PAGE_NUMBER
    ]
    assert [block.plain_text for block in folios] == ["17"]
    assert all(
        block.block_type is not PageBlockType.FOOTNOTE
        for block in folios
    )


def test_math_region_coalesces_superscript_fraction_and_binomial_source_objects():
    source_entries = [
        _raw_text_entry(
            10,
            (100.0, 100.0, 145.0, 115.0),
            "( n )",
            math_likelihood=0.70,
            fonts=("CMEX10", "CMMI12"),
        ),
        _raw_text_entry(
            11,
            (118.0, 92.0, 126.0, 101.0),
            "2",
            math_likelihood=0.60,
            font_size=8.0,
            fonts=("CMR8",),
        ),
        _raw_text_entry(
            12,
            (112.0, 105.0, 133.0, 107.0),
            "-",
            math_likelihood=0.95,
            fonts=("CMSY10",),
        ),
        _raw_text_entry(
            13,
            (116.0, 109.0, 130.0, 118.0),
            "k+1",
            math_likelihood=0.65,
            font_size=8.0,
            fonts=("CMMI8", "CMR8"),
        ),
        _raw_text_entry(
            14,
            (98.0, 90.0, 147.0, 120.0),
            "()",
            math_likelihood=0.55,
            fonts=("CMEX10",),
        ),
    ]

    first = ocr_extraction._coalesce_math_regions(
        source_entries,
        page_width=400.0,
        median_font_size=12.0,
        double_column_likelihood=0.0,
    )
    second = ocr_extraction._coalesce_math_regions(
        tuple(reversed(source_entries)),
        page_width=400.0,
        median_font_size=12.0,
        double_column_likelihood=0.0,
    )

    assert first == second
    assert len(first) == 1
    region = first[0]
    assert region["bbox"] == (98.0, 90.0, 147.0, 120.0)
    assert region["block_type_override"] is PageBlockType.DISPLAY_MATH
    assert region["source_object_count"] == len(source_entries)
    assert region["evidence"]["kind"] == "coalesced_math_region"
    assert len(region["evidence"]["source_object_hashes"]) == len(source_entries)
    assert len(region["evidence"]["source_objects"]) == len(source_entries)
    assert ocr_extraction._hash_object(region["evidence"]) == ocr_extraction._hash_object(
        second[0]["evidence"]
    )


def test_math_region_coalesces_overlapping_inline_math_with_its_paragraph():
    entries = [
        _raw_text_entry(
            1,
            (40.0, 100.0, 350.0, 118.0),
            "For every graph the displayed value is visible.",
            math_likelihood=0.04,
        ),
        _raw_text_entry(
            2,
            (236.0, 99.0, 252.0, 114.0),
            "x",
            math_likelihood=0.72,
            fonts=("CMMI12",),
        ),
        _raw_text_entry(
            3,
            (250.0, 93.0, 257.0, 102.0),
            "2",
            math_likelihood=0.60,
            font_size=8.0,
            fonts=("CMR8",),
        ),
    ]

    regions = ocr_extraction._coalesce_math_regions(
        entries,
        page_width=400.0,
        median_font_size=12.0,
        double_column_likelihood=0.0,
    )

    assert len(regions) == 1
    assert regions[0]["bbox"] == (40.0, 93.0, 350.0, 118.0)
    assert regions[0]["block_type_override"] is PageBlockType.MIXED_TEXT_MATH
    assert regions[0]["source_object_count"] == 3


def test_math_region_keeps_adjacent_independent_formulas_separate():
    entries = [
        _raw_text_entry(
            1,
            (60.0, 100.0, 120.0, 115.0),
            "a=b",
            math_likelihood=0.75,
            fonts=("CMMI12", "CMSY10"),
        ),
        _raw_text_entry(
            2,
            (112.0, 93.0, 120.0, 102.0),
            "2",
            math_likelihood=0.60,
            font_size=8.0,
            fonts=("CMR8",),
        ),
        _raw_text_entry(
            3,
            (220.0, 100.0, 280.0, 115.0),
            "c=d",
            math_likelihood=0.75,
            fonts=("CMMI12", "CMSY10"),
        ),
        _raw_text_entry(
            4,
            (100.0, 140.0, 170.0, 155.0),
            "u=v",
            math_likelihood=0.75,
            fonts=("CMEX10", "CMMI12", "CMSY10"),
        ),
        _raw_text_entry(
            5,
            (100.0, 154.5, 170.0, 169.5),
            "w=z",
            math_likelihood=0.75,
            fonts=("CMEX10", "CMMI12", "CMSY10"),
        ),
    ]

    regions = ocr_extraction._coalesce_math_regions(
        entries,
        page_width=400.0,
        median_font_size=12.0,
        double_column_likelihood=0.0,
    )

    assert len(regions) == 4
    assert sorted(int(region.get("source_object_count") or 1) for region in regions) == [
        1,
        1,
        1,
        2,
    ]


def test_math_region_never_coalesces_across_detected_physical_columns():
    entries = [
        _raw_text_entry(
            1,
            (250.0, 100.0, 300.0, 115.0),
            "a=b",
            math_likelihood=0.75,
            fonts=("CMMI12", "CMSY10"),
        ),
        _raw_text_entry(
            2,
            (300.0, 100.0, 350.0, 115.0),
            "c=d",
            math_likelihood=0.75,
            fonts=("CMMI12", "CMSY10"),
        ),
    ]

    regions = ocr_extraction._coalesce_math_regions(
        entries,
        page_width=600.0,
        median_font_size=12.0,
        double_column_likelihood=0.80,
    )

    assert len(regions) == 2


def test_scanned_and_hybrid_pages_take_visual_paths():
    scanned, hybrid = extract_pdf_pages(_pdf(_scanned_page, _hybrid_page))

    assert scanned.strategy is PageStrategy.SCANNED
    assert scanned.features.single_full_page_image is True
    assert scanned.features.image_coverage_ratio >= 0.99
    assert scanned.features.text_character_count == 0
    assert [block.block_type for block in scanned.blocks] == [PageBlockType.FIGURE]
    assert scanned.candidate_tex == ""

    assert hybrid.strategy is PageStrategy.HYBRID
    assert hybrid.features.has_text_objects is True
    assert hybrid.features.image_coverage_ratio >= 0.50
    assert {block.block_type for block in hybrid.blocks} >= {
        PageBlockType.TEXT,
        PageBlockType.FIGURE,
    }


def test_corrupt_text_layer_is_never_classified_clean():
    damaged = _features(
        printable_character_ratio=0.70,
        unicode_replacement_ratio=0.12,
        garbled_character_ratio=0.20,
        font_mapping_health=0.55,
    )
    damaged_with_raster = _features(
        printable_character_ratio=0.70,
        unicode_replacement_ratio=0.12,
        garbled_character_ratio=0.20,
        font_mapping_health=0.55,
        image_count=1,
        image_coverage_ratio=0.10,
    )

    assert classify_page_features(damaged) is PageStrategy.BORN_DIGITAL_RISKY
    assert classify_page_features(damaged_with_raster) is PageStrategy.HYBRID


def test_extraction_and_block_ids_are_stable_and_bound_to_selected_order():
    source = _pdf(_clean_page, _clean_page)
    first_run = extract_pdf_pages(source, (2, 1))
    second_run = extract_pdf_pages(source, (2, 1))

    assert first_run == second_run
    assert [page.source_page_number for page in first_run] == [2, 1]
    assert [page.page_id for page in first_run] == [
        "ocr-page-000001",
        "ocr-page-000002",
    ]
    assert all(
        block.block_id.startswith(f"{page.page_id}-block-")
        for page in first_run
        for block in page.blocks
    )
    assert first_run[0].source_page_object_hash != first_run[1].source_page_object_hash
    assert len(first_run[0].source_text_layer_sha256) == 64


def test_parallel_and_serial_extraction_are_byte_identical_in_frozen_order():
    source = _pdf(*([_clean_page] * 8))
    selected = (8, 2, 7, 1, 6, 3, 5, 4)

    serial = extract_pdf_pages(source, selected, extraction_workers=1)
    parallel = extract_pdf_pages(source, selected, extraction_workers=4)

    assert _canonical_pages(parallel) == _canonical_pages(serial)
    assert [page.source_page_number for page in parallel] == list(selected)
    assert [page.page_id for page in parallel] == [
        f"ocr-page-{index:06d}" for index in range(1, 9)
    ]


def test_extraction_pool_is_bounded_and_rejects_unbounded_worker_counts(monkeypatch):
    source = _pdf(*([_clean_page] * 10))
    real_wait = ocr_extraction.wait
    observed_in_flight: list[int] = []

    def measured_wait(futures, **kwargs):
        observed_in_flight.append(len(futures))
        return real_wait(futures, **kwargs)

    monkeypatch.setattr(ocr_extraction, "wait", measured_wait)
    pages = extract_pdf_pages(source, extraction_workers=4)

    assert len(pages) == 10
    assert observed_in_flight
    assert max(observed_in_flight) == 4
    assert all(1 <= count <= 4 for count in observed_in_flight)
    for invalid in (0, 2, 3, 9, True, 1.5):
        with pytest.raises(ValueError, match="extraction_workers"):
            extract_pdf_pages(source, extraction_workers=invalid)  # type: ignore[arg-type]


def test_parallel_extraction_fails_closed_when_any_page_worker_fails():
    source = _pdf(*([_clean_page] * 4))

    with pytest.raises(ValueError):
        ocr_extraction._extract_pages_parallel(
            source,
            source_pdf_sha256=hashlib.sha256(source).hexdigest(),
            page_numbers=(1, 99, 2, 3),
            extraction_workers=4,
        )


def test_parallel_extraction_is_safe_for_concurrent_callers():
    source = _pdf(*([_clean_page] * 6))
    selected = (6, 1, 5, 2, 4, 3)
    expected = _canonical_pages(
        extract_pdf_pages(source, selected, extraction_workers=1)
    )

    with ThreadPoolExecutor(max_workers=2) as callers:
        futures = [
            callers.submit(
                extract_pdf_pages,
                source,
                selected,
                extraction_workers=4,
            )
            for _ in range(2)
        ]

    assert [_canonical_pages(future.result()) for future in futures] == [
        expected,
        expected,
    ]


def test_visible_semantic_words_never_create_semantic_latex_environments():
    def visible_semantic_words(page) -> None:
        page.insert_textbox(
            (40, 40, 360, 400),
            "Chapter 2\nSection 3\nTheorem 4. Every graph has a vertex.\n"
            "Proof. This sentence is visible source text.",
            fontsize=13,
        )

    extracted = extract_pdf_pages(_pdf(visible_semantic_words))[0]
    candidate = extracted.candidate_tex.casefold()

    assert "theorem" in candidate
    assert "proof" in candidate
    for forbidden in (
        r"\begin{theorem}",
        r"\begin{proof}",
        r"\chapter{",
        r"\section{",
    ):
        assert forbidden not in candidate


def test_original_image_input_is_image_only_and_hash_bound():
    source = _png(90, 130, 0x112233)
    page = extract_image_page(source, source_page_number=7, selected_index=3)

    assert page.strategy is PageStrategy.IMAGE_ONLY
    assert page.page_id == "ocr-page-000003"
    assert page.source_page_number == 7
    assert page.source_page_object_hash == hashlib.sha256(source).hexdigest()
    assert page.features.image_coverage_ratio == 1.0
    assert page.blocks[0].block_type is PageBlockType.FIGURE


def test_document_strategy_does_not_average_away_visual_pages():
    assert classify_document([
        PageStrategy.BORN_DIGITAL_CLEAN,
        PageStrategy.BORN_DIGITAL_RISKY,
    ]) is DocumentStrategy.BORN_DIGITAL_FAST
    assert classify_document([
        PageStrategy.BORN_DIGITAL_CLEAN,
        PageStrategy.HYBRID,
    ]) is DocumentStrategy.HYBRID_MIXED
    assert classify_document([
        PageStrategy.SCANNED,
        PageStrategy.BORN_DIGITAL_CLEAN,
    ]) is DocumentStrategy.VISUAL_STRICT


def test_double_column_likelihood_and_reading_order_are_deterministic():
    def two_columns(page) -> None:
        page.insert_textbox((30, 50, 175, 180), "Left top paragraph has enough text.", fontsize=10)
        page.insert_textbox((30, 220, 175, 350), "Left lower paragraph has enough text.", fontsize=10)
        page.insert_textbox((225, 50, 370, 180), "Right top paragraph has enough text.", fontsize=10)
        page.insert_textbox((225, 220, 370, 350), "Right lower paragraph has enough text.", fontsize=10)

    page = extract_pdf_pages(_pdf(two_columns))[0]

    assert page.features.double_column_likelihood >= 0.55
    assert page.strategy is PageStrategy.BORN_DIGITAL_RISKY
    texts = [" ".join(block.plain_text.split()) for block in page.blocks]
    assert texts == [
        "Left top paragraph has enough text.",
        "Left lower paragraph has enough text.",
        "Right top paragraph has enough text.",
        "Right lower paragraph has enough text.",
    ]

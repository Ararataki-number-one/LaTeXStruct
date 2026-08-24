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

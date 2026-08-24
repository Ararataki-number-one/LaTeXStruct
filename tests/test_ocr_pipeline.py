from __future__ import annotations

import pytest

from latexstruct.core.ocr_pipeline import (
    classify_source_pages,
    estimate_ocr_requests,
    visual_strict_fallback_classification,
)


def _pdf_bytes() -> bytes:
    import pymupdf

    document = pymupdf.open()
    first = document.new_page()
    first.insert_text((72, 72), "Visible mathematical text x + y = z")
    document.new_page()
    data = document.tobytes()
    document.close()
    return data


def test_source_classification_freezes_selected_order_and_truthful_estimate():
    classification = classify_source_pages(
        source_type="pdf",
        source_bytes=_pdf_bytes(),
        selected_pages=(1, 2),
    )

    assert [page.page_id for page in classification.pages] == [
        "ocr-page-000001", "ocr-page-000002",
    ]
    assert classification.text_layer_status == "PARTIAL"
    assert [row["source_page"] for row in classification.snapshot_contract_pages()] == [1, 2]
    estimate = estimate_ocr_requests(classification)
    assert estimate["selected_pages"] == 2
    assert estimate["estimated_cost"] is None
    assert estimate["estimate_basis"].startswith("request topology")


def test_source_classification_rejects_cross_page_or_unsupported_inputs():
    with pytest.raises(ValueError, match="single-image"):
        classify_source_pages(
            source_type="image",
            source_bytes=b"not-an-image",
            selected_pages=(1, 2),
        )


def test_visual_strict_fallback_never_invents_candidate_coverage():
    fallback = visual_strict_fallback_classification(
        source_type="pdf",
        source_bytes=b"%PDF-1.7\ncorrupt-object-layer",
        selected_pages=(4, 9),
    )

    assert fallback.document_strategy.value == "VISUAL_STRICT"
    assert [page.strategy.value for page in fallback.pages] == ["UNKNOWN", "UNKNOWN"]
    assert all(not page.blocks and not page.candidate_tex for page in fallback.pages)
    with pytest.raises(ValueError, match="unsupported"):
        classify_source_pages(
            source_type="docx",
            source_bytes=b"data",
            selected_pages=(1,),
        )

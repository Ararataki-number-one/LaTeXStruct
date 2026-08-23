from __future__ import annotations

import json

import pymupdf

from latexstruct.core import visual_quality
from latexstruct.core.preview import COMPILED, PARTIAL_COMPILED
from latexstruct.core.visual_quality import (
    CANDIDATE_SCOPE_REFLOW,
    CANDIDATE_SCOPE_SELECTED_RANGE,
    GEOMETRY_POLICY_TEMPLATE_REFLOW,
    VisualQualityStatus,
    assess_visual_quality,
    build_page_alignment,
    evaluate_visual_quality,
    verify_visual_evidence_hash,
    visual_evidence_sha256,
)


def _pdf_bytes(
    pages: list[str],
    *,
    width: float = 595,
    height: float = 842,
    x: float = 72,
    y: float = 84,
) -> bytes:
    document = pymupdf.open()
    try:
        for index, text in enumerate(pages, 1):
            page = document.new_page(width=width, height=height)
            if text:
                page.insert_text((x, y), f"{index}. {text}", fontsize=11)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _all_codes(report) -> set[str]:
    return {
        finding.code
        for finding in report.findings
    } | {
        finding.code
        for page in report.pages
        for finding in page.findings
    }


def test_identical_pdf_is_source_reuse_not_reconstruction_success():
    source = _pdf_bytes(["Theorem and proof with enough visible content."])

    report = evaluate_visual_quality(source, source, "1", preview_status=COMPILED)

    assert report.status is VisualQualityStatus.FAIL
    assert report.source_reuse_detected is True
    assert report.visual_preflight_passed is False
    assert "IDENTICAL_PDF_BYTES" in _all_codes(report)
    assert report.pages[0].difference.pixel_identical is True
    assert report.source_pdf_sha256 == report.candidate_pdf_sha256
    assert len(report.evidence_sha256) == 64
    # Public evidence is directly JSON serializable and contains no PDF text.
    serialized = report.to_json()
    assert json.loads(serialized)["status"] == "FAIL"
    assert "Theorem and proof" not in serialized


def test_page_alignment_exposes_source_to_candidate_mapping():
    selected_build = build_page_alignment(10, 3, {"pages": [4, 5, 6]})
    assert selected_build.policy == "selected_range_sequence"
    assert [item.to_dict() for item in selected_build.mappings] == [
        {"source_page": 4, "candidate_page": 1},
        {"source_page": 5, "candidate_page": 2},
        {"source_page": 6, "candidate_page": 3},
    ]

    partial_build = build_page_alignment(3, 2)
    assert partial_build.policy == "selected_range_sequence_partial"
    assert partial_build.mappings[-1].candidate_page is None

    strict_selected = build_page_alignment(
        100,
        100,
        {"start": 21, "end": 40},
        candidate_scope=CANDIDATE_SCOPE_SELECTED_RANGE,
    )
    assert strict_selected.policy == "selected_range_sequence_explicit"
    assert strict_selected.expected_candidate_page_count == 20
    assert strict_selected.selected_source_pages == tuple(range(21, 41))
    assert strict_selected.mappings[0].candidate_page == 1
    assert strict_selected.mappings[-1].candidate_page == 20
    assert strict_selected.candidate_scope == CANDIDATE_SCOPE_SELECTED_RANGE


def test_reflow_alignment_covers_fewer_candidate_pages_with_minimum_pairs():
    alignment = build_page_alignment(
        5,
        3,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_page_texts={page: f"source topic {page}" for page in range(1, 6)},
        candidate_page_texts={page: f"candidate topic {page}" for page in range(1, 4)},
    )

    assert alignment.expected_candidate_page_count == 3
    assert len(alignment.mappings) == 5
    assert {item.source_page for item in alignment.mappings} == set(range(1, 6))
    assert {item.candidate_page for item in alignment.mappings} == {1, 2, 3}
    assert all(
        left.source_page <= right.source_page
        and left.candidate_page <= right.candidate_page
        for left, right in zip(alignment.mappings, alignment.mappings[1:])
    )


def test_reflow_alignment_covers_extra_toc_pages_with_minimum_pairs():
    alignment = build_page_alignment(
        3,
        5,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_page_texts={
            1: "chapter alpha unique theorem",
            2: "chapter beta unique lemma",
            3: "chapter gamma unique proof",
        },
        candidate_page_texts={
            1: "contents alpha beta gamma",
            2: "chapter alpha unique theorem",
            3: "chapter beta unique lemma",
            4: "chapter gamma unique proof",
            5: "template colophon",
        },
    )

    assert alignment.candidate_scope == CANDIDATE_SCOPE_REFLOW
    assert len(alignment.mappings) == 5
    assert {item.source_page for item in alignment.mappings} == {1, 2, 3}
    assert {item.candidate_page for item in alignment.mappings} == set(range(1, 6))
    assert alignment.mapping_sha256


def test_reflow_alignment_large_and_equal_ranges_do_not_expand_review_calls():
    equal = build_page_alignment(
        17,
        17,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_page_texts={page: f"source {page}" for page in range(1, 18)},
        candidate_page_texts={page: f"candidate {page}" for page in range(1, 18)},
    )
    large = build_page_alignment(
        473,
        480,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_page_texts={page: f"source {page}" for page in range(1, 474)},
        candidate_page_texts={page: f"candidate {page}" for page in range(1, 481)},
    )

    assert len(equal.mappings) == 17
    assert [item.to_dict() for item in equal.mappings] == [
        {"source_page": page, "candidate_page": page}
        for page in range(1, 18)
    ]
    assert len(large.mappings) == 480
    assert len({item.source_page for item in large.mappings}) == 473
    assert len({item.candidate_page for item in large.mappings}) == 480


def test_equal_page_count_reflow_can_warp_around_generated_contents_page():
    alignment = build_page_alignment(
        4,
        4,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_page_texts={
            1: "alpha unique theorem statement and introductory paragraph",
            2: "beta unique lemma statement and complete proof paragraph",
            3: "gamma unique proposition statement and detailed discussion",
            4: "delta unique references bibliography closing paragraph",
        },
        candidate_page_texts={
            1: "alpha unique theorem statement and introductory paragraph",
            2: "contents alpha beta gamma delta generated navigation",
            3: "beta unique lemma statement and complete proof paragraph",
            4: (
                "gamma unique proposition statement and detailed discussion "
                "delta unique references bibliography closing paragraph"
            ),
        },
    )

    pairs = [
        (item.source_page, item.candidate_page) for item in alignment.mappings
    ]
    assert alignment.strategy == "content_anchor_warp"
    assert len(alignment.mappings) > 4
    assert set(item.source_page for item in alignment.mappings) == {1, 2, 3, 4}
    assert set(item.candidate_page for item in alignment.mappings) == {1, 2, 3, 4}
    assert (2, 3) in pairs
    assert pairs != [(page, page) for page in range(1, 5)]


def test_reflow_page_count_change_is_not_a_strict_pagination_failure():
    source = _pdf_bytes(["alpha", "beta", "gamma"])
    candidate = _pdf_bytes(["contents", "alpha beta", "gamma", "colophon"], x=92)

    report = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    )

    assert "EXTRA_CANDIDATE_PAGES" not in _all_codes(report)
    assert "PAGE_COUNT_MISMATCH" not in _all_codes(report)
    assert len(report.pages) == 4
    assert report.page_alignment is not None
    assert {page.source_page for page in report.pages} == {1, 2, 3}
    assert {page.candidate_page for page in report.pages} == {1, 2, 3, 4}


def test_reflow_without_source_text_layer_requires_visual_review():
    source = _pdf_bytes(["", ""])
    candidate = _pdf_bytes(["candidate one", "candidate two", "contents"], x=92)

    report = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    )

    assert report.status is VisualQualityStatus.REVIEW
    assert report.visual_preflight_passed is False
    assert report.needs_model_review is True
    assert report.page_alignment.requires_model_review is True
    assert "REFLOW_ALIGNMENT_PROPORTIONAL_FALLBACK" in _all_codes(report)


def test_selected_range_scope_rejects_full_source_candidate_as_extra_pages():
    source = _pdf_bytes([f"source page {page}" for page in range(1, 6)])
    candidate = _pdf_bytes(
        [f"candidate page {page}" for page in range(1, 6)],
        x=92,
    )

    report = evaluate_visual_quality(
        source,
        candidate,
        {"start": 2, "end": 3},
        candidate_scope=CANDIDATE_SCOPE_SELECTED_RANGE,
    )

    assert report.status is VisualQualityStatus.FAIL
    assert "EXTRA_CANDIDATE_PAGES" in _all_codes(report)
    assert report.compared_page_count == 2
    assert report.aggregate_metrics["candidate_scope"] == "selected_range"
    assert report.aggregate_metrics["expected_candidate_page_count"] == 2
    assert [page.source_page for page in report.pages] == [2, 3]
    assert [page.candidate_page for page in report.pages] == [1, 2]


def test_source_page_slice_with_different_pdf_bytes_is_still_rejected():
    source = _pdf_bytes(["first source page", "second source page"])
    source_document = pymupdf.open(stream=source, filetype="pdf")
    candidate_document = pymupdf.open()
    try:
        candidate_document.insert_pdf(source_document, from_page=0, to_page=0)
        candidate = candidate_document.tobytes(garbage=4, deflate=True)
    finally:
        candidate_document.close()
        source_document.close()

    assert candidate != source
    report = evaluate_visual_quality(source, candidate, (1, 1))

    assert report.status is VisualQualityStatus.FAIL
    assert report.source_reuse_detected is True
    assert "SOURCE_PAGE_REUSE_DETECTED" in _all_codes(report)


def test_reasonable_reflow_is_measured_without_false_hard_failure():
    text = (
        "A deterministic visual comparison should tolerate ordinary typesetting "
        "movement while retaining evidence for external review."
    )
    source = _pdf_bytes([text], x=72, y=84)
    candidate = _pdf_bytes([text], x=96, y=126)

    report = evaluate_visual_quality(source, candidate, {"start": 1, "end": 1})

    assert report.status in {VisualQualityStatus.PASS, VisualQualityStatus.REVIEW}
    assert report.source_reuse_detected is False
    assert report.compared_page_count == 1
    page = report.pages[0]
    assert page.difference.pixel_identical is False
    assert page.difference.low_resolution_pixel_difference > 0
    # A wider left margin can clip the last few glyphs in this synthetic page,
    # but ordinary reflow must remain a high-similarity, non-failing case.
    assert page.difference.extracted_text_similarity > 0.95
    assert page.source.text_block_count >= 1
    assert page.candidate.text_block_count >= 1


def test_partial_compiled_pdf_keeps_page_evidence_and_cannot_pass():
    source = _pdf_bytes(["same text, source layout"])
    candidate = _pdf_bytes(["same text, source layout"], x=92, y=118)

    report = evaluate_visual_quality(
        source,
        candidate,
        preview_status=PARTIAL_COMPILED,
    )

    assert report.partial_compiled is True
    assert report.status is VisualQualityStatus.REVIEW
    assert report.compared_page_count == 1
    assert report.needs_model_review is True
    assert "PARTIAL_COMPILED_INPUT" in _all_codes(report)


def test_blank_candidate_page_is_a_deterministic_failure():
    source = _pdf_bytes(["This visible source material must not disappear."])
    candidate = _pdf_bytes([""])

    report = evaluate_visual_quality(source, candidate)

    assert report.status is VisualQualityStatus.FAIL
    assert "BLANK_CANDIDATE_PAGE" in _all_codes(report)
    assert report.pages[0].candidate.ink_ratio < 0.0015


def test_missing_candidate_page_is_reported_even_for_partial_compile():
    source = _pdf_bytes(["source page one", "source page two"])
    candidate = _pdf_bytes(["candidate page one has a deliberately changed layout"], x=92)

    report = evaluate_visual_quality(
        source,
        candidate,
        preview_status=PARTIAL_COMPILED,
    )

    assert report.status is VisualQualityStatus.FAIL
    assert report.source_page_count == 2
    assert report.candidate_page_count == 1
    assert report.compared_page_count == 1
    assert {"PAGE_COUNT_MISMATCH", "MISSING_CANDIDATE_PAGE"} <= _all_codes(report)


def test_extra_candidate_page_is_a_hard_failure_not_an_uninspected_warning():
    source = _pdf_bytes(["source page"])
    candidate = _pdf_bytes(["candidate page", "unexpected appendix page"], x=92)

    report = evaluate_visual_quality(source, candidate)

    assert report.status is VisualQualityStatus.FAIL
    assert "EXTRA_CANDIDATE_PAGES" in _all_codes(report)


def test_material_page_size_change_is_a_failure():
    source = _pdf_bytes(["page size evidence"])
    candidate = _pdf_bytes(["page size evidence"], width=320, height=420)

    report = evaluate_visual_quality(source, candidate)

    assert report.status is VisualQualityStatus.FAIL
    assert "PAGE_SIZE_MISMATCH" in _all_codes(report)
    assert report.pages[0].difference.width_relative_delta > 0.20


def test_image_wrapper_size_is_review_only_but_other_hard_gates_remain():
    image_wrapper = _pdf_bytes(
        ["image OCR page with visible source content"],
        width=240,
        height=320,
        x=24,
    )
    book_page = _pdf_bytes(
        ["image OCR page with visible source content"],
        width=595,
        height=842,
    )

    size_report = evaluate_visual_quality(
        image_wrapper,
        book_page,
        source_geometry_authoritative=False,
    )

    assert size_report.status is VisualQualityStatus.REVIEW
    assert "SOURCE_PAGE_SIZE_NON_AUTHORITATIVE" in _all_codes(size_report)
    assert "PAGE_SIZE_MISMATCH" not in _all_codes(size_report)
    assert size_report.aggregate_metrics["source_geometry_authoritative"] is False
    size_finding = next(
        finding
        for finding in size_report.pages[0].findings
        if finding.code == "SOURCE_PAGE_SIZE_NON_AUTHORITATIVE"
    )
    assert size_finding.severity is visual_quality.VisualSeverity.WARNING
    assert size_finding.needs_model_review is True

    landscape_wrapper = _pdf_bytes(
        ["landscape image source"],
        width=420,
        height=300,
    )
    orientation_report = evaluate_visual_quality(
        landscape_wrapper,
        book_page,
        source_geometry_authoritative=False,
    )
    assert orientation_report.status is VisualQualityStatus.FAIL
    assert "PAGE_ORIENTATION_MISMATCH" in _all_codes(orientation_report)

    blank_report = evaluate_visual_quality(
        image_wrapper,
        _pdf_bytes([""], width=595, height=842),
        source_geometry_authoritative=False,
    )
    assert blank_report.status is VisualQualityStatus.FAIL
    assert "BLANK_CANDIDATE_PAGE" in _all_codes(blank_report)

    missing_report = evaluate_visual_quality(
        _pdf_bytes(["page one", "page two"], width=240, height=320),
        book_page,
        source_geometry_authoritative=False,
    )
    assert missing_report.status is VisualQualityStatus.FAIL
    assert "MISSING_CANDIDATE_PAGE" in _all_codes(missing_report)


def test_mojibake_text_layer_is_reported_as_garbled():
    source = _pdf_bytes([
        "Readable mathematical prose and references remain readable in the rebuilt PDF."
    ])
    candidate = _pdf_bytes([
        "Ã Â â€ Ã Â â€ Ã Â â€ unreadable encoding artifacts"
    ])

    report = evaluate_visual_quality(source, candidate)

    assert report.status is VisualQualityStatus.FAIL
    assert "GARBLED_TEXT_LAYER" in _all_codes(report)
    assert report.pages[0].candidate.suspicious_character_ratio > 0


def test_template_reflow_text_signal_requires_model_review_instead_of_skipping_it():
    source = _pdf_bytes(["Readable source prose for the reflowed page."])
    candidate = _pdf_bytes(["Ã Â â€ Ã Â â€ Ã Â â€ extraction indicators"])

    report = evaluate_visual_quality(
        source,
        candidate,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    )

    assert report.status is VisualQualityStatus.REVIEW
    assert report.needs_model_review is True
    assert "TEMPLATE_REFLOW_TEXT_LAYER_REVIEW" in _all_codes(report)
    assert "GARBLED_TEXT_LAYER" not in _all_codes(report)


def test_renderer_unavailable_is_fail_closed(monkeypatch):
    source = _pdf_bytes(["source"])
    candidate = _pdf_bytes(["candidate"])
    monkeypatch.setattr(visual_quality, "_load_pymupdf", lambda: None)

    report = evaluate_visual_quality(source, candidate)

    assert report.status is VisualQualityStatus.UNAVAILABLE
    assert report.visual_preflight_passed is False
    assert report.needs_model_review is True
    assert report.renderer == "none"
    assert "RENDERER_UNAVAILABLE" in _all_codes(report)


def test_candidate_open_or_render_failure_is_fail_closed_without_path_leak(monkeypatch):
    source = _pdf_bytes(["source"])
    malformed = b"not a PDF C:\\Users\\Private\\secret.pdf"

    open_report = evaluate_visual_quality(source, malformed)
    assert open_report.status is VisualQualityStatus.UNAVAILABLE
    assert "CANDIDATE_PDF_OPEN_FAILED" in _all_codes(open_report)
    assert "C:\\Users\\Private" not in json.dumps(open_report.to_dict())

    candidate = _pdf_bytes(["candidate"])
    original_render = visual_quality._render_page
    calls = 0

    def fail_candidate_render(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("C:\\Users\\Private\\render-cache")
        return original_render(*args, **kwargs)

    monkeypatch.setattr(visual_quality, "_render_page", fail_candidate_render)
    render_report = evaluate_visual_quality(source, candidate)

    assert render_report.status is VisualQualityStatus.UNAVAILABLE
    assert "CANDIDATE_PAGE_RENDER_FAILED" in _all_codes(render_report)
    assert "C:\\Users\\Private" not in json.dumps(render_report.to_dict())


def test_evidence_hash_is_deterministic_for_same_inputs():
    source = _pdf_bytes(["source text"])
    candidate = _pdf_bytes(["candidate text"], y=112)

    first = evaluate_visual_quality(source, candidate)
    second = evaluate_visual_quality(source, candidate)

    assert first.evidence_sha256 == second.evidence_sha256
    assert first.to_dict() == second.to_dict()
    assert verify_visual_evidence_hash(first) is True
    loaded = json.loads(first.to_json())
    assert visual_evidence_sha256(loaded) == first.evidence_sha256
    loaded["candidate_page_count"] = 99
    assert verify_visual_evidence_hash(loaded) is False

    wrapped = assess_visual_quality(
        source_pdf_bytes=source,
        generated_pdf_bytes=candidate,
    )
    assert wrapped.to_dict() == first.to_dict()

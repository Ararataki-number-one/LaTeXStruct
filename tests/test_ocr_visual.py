from __future__ import annotations

import hashlib

import pytest

from latexstruct.core.ocr_schema import (
    PageBlock,
    PageBlockType,
    PageCandidate,
    PageFeatures,
)
from latexstruct.core.ocr_visual import (
    PageVisualVerification,
    VISUAL_VERIFIER_SYSTEM_PROMPT,
    VisualVerdict,
    resolve_visual_candidate,
    validate_visual_verification_response,
    visual_verification_output_schema,
    visual_verification_request_payload,
)


def _candidate() -> PageCandidate:
    page_id = "ocr-page-000001"
    block_hash = hashlib.sha256(b"block").hexdigest()
    features = PageFeatures(
        page_width=612,
        page_height=792,
        rotation=0,
        has_text_objects=True,
        text_character_count=32,
        printable_character_ratio=1,
        unicode_replacement_ratio=0,
        garbled_character_ratio=0,
        font_mapping_health=1,
        text_block_count=1,
        image_count=0,
        image_coverage_ratio=0,
        single_full_page_image=False,
        math_symbol_density=0.2,
        formula_region_count=1,
        double_column_likelihood=0,
        text_pixel_alignment_confidence=0.98,
        reading_order_confidence=0.99,
    )
    block = PageBlock(
        block_id=f"{page_id}-block-0001-{block_hash[:12]}",
        block_type=PageBlockType.DISPLAY_MATH,
        bbox=(72, 100, 540, 140),
        reading_order=1,
        plain_text="x ≤ y",
        style_features={},
        math_likelihood=0.8,
        source_object_hash=block_hash,
        candidate_latex="x ≤ y",
    )
    return PageCandidate(
        page_id=page_id,
        source_page_number=7,
        selected_index=1,
        features=features,
        blocks=(block,),
        source_page_object_hash=hashlib.sha256(b"page").hexdigest(),
        source_text_layer_sha256=hashlib.sha256(b"text").hexdigest(),
        candidate_tex="x ≤ y",
    )


def _response(candidate: PageCandidate, verdict="PASS", **updates):
    page = {
        "page_id": candidate.page_id,
        "verdict": verdict,
        "reading_order_ok": True,
        "coverage_ok": True,
        "block_findings": [],
        "missing_regions": [],
        "unresolved_regions": [],
    }
    page.update(updates)
    return {"batch_id": "ocr-verify-batch-test", "pages": [page]}


def test_visual_schema_and_request_are_bounded_and_do_not_invite_page_rewrite():
    candidate = _candidate()
    schema = visual_verification_output_schema()
    payload = visual_verification_request_payload(
        "ocr-verify-batch-test", (candidate,)
    )

    assert schema["additionalProperties"] is False
    assert schema["properties"]["pages"]["maxItems"] == 8
    page_schema = schema["properties"]["pages"]["items"]
    assert "latex" not in page_schema["properties"]
    assert payload["pages"][0]["page_id"] == candidate.page_id
    assert payload["pages"][0]["candidate_blocks"][0]["block_id"].startswith(
        candidate.page_id
    )
    assert "0 <= x0 < x1 <= 1" in VISUAL_VERIFIER_SYSTEM_PROMPT
    assert "never emit [0,0,0,0]" in VISUAL_VERIFIER_SYSTEM_PROMPT
    assert "every replacement_latex must be exactly\nempty" in (
        VISUAL_VERIFIER_SYSTEM_PROMPT
    )


def test_visual_pass_preserves_candidate_byte_for_byte():
    candidate = _candidate()
    batch = validate_visual_verification_response(
        _response(candidate),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )
    resolved = resolve_visual_candidate(candidate, batch.pages[0])

    # The object layer only exposes Unicode math glyphs here.  A PASS cannot
    # silently promote that into mathematical LaTeX, so the host escalates.
    assert resolved.requires_full_ocr is True
    assert resolved.candidate_tex == candidate.candidate_tex
    assert resolved.patched_block_ids == ()


def test_visual_patch_can_only_replace_a_known_block():
    candidate = _candidate()
    finding = {
        "block_id": candidate.blocks[0].block_id,
        "issue_type": "MATH_MISMATCH",
        "severity": "HIGH",
        "replacement_latex": r"\[x \leq y\]",
        "evidence_region": [0.1, 0.1, 0.9, 0.2],
        "confidence": 0.99,
    }
    batch = validate_visual_verification_response(
        _response(candidate, "PATCH", block_findings=[finding]),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )
    resolved = resolve_visual_candidate(candidate, batch.pages[0])

    assert resolved.candidate_tex == r"\[x \leq y\]"
    assert resolved.patched_block_ids == (candidate.blocks[0].block_id,)

    finding["block_id"] = "ocr-page-000002-block-0001-deadbeef0000"
    with pytest.raises(ValueError, match="foreign or unknown"):
        validate_visual_verification_response(
            _response(candidate, "PATCH", block_findings=[finding]),
            batch_id="ocr-verify-batch-test",
            candidates=(candidate,),
        )


def test_visual_missing_or_unresolved_content_cannot_be_marked_pass_or_patch():
    candidate = _candidate()
    with pytest.raises(ValueError, match="PASS must be complete"):
        validate_visual_verification_response(
            _response(candidate, missing_regions=[[0.1, 0.1, 0.2, 0.2]]),
            batch_id="ocr-verify-batch-test",
            candidates=(candidate,),
        )

    unresolved = validate_visual_verification_response(
        _response(
            candidate,
            "UNRESOLVED",
            reading_order_ok=False,
            coverage_ok=False,
            unresolved_regions=[[0.1, 0.1, 0.2, 0.2]],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )
    resolution = resolve_visual_candidate(candidate, unresolved.pages[0])
    assert resolution.requires_full_ocr is True
    assert resolution.needs_review is True


def test_visual_batch_rejects_missing_reordered_duplicate_and_foreign_pages():
    candidate = _candidate()
    second = PageCandidate(
        page_id="ocr-page-000002",
        source_page_number=8,
        selected_index=2,
        features=candidate.features,
        blocks=(
            PageBlock(
                block_id="ocr-page-000002-block-0001-" + "a" * 12,
                block_type=PageBlockType.TEXT,
                bbox=(1, 1, 2, 2),
                reading_order=1,
                plain_text="text",
                style_features={},
                math_likelihood=0,
                source_object_hash="a" * 64,
                candidate_latex="text",
            ),
        ),
        source_page_object_hash="b" * 64,
        source_text_layer_sha256="c" * 64,
        candidate_tex="text",
    )
    response = {
        "batch_id": "ocr-verify-batch-test",
        "pages": [
            _response(second)["pages"][0],
            _response(candidate)["pages"][0],
        ],
    }
    with pytest.raises(ValueError, match="omitted, reordered, or invented"):
        validate_visual_verification_response(
            response,
            batch_id="ocr-verify-batch-test",
            candidates=(candidate, second),
        )


def test_escalation_verdict_cannot_smuggle_forbidden_structure():
    candidate = _candidate()
    finding = {
        "block_id": candidate.blocks[0].block_id,
        "issue_type": "MATH_MISMATCH",
        "severity": "HIGH",
        "replacement_latex": r"\section{invented}",
        "evidence_region": [0.1, 0.1, 0.9, 0.2],
        "confidence": 1,
    }
    with pytest.raises(ValueError, match="forbidden"):
        validate_visual_verification_response(
            _response(candidate, "PATCH", block_findings=[finding]),
            batch_id="ocr-verify-batch-test",
            candidates=(candidate,),
        )

    direct = PageVisualVerification(
        page_id=candidate.page_id,
        verdict=VisualVerdict.FULL_OCR_REQUIRED,
        reading_order_ok=False,
        coverage_ok=False,
    )
    assert resolve_visual_candidate(candidate, direct).requires_full_ocr is True

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from latexstruct.core.ocr_schema import (
    PageBlock,
    PageBlockType,
    PageCandidate,
    PageClassification,
    PageFeatures,
    PageStrategy,
)
from latexstruct.core.ocr_visual import (
    PageVisualVerification,
    VISUAL_VERIFIER_SYSTEM_PROMPT,
    VisualVerdict,
    classification_requires_full_page_ocr,
    merge_local_patch_retry,
    requires_full_page_ocr,
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


def _candidate_with_two_unrepresented_math_blocks() -> PageCandidate:
    candidate = _candidate()
    second_hash = hashlib.sha256(b"second-block").hexdigest()
    second = PageBlock(
        block_id=f"{candidate.page_id}-block-0002-{second_hash[:12]}",
        block_type=PageBlockType.INLINE_MATH,
        bbox=(72, 160, 540, 190),
        reading_order=2,
        plain_text="a + b",
        style_features={},
        math_likelihood=0.7,
        source_object_hash=second_hash,
        candidate_latex="a + b",
    )
    return PageCandidate(
        page_id=candidate.page_id,
        source_page_number=candidate.source_page_number,
        selected_index=candidate.selected_index,
        features=candidate.features,
        blocks=(*candidate.blocks, second),
        source_page_object_hash=candidate.source_page_object_hash,
        source_text_layer_sha256=candidate.source_text_layer_sha256,
        candidate_tex=f"{candidate.candidate_tex}\n\n{second.candidate_latex}",
    )


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
    assert payload["pages"][0]["local_patch_required_block_ids"] == [
        candidate.blocks[0].block_id
    ]
    assert "Do not request whole-page OCR" in payload["pages"][0]["full_ocr_guard"]
    assert "0 <= x0 < x1 <= 1" in VISUAL_VERIFIER_SYSTEM_PROMPT
    assert "never emit [0,0,0,0]" in VISUAL_VERIFIER_SYSTEM_PROMPT
    assert "every replacement_latex must be exactly\nempty" in (
        VISUAL_VERIFIER_SYSTEM_PROMPT
    )


def test_local_retry_request_is_host_bounded_to_known_blocks():
    candidate = _candidate()
    block_id = candidate.blocks[0].block_id
    payload = visual_verification_request_payload(
        "ocr-verify-batch-retry",
        (candidate,),
        retry_required_block_ids_by_page_id={candidate.page_id: (block_id,)},
    )

    page = payload["pages"][0]
    assert page["local_patch_retry"] is True
    assert page["retry_required_block_ids"] == [block_id]
    assert "whole-page OCR" in page["retry_instruction"]
    with pytest.raises(ValueError, match="foreign block_id"):
        visual_verification_request_payload(
            "ocr-verify-batch-retry-bad",
            (candidate,),
            retry_required_block_ids_by_page_id={
                candidate.page_id: ("foreign-block",)
            },
        )


def test_local_retry_merge_closes_only_the_exact_omitted_blocks():
    candidate = _candidate_with_two_unrepresented_math_blocks()
    first_id, second_id = (block.block_id for block in candidate.blocks)

    def finding(block_id, replacement):
        return {
            "block_id": block_id,
            "issue_type": "MATH_MISMATCH",
            "severity": "HIGH",
            "replacement_latex": replacement,
            "evidence_region": [0.1, 0.1, 0.9, 0.3],
            "confidence": 0.99,
        }

    first = validate_visual_verification_response(
        _response(
            candidate,
            verdict="PATCH",
            block_findings=[finding(first_id, r"\[x \le y\]")],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    ).pages[0]
    retry = validate_visual_verification_response(
        _response(
            candidate,
            verdict="PATCH",
            block_findings=[finding(second_id, r"\(a+b\)")],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    ).pages[0]

    combined = merge_local_patch_retry(candidate, first, retry, (second_id,))
    assert combined is not None
    resolved = resolve_visual_candidate(candidate, combined)
    assert resolved.needs_review is False
    assert resolved.patched_block_ids == (first_id, second_id)
    assert merge_local_patch_retry(candidate, first, retry, (first_id,)) is None


def test_mixed_text_math_region_remains_one_precise_local_patch_target():
    candidate = _candidate()
    mixed_block = replace(
        candidate.blocks[0],
        block_type=PageBlockType.MIXED_TEXT_MATH,
        plain_text="For every graph, x ≤ y is visible.",
        candidate_latex="For every graph, x ≤ y is visible.",
    )
    candidate = replace(
        candidate,
        blocks=(mixed_block,),
        candidate_tex=mixed_block.candidate_latex,
    )

    payload = visual_verification_request_payload(
        "ocr-verify-batch-mixed", (candidate,)
    )

    assert payload["pages"][0]["local_patch_required_block_ids"] == [
        mixed_block.block_id
    ]
    assert payload["pages"][0]["high_risk_regions"] == [mixed_block.block_id]


def test_visual_pass_preserves_candidate_byte_for_byte():
    candidate = _candidate()
    batch = validate_visual_verification_response(
        _response(candidate),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )
    resolved = resolve_visual_candidate(candidate, batch.pages[0])

    # A verifier should PATCH this known math block.  If it incorrectly emits
    # PASS, the host preserves the candidate for local repair/review and must
    # not spend a whole-page OCR call for a block-local defect.
    assert resolved.requires_full_ocr is False
    assert resolved.needs_review is True
    assert resolved.local_patch_block_ids == (candidate.blocks[0].block_id,)
    assert resolved.candidate_tex == candidate.candidate_tex
    assert resolved.patched_block_ids == ()


def test_local_patch_ids_are_stable_in_frozen_candidate_order():
    candidate = _candidate_with_two_unrepresented_math_blocks()
    batch = validate_visual_verification_response(
        _response(candidate),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )

    first = resolve_visual_candidate(candidate, batch.pages[0])
    second = resolve_visual_candidate(candidate, batch.pages[0])

    expected = tuple(block.block_id for block in candidate.blocks)
    assert first.local_patch_block_ids == expected
    assert second.local_patch_block_ids == expected
    assert first.verification_sha256 == second.verification_sha256
    assert len(first.verification_sha256) == 64


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
    assert resolved.local_patch_block_ids == ()
    assert resolved.needs_review is False

    finding["block_id"] = "ocr-page-000002-block-0001-deadbeef0000"
    with pytest.raises(ValueError, match="foreign or unknown"):
        validate_visual_verification_response(
            _response(candidate, "PATCH", block_findings=[finding]),
            batch_id="ocr-verify-batch-test",
            candidates=(candidate,),
        )


def test_math_patch_without_tex_delimiters_remains_a_local_residual():
    candidate = _candidate()
    block_id = candidate.blocks[0].block_id
    finding = {
        "block_id": block_id,
        "issue_type": "MATH_MISMATCH",
        "severity": "HIGH",
        "replacement_latex": "x+y",
        "evidence_region": [0.1, 0.1, 0.9, 0.2],
        "confidence": 0.99,
    }
    first = validate_visual_verification_response(
        _response(candidate, "PATCH", block_findings=[finding]),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    ).pages[0]

    resolved = resolve_visual_candidate(candidate, first)

    assert resolved.requires_full_ocr is False
    assert resolved.needs_review is True
    assert resolved.local_patch_block_ids == (block_id,)
    assert merge_local_patch_retry(candidate, first, first, (block_id,)) is None


@pytest.mark.parametrize("field", ["reading_order_ok", "coverage_ok"])
def test_visual_response_rejects_truthy_strings_for_boolean_fields(field: str):
    candidate = _candidate()
    response = _response(candidate)
    response["pages"][0][field] = "false"

    with pytest.raises(ValueError, match="JSON booleans"):
        validate_visual_verification_response(
            response,
            batch_id="ocr-verify-batch-test",
            candidates=(candidate,),
        )


def test_visual_response_rejects_coerced_numeric_evidence_fields():
    candidate = _candidate()
    finding = {
        "block_id": candidate.blocks[0].block_id,
        "issue_type": "MATH_MISMATCH",
        "severity": "HIGH",
        "replacement_latex": r"\[x+y\]",
        "evidence_region": ["0.1", 0.1, 0.9, 0.2],
        "confidence": True,
    }

    with pytest.raises(ValueError, match="JSON number"):
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

    low_order_candidate = replace(
        candidate,
        features=replace(candidate.features, reading_order_confidence=0.2),
    )
    unresolved = validate_visual_verification_response(
        _response(
            low_order_candidate,
            "UNRESOLVED",
            reading_order_ok=False,
            coverage_ok=False,
            unresolved_regions=[[0.1, 0.1, 0.2, 0.2]],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(low_order_candidate,),
    )
    resolution = resolve_visual_candidate(low_order_candidate, unresolved.pages[0])
    assert resolution.requires_full_ocr is True
    assert resolution.needs_review is True


def test_uncorroborated_model_reading_order_failure_stays_local_review():
    candidate = _candidate()
    unresolved = validate_visual_verification_response(
        _response(
            candidate,
            "UNRESOLVED",
            reading_order_ok=False,
            coverage_ok=True,
            unresolved_regions=[[0.1, 0.1, 0.2, 0.2]],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )

    resolution = resolve_visual_candidate(candidate, unresolved.pages[0])

    assert resolution.requires_full_ocr is False
    assert resolution.needs_review is True
    assert resolution.local_patch_block_ids == (candidate.blocks[0].block_id,)


def test_local_unresolved_region_is_reviewed_without_whole_page_ocr():
    candidate = _candidate()
    unresolved = validate_visual_verification_response(
        _response(
            candidate,
            "UNRESOLVED",
            unresolved_regions=[[0.1, 0.1, 0.9, 0.2]],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )

    resolution = resolve_visual_candidate(candidate, unresolved.pages[0])

    assert resolution.requires_full_ocr is False
    assert resolution.needs_review is True
    assert resolution.local_patch_block_ids == (candidate.blocks[0].block_id,)


def test_large_missing_area_still_requires_whole_page_ocr():
    candidate = _candidate()
    unresolved = validate_visual_verification_response(
        _response(
            candidate,
            "UNRESOLVED",
            coverage_ok=False,
            unresolved_regions=[[0.0, 0.0, 0.8, 0.8]],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )

    resolution = resolve_visual_candidate(candidate, unresolved.pages[0])

    assert resolution.requires_full_ocr is True
    assert resolution.needs_review is True
    assert resolution.local_patch_block_ids == ()


def test_model_full_ocr_misreport_for_known_local_block_is_fail_closed_locally():
    candidate = _candidate()
    local_finding = {
        "block_id": candidate.blocks[0].block_id,
        "issue_type": "MATH_MISMATCH",
        "severity": "HIGH",
        "replacement_latex": "",
        "evidence_region": [0.1, 0.1, 0.9, 0.2],
        "confidence": 0.99,
    }
    batch = validate_visual_verification_response(
        _response(
            candidate,
            "FULL_OCR_REQUIRED",
            block_findings=[local_finding],
        ),
        batch_id="ocr-verify-batch-test",
        candidates=(candidate,),
    )

    resolution = resolve_visual_candidate(candidate, batch.pages[0])

    assert resolution.requires_full_ocr is False
    assert resolution.needs_review is True
    assert resolution.local_patch_block_ids == (candidate.blocks[0].block_id,)
    assert resolution.candidate_tex == candidate.candidate_tex


def test_only_page_wide_host_validation_code_authorizes_full_ocr():
    candidate = _candidate()

    assert requires_full_page_ocr(
        candidate,
        validation_issue_codes=("UNBALANCED_BRACES",),
    ) is False
    assert requires_full_page_ocr(
        candidate,
        validation_issue_codes=("SEVERE_TEXT_COVERAGE_GAP",),
    ) is True


def test_frozen_scanned_or_unknown_strategy_authorizes_direct_full_ocr():
    candidate = _candidate()

    def classified(strategy: PageStrategy) -> PageClassification:
        return PageClassification(
            page_id=candidate.page_id,
            source_page_number=candidate.source_page_number,
            selected_index=candidate.selected_index,
            strategy=strategy,
            features=candidate.features,
            blocks=candidate.blocks,
            source_page_object_hash=candidate.source_page_object_hash,
            source_text_layer_sha256=candidate.source_text_layer_sha256,
            candidate_tex=candidate.candidate_tex,
        )

    assert classification_requires_full_page_ocr(
        classified(PageStrategy.BORN_DIGITAL_CLEAN)
    ) is False
    assert classification_requires_full_page_ocr(
        classified(PageStrategy.SCANNED)
    ) is True
    assert classification_requires_full_page_ocr(
        classified(PageStrategy.IMAGE_ONLY)
    ) is True
    assert classification_requires_full_page_ocr(
        classified(PageStrategy.UNKNOWN)
    ) is True


def test_scanned_page_evidence_requires_whole_page_ocr_even_on_pass():
    candidate = _candidate()
    scanned_features = PageFeatures(
        page_width=612,
        page_height=792,
        rotation=0,
        has_text_objects=False,
        text_character_count=0,
        printable_character_ratio=0,
        unicode_replacement_ratio=0,
        garbled_character_ratio=0,
        font_mapping_health=0,
        text_block_count=0,
        image_count=1,
        image_coverage_ratio=1,
        single_full_page_image=True,
        math_symbol_density=0,
        formula_region_count=0,
        double_column_likelihood=0,
        text_pixel_alignment_confidence=0,
        reading_order_confidence=0,
    )
    scanned = PageCandidate(
        page_id=candidate.page_id,
        source_page_number=candidate.source_page_number,
        selected_index=candidate.selected_index,
        features=scanned_features,
        blocks=candidate.blocks,
        source_page_object_hash=candidate.source_page_object_hash,
        source_text_layer_sha256=candidate.source_text_layer_sha256,
        candidate_tex=candidate.candidate_tex,
    )
    batch = validate_visual_verification_response(
        _response(scanned),
        batch_id="ocr-verify-batch-test",
        candidates=(scanned,),
    )

    resolution = resolve_visual_candidate(scanned, batch.pages[0])

    assert resolution.requires_full_ocr is True
    assert resolution.local_patch_block_ids == ()


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
        reading_order_ok=True,
        coverage_ok=True,
        block_findings=(
            validate_visual_verification_response(
                _response(
                    candidate,
                    "FULL_OCR_REQUIRED",
                    block_findings=[{
                        "block_id": candidate.blocks[0].block_id,
                        "issue_type": "MATH_MISMATCH",
                        "severity": "HIGH",
                        "replacement_latex": "",
                        "evidence_region": [0.1, 0.1, 0.9, 0.2],
                        "confidence": 1,
                    }],
                ),
                batch_id="ocr-verify-batch-test",
                candidates=(candidate,),
            ).pages[0].block_findings
        ),
    )
    resolved = resolve_visual_candidate(candidate, direct)
    assert resolved.requires_full_ocr is False
    assert resolved.needs_review is True
    assert resolved.local_patch_block_ids == (candidate.blocks[0].block_id,)

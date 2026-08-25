from __future__ import annotations

from dataclasses import replace
import json

import pytest

from latexstruct.core.ocr_evidence_correction import (
    EVIDENCE_CORRECTION_POLICY_SHA256,
    EvidenceCorrectionOperation,
    EvidenceCorrectionOperationStatus,
    EvidenceCorrectionStatus,
    IndependentEvidenceVerification,
    SourceEvidenceAuthorization,
    canonical_json_bytes,
    produce_evidence_corrected_baseline,
    sha256_text,
    verify_evidence_correction_report_bytes,
)


RAW_TEX = "% Page 1\nThe colur is blue.\n$x+1$\n"
SYNTAX_TEX = "% Page 1\nThe colur is blue.\n$x+1$\n"
PAGE_ID = "page-000001"
SOURCE_PAGE_SHA256 = sha256_text("immutable source PDF page 1")
SOURCE_EVIDENCE_SHA256 = sha256_text("whole-page source evidence")
CROP_SHA256 = sha256_text("source crop around colur")


def _operation(
    *,
    syntax: str = SYNTAX_TEX,
    old_text: str = "colur",
    new_text: str = "colour",
    start_offset: int | None = None,
    end_offset: int | None = None,
    operation_id: str = "correct-colour",
    source_evidence_sha256: str = SOURCE_EVIDENCE_SHA256,
    crop_sha256: str = CROP_SHA256,
) -> EvidenceCorrectionOperation:
    start = syntax.index(old_text) if start_offset is None else start_offset
    end = start + len(old_text) if end_offset is None else end_offset
    return EvidenceCorrectionOperation(
        operation_id=operation_id,
        syntax_baseline_sha256=sha256_text(syntax),
        page_id=PAGE_ID,
        source_page_number=1,
        start_offset=start,
        end_offset=end,
        old_text=old_text,
        new_text=new_text,
        reason="source crop resolves the OCR spelling error exactly",
        source_page_sha256=SOURCE_PAGE_SHA256,
        source_evidence_sha256=source_evidence_sha256,
        crop_sha256=crop_sha256,
        recognition_model="gpt-test-vision",
    )


def _authorization(
    operation: EvidenceCorrectionOperation,
    *,
    syntax: str = SYNTAX_TEX,
    authorized: bool = True,
    crop_authorized: bool = True,
) -> SourceEvidenceAuthorization:
    return SourceEvidenceAuthorization(
        syntax_baseline_sha256=sha256_text(syntax),
        page_id=PAGE_ID,
        source_page_number=1,
        syntax_start_offset=0,
        syntax_end_offset=len(syntax),
        syntax_region_sha256=sha256_text(syntax),
        source_page_sha256=SOURCE_PAGE_SHA256,
        source_evidence_sha256=SOURCE_EVIDENCE_SHA256,
        authorized_operation_sha256s=((operation.digest,) if authorized else ()),
        authorized_crop_sha256s=((CROP_SHA256,) if crop_authorized else ()),
    )


def _verification(
    operation: EvidenceCorrectionOperation,
    **changes: object,
) -> IndependentEvidenceVerification:
    values = {
        "operation_sha256": operation.digest,
        "source_evidence_sha256": operation.source_evidence_sha256,
        "old_text_sha256": sha256_text(operation.old_text),
        "new_text_sha256": sha256_text(operation.new_text),
        "verification_evidence_sha256": sha256_text(
            f"independent verification:{operation.digest}"
        ),
        "verifier": "independent-host-check-02",
        "verdict": "PASS",
        "independent": True,
        "math_unchanged": True,
        "structure_unchanged": True,
        "notes": "whole page and crop agree with the replacement",
    }
    values.update(changes)
    return IndependentEvidenceVerification(**values)  # type: ignore[arg-type]


def _produce(
    operation: EvidenceCorrectionOperation,
    *,
    syntax: str = SYNTAX_TEX,
    authorization: SourceEvidenceAuthorization | None = None,
    verification: IndependentEvidenceVerification | None = None,
):
    return produce_evidence_corrected_baseline(
        raw_ocr_tex=RAW_TEX,
        syntax_baseline_tex=syntax,
        operations=(operation,),
        source_authorizations=(
            authorization if authorization is not None else _authorization(
                operation,
                syntax=syntax,
            ),
        ),
        independent_verifications=(
            verification if verification is not None else _verification(operation),
        ),
    )


def test_no_operations_is_not_applicable_and_does_not_emit_duplicate_tex() -> None:
    result = produce_evidence_corrected_baseline(
        raw_ocr_tex=RAW_TEX,
        syntax_baseline_tex=SYNTAX_TEX,
    )

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.NOT_APPLICABLE
    assert result.report.selected_baseline_role == "SYNTAX_BASELINE_TEX"
    assert result.report.applied_operation_count == 0
    assert result.report.failure_reasons == ()
    assert result.report.raw_ocr_sha256 == sha256_text(RAW_TEX)
    assert result.report.syntax_baseline_sha256 == sha256_text(SYNTAX_TEX)
    serialized = json.loads(result.report.canonical_json_bytes())
    assert serialized["report_sha256"] == result.report.digest
    assert serialized["policy_sha256"] == EVIDENCE_CORRECTION_POLICY_SHA256
    assert EVIDENCE_CORRECTION_POLICY_SHA256 == (
        "c7179f504d046c5671cbe56b37468354e97729da83557f0769ab2ee3a5eb641e"
    )


def test_authorized_text_correction_emits_bound_evidence_tex_and_audit() -> None:
    operation = _operation()

    result = _produce(operation)

    assert result.evidence_tex == "% Page 1\nThe colour is blue.\n$x+1$\n"
    assert result.report.status is EvidenceCorrectionStatus.PASS
    assert result.report.selected_baseline_role == "EVIDENCE_CORRECTED_BASELINE_TEX"
    assert result.report.evidence_tex_sha256 == sha256_text(result.evidence_tex)
    assert result.report.applied_operation_count == 1
    audit = result.report.operation_audits[0]
    assert audit.status is EvidenceCorrectionOperationStatus.APPLIED
    assert audit.operation.old_text == "colur"
    assert audit.operation.new_text == "colour"
    assert audit.operation.page_id == PAGE_ID
    assert audit.operation.crop_sha256 == CROP_SHA256
    assert audit.authorization_sha256 == _authorization(operation).digest
    assert audit.independent_verification == _verification(operation)
    # Pure producer: both exact input values remain the bound originals.
    assert result.report.raw_ocr_sha256 == sha256_text(RAW_TEX)
    assert result.report.syntax_baseline_sha256 == sha256_text(SYNTAX_TEX)


def test_multiple_authorized_operations_are_order_independent_and_deterministic() -> None:
    first = _operation()
    blue_start = SYNTAX_TEX.index("blue")
    second = _operation(
        old_text="blue",
        new_text="azure",
        start_offset=blue_start,
        end_offset=blue_start + len("blue"),
        operation_id="correct-blue",
        crop_sha256="",
    )
    authorization = replace(
        _authorization(first),
        authorized_operation_sha256s=(second.digest, first.digest),
    )
    verifications = (_verification(second), _verification(first))

    forward = produce_evidence_corrected_baseline(
        raw_ocr_tex=RAW_TEX,
        syntax_baseline_tex=SYNTAX_TEX,
        operations=(first, second),
        source_authorizations=(authorization,),
        independent_verifications=verifications,
    )
    reversed_input = produce_evidence_corrected_baseline(
        raw_ocr_tex=RAW_TEX,
        syntax_baseline_tex=SYNTAX_TEX,
        operations=(second, first),
        source_authorizations=(authorization,),
        independent_verifications=tuple(reversed(verifications)),
    )

    assert forward.evidence_tex == "% Page 1\nThe colour is azure.\n$x+1$\n"
    assert reversed_input.evidence_tex == forward.evidence_tex
    assert reversed_input.report.digest == forward.report.digest
    assert [
        audit.operation.operation_id for audit in forward.report.operation_audits
    ] == ["correct-colour", "correct-blue"]


def test_tampered_new_text_is_rejected_by_exact_operation_authorization() -> None:
    authorized_operation = _operation()
    authorization = _authorization(authorized_operation)
    verification = _verification(authorized_operation)
    tampered = replace(authorized_operation, new_text="green")

    result = _produce(
        tampered,
        authorization=authorization,
        verification=verification,
    )

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.FAILED
    assert "OPERATION_NOT_AUTHORIZED" in result.report.failure_reasons
    assert "INDEPENDENT_VERIFICATION_MISSING" in result.report.failure_reasons


def test_out_of_bounds_replacement_is_rejected_even_when_digest_is_authorized() -> None:
    operation = _operation(start_offset=len(SYNTAX_TEX) + 1, end_offset=len(SYNTAX_TEX) + 6)
    authorization = _authorization(operation)

    result = _produce(operation, authorization=authorization)

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.FAILED
    assert "OPERATION_RANGE_OUT_OF_BOUNDS" in result.report.failure_reasons
    assert result.report.applied_operation_count == 0


def test_operation_absent_from_source_authority_is_rejected() -> None:
    operation = _operation()
    authorization = _authorization(operation, authorized=False)

    result = _produce(operation, authorization=authorization)

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.FAILED
    assert result.report.operation_audits[0].status is (
        EvidenceCorrectionOperationStatus.REJECTED
    )
    assert "OPERATION_NOT_AUTHORIZED" in result.report.failure_reasons


def test_unbound_crop_is_rejected() -> None:
    operation = _operation()
    authorization = _authorization(operation, crop_authorized=False)

    result = _produce(operation, authorization=authorization)

    assert result.evidence_tex is None
    assert "CROP_NOT_AUTHORIZED" in result.report.failure_reasons


def test_math_rewrite_is_rejected_despite_authorization_and_claimed_pass() -> None:
    start = SYNTAX_TEX.index("x+1")
    operation = _operation(
        old_text="x+1",
        new_text="x+2",
        start_offset=start,
        end_offset=start + 3,
        operation_id="rewrite-equation",
        crop_sha256="",
    )
    authorization = _authorization(operation, crop_authorized=False)

    result = _produce(operation, authorization=authorization)

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.FAILED
    assert "MATH_REWRITE_FORBIDDEN" in result.report.failure_reasons


def test_structure_inference_is_rejected() -> None:
    syntax = "Heading\nPlain text.\n"
    operation = _operation(
        syntax=syntax,
        old_text="Heading",
        new_text=r"\section{Heading}",
        operation_id="invent-section",
        crop_sha256="",
    )
    authorization = _authorization(
        operation,
        syntax=syntax,
        crop_authorized=False,
    )

    result = _produce(operation, syntax=syntax, authorization=authorization)

    assert result.evidence_tex is None
    assert "STRUCTURAL_REWRITE_FORBIDDEN" in result.report.failure_reasons


@pytest.mark.parametrize(
    ("verification_changes", "expected_reason"),
    (
        ({"verdict": "FAIL"}, "INDEPENDENT_VERIFICATION_NOT_PASS"),
        ({"independent": False}, "VERIFICATION_NOT_INDEPENDENT"),
        ({"math_unchanged": False}, "VERIFICATION_MATH_CHANGE"),
        ({"structure_unchanged": False}, "VERIFICATION_STRUCTURE_CHANGE"),
    ),
)
def test_independent_verification_must_be_an_exact_pass(
    verification_changes: dict[str, object],
    expected_reason: str,
) -> None:
    operation = _operation()
    result = _produce(
        operation,
        verification=_verification(operation, **verification_changes),
    )

    assert result.evidence_tex is None
    assert expected_reason in result.report.failure_reasons


def test_no_effect_operation_is_failed_not_misreported_as_not_applicable() -> None:
    operation = _operation(new_text="colur")

    result = _produce(operation)

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.FAILED
    assert "NO_EFFECT_OPERATION" in result.report.failure_reasons


def test_one_invalid_operation_aborts_other_valid_operations_atomically() -> None:
    first = _operation()
    start = SYNTAX_TEX.index("blue")
    second = _operation(
        old_text="blue",
        new_text="azure",
        start_offset=start,
        end_offset=start + 4,
        operation_id="unauthorized-blue-change",
        crop_sha256="",
    )
    authorization = replace(
        _authorization(first),
        authorized_operation_sha256s=(first.digest,),
    )

    result = produce_evidence_corrected_baseline(
        raw_ocr_tex=RAW_TEX,
        syntax_baseline_tex=SYNTAX_TEX,
        operations=(second, first),
        source_authorizations=(authorization,),
        independent_verifications=(_verification(first), _verification(second)),
    )

    assert result.evidence_tex is None
    assert result.report.status is EvidenceCorrectionStatus.FAILED
    by_id = {
        audit.operation.operation_id: audit for audit in result.report.operation_audits
    }
    assert by_id[first.operation_id].status is (
        EvidenceCorrectionOperationStatus.NOT_APPLIED
    )
    assert by_id[first.operation_id].reason_codes == ("ATOMIC_BATCH_ABORT",)
    assert by_id[second.operation_id].status is (
        EvidenceCorrectionOperationStatus.REJECTED
    )
    assert "OPERATION_NOT_AUTHORIZED" in by_id[second.operation_id].reason_codes


def test_serialized_pass_report_is_recomputed_and_rejects_semantic_tamper() -> None:
    result = _produce(_operation())
    assert result.evidence_tex is not None

    verified = verify_evidence_correction_report_bytes(
        result.report.canonical_json_bytes(),
        raw_ocr_tex=RAW_TEX,
        syntax_baseline_tex=SYNTAX_TEX,
        evidence_tex=result.evidence_tex,
    )
    assert verified["status"] == "PASS"

    tampered = json.loads(result.report.canonical_json_bytes())
    tampered["operations"][0]["reason_codes"] = ["FABRICATED_PASS_REASON"]
    body = {key: value for key, value in tampered.items() if key != "report_sha256"}
    tampered["report_sha256"] = sha256_text(
        canonical_json_bytes(body).decode("utf-8")
    )
    with pytest.raises(ValueError, match="producer-recomputable"):
        verify_evidence_correction_report_bytes(
            canonical_json_bytes(tampered),
            raw_ocr_tex=RAW_TEX,
            syntax_baseline_tex=SYNTAX_TEX,
            evidence_tex=result.evidence_tex,
        )

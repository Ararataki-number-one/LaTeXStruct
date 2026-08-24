import hashlib
import json
from pathlib import Path

import pytest

from latexstruct.core.ocr_recovery import (
    AttemptOutcome,
    OcrRecoveryEvidenceStore,
    RECOVERY_LEVELS,
    RecoveryEvidenceError,
    RecoveryImageInput,
    RecoveryImageRole,
    RecoveryPageStatus,
    RecoveryStage,
    next_stage,
    second_read_status,
)


RUN_ID = "a" * 32
PAGE_ID = "ocr-page-000001"
TEX_HASH = hashlib.sha256(b"faithful page tex").hexdigest()
OTHER_TEX_HASH = hashlib.sha256(b"different page tex").hexdigest()


def _full_image(content: bytes, dpi: int) -> RecoveryImageInput:
    return RecoveryImageInput(
        role=RecoveryImageRole.FULL_PAGE,
        content=content,
        dpi=dpi,
        width_pixels=1200,
        height_pixels=1800,
    )


def _crop_image(content: bytes, full_content: bytes, dpi: int) -> RecoveryImageInput:
    return RecoveryImageInput(
        role=RecoveryImageRole.CROP,
        content=content,
        dpi=dpi,
        width_pixels=360,
        height_pixels=220,
        crop_id="formula-01",
        bbox_pixels=(320, 520, 680, 740),
        source_image_sha256=hashlib.sha256(full_content).hexdigest(),
        region_type="display_formula",
    )


def _append(
    store: OcrRecoveryEvidenceStore,
    *,
    stage: RecoveryStage,
    outcome: AttemptOutcome,
    dpi: int,
    sequence: int,
    full_content: bytes,
    tex_sha256: str = "",
    comparison_tex_sha256: str = "",
    batched: bool = False,
    with_crop: bool = False,
    context_id: str | None = None,
):
    images = [_full_image(full_content, dpi)]
    if with_crop:
        images.append(_crop_image(b"formula crop", full_content, dpi))
    is_failure = outcome in {
        AttemptOutcome.RETRYABLE_FAILURE,
        AttemptOutcome.PAUSED,
        AttemptOutcome.FAILED,
    }
    return store.record_attempt(
        run_id=RUN_ID,
        page_id=PAGE_ID,
        source_page=17,
        task_index=1,
        stage=stage,
        outcome=outcome,
        base_dpi=200,
        dpi=dpi,
        model="vision-model",
        backend="codex-cli",
        model_context_id=context_id or f"context-{sequence}",
        images=images,
        raw_response=json.dumps({"attempt": sequence, "page_id": PAGE_ID}),
        duration_ms=sequence * 10,
        usage={"input_tokens": sequence, "output_tokens": sequence * 2},
        error={"code": "quality", "attempt": sequence} if is_failure else None,
        tex_sha256=tex_sha256,
        comparison_tex_sha256=comparison_tex_sha256,
        is_batched=batched,
        batch_id=f"batch-{sequence}" if batched else "",
        batch_size=3 if batched else 1,
        quality_issue_codes=("formula_missing",) if is_failure else (),
        started_at=f"2026-08-24T00:00:{sequence:02d}.000Z",
        ended_at=f"2026-08-24T00:00:{sequence:02d}.010Z",
        attempt_id=f"attempt{sequence:02d}",
    )


def _drive_to_second_read(
    store: OcrRecoveryEvidenceStore,
    *,
    second_tex_sha256: str,
    comparison_tex_sha256: str = TEX_HASH,
):
    _append(
        store,
        stage=RecoveryStage.INITIAL_READ,
        outcome=AttemptOutcome.RETRYABLE_FAILURE,
        dpi=200,
        sequence=1,
        full_content=b"page-200",
        batched=True,
    )
    _append(
        store,
        stage=RecoveryStage.SAME_DPI_RETRY,
        outcome=AttemptOutcome.RETRYABLE_FAILURE,
        dpi=200,
        sequence=2,
        full_content=b"page-200",
        batched=True,
    )
    _append(
        store,
        stage=RecoveryStage.BATCH_TO_SINGLE,
        outcome=AttemptOutcome.RETRYABLE_FAILURE,
        dpi=200,
        sequence=3,
        full_content=b"page-200",
    )
    _append(
        store,
        stage=RecoveryStage.DPI_300_RETRY,
        outcome=AttemptOutcome.RETRYABLE_FAILURE,
        dpi=300,
        sequence=4,
        full_content=b"page-300",
    )
    _append(
        store,
        stage=RecoveryStage.PAGE_WITH_CROPS,
        outcome=AttemptOutcome.RETRYABLE_FAILURE,
        dpi=300,
        sequence=5,
        full_content=b"page-300",
        with_crop=True,
    )
    return _append(
        store,
        stage=RecoveryStage.INDEPENDENT_SECOND_READ,
        outcome=AttemptOutcome.PASSED,
        dpi=300,
        sequence=6,
        full_content=b"page-300-independent",
        tex_sha256=second_tex_sha256,
        comparison_tex_sha256=comparison_tex_sha256,
        context_id="independent-context",
    )


def test_next_stage_is_the_host_owned_five_level_ladder():
    current = RecoveryStage.INITIAL_READ
    observed = []
    while True:
        current = next_stage(current)
        if current is None:
            break
        observed.append(current)

    assert tuple(observed) == RECOVERY_LEVELS
    assert next_stage(None) is RecoveryStage.INITIAL_READ
    assert (
        next_stage(
            RecoveryStage.SAME_DPI_RETRY,
            source_was_batched=False,
        )
        is RecoveryStage.DPI_300_RETRY
    )
    assert (
        next_stage(
            RecoveryStage.DPI_300_RETRY,
            crops_available=False,
        )
        is RecoveryStage.INDEPENDENT_SECOND_READ
    )
    assert (
        next_stage(
            RecoveryStage.DPI_300_RETRY,
            crops_available=False,
            independent_second_read=False,
        )
        is None
    )


def test_all_attempt_evidence_is_hashed_chained_summarized_and_recoverable(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    final = _drive_to_second_read(store, second_tex_sha256=TEX_HASH)

    attempts, state = store.recover_page(RUN_ID, PAGE_ID)
    assert state.status is RecoveryPageStatus.SUCCESS
    assert state.attempt_count == 6
    assert state.retry_count == 5
    assert state.next_stage is None
    assert [item.stage for item in attempts] == [
        RecoveryStage.INITIAL_READ,
        *RECOVERY_LEVELS,
    ]
    assert attempts[0].previous_attempt_sha256 == ""
    assert all(
        attempts[index].previous_attempt_sha256 == attempts[index - 1].record_sha256
        for index in range(1, len(attempts))
    )
    assert all(item.images[0].blob.sha256 for item in attempts)
    assert all(item.response and item.response.sha256 for item in attempts)
    assert all(item.usage_sha256 and item.duration_sha256 for item in attempts)
    assert all(item.error_sha256 for item in attempts[:-1])
    assert final.model_context_id == "independent-context"

    summary = store.read_terminal_summary(RUN_ID, PAGE_ID)
    assert summary.status is RecoveryPageStatus.SUCCESS
    assert summary.attempt_count == 6
    assert summary.retry_count == 5
    assert summary.total_duration_ms == 210
    assert summary.usage_totals == {"input_tokens": 21, "output_tokens": 42}
    assert summary.batch_call_count == 2
    assert summary.batch_to_single_count == 1
    assert summary.crop_call_count == 1
    assert summary.independent_read_count == 1
    assert summary.stage_counts[RecoveryStage.PAGE_WITH_CROPS.value] == 1
    assert summary.dpi_counts == {"200": 3, "300": 3}
    assert summary.final_tex_sha256 == TEX_HASH
    assert len(summary.summary_sha256) == 64

    page_dir = tmp_path / "recovery" / RUN_ID / "pages" / PAGE_ID
    journal_before = {item.name: item.read_bytes() for item in (page_dir / "attempts").iterdir()}
    (page_dir / "state.json").unlink()
    (page_dir / "terminal-summary.json").unlink()

    recovered_attempts, recovered_state = store.recover_page(RUN_ID, PAGE_ID)
    assert recovered_state == state
    assert tuple(item.record_sha256 for item in recovered_attempts) == tuple(
        item.record_sha256 for item in attempts
    )
    assert (page_dir / "state.json").is_file()
    assert (page_dir / "terminal-summary.json").is_file()
    assert journal_before == {
        item.name: item.read_bytes() for item in (page_dir / "attempts").iterdir()
    }


def test_independent_second_read_conflict_is_never_promoted_to_success(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    _drive_to_second_read(store, second_tex_sha256=OTHER_TEX_HASH)

    _, state = store.recover_page(RUN_ID, PAGE_ID)
    summary = store.read_terminal_summary(RUN_ID, PAGE_ID)
    assert second_read_status(TEX_HASH, OTHER_TEX_HASH) is RecoveryPageStatus.NEEDS_REVIEW
    assert state.status is RecoveryPageStatus.NEEDS_REVIEW
    assert state.conflict_detected is True
    assert state.recoverable is False
    assert summary.status is RecoveryPageStatus.NEEDS_REVIEW


def test_valid_response_with_unresolved_review_is_recorded_honestly(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    _append(
        store,
        stage=RecoveryStage.INITIAL_READ,
        outcome=AttemptOutcome.NEEDS_REVIEW,
        dpi=200,
        sequence=1,
        full_content=b"page-review",
        tex_sha256=TEX_HASH,
    )

    _, state = store.recover_page(RUN_ID, PAGE_ID)
    assert state.status is RecoveryPageStatus.NEEDS_REVIEW
    assert state.recoverable is False


def test_independent_read_must_use_a_new_model_context(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    for sequence, (stage, dpi, batched, crop) in enumerate(
        [
            (RecoveryStage.INITIAL_READ, 200, True, False),
            (RecoveryStage.SAME_DPI_RETRY, 200, True, False),
            (RecoveryStage.BATCH_TO_SINGLE, 200, False, False),
            (RecoveryStage.DPI_300_RETRY, 300, False, False),
            (RecoveryStage.PAGE_WITH_CROPS, 300, False, True),
        ],
        1,
    ):
        _append(
            store,
            stage=stage,
            outcome=AttemptOutcome.RETRYABLE_FAILURE,
            dpi=dpi,
            sequence=sequence,
            full_content=b"page-300" if dpi == 300 else b"page-200",
            batched=batched,
            with_crop=crop,
            context_id="reused-context" if sequence == 1 else f"context-{sequence}",
        )

    with pytest.raises(RecoveryEvidenceError, match="reused a previous model context"):
        _append(
            store,
            stage=RecoveryStage.INDEPENDENT_SECOND_READ,
            outcome=AttemptOutcome.PASSED,
            dpi=300,
            sequence=6,
            full_content=b"independent",
            tex_sha256=TEX_HASH,
            comparison_tex_sha256=TEX_HASH,
            context_id="reused-context",
        )


def test_paused_attempt_resumes_the_same_stage_without_overwriting_evidence(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    first = _append(
        store,
        stage=RecoveryStage.INITIAL_READ,
        outcome=AttemptOutcome.PAUSED,
        dpi=200,
        sequence=1,
        full_content=b"page",
    )
    _, paused = store.recover_page(RUN_ID, PAGE_ID)
    assert paused.status is RecoveryPageStatus.PAUSED
    assert paused.next_stage is RecoveryStage.INITIAL_READ

    second = _append(
        store,
        stage=RecoveryStage.INITIAL_READ,
        outcome=AttemptOutcome.PASSED,
        dpi=200,
        sequence=2,
        full_content=b"page",
        tex_sha256=TEX_HASH,
    )
    attempts, completed = store.recover_page(RUN_ID, PAGE_ID)
    assert completed.status is RecoveryPageStatus.SUCCESS
    assert completed.retry_count == 1
    assert attempts[0].record_sha256 == first.record_sha256
    assert attempts[1].previous_attempt_sha256 == first.record_sha256
    assert second.record_sha256 != first.record_sha256


def test_illegal_stage_skip_and_crop_without_binding_are_rejected(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    with pytest.raises(RecoveryEvidenceError, match="illegal recovery stage append"):
        _append(
            store,
            stage=RecoveryStage.DPI_300_RETRY,
            outcome=AttemptOutcome.PASSED,
            dpi=300,
            sequence=1,
            full_content=b"page",
            tex_sha256=TEX_HASH,
        )

    bad_crop = RecoveryImageInput(
        role=RecoveryImageRole.CROP,
        content=b"crop",
        dpi=300,
        width_pixels=100,
        height_pixels=100,
        crop_id="formula",
        bbox_pixels=(0, 0, 100, 100),
        source_image_sha256=hashlib.sha256(b"some other page").hexdigest(),
        region_type="formula",
    )
    with pytest.raises(ValueError, match="hash-bound"):
        from latexstruct.core.ocr_recovery import (
            EvidenceBlob,
            RecoveryAttempt,
            RecoveryImageEvidence,
        )

        page_blob = EvidenceBlob("1" * 64, 4, "image/png", "blobs/11/" + "1" * 64)
        crop_blob = EvidenceBlob("2" * 64, 4, "image/png", "blobs/22/" + "2" * 64)
        RecoveryAttempt(
            run_id=RUN_ID,
            page_id=PAGE_ID,
            source_page=1,
            task_index=1,
            attempt_id="attempt01",
            sequence=1,
            stage=RecoveryStage.PAGE_WITH_CROPS,
            outcome=AttemptOutcome.RETRYABLE_FAILURE,
            base_dpi=200,
            dpi=300,
            model="vision",
            backend="api",
            model_context_id="context",
            images=(
                RecoveryImageEvidence(RecoveryImageRole.FULL_PAGE, page_blob, 300, 1000, 1600),
                RecoveryImageEvidence(
                    RecoveryImageRole.CROP,
                    crop_blob,
                    300,
                    100,
                    100,
                    crop_id=bad_crop.crop_id,
                    bbox_pixels=bad_crop.bbox_pixels,
                    source_image_sha256=bad_crop.source_image_sha256,
                    region_type=bad_crop.region_type,
                ),
            ),
            response=None,
            started_at="2026-08-24T00:00:00.000Z",
            ended_at="2026-08-24T00:00:01.000Z",
            duration_ms=1000,
            duration_sha256="",
            error={"code": "quality"},
        )


def test_recovery_detects_tampered_content_addressed_blob(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    attempt = _append(
        store,
        stage=RecoveryStage.INITIAL_READ,
        outcome=AttemptOutcome.PASSED,
        dpi=200,
        sequence=1,
        full_content=b"page",
        tex_sha256=TEX_HASH,
    )
    assert attempt.response is not None
    blob_path = tmp_path / "recovery" / RUN_ID / Path(attempt.response.storage_key)
    blob_path.write_bytes(b"tampered")

    with pytest.raises(RecoveryEvidenceError, match="blob hash failed"):
        store.recover_page(RUN_ID, PAGE_ID)


def test_recovery_detects_a_tampered_or_non_contiguous_journal(tmp_path):
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    attempt = _append(
        store,
        stage=RecoveryStage.INITIAL_READ,
        outcome=AttemptOutcome.RETRYABLE_FAILURE,
        dpi=200,
        sequence=1,
        full_content=b"page",
    )
    page_dir = tmp_path / "recovery" / RUN_ID / "pages" / PAGE_ID / "attempts"
    journal = next(page_dir.iterdir())
    payload = json.loads(journal.read_text(encoding="utf-8"))
    payload["duration_ms"] = 99999
    journal.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RecoveryEvidenceError, match="invalid recovery attempt journal"):
        store.recover_page(RUN_ID, PAGE_ID)
    assert len(attempt.record_sha256) == 64

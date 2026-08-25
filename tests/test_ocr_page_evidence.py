from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from latexstruct.core.ocr_page_evidence import (
    CoverageCheck,
    FinalPageStatus,
    PageCoverageFacts,
    PageCoverageRecord,
    PageEvidenceConflictError,
    PageEvidenceError,
    PageEvidenceIntegrityError,
    PageEvidenceStore,
    VisualMode,
    build_page_coverage_record,
    build_page_summaries,
    verify_page_summaries,
)
from latexstruct.core.ocr_schema import (
    PageBlock,
    PageBlockType,
    PageCandidate,
    PageFeatures,
)
from latexstruct.core.ocr_visual import PageVisualVerification, VisualVerdict


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _candidate(selected_index: int = 1, source_page: int = 7) -> PageCandidate:
    page_id = f"ocr-page-{selected_index:06d}"
    block_hash = _sha(f"block-{selected_index}".encode())
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
        text_pixel_alignment_confidence=0.99,
        reading_order_confidence=0.99,
    )
    block = PageBlock(
        block_id=f"{page_id}-block-0001-{block_hash[:12]}",
        block_type=PageBlockType.DISPLAY_MATH,
        bbox=(72, 100, 540, 140),
        reading_order=1,
        plain_text="x ≤ y",
        style_features={},
        math_likelihood=0.9,
        source_object_hash=block_hash,
        candidate_latex="x \\le y",
    )
    return PageCandidate(
        page_id=page_id,
        source_page_number=source_page,
        selected_index=selected_index,
        features=features,
        blocks=(block,),
        source_page_object_hash=_sha(f"page-{source_page}".encode()),
        source_text_layer_sha256=_sha(f"text-{source_page}".encode()),
        candidate_tex="x \\le y",
    )


def _verification(candidate: PageCandidate) -> PageVisualVerification:
    return PageVisualVerification(
        page_id=candidate.page_id,
        verdict=VisualVerdict.PASS,
        reading_order_ok=True,
        coverage_ok=True,
    )


def _store(tmp_path, source_sha: str) -> PageEvidenceStore:
    return PageEvidenceStore(tmp_path, "a" * 32, source_sha)


def _persisted_success(store: PageEvidenceStore, candidate: PageCandidate):
    verification = _verification(candidate)
    tex = candidate.candidate_tex
    store.persist_page_bundle(
        candidate,
        verification=verification,
        raw_response={"page_id": candidate.page_id, "verdict": "PASS"},
        page_tex=tex,
    )
    facts = PageCoverageFacts(
        source_sha256=store.source_sha256,
        source_page_object_hash=candidate.source_page_object_hash,
        final_page_tex=tex,
        final_status=FinalPageStatus.SUCCESS,
        verification=verification,
        syntax_checked=True,
    )
    return store.build_coverage_record(candidate, facts)


def test_empty_page_record_never_counts_as_completed():
    record = PageCoverageRecord(
        page_id="ocr-page-000001",
        source_page_number=7,
        source_sha256=_sha(b"source"),
        source_page_object_hash=_sha(b"page"),
    )

    assert record.completed is False
    assert record.evidence_complete is False
    assert set(record.checks.to_dict().values()) == {CoverageCheck.FAIL.value}


def test_store_builds_all_pass_verifier_coverage(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)

    record = _persisted_success(store, candidate)

    assert record.completed is True
    assert record.visual_mode is VisualMode.VERIFIER
    assert record.final_status is FinalPageStatus.SUCCESS
    assert record.checks.all_pass
    assert set(record.artifact_hashes) == {
        "source.json",
        "candidate.json",
        "verification.json",
        "raw-response.json",
        "page.tex",
    }


def test_success_rejects_unresolved_regions(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    verification = _verification(candidate)
    store.persist_page_bundle(
        candidate,
        verification=verification,
        raw_response={"page_id": candidate.page_id},
        page_tex=candidate.candidate_tex,
    )
    facts = PageCoverageFacts(
        source_sha256=source_sha,
        source_page_object_hash=candidate.source_page_object_hash,
        final_page_tex=candidate.candidate_tex,
        final_status=FinalPageStatus.SUCCESS,
        verification=verification,
        syntax_checked=True,
        unresolved_regions=({"reason": "formula uncertain"},),
    )

    with pytest.raises(ValueError, match="SUCCESS.*unresolved"):
        store.build_coverage_record(candidate, facts)


def test_needs_review_is_completed_only_with_all_evidence(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    verification = _verification(candidate)
    store.persist_page_bundle(
        candidate,
        verification=verification,
        raw_response={"page_id": candidate.page_id},
        page_tex=candidate.candidate_tex,
    )
    record = store.build_coverage_record(
        candidate,
        PageCoverageFacts(
            source_sha256=source_sha,
            source_page_object_hash=candidate.source_page_object_hash,
            final_page_tex=candidate.candidate_tex,
            final_status=FinalPageStatus.NEEDS_REVIEW,
            verification=verification,
            syntax_checked=True,
            unresolved_regions=({"reason": "low-confidence glyph"},),
        ),
    )

    assert record.completed is True
    assert record.checks.all_pass
    assert len(record.unresolved_region_hashes) == 1
    bundle = build_page_summaries(
        [record],
        run_id=store.run_id,
        source_sha256=source_sha,
        expected_source_pages=[7],
    )
    assert bundle.coverage["completed"] == 1
    assert bundle.coverage["needs_review"] == 1
    assert bundle.coverage["unresolved_pages"] == 1


def test_full_ocr_facts_select_visual_mode_and_fail_closed_check(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    full_tex = "full visual OCR"
    store.persist_page_bundle(
        candidate,
        verification={"page_id": candidate.page_id, "mode": "FULL_OCR"},
        raw_response={"page_id": candidate.page_id, "latex": full_tex},
        page_tex=full_tex,
    )
    record = store.build_coverage_record(
        candidate,
        PageCoverageFacts(
            source_sha256=source_sha,
            source_page_object_hash=candidate.source_page_object_hash,
            final_page_tex=full_tex,
            final_status=FinalPageStatus.NEEDS_REVIEW,
            full_ocr_performed=True,
            full_ocr_with_crops=True,
            full_ocr_reading_order_checked=True,
            full_ocr_text_coverage_checked=True,
            full_ocr_math_region_coverage_checked=False,
            syntax_checked=True,
        ),
    )

    assert record.visual_mode is VisualMode.FULL_OCR_WITH_CROPS
    assert record.checks.math_region_coverage_checked is CoverageCheck.FAIL
    assert record.completed is False


def test_coverage_rejects_cross_page_visual_evidence(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate(1, 7)
    other_verification = _verification(_candidate(2, 9))
    facts = PageCoverageFacts(
        source_sha256=source_sha,
        source_page_object_hash=candidate.source_page_object_hash,
        final_page_tex=candidate.candidate_tex,
        final_status=FinalPageStatus.NEEDS_REVIEW,
        verification=other_verification,
        syntax_checked=True,
    )

    with pytest.raises(ValueError, match="page_id mismatch"):
        build_page_coverage_record(
            candidate,
            facts,
            expected_source_sha256=source_sha,
        )


def test_append_only_same_name_is_idempotent_but_rejects_different_bytes(tmp_path):
    store = _store(tmp_path, _sha(b"source"))
    page_id = "ocr-page-000001"

    first = store.write_artifact(page_id, "page.tex", b"same")
    second = store.write_artifact(page_id, "page.tex", b"same")

    assert first.sha256 == second.sha256
    with pytest.raises(PageEvidenceConflictError, match="different bytes"):
        store.write_artifact(page_id, "page.tex", b"different")
    assert first.path.read_bytes() == b"same"


def test_concurrent_same_name_conflict_never_overwrites(tmp_path):
    store = _store(tmp_path, _sha(b"source"))
    page_id = "ocr-page-000001"

    def write(payload: bytes):
        try:
            return store.write_artifact(page_id, "page.tex", payload).sha256
        except PageEvidenceConflictError:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, (b"alpha", b"beta")))

    assert results.count("CONFLICT") == 1
    assert (store.page_dir(page_id) / "page.tex").read_bytes() in {b"alpha", b"beta"}


@pytest.mark.parametrize(
    ("page_id", "name"),
    [
        ("ocr-page-000001", "../outside.json"),
        ("ocr-page-000001", "retries/../../outside.json"),
        ("../escape", "page.tex"),
    ],
)
def test_store_rejects_path_escape(page_id, name, tmp_path):
    store = _store(tmp_path, _sha(b"source"))

    with pytest.raises((PageEvidenceError, ValueError)):
        store.write_artifact(page_id, name, b"no")
    assert not (tmp_path / "outside.json").exists()


def test_tamper_is_detected_by_page_and_summary_verification(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    record = _persisted_success(store, candidate)
    store.persist_summaries([record], expected_source_pages=[7])
    store.verify_summaries(expected_source_pages=[7])

    (store.page_dir(candidate.page_id) / "raw-response.json").write_text(
        '{"tampered":true}\n', encoding="utf-8"
    )

    with pytest.raises(PageEvidenceIntegrityError, match="artifact binding"):
        store.verify_page_artifacts(candidate.page_id)
    with pytest.raises(PageEvidenceIntegrityError):
        store.verify_summaries(expected_source_pages=[7])


def test_retry_bundle_is_append_only_hash_bound_and_tamper_evident(tmp_path):
    store = _store(tmp_path, _sha(b"source"))
    page_id = "ocr-page-000001"

    hashes = store.persist_retry_bundle(
        page_id,
        "retry-0001",
        request={"page_id": page_id, "dpi": 300},
        verification={"page_id": page_id, "status": "NEEDS_REVIEW"},
        raw_response={"page_id": page_id, "latex": "x"},
        page_tex="x",
        parent_artifact_hashes={"candidate.json": _sha(b"parent")},
    )

    assert set(hashes) == {
        "request.json",
        "verification.json",
        "raw-response.json",
        "page.tex",
        "record.json",
    }
    assert store.persist_retry_bundle(
        page_id,
        "retry-0001",
        request={"page_id": page_id, "dpi": 300},
        verification={"page_id": page_id, "status": "NEEDS_REVIEW"},
        raw_response={"page_id": page_id, "latex": "x"},
        page_tex="x",
        parent_artifact_hashes={"candidate.json": _sha(b"parent")},
    ) == hashes
    retry_tex = store.page_dir(page_id) / "retries" / "retry-0001" / "page.tex"
    retry_tex.write_text("tampered", encoding="utf-8")
    with pytest.raises(PageEvidenceIntegrityError, match="hash binding"):
        store.verify_retry_artifacts(page_id, "retry-0001")


def test_retry_coverage_head_preserves_base_and_drives_terminal_summaries(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    base = _persisted_success(store, candidate)
    retry_tex = "x \\le y with a host-verified correction"
    retry_response = {"page_id": candidate.page_id, "verdict": "PASS-RETRY"}

    # An interrupted, uncommitted retry directory is not an evidence head.
    store.write_retry_artifact(
        candidate.page_id,
        "retry-0001-interrupted",
        "request.json",
        {"page_id": candidate.page_id},
    )
    assert store.verify_coverage_artifact_hashes(
        candidate.page_id, base.artifact_hashes
    ) == base.artifact_hashes

    head = store.persist_retry_coverage_bundle(
        candidate.page_id,
        "retry-0002-manual",
        request={"page_id": candidate.page_id, "lane_owner": "VISUAL"},
        verification={"page_id": candidate.page_id, "visual_mode": "VERIFIER"},
        raw_response=retry_response,
        page_tex=retry_tex,
        parent_artifact_hashes=base.artifact_hashes,
    )
    retried = build_page_coverage_record(
        candidate,
        PageCoverageFacts(
            source_sha256=source_sha,
            source_page_object_hash=candidate.source_page_object_hash,
            final_page_tex=retry_tex,
            final_status=FinalPageStatus.SUCCESS,
            verification=_verification(candidate),
            syntax_checked=True,
            persisted=True,
            artifact_hashes=head,
        ),
        expected_source_sha256=source_sha,
    )
    terminal = store.verify_terminal_page_artifacts(
        candidate.page_id,
        raw_response=retry_response,
        page_tex=retry_tex,
    )

    assert retried.checks.all_pass
    assert terminal["retry_id"] == "retry-0002-manual"
    assert dict(terminal["artifact_hashes"]) == dict(head)
    assert head["source.json"] == base.artifact_hashes["source.json"]
    assert head["candidate.json"] == base.artifact_hashes["candidate.json"]
    assert "retry-record.json" in head
    store.persist_summaries([retried], expected_source_pages=[7])
    assert store.verify_summaries(expected_source_pages=[7]).records == (retried,)

    retry_path = (
        store.page_dir(candidate.page_id)
        / "retries"
        / "retry-0002-manual"
        / "page.tex"
    )
    retry_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(PageEvidenceIntegrityError):
        store.verify_summaries(expected_source_pages=[7])


def test_durable_retry_intent_is_reused_by_terminal_record(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    base = _persisted_success(store, candidate)
    retry_id = "retry-0003-manual-2"
    request = {
        "schema_version": "latexstruct-ocr-manual-retry-request-v2",
        "page_id": candidate.page_id,
        "retry_id": retry_id,
        "intended_call_index": 2,
        "lane_owner": "VISUAL",
    }
    intent = store.persist_retry_intent(
        candidate.page_id,
        retry_id,
        intended_call_index=2,
        request=request,
        parent_artifact_hashes=base.artifact_hashes,
    )
    request_path = (
        store.page_dir(candidate.page_id) / "retries" / retry_id / "request.json"
    )
    intent_bytes = request_path.read_bytes()

    head = store.persist_retry_coverage_bundle(
        candidate.page_id,
        retry_id,
        request=intent["intent"],
        verification={"page_id": candidate.page_id, "visual_mode": "VERIFIER"},
        raw_response={"page_id": candidate.page_id, "verdict": "PASS-RETRY"},
        page_tex="x \\le y after retry",
        parent_artifact_hashes=base.artifact_hashes,
        expected_retry_intent_sha256=str(intent["intent_sha256"]),
    )

    assert request_path.read_bytes() == intent_bytes
    assert head["retry-record.json"]
    assert store.retry_commit_marker_exists(candidate.page_id, retry_id) is True
    assert (
        store.verify_retry_artifacts(candidate.page_id, retry_id)["request.json"]
        == intent["intent_sha256"]
    )
    retry_dir = request_path.parent
    verification_wrapper = json.loads(
        (retry_dir / "verification.json").read_text(encoding="utf-8")
    )
    assert set(verification_wrapper) == {
        "schema_version",
        "run_id",
        "page_id",
        "source_sha256",
        "candidate_artifact_sha256",
        "raw_response_sha256",
        "final_page_tex_sha256",
        "verification",
    }
    assert (
        verification_wrapper["schema_version"]
        == "latexstruct-ocr-page-verification-v1"
    )
    assert verification_wrapper["candidate_artifact_sha256"] == (
        base.artifact_hashes["candidate.json"]
    )
    assert verification_wrapper["raw_response_sha256"] == head[
        "raw-response.json"
    ]
    assert verification_wrapper["final_page_tex_sha256"] == head["page.tex"]
    assert verification_wrapper["verification"] == {
        "page_id": candidate.page_id,
        "visual_mode": "VERIFIER",
    }
    retry_record = json.loads(
        (retry_dir / "record.json").read_text(encoding="utf-8")
    )
    assert retry_record["schema_version"] == "latexstruct-ocr-page-retry-record-v2"


def test_abandoned_retry_intent_does_not_replace_base_or_block_later_retry(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    base = _persisted_success(store, candidate)
    base_bytes = {
        name: (store.page_dir(candidate.page_id) / name).read_bytes()
        for name in base.artifact_hashes
    }

    first_retry = "retry-0004-manual-2"
    store.persist_retry_intent(
        candidate.page_id,
        first_retry,
        intended_call_index=2,
        request={
            "page_id": candidate.page_id,
            "retry_id": first_retry,
            "intended_call_index": 2,
        },
        parent_artifact_hashes=base.artifact_hashes,
    )
    assert store.retry_commit_marker_exists(candidate.page_id, first_retry) is False

    second_retry = "retry-0005-manual-3"
    intent = store.persist_retry_intent(
        candidate.page_id,
        second_retry,
        intended_call_index=3,
        request={
            "page_id": candidate.page_id,
            "retry_id": second_retry,
            "intended_call_index": 3,
        },
        parent_artifact_hashes=base.artifact_hashes,
    )
    store.persist_retry_coverage_bundle(
        candidate.page_id,
        second_retry,
        request=intent["intent"],
        verification={"page_id": candidate.page_id, "visual_mode": "VERIFIER"},
        raw_response={"page_id": candidate.page_id, "verdict": "PASS"},
        page_tex="successful second retry",
        parent_artifact_hashes=base.artifact_hashes,
        expected_retry_intent_sha256=str(intent["intent_sha256"]),
    )

    assert {
        name: (store.page_dir(candidate.page_id) / name).read_bytes()
        for name in base.artifact_hashes
    } == base_bytes
    assert store.latest_committed_coverage_head(candidate.page_id)["retry_id"] == second_retry


def test_retry_after_abandoned_intent_keeps_latest_committed_retry_parent(tmp_path):
    source_sha = _sha(b"source")
    candidate = _candidate()
    store = _store(tmp_path, source_sha)
    base = _persisted_success(store, candidate)

    head1_id = "retry-0001-manual-2"
    head1_intent = store.persist_retry_intent(
        candidate.page_id,
        head1_id,
        intended_call_index=2,
        request={
            "page_id": candidate.page_id,
            "retry_id": head1_id,
            "intended_call_index": 2,
        },
        parent_artifact_hashes=base.artifact_hashes,
    )
    head1 = store.persist_retry_coverage_bundle(
        candidate.page_id,
        head1_id,
        request=head1_intent["intent"],
        verification={"page_id": candidate.page_id, "visual_mode": "VERIFIER"},
        raw_response={"page_id": candidate.page_id, "verdict": "PASS-HEAD-1"},
        page_tex="committed retry head one",
        parent_artifact_hashes=base.artifact_hashes,
        expected_retry_intent_sha256=str(head1_intent["intent_sha256"]),
    )

    abandoned_id = "retry-0002-manual-3"
    store.persist_retry_intent(
        candidate.page_id,
        abandoned_id,
        intended_call_index=3,
        request={
            "page_id": candidate.page_id,
            "retry_id": abandoned_id,
            "intended_call_index": 3,
        },
        parent_artifact_hashes=head1,
    )
    assert store.retry_commit_marker_exists(candidate.page_id, abandoned_id) is False

    head3_id = "retry-0003-manual-4"
    head3_intent = store.persist_retry_intent(
        candidate.page_id,
        head3_id,
        intended_call_index=4,
        request={
            "page_id": candidate.page_id,
            "retry_id": head3_id,
            "intended_call_index": 4,
        },
        parent_artifact_hashes=head1,
    )
    head3 = store.persist_retry_coverage_bundle(
        candidate.page_id,
        head3_id,
        request=head3_intent["intent"],
        verification={"page_id": candidate.page_id, "visual_mode": "VERIFIER"},
        raw_response={"page_id": candidate.page_id, "verdict": "PASS-HEAD-3"},
        page_tex="successful retry head three",
        parent_artifact_hashes=head1,
        expected_retry_intent_sha256=str(head3_intent["intent_sha256"]),
    )

    retry3_record = json.loads(
        (
            store.page_dir(candidate.page_id)
            / "retries"
            / head3_id
            / "record.json"
        ).read_text(encoding="utf-8")
    )
    assert retry3_record["parent_artifact_hashes"] == dict(head1)
    assert retry3_record["parent_artifact_hashes"] != dict(base.artifact_hashes)
    assert store.latest_committed_coverage_head(candidate.page_id) == {
        "retry_id": head3_id,
        "artifact_hashes": head3,
    }


def test_corrupt_existing_base_commit_marker_is_never_overwritten(tmp_path):
    candidate = _candidate()
    store = _store(tmp_path, _sha(b"source"))
    _persisted_success(store, candidate)
    marker = store.page_dir(candidate.page_id) / "verification.json"
    marker.write_bytes(b"{corrupt-base-marker")
    corrupt = marker.read_bytes()

    assert store.base_commit_marker_exists(candidate.page_id) is True
    with pytest.raises(PageEvidenceIntegrityError):
        store.verify_page_artifacts(candidate.page_id)
    with pytest.raises(PageEvidenceConflictError):
        store.persist_page_bundle(
            candidate,
            verification=_verification(candidate),
            raw_response={"page_id": candidate.page_id, "verdict": "PASS"},
            page_tex=candidate.candidate_tex,
        )
    assert marker.read_bytes() == corrupt


def test_corrupt_existing_retry_commit_marker_is_never_overwritten(tmp_path):
    page_id = "ocr-page-000001"
    store = _store(tmp_path, _sha(b"source"))
    retry_id = "retry-0006"
    kwargs = {
        "request": {"page_id": page_id, "dpi": 300},
        "verification": {"page_id": page_id, "status": "NEEDS_REVIEW"},
        "raw_response": {"page_id": page_id, "latex": "x"},
        "page_tex": "x",
        "parent_artifact_hashes": {"candidate.json": _sha(b"parent")},
    }
    store.persist_retry_bundle(page_id, retry_id, **kwargs)
    marker = store.page_dir(page_id) / "retries" / retry_id / "record.json"
    marker.write_bytes(b"{corrupt-retry-marker")
    corrupt = marker.read_bytes()

    assert store.retry_commit_marker_exists(page_id, retry_id) is True
    with pytest.raises(PageEvidenceIntegrityError):
        store.verify_retry_artifacts(page_id, retry_id)
    with pytest.raises(PageEvidenceConflictError):
        store.persist_retry_bundle(page_id, retry_id, **kwargs)
    assert marker.read_bytes() == corrupt


def test_summary_rejects_duplicate_missing_and_reordered_pages(tmp_path):
    source_sha = _sha(b"source")
    store = _store(tmp_path, source_sha)
    first = _persisted_success(store, _candidate(1, 7))
    second = _persisted_success(store, _candidate(2, 9))

    with pytest.raises(ValueError, match="missing or inventing"):
        build_page_summaries(
            [first],
            run_id=store.run_id,
            source_sha256=source_sha,
            expected_source_pages=[7, 9],
        )
    with pytest.raises(ValueError, match="repeats"):
        build_page_summaries(
            [first, first],
            run_id=store.run_id,
            source_sha256=source_sha,
            expected_source_pages=[7, 9],
        )
    with pytest.raises(ValueError, match="order/identity"):
        build_page_summaries(
            [second, first],
            run_id=store.run_id,
            source_sha256=source_sha,
            expected_source_pages=[7, 9],
        )


def test_summaries_are_canonical_hash_bound_and_append_only(tmp_path):
    source_sha = _sha(b"source")
    store = _store(tmp_path, source_sha)
    records = [
        _persisted_success(store, _candidate(1, 7)),
        _persisted_success(store, _candidate(2, 9)),
    ]

    bundle = store.persist_summaries(records, expected_source_pages=[7, 9])
    verified = verify_page_summaries(
        bundle.page_records_bytes,
        bundle.coverage_bytes,
        expected_source_pages=[7, 9],
    )

    assert verified.page_records_sha256 == bundle.page_records_sha256
    assert verified.coverage_sha256 == bundle.coverage_sha256
    assert verified.coverage["completed"] == 2
    assert store.persist_summaries(records, expected_source_pages=[7, 9]) == bundle
    with pytest.raises(PageEvidenceConflictError):
        store.persist_summaries(
            [records[0], replace(records[1], final_status=FinalPageStatus.NEEDS_REVIEW)],
            expected_source_pages=[7, 9],
        )


@pytest.mark.parametrize(
    "tampered_artifact",
    ["intent.json", "result.json", "consumed.json"],
)
def test_visual_call_chain_is_exact_append_only_and_tamper_evident(
    tmp_path,
    tampered_artifact: str,
):
    candidate = _candidate()
    store = _store(tmp_path, _sha(b"visual-call-source"))
    call_id = "visual-0001-" + "b" * 32
    batch_id = "ocr-verify-batch-" + "c" * 24
    intent = store.persist_visual_call_intent(
        candidate.page_id,
        call_id,
        source_page=candidate.source_page_number,
        task_index=candidate.selected_index,
        call_kind="INITIAL",
        runtime_call_index=1,
        visual_call_sequence=1,
        provider_batch_id=batch_id,
        image_sha256=_sha(b"visual-page-image"),
        candidate_tex_sha256=_sha(candidate.candidate_tex.encode()),
    )
    raw_response = {
        "batch_id": batch_id,
        "pages": [_verification(candidate).to_dict()],
    }
    response_sha256 = _sha(json.dumps(
        raw_response,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode())
    if tampered_artifact != "intent.json":
        store.persist_visual_call_result(
            candidate.page_id,
            call_id,
            expected_intent_sha256=str(intent["intent_sha256"]),
            response_sha256=response_sha256,
            raw_response=raw_response,
            verification=_verification(candidate).to_dict(),
        )
    if tampered_artifact == "consumed.json":
        store.persist_visual_call_consumed(
            candidate.page_id,
            call_id,
            disposition="COMMITTED",
            runtime_record_sha256=_sha(b"runtime-record"),
            record_status="SUCCESS",
            lane_owner="TERMINAL_VISUAL",
            lane_route_sha256=_sha(b"lane-route"),
        )
        assert store.pending_visual_calls(candidate.page_id) == ()
    else:
        assert len(store.pending_visual_calls(candidate.page_id)) == 1

    artifact = (
        store.page_dir(candidate.page_id)
        / "visual-calls"
        / call_id
        / tampered_artifact
    )
    value = json.loads(artifact.read_text(encoding="utf-8"))
    value["page_id"] = "ocr-page-999999"
    artifact.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PageEvidenceIntegrityError):
        store.pending_visual_calls(candidate.page_id)

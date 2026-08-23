# -*- coding: utf-8 -*-
"""Host-side v2 OCR runtime invariants; no network/model simulation claims."""

from __future__ import annotations

import hashlib
import json
import threading
import time

import pytest

from latexstruct.core.ocr_runtime import (
    AdaptivePageConcurrency,
    BoundedOcrExecutor,
    OcrBatchValidationError,
    OcrErrorCategory,
    OcrPageRecord,
    OcrPageRequest,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunPaused,
    OcrRunStore,
    OcrStoreError,
    classify_ocr_error,
    inspect_latex_fragment,
    make_page_id,
    make_run_snapshot,
    normalize_quality_tier,
    ocr_batch_output_schema,
    ocr_batch_request_payload,
    progress_metrics,
    public_page_state,
    quality_tier_policy,
    validate_ocr_batch_response,
)
from latexstruct.ocr import make_host_ocr_page_request


def _snapshot(source=b"%PDF-1.7\nsource", pages=(1, 2), **overrides):
    values = {
        "source_bytes": source,
        "source_type": "pdf",
        "original_filename": "中文 数学书.pdf",
        "source_total_pages": max(pages),
        "selected_pages": pages,
        "ocr_model": "vision-model",
        "api_backend": "api",
        "app_version": "2.0.0",
        "quality_tier": "recommended",
        "run_id": "a" * 32,
        "started_at": "2026-08-23T00:00:00.000Z",
    }
    values.update(overrides)
    return make_run_snapshot(**values)


def _response(page_id, latex="Text with enough content and \\(x+y\\).", **extra):
    return {
        "page_id": page_id,
        "latex": latex,
        "figures": [],
        "unresolved_regions": [],
        **extra,
    }


def test_batch_output_schema_is_strict_for_every_nested_object():
    schema = ocr_batch_output_schema([make_page_id(1)])

    def assert_strict_objects(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
                assert set(node.get("required") or ()) == set((node.get("properties") or {}).keys())
            for value in node.values():
                assert_strict_objects(value)
        elif isinstance(node, list):
            for value in node:
                assert_strict_objects(value)

    assert_strict_objects(schema)
    page_schema = schema["properties"]["pages"]["items"]
    assert page_schema["properties"]["figures"]["items"]["required"] == [
        "path", "index", "bbox_normalized", "bbox_pixels",
    ]


def _success(record, response, *, ended_at="2026-08-23T00:01:00.000Z"):
    raw = json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    latex = response["latex"]
    return record.transition(OcrPageStatus.RENDERING).transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(b"image").hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=200,
        model="vision-model",
        call_index=1,
        started_at="2026-08-23T00:00:30.000Z",
    ).transition(OcrPageStatus.VALIDATING).transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=hashlib.sha256(raw).hexdigest(),
        raw_tex=latex,
        cleaned_tex=latex,
        ended_at=ended_at,
        elapsed_seconds=30,
    )


def test_quality_tier_and_snapshot_freeze_legacy_names_and_reject_secrets():
    assert normalize_quality_tier("standard").value == "recommended"
    assert normalize_quality_tier("publication").value == "high"
    assert quality_tier_policy("fast").initial_dpi == 200
    assert quality_tier_policy("recommended").retry_dpi == 300
    snapshot = _snapshot()
    assert snapshot.quality_tier.value == "recommended"
    assert snapshot.batch_size == snapshot.concurrency_limit == 3
    assert snapshot.original_filename == "中文 数学书.pdf"
    with pytest.raises(ValueError, match="sensitive/path"):
        _snapshot(runtime_options={"api_key": "secret"})


def test_six_hundred_page_snapshot_assigns_unique_stable_page_ids():
    snapshot = _snapshot(pages=tuple(range(1, 601)), source_total_pages=600)
    identities = [snapshot.page_identity(index) for index in range(1, 601)]
    assert identities[0] == ("ocr-page-000001", 1)
    assert identities[-1] == ("ocr-page-000600", 600)
    assert len({page_id for page_id, _page in identities}) == 600


def test_page_state_machine_is_fail_closed_and_public_state_has_no_tex():
    record = OcrPageRecord.pending(1, 7)
    assert record.page_id == make_page_id(1)
    with pytest.raises(ValueError, match="illegal"):
        record.transition(OcrPageStatus.SUCCESS, cleaned_tex="text")
    running = record.transition(OcrPageStatus.RENDERING)
    recovered = running.recovered_after_interruption()
    assert recovered.status == OcrPageStatus.PENDING
    assert recovered.quality_issues[0]["code"] == "INTERRUPTED_ATTEMPT_RECOVERED"
    assert "cleaned_tex" not in public_page_state(recovered)


def test_existing_ocr_renderer_can_bind_a_stable_runtime_page_request():
    request = make_host_ocr_page_request(
        b"rendered-page", 17, 3, dpi=200, text_layer_hint="untrusted hint",
    )
    assert request.page_id == "ocr-page-000003"
    assert request.source_page == 17
    assert request.public_payload()["image_sha256"] == hashlib.sha256(b"rendered-page").hexdigest()


def test_atomic_store_resume_skips_hash_verified_success_and_recovers_transient(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source)
    store = OcrRunStore(tmp_path / "中文 OCR 运行")
    store.initialize(snapshot, source)
    response = _response(make_page_id(1))
    success = _success(store.load_record(snapshot.run_id, make_page_id(1)), response)
    store.persist_record(snapshot.run_id, success, raw_response=response)
    running = store.load_record(snapshot.run_id, make_page_id(2)).transition(OcrPageStatus.RENDERING)
    store.persist_record(snapshot.run_id, running)

    resumable = store.resumable_records(snapshot.run_id)

    assert [record.page_id for record in resumable] == [make_page_id(2)]
    assert store.load_record(snapshot.run_id, make_page_id(1)).status == OcrPageStatus.SUCCESS
    assert store.load_record(snapshot.run_id, make_page_id(2)).status == OcrPageStatus.PENDING
    with pytest.raises(OcrStoreError, match="immutable"):
        store.persist_record(
            snapshot.run_id,
            success.transition(OcrPageStatus.SUCCESS, error_reason="must not rewrite success"),
        )


def test_store_rejects_source_and_success_tex_tampering(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    directory = store.initialize(snapshot, source)
    next(directory.glob("source.*")).write_bytes(b"tampered")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        store.recover(snapshot.run_id)


def test_store_persists_exact_visual_input_without_overwrite(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    image = b"exact rendered page pixels"
    record = store.load_record(snapshot.run_id, make_page_id(1)).transition(
        OcrPageStatus.RENDERING,
        dpi=200,
    ).transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=200,
        model="vision-model",
        call_index=1,
    )

    path = store.persist_page_image(snapshot.run_id, record, image)

    assert path.read_bytes() == image
    assert store.verify_page_image(snapshot.run_id, record) == path
    with pytest.raises(OcrStoreError, match="do not match"):
        store.persist_page_image(snapshot.run_id, record, b"different pixels")
    path.write_bytes(b"tampered")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        store.verify_page_image(snapshot.run_id, record)


@pytest.mark.parametrize(
    ("pages", "code"),
    [
        (["ocr-page-000001"], "MISSING_PAGE_ID"),
        (["ocr-page-000001", "ocr-page-000001"], "DUPLICATE_PAGE_ID"),
        (["ocr-page-000001", "ocr-page-000003"], "UNKNOWN_PAGE_ID"),
    ],
)
def test_batch_validator_rejects_missing_duplicate_and_unknown_page_ids(pages, code):
    response = {"pages": [_response(page_id) for page_id in pages]}
    with pytest.raises(OcrBatchValidationError) as caught:
        validate_ocr_batch_response(
            response, ["ocr-page-000001", "ocr-page-000002"],
        )
    assert caught.value.code == code


def test_batch_validator_returns_host_order_and_flags_latex_damage():
    response = {"pages": [
        _response("ocr-page-000002", "```latex\n\\documentclass{book}\n```"),
        _response("ocr-page-000001", "A complete first page with \\(x+y\\)."),
    ]}
    pages = validate_ocr_batch_response(
        response, ["ocr-page-000001", "ocr-page-000002"],
    )
    assert [page.page_id for page in pages] == ["ocr-page-000001", "ocr-page-000002"]
    codes = {issue.code for issue in pages[1].issues}
    assert {"MARKDOWN_FENCE", "DOCUMENT_PREAMBLE"} <= codes
    assert pages[1].needs_retry


def test_pixel_transcription_flags_semantic_structure_without_discarding_text():
    latex = "Visible heading\\n\\section{Invented structure}\\nBody text."

    issues = inspect_latex_fragment(latex)
    page = validate_ocr_batch_response(
        _response(make_page_id(1), latex), [make_page_id(1)],
    )[0]

    semantic = [issue for issue in issues if issue.code == "FORBIDDEN_SEMANTIC_STRUCTURE"]
    assert len(semantic) == 1
    assert semantic[0].severity == "warning"
    assert semantic[0].retryable is False
    assert page.latex == latex
    assert page.needs_review is True
    assert page.needs_retry is False


def test_single_executor_preserves_controlled_retry_metadata_for_host_policy():
    request = OcrPageRequest(make_page_id(1), 1, 1, b"image", 200)

    class ControlledRetry(RuntimeError):
        retry_instruction = "Keep all visible symbols; repair only the broken display."
        retry_state = {"reason": "BROKEN_DISPLAY", "source_page": 1}

    result = BoundedOcrExecutor().run(
        [request], single_call=lambda _request: (_ for _ in ()).throw(
            ControlledRetry("quality gate requested a local correction")
        ),
    )[0]

    assert result.page is None
    assert result.retry_instruction.startswith("Keep all visible symbols")
    assert dict(result.retry_state) == {"reason": "BROKEN_DISPLAY", "source_page": 1}


def test_single_page_never_calls_batch_provider_even_when_batch_is_available():
    request = OcrPageRequest(make_page_id(1), 1, 1, b"image", 200)
    calls = []

    def single_call(item):
        calls.append(("single", item.page_id, item.dpi))
        return _response(item.page_id)

    def batch_call(_items):
        calls.append(("batch",))
        raise AssertionError("a single page must never use batch_call")

    result = BoundedOcrExecutor(batch_size=3, concurrency_limit=3).run(
        [request], single_call=single_call, batch_call=batch_call,
    )[0]

    assert calls == [("single", make_page_id(1), 200)]
    assert result.page is not None
    assert result.used_batch is False
    assert result.fell_back_to_single is False


def test_codex_runtime_exit_failure_is_unknown_and_not_claimed_transient():
    initial = OcrPageRequest(make_page_id(1), 1, 1, b"image-200", 200)
    calls = []
    batch_calls = []

    def initial_call(item):
        calls.append(item.dpi)
        raise RuntimeError("Codex 本地 runtime 调用失败（退出码 1）")

    first = BoundedOcrExecutor(batch_size=3, concurrency_limit=3).run(
        [initial],
        single_call=initial_call,
        batch_call=lambda items: batch_calls.append(tuple(items)),
    )[0]

    assert first.page is None
    assert first.error_category == OcrErrorCategory.UNKNOWN
    assert batch_calls == []
    assert calls == [200]


@pytest.mark.parametrize(
    ("message", "category"),
    [
        ("Codex 本地 runtime 调用失败（退出码 1）：HTTP 401 unauthorized", OcrErrorCategory.AUTH),
        ("Codex 本地 runtime 调用失败（退出码 1）：quota 额度耗尽", OcrErrorCategory.QUOTA),
        ("Codex 本地 runtime 调用失败（退出码 1）：model not found", OcrErrorCategory.CONFIG),
        ("Codex 本地 runtime 调用失败（退出码 1）：content refusal", OcrErrorCategory.REFUSAL),
        ("Codex runtime 与当前安全配置不兼容", OcrErrorCategory.CONFIG),
    ],
)
def test_codex_runtime_wrapper_never_hides_non_retryable_provider_category(message, category):
    assert classify_ocr_error(message) == category


def test_retry_request_forwards_only_host_controlled_correction_evidence():
    request = OcrPageRequest(
        make_page_id(1),
        9,
        1,
        b"image",
        300,
        correction_instruction="Repair only the independently located relation sign.",
        retry_state={"evidence_id": "p9-relation-1", "operator": "geq"},
    )
    payload = json.loads(ocr_batch_request_payload([request]))["page_requests"][0]
    assert payload["page_id"] == make_page_id(1)
    assert payload["dpi"] == 300
    assert payload["retry_correction"].startswith("Repair only")
    assert payload["host_verified_retry_evidence"]["evidence_id"] == "p9-relation-1"
    assert "retry_state" not in request.public_payload()


def test_batch_executor_falls_back_to_bounded_single_calls_and_keeps_page_results():
    requests = [
        OcrPageRequest(make_page_id(index), index, index, b"image", 200)
        for index in range(1, 4)
    ]
    active = 0
    peak = 0
    lock = threading.Lock()
    parallel = threading.Event()

    def batch_call(_requests):
        return {"pages": [_response(make_page_id(1))]}  # missing two IDs

    def single_call(request):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active >= 2:
                parallel.set()
        assert parallel.wait(1.0)
        time.sleep(0.005)
        with lock:
            active -= 1
        return _response(request.page_id)

    results = BoundedOcrExecutor(batch_size=3, concurrency_limit=2).run(
        requests, single_call=single_call, batch_call=batch_call,
    )
    assert [result.request.page_id for result in results] == [request.page_id for request in requests]
    assert all(result.page is not None and result.fell_back_to_single for result in results)
    assert peak == 2


def test_batch_executor_does_not_fan_out_auth_or_quota_failure():
    requests = [OcrPageRequest(make_page_id(index), index, index, b"image") for index in (1, 2)]
    singles = []

    def batch_call(_requests):
        raise RuntimeError("HTTP 401 invalid API key")

    with pytest.raises(OcrRunPaused) as caught:
        BoundedOcrExecutor().run(
            requests,
            batch_call=batch_call,
            single_call=lambda request: singles.append(request),
        )
    assert caught.value.category.value == "AUTH"
    assert singles == []


def test_raw_ocr_freeze_never_silently_omits_failed_page_and_is_immutable(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    response = _response(make_page_id(1))
    success = _success(store.load_record(snapshot.run_id, make_page_id(1)), response)
    store.persist_record(snapshot.run_id, success, raw_response=response)
    failed = store.load_record(snapshot.run_id, make_page_id(2)).transition(
        OcrPageStatus.RENDERING,
    ).transition(OcrPageStatus.FAILED, error_reason="provider timeout")
    store.persist_record(snapshot.run_id, failed)

    manifest = store.freeze_raw_ocr(snapshot.run_id)
    raw = (store.run_dir(snapshot.run_id) / "artifacts" / "raw-ocr.tex").read_text()
    assert "% Page 1" in raw and "% Page 2" in raw
    assert "OCR PAGE UNAVAILABLE: ocr-page-000002 status=FAILED" in raw
    assert manifest["error_pages"] == [2]
    assert store.freeze_raw_ocr(snapshot.run_id)["raw_ocr_sha256"] == manifest["raw_ocr_sha256"]


def test_compiled_baseline_requires_real_pdf_and_two_successful_passes(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    response = _response(make_page_id(1))
    success = _success(store.load_record(snapshot.run_id, make_page_id(1)), response)
    store.persist_record(snapshot.run_id, success, raw_response=response)
    store.freeze_raw_ocr(snapshot.run_id)
    with pytest.raises(OcrStoreError, match="two successful"):
        store.save_compile_baseline(
            snapshot.run_id,
            baseline_tex="text",
            compile_log="ok",
            preview_status=OcrPreviewStatus.COMPILED,
            exit_code=0,
            successful_passes=1,
            pdf_bytes=b"%PDF-1.7\nreal",
        )
    manifest = store.save_compile_baseline(
        snapshot.run_id,
        baseline_tex="text",
        compile_log="two real xelatex passes",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.7\nreal",
    )
    assert manifest["preview_status"] == "COMPILED"
    assert (store.run_dir(snapshot.run_id) / "artifacts" / "baseline.pdf").is_file()


def test_progress_is_derived_from_page_states_and_measured_times():
    snapshot = _snapshot()
    response = _response(make_page_id(1))
    first = _success(OcrPageRecord.pending(1, 1), response)
    second = OcrPageRecord.pending(2, 2).transition(OcrPageStatus.RENDERING, dpi=300)
    metrics = progress_metrics(
        snapshot,
        [first, second],
        now_epoch=datetime_epoch("2026-08-23T00:01:00.000Z"),
    )
    assert metrics["counts"]["success"] == 1
    assert metrics["counts"]["processing"] == 1
    assert metrics["recognition_progress"] == 0.5
    assert metrics["overall_progress"] < 0.9
    assert metrics["current_dpi"] == 300
    assert metrics["eta_seconds"] is not None


def test_terminal_progress_includes_post_ocr_work_and_freezes_only_at_job_terminal():
    snapshot = _snapshot()
    first = _success(
        OcrPageRecord.pending(1, 1),
        _response(make_page_id(1)),
        ended_at="2026-08-23T00:00:40.000Z",
    )
    second = _success(
        OcrPageRecord.pending(2, 2),
        _response(make_page_id(2)),
        ended_at="2026-08-23T00:01:10.000Z",
    )

    first_poll = progress_metrics(
        snapshot,
        [first, second],
        now_epoch=datetime_epoch("2026-08-23T00:02:00.000Z"),
        terminal_epoch=datetime_epoch("2026-08-23T00:01:30.000Z"),
    )
    later_poll = progress_metrics(
        snapshot,
        [first, second],
        now_epoch=datetime_epoch("2026-08-24T00:02:00.000Z"),
        terminal_epoch=datetime_epoch("2026-08-23T00:01:30.000Z"),
    )

    assert first_poll["elapsed_frozen"] is True
    # Last page OCR ended at 70s; merge/repair/two-pass compile ended at 90s.
    assert first_poll["elapsed_seconds"] == 90.0
    assert later_poll["elapsed_seconds"] == first_poll["elapsed_seconds"]
    assert later_poll["average_pages_per_minute"] == first_poll[
        "average_pages_per_minute"
    ]


def test_final_pages_do_not_freeze_workflow_clock_before_compile_terminal():
    snapshot = _snapshot()
    records = [
        _success(
            OcrPageRecord.pending(index, index),
            _response(make_page_id(index)),
            ended_at=f"2026-08-23T00:00:{30 + index:02d}.000Z",
        )
        for index in (1, 2)
    ]

    compiling = progress_metrics(
        snapshot,
        records,
        now_epoch=datetime_epoch("2026-08-23T00:01:20.000Z"),
        merge_complete=True,
        raw_frozen=True,
    )
    later = progress_metrics(
        snapshot,
        records,
        now_epoch=datetime_epoch("2026-08-23T00:01:35.000Z"),
        merge_complete=True,
        raw_frozen=True,
    )

    assert compiling["elapsed_frozen"] is False
    assert compiling["elapsed_seconds"] == 80.0
    assert later["elapsed_seconds"] == 95.0


def datetime_epoch(value):
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def test_adaptive_concurrency_reduces_immediately_and_recovers_slowly():
    limiter = AdaptivePageConcurrency(maximum=3, recovery_successes=2)
    assert limiter.on_rate_limit() == 2
    assert limiter.on_success() == 2
    assert limiter.on_success() == 3

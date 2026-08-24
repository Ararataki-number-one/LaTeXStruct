# -*- coding: utf-8 -*-
"""Host-side v2 OCR runtime invariants; no network/model simulation claims."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest

from latexstruct.core.ocr_runtime import (
    AdaptivePageConcurrency,
    BoundedOcrExecutor,
    OcrBatchAttemptEvidence,
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


def test_recover_rejects_missing_or_tampered_success_response_sidecar(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    response = _response(make_page_id(1))
    success = _success(store.load_record(snapshot.run_id, make_page_id(1)), response)
    store.persist_record(snapshot.run_id, success, raw_response=response)
    response_path = (
        store.run_dir(snapshot.run_id)
        / "responses"
        / f"{success.page_id}-{success.raw_response_sha256}.json"
    )

    response_path.write_text("{}", encoding="utf-8")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        store.recover(snapshot.run_id)


def test_store_serializes_record_read_with_atomic_commit(tmp_path, monkeypatch):
    """Polling must not hold a Windows read handle across ``os.replace``."""

    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    page_id = make_page_id(1)
    pending = store.load_record(snapshot.run_id, page_id)
    rendering = pending.transition(OcrPageStatus.RENDERING, dpi=200)
    record_path = store._record_path(snapshot.run_id, page_id)

    read_started = threading.Event()
    release_read = threading.Event()
    replace_entered = threading.Event()
    failures = []
    original_read_text = Path.read_text
    original_replace = os.replace

    def blocking_read_text(path, *args, **kwargs):
        if path == record_path and threading.current_thread().name == "ocr-record-reader":
            read_started.set()
            if not release_read.wait(timeout=2):
                raise TimeoutError("test reader was not released")
        return original_read_text(path, *args, **kwargs)

    def observed_replace(source_path, destination_path):
        if Path(destination_path) == record_path:
            replace_entered.set()
        return original_replace(source_path, destination_path)

    monkeypatch.setattr(Path, "read_text", blocking_read_text)
    monkeypatch.setattr(os, "replace", observed_replace)

    def read_record():
        try:
            store.load_record(snapshot.run_id, page_id)
        except BaseException as exc:  # noqa: BLE001 - captured from worker thread
            failures.append(exc)

    def write_record():
        try:
            store.persist_record(snapshot.run_id, rendering)
        except BaseException as exc:  # noqa: BLE001 - captured from worker thread
            failures.append(exc)

    reader = threading.Thread(target=read_record, name="ocr-record-reader")
    writer = threading.Thread(target=write_record, name="ocr-record-writer")
    reader.start()
    assert read_started.wait(timeout=2)
    writer.start()
    assert not replace_entered.wait(timeout=0.1)
    release_read.set()
    reader.join(timeout=2)
    writer.join(timeout=2)

    assert not reader.is_alive()
    assert not writer.is_alive()
    assert failures == []
    assert replace_entered.is_set()
    assert store.load_record(snapshot.run_id, page_id).status == OcrPageStatus.RENDERING


def test_store_lists_records_under_one_consistent_lock(tmp_path, monkeypatch):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    first_id = make_page_id(1)
    second_id = make_page_id(2)
    second = store.load_record(snapshot.run_id, second_id).transition(
        OcrPageStatus.RENDERING,
        dpi=200,
    )
    second_path = store._record_path(snapshot.run_id, second_id)

    first_loaded = threading.Event()
    release_list = threading.Event()
    replace_entered = threading.Event()
    failures = []
    listed = []
    original_load_record = store.load_record
    original_replace = os.replace

    def blocking_load_record(run_id, page_id):
        record = original_load_record(run_id, page_id)
        if page_id == first_id and threading.current_thread().name == "ocr-list-reader":
            first_loaded.set()
            if not release_list.wait(timeout=2):
                raise TimeoutError("test list reader was not released")
        return record

    def observed_replace(source_path, destination_path):
        if Path(destination_path) == second_path:
            replace_entered.set()
        return original_replace(source_path, destination_path)

    monkeypatch.setattr(store, "load_record", blocking_load_record)
    monkeypatch.setattr(os, "replace", observed_replace)

    def list_records():
        try:
            listed.extend(store.list_records(snapshot.run_id))
        except BaseException as exc:  # noqa: BLE001 - captured from worker thread
            failures.append(exc)

    def write_second():
        try:
            store.persist_record(snapshot.run_id, second)
        except BaseException as exc:  # noqa: BLE001 - captured from worker thread
            failures.append(exc)

    reader = threading.Thread(target=list_records, name="ocr-list-reader")
    writer = threading.Thread(target=write_second, name="ocr-list-writer")
    reader.start()
    assert first_loaded.wait(timeout=2)
    writer.start()
    assert not replace_entered.wait(timeout=0.1)
    release_list.set()
    reader.join(timeout=2)
    writer.join(timeout=2)

    assert not reader.is_alive()
    assert not writer.is_alive()
    assert failures == []
    assert [record.status for record in listed] == [
        OcrPageStatus.PENDING,
        OcrPageStatus.PENDING,
    ]
    assert replace_entered.is_set()


def test_store_rejects_source_and_success_tex_tampering(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    directory = store.initialize(snapshot, source)
    next(directory.glob("source.*")).write_bytes(b"tampered")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        store.recover(snapshot.run_id)


def test_store_rejects_tampered_hash_bound_page_source_evidence(tmp_path):
    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    page_id = make_page_id(1)
    record = store.load_record(snapshot.run_id, page_id).transition(
        OcrPageStatus.RENDERING,
        dpi=200,
    )
    digest = store.persist_page_source_evidence(
        snapshot.run_id,
        record,
        {"equation_tag_regions": [{"label": "1", "bbox_normalized": [0.8, 0.4, 0.9, 0.5]}]},
    )
    record = record.transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(b"image").hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=200,
        model="vision-model",
        call_index=1,
        source_evidence_sha256=digest,
    )
    store.persist_record(snapshot.run_id, record)
    loaded = store.load_page_source_evidence(snapshot.run_id, record)
    assert loaded["equation_tag_regions"][0]["label"] == "1"

    evidence_path = (
        store.run_dir(snapshot.run_id)
        / "source-evidence"
        / f"{page_id}-{digest}.json"
    )
    evidence_path.write_text("{}", encoding="utf-8")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        store.load_page_source_evidence(snapshot.run_id, record)


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


def test_store_materializes_hash_bound_figure_crop_for_compile(tmp_path):
    import pymupdf

    source = b"%PDF-1.7\nsource"
    snapshot = _snapshot(source=source, pages=(1,), source_total_pages=1)
    store = OcrRunStore(tmp_path)
    store.initialize(snapshot, source)
    pixmap = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 100, 80), False)
    pixmap.clear_with(220)
    image = pixmap.tobytes("png")
    page_id = make_page_id(1)
    response = _response(
        page_id,
        "Visible text.\\n\\includegraphics{figures/page_0001_figure_01.png}",
        figures=[{
            "path": "figures/page_0001_figure_01.png",
            "index": 1,
            "bbox_normalized": [0.1, 0.125, 0.6, 0.625],
            "bbox_pixels": [10, 10, 60, 50],
        }],
    )
    raw = json.dumps(
        response, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()
    running = store.load_record(snapshot.run_id, page_id).transition(
        OcrPageStatus.RENDERING,
        dpi=200,
    ).transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_size_pixels=(100, 80),
        dpi=200,
        model="vision-model",
        call_index=1,
    )
    store.persist_record(snapshot.run_id, running)
    store.persist_page_image(snapshot.run_id, running, image)
    final = running.transition(OcrPageStatus.VALIDATING).transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=hashlib.sha256(raw).hexdigest(),
        raw_tex=response["latex"],
        cleaned_tex=response["latex"],
    )
    store.persist_record(snapshot.run_id, final, raw_response=response)

    assets, figure_manifest = store.materialize_figure_assets(snapshot.run_id)

    crop = assets["figures/page_0001_figure_01.png"]
    assert crop.startswith(b"\x89PNG\r\n\x1a\n")
    assert figure_manifest["figures"][0]["crop_size_pixels"] == [50, 40]
    assert figure_manifest["figures"][0]["sha256"] == hashlib.sha256(crop).hexdigest()
    frozen = store.freeze_raw_ocr(snapshot.run_id, figure_manifest=figure_manifest)
    assert frozen["figure_manifest_sha256"] == figure_manifest["manifest_sha256"]


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


@pytest.mark.parametrize(
    "response",
    [
        {
            "pages": [_response("ocr-page-000001")],
            "host_quality_flags": [],
        },
        {
            "pages": [{
                **_response("ocr-page-000001"),
                "model_raw_latex": "untrusted host field",
            }],
        },
    ],
)
def test_batch_validator_rejects_provider_attempts_to_inject_host_fields(response):
    with pytest.raises(OcrBatchValidationError) as caught:
        validate_ocr_batch_response(response, ["ocr-page-000001"])
    assert caught.value.code == "TOP_LEVEL_SCHEMA"


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


def test_batch_validator_binds_figure_paths_and_coordinates_to_host_page():
    page_id = make_page_id(1)
    response = _response(
        page_id,
        "Visible text.\\n\\includegraphics[width=.5\\linewidth]"
        "{figures/page_0007_figure_01.png}",
        figures=[{
            "path": "figures/page_0007_figure_01.png",
            "index": 1,
            "bbox_normalized": [0.1, 0.2, 0.6, 0.7],
            "bbox_pixels": [100, 400, 600, 1400],
        }],
    )

    page = validate_ocr_batch_response(
        response,
        [page_id],
        page_context_by_page_id={page_id: {
            "source_page": 7,
            "image_size_pixels": (1000, 2000),
        }},
    )[0]

    assert page.figures[0]["path"] == "figures/page_0007_figure_01.png"
    assert tuple(page.figures[0]["image_size_pixels"]) == (1000, 2000)
    assert page.figures[0]["display_width_ratio"] == 0.62
    assert (
        r"\includegraphics[width=0.62\linewidth,height=0.72\textheight,"
        r"keepaspectratio]{figures/page_0007_figure_01.png}"
    ) in page.latex
    assert "width=.5\\linewidth" not in page.latex


def test_batch_validator_sizes_real_bbox_and_is_idempotent():
    page_id = make_page_id(1)
    raw_figure = {
        "path": "figures/page_0023_figure_01.png",
        "index": 1,
        "bbox_normalized": [0.3098, 0.0742, 0.6902, 0.3455],
        "bbox_pixels": [790, 245, 1760, 1140],
    }
    response = _response(
        page_id,
        "Visible text.\n"
        "\\includegraphics[width=2\\textwidth,height=3\\textheight,"
        "keepaspectratio,trim={0,0,0,0}]"
        "{figures/page_0023_figure_01.png}",
        figures=[raw_figure],
    )
    context = {page_id: {
        "source_page": 23,
        "image_size_pixels": (2550, 3300),
    }}

    first = validate_ocr_batch_response(
        response, [page_id], page_context_by_page_id=context,
    )[0]
    second_response = dict(response, latex=first.latex)
    second = validate_ocr_batch_response(
        second_response, [page_id], page_context_by_page_id=context,
    )[0]

    expected = (
        r"\includegraphics[width=0.47\linewidth,height=0.72\textheight,"
        r"keepaspectratio,trim={0,0,0,0}]{figures/page_0023_figure_01.png}"
    )
    assert expected in first.latex
    assert second.latex == first.latex
    assert first.figures[0]["display_width_ratio"] == 0.47


def test_batch_validator_removes_only_host_supported_boundary_folios():
    page_id = make_page_id(1)
    latex = "23\nBody starts here.\n\n23\nBody continues.\n23"

    page = validate_ocr_batch_response(
        _response(page_id, latex),
        [page_id],
        reference_text_by_page_id={page_id: "23\nBody text\n23"},
        page_context_by_page_id={page_id: {
            "source_page": 23,
            "image_size_pixels": (2550, 3300),
        }},
    )[0]

    assert page.latex == "Body starts here.\n\n23\nBody continues."
    assert sum(issue.code == "BOUNDARY_FOLIO_REMOVED" for issue in page.issues) == 1
    assert page.needs_retry is False
    assert page.needs_review is False


def test_batch_validator_keeps_unsupported_boundary_number():
    page_id = make_page_id(1)
    latex = "7\nBody text.\n11"

    page = validate_ocr_batch_response(
        _response(page_id, latex),
        [page_id],
        reference_text_by_page_id={page_id: "Body text only"},
        page_context_by_page_id={page_id: {
            "source_page": 23,
            "image_size_pixels": (2550, 3300),
        }},
    )[0]

    assert page.latex == latex
    assert not any(issue.code == "BOUNDARY_FOLIO_REMOVED" for issue in page.issues)


def test_bbox_disagreement_reports_host_dimensions_and_both_coordinate_forms():
    page_id = make_page_id(1)
    figure = {
        "path": "figures/page_0023_figure_01.png",
        "index": 1,
        "bbox_normalized": [0.30, 0.10, 0.70, 0.30],
        # A model-internal 0..1000 grid is not an original-raster pixel bbox.
        "bbox_pixels": [300, 100, 700, 300],
    }

    with pytest.raises(OcrBatchValidationError) as caught:
        validate_ocr_batch_response(
            _response(
                page_id,
                "Visible text.\n"
                "\\includegraphics{figures/page_0023_figure_01.png}",
                figures=[figure],
            ),
            [page_id],
            page_context_by_page_id={page_id: {
                "source_page": 23,
                "image_size_pixels": (1700, 2200),
            }},
        )

    message = str(caught.value)
    assert caught.value.code == "INVALID_FIGURES"
    assert "bbox_normalized=[0.3, 0.1, 0.7, 0.3]" in message
    assert "bbox_pixels=[300, 100, 700, 300]" in message
    assert "image_size_pixels=[1700, 2200]" in message
    assert "expected_pixels=[510.0, 220.0, 1190.0, 660.0]" in message


@pytest.mark.parametrize(
    "figure,latex",
    [
        (
            {
                "path": "../../escape.png", "index": 1,
                "bbox_normalized": [0.1, 0.2, 0.6, 0.7],
                "bbox_pixels": [100, 400, 600, 1400],
            },
            "Visible text.\\n\\includegraphics{../../escape.png}",
        ),
        (
            {
                "path": "figures/page_0007_figure_01.png", "index": 1,
                "bbox_normalized": [0, 0, 1, 1],
                "bbox_pixels": [0, 0, 1000, 2000],
            },
            "Visible text.\\n\\includegraphics{figures/page_0007_figure_01.png}",
        ),
        (
            {
                "path": "figures/page_0007_figure_01.png", "index": 1,
                "bbox_normalized": [0.1, 0.2, 0.6, 0.7],
                "bbox_pixels": [300, 400, 800, 1400],
            },
            "Visible text.\\n\\includegraphics{figures/page_0007_figure_01.png}",
        ),
    ],
)
def test_batch_validator_rejects_untrusted_figure_evidence(figure, latex):
    page_id = make_page_id(1)
    with pytest.raises(OcrBatchValidationError) as caught:
        validate_ocr_batch_response(
            _response(page_id, latex, figures=[figure]),
            [page_id],
            page_context_by_page_id={page_id: {
                "source_page": 7,
                "image_size_pixels": (1000, 2000),
            }},
        )
    assert caught.value.code == "INVALID_FIGURES"


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
        ("Codex 分析超时，原项目保持不变", OcrErrorCategory.TRANSIENT),
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


def test_ocr_request_payload_exposes_current_raster_dimensions_for_pixel_bboxes():
    request = OcrPageRequest(
        make_page_id(23),
        23,
        23,
        b"page-23-at-300-dpi",
        300,
        image_size_pixels=(2550, 3300),
    )

    payload = json.loads(ocr_batch_request_payload([request]))["page_requests"][0]

    assert payload["dpi"] == 300
    assert payload["image_size_pixels"] == [2550, 3300]
    assert "0..1000" in payload["bbox_pixel_policy"]


def test_retry_payload_binds_formula_crop_hashes_and_image_order():
    request = OcrPageRequest(
        make_page_id(1),
        9,
        1,
        b"full-page",
        300,
        crops=(b"crop-one", b"crop-two"),
    )

    payload = json.loads(ocr_batch_request_payload([request]))["page_requests"][0]

    assert [item["image_index"] for item in payload["formula_crop_evidence"]] == [2, 3]
    assert payload["formula_crop_evidence"][0]["sha256"] == hashlib.sha256(
        b"crop-one"
    ).hexdigest()


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


def test_invalid_shared_batch_emits_one_private_attempt_before_three_singles():
    requests = [
        OcrPageRequest(make_page_id(index), index, index, b"image", 200)
        for index in range(1, 4)
    ]
    events: list[tuple[str, str]] = []
    attempts: list[OcrBatchAttemptEvidence] = []

    invalid_batch = {
        "pages": [_response(make_page_id(1))],  # missing pages 2 and 3
        "Authorization": "Bearer should-never-be-saved",
        "debug_path": r"C:\Users\ZQY\private\page.png",
    }

    def on_batch_attempt(attempt):
        attempts.append(attempt)
        events.append(("batch", attempt.batch_id))

    def single_call(request):
        events.append(("single", request.page_id))
        return _response(request.page_id)

    results = BoundedOcrExecutor(batch_size=3, concurrency_limit=1).run(
        requests,
        single_call=single_call,
        batch_call=lambda _requests: invalid_batch,
        on_batch_attempt=on_batch_attempt,
    )

    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.classification == "VALIDATION:MISSING_PAGE_ID"
    assert attempt.page_ids == tuple(request.page_id for request in requests)
    assert attempt.fallback_to_single is True
    assert events[0] == ("batch", attempt.batch_id)
    assert [result.request.page_id for result in results] == list(attempt.page_ids)
    assert all(result.fell_back_to_single for result in results)
    assert {result.batch_id for result in results} == {attempt.batch_id}
    serialized = json.dumps(attempt.to_dict(), ensure_ascii=False)
    assert "should-never-be-saved" not in serialized
    assert r"C:\\Users\\ZQY" not in serialized
    assert "[REDACTED_CREDENTIAL]" in serialized
    assert "[REDACTED_ABSOLUTE_PATH]" in serialized
    with pytest.raises(TypeError):
        attempt.raw_response["pages"] = []


def test_fallback_provider_error_emits_sanitized_batch_attempt_once():
    requests = [
        OcrPageRequest(make_page_id(index), index, index, b"image", 200)
        for index in (1, 2)
    ]
    attempts: list[OcrBatchAttemptEvidence] = []

    results = BoundedOcrExecutor(batch_size=2, concurrency_limit=1).run(
        requests,
        single_call=lambda request: _response(request.page_id),
        batch_call=lambda _requests: (_ for _ in ()).throw(
            RuntimeError(
                r"temporary timeout at /workspace/private/request.json "
                "Authorization=sk-privatecredential"
            )
        ),
        on_batch_attempt=attempts.append,
    )

    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.classification == "PROVIDER:TRANSIENT"
    assert attempt.raw_response is None
    assert len(attempt.error_sha256) == 64
    assert "workspace" not in attempt.error_summary
    assert "privatecredential" not in attempt.error_summary
    assert {result.batch_id for result in results} == {attempt.batch_id}


def test_batch_evidence_path_redaction_preserves_latex_math_commands():
    mathematical_text = (
        r"u\in V:\lvert N(u)\cap B\rvert and x\in C:\mathcal{P}(X)"
    )
    attempt = OcrBatchAttemptEvidence.provider_failure(
        batch_id="ocr-batch-math",
        page_ids=(make_page_id(1),),
        error=(
            mathematical_text
            + r"; diagnostics=C:\Users\ZQY\private\request.json"
        ),
        category=OcrErrorCategory.UNKNOWN,
    )

    assert mathematical_text in attempt.error_summary
    assert r"C:\Users\ZQY" not in attempt.error_summary
    assert "[REDACTED_ABSOLUTE_PATH]" in attempt.error_summary


def test_single_results_are_emitted_before_slowest_sibling_finishes():
    requests = [
        OcrPageRequest(make_page_id(index), index, index, b"image", 200)
        for index in range(1, 4)
    ]
    slow_finished = threading.Event()
    emitted: list[tuple[int, bool]] = []

    def single_call(request):
        if request.source_page == 3:
            time.sleep(0.25)
            slow_finished.set()
        else:
            time.sleep(0.01)
        return _response(request.page_id)

    results = BoundedOcrExecutor(batch_size=1, concurrency_limit=3).run(
        requests,
        single_call=single_call,
        on_result=lambda result: emitted.append(
            (result.request.source_page, slow_finished.is_set())
        ),
    )

    assert [result.request.source_page for result in results] == [1, 2, 3]
    assert sorted(page for page, _ in emitted) == [1, 2, 3]
    assert any(page in {1, 2} and not was_slow_done for page, was_slow_done in emitted)


def test_auth_pause_still_persists_already_inflight_successful_sibling():
    requests = [
        OcrPageRequest(make_page_id(index), index, index, b"image", 200)
        for index in (1, 2)
    ]
    emitted: list[int] = []

    def single_call(request):
        if request.source_page == 1:
            raise RuntimeError("HTTP 401 invalid API key")
        time.sleep(0.05)
        return _response(request.page_id)

    with pytest.raises(OcrRunPaused) as caught:
        BoundedOcrExecutor(batch_size=1, concurrency_limit=2).run(
            requests,
            single_call=single_call,
            on_result=lambda result: emitted.append(result.request.source_page),
        )

    assert caught.value.category == OcrErrorCategory.AUTH
    assert emitted == [2]


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


def test_failed_pages_do_not_count_as_recognized_or_unlock_later_milestones():
    snapshot = _snapshot(pages=tuple(range(1, 38)), source_total_pages=37)
    response_sha = hashlib.sha256(b"response").hexdigest()
    records = [
        OcrPageRecord(
            page_id=make_page_id(index),
            source_page=index,
            task_index=index,
            status=OcrPageStatus.SUCCESS,
            raw_response_sha256=response_sha,
            raw_tex="Recognized page.",
            cleaned_tex="Recognized page.",
        )
        if index <= 3
        else OcrPageRecord(
            page_id=make_page_id(index),
            source_page=index,
            task_index=index,
            status=OcrPageStatus.FAILED,
            error_reason="provider failed",
        )
        for index in range(1, 38)
    ]

    metrics = progress_metrics(
        snapshot,
        records,
        # Exercise the fail-closed boundary with every optimistic flag set.
        merge_complete=True,
        raw_frozen=True,
        compile_status=OcrPreviewStatus.COMPILED,
    )

    assert metrics["attempt_progress"] == 1.0
    assert metrics["recognition_progress"] == round(3 / 37, 6)
    assert metrics["overall_progress"] < 0.1
    assert metrics["merge_complete"] is False
    assert metrics["raw_frozen"] is False
    assert metrics["compile_status"] == "COMPILED"


@pytest.mark.parametrize(
    ("merge_complete", "raw_frozen", "compile_status", "is_complete"),
    [
        (True, True, OcrPreviewStatus.COMPILED, True),
        (False, True, OcrPreviewStatus.COMPILED, False),
        (True, False, OcrPreviewStatus.COMPILED, False),
        (False, False, OcrPreviewStatus.COMPILED, False),
        (True, True, OcrPreviewStatus.PARTIAL_COMPILED, False),
        (True, True, OcrPreviewStatus.SOURCE_PREVIEW, False),
    ],
)
def test_overall_progress_requires_compiled_merge_and_raw_freeze(
    merge_complete,
    raw_frozen,
    compile_status,
    is_complete,
):
    snapshot = _snapshot()
    records = [
        _success(OcrPageRecord.pending(index, index), _response(make_page_id(index)))
        for index in (1, 2)
    ]

    metrics = progress_metrics(
        snapshot,
        records,
        merge_complete=merge_complete,
        raw_frozen=raw_frozen,
        compile_status=compile_status,
    )

    assert (metrics["overall_progress"] == 1.0) is is_complete


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

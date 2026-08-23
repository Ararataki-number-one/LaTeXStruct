from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunStore,
    make_run_snapshot,
)
from latexstruct.server import app as srv
from latexstruct.store import ProjectStore


def _persist_result(
    store: OcrRunStore,
    run_id: str,
    task_index: int,
    source_page: int,
    *,
    success: bool,
) -> None:
    image = b"\x89PNG\r\n\x1a\n" + f"rendered-page-{source_page}".encode()
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    record = OcrPageRecord.pending(task_index, source_page)
    record = record.transition(OcrPageStatus.RENDERING, dpi=200)
    record = record.transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=200,
        model="vision-test",
        call_index=1,
        started_at=started_at,
    )
    store.persist_page_image(run_id, record, image)
    if not success:
        store.persist_record(
            run_id,
            record.transition(
                OcrPageStatus.FAILED,
                ended_at=datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                ),
                error_reason="provider interrupted",
            ),
        )
        return
    raw = {
        "page_id": record.page_id,
        "latex": f"Recovered page {source_page}.",
        "figures": [],
        "unresolved_regions": [],
    }
    raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    record = record.transition(OcrPageStatus.VALIDATING)
    record = record.transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_tex=raw["latex"],
        cleaned_tex=raw["latex"],
        ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    store.persist_record(run_id, record, raw_response=raw)


def _setup_store(tmp_path: Path, pages: tuple[int, ...]) -> tuple[OcrRunStore, str]:
    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nrestart evidence\n"
    run_id = "b" * 32
    snapshot = make_run_snapshot(
        source_bytes=source,
        source_type="pdf",
        original_filename="中文恢复.pdf",
        source_total_pages=max(pages),
        selected_pages=pages,
        ocr_model="vision-test",
        api_backend="api",
        app_version="2.0.0",
        run_id=run_id,
    )
    store = OcrRunStore(tmp_path / "ocr-runs")
    store.initialize(snapshot, source)
    return store, run_id


def test_status_reconstructs_partial_run_from_immutable_snapshot(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (4, 5))
    _persist_result(store, run_id, 1, 4, success=True)
    _persist_result(store, run_id, 2, 5, success=False)
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()
    response = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}")
    assert response.status_code == 200
    state = response.json()
    assert state["status"] == "partial"
    assert state["recovered_after_restart"] is True
    assert state["can_resume"] is True
    assert state["pages"]["4"]["status"] == "done"
    assert state["pages"]["5"]["status"] == "error"
    assert state["progress"] < 1.0
    assert str(tmp_path) not in response.text


def test_completed_run_restores_and_serves_only_hash_verified_artifacts(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    store.freeze_raw_ocr(run_id)
    store.save_compile_baseline(
        run_id,
        baseline_tex="Recovered page 1.",
        compile_log="two successful passes",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.7\ncompiled\n",
    )
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()
    client = TestClient(srv.create_app())
    state = client.get(f"/api/ocr/jobs/{run_id}").json()
    assert state["status"] == "done"
    assert state["quality_report"]["counts"]["missing_provenance_pages"] == 0
    assert state["quality_report"]["resources"]["source_pages"] == 1
    assert state["pages"]["1"]["visual_input_persisted"] is True
    assert state["progress_metrics"]["elapsed_frozen"] is True
    assert state["artifacts"]["baseline_pdf"]["available"] is True
    assert client.get(f"/api/ocr/jobs/{run_id}/pages/1").status_code == 200
    raw = client.get(f"/api/ocr/jobs/{run_id}/artifacts/raw-ocr")
    assert raw.status_code == 200
    assert hashlib.sha256(raw.content).hexdigest() == raw.headers["x-latexstruct-sha256"]
    bad = client.get(f"/api/ocr/jobs/{run_id}/artifacts/../../secret")
    assert bad.status_code in {404, 405}


def test_restore_does_not_promote_missing_persisted_visual_evidence(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    for page_image in (store.run_dir(run_id) / "page-images").iterdir():
        page_image.unlink()
    store.freeze_raw_ocr(run_id)
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    state = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}").json()

    assert state["status"] == "done"
    assert state["pages"]["1"]["visual_input_persisted"] is False
    assert state["quality_report"]["counts"]["missing_provenance_pages"] == 1
    assert state["quality_report"]["resources"]["source_pages"] == 0


def test_bundle_snapshot_exports_page_telemetry_without_local_paths():
    source = b"%PDF-1.7\ntelemetry\n"
    runtime_snapshot = make_run_snapshot(
        source_bytes=source,
        source_type="pdf",
        original_filename="中文证据.pdf",
        source_total_pages=1,
        selected_pages=(1,),
        ocr_model="vision-test",
        api_backend="codex_cli",
        app_version="2.0.0",
        run_id="c" * 32,
    )
    image_sha = hashlib.sha256(b"page-image").hexdigest()
    raw_response_sha = hashlib.sha256(b"response").hexdigest()
    record = OcrPageRecord(
        page_id="ocr-page-000001",
        source_page=1,
        task_index=1,
        status=OcrPageStatus.SUCCESS,
        image_sha256=image_sha,
        image_size_pixels=(1200, 1800),
        dpi=300,
        model="vision-test",
        call_index=2,
        raw_response_sha256=raw_response_sha,
        raw_tex="Telemetry page.",
        cleaned_tex="Telemetry page.",
        started_at="2026-08-24T00:00:00Z",
        ended_at="2026-08-24T00:00:12Z",
        elapsed_seconds=12.0,
        retry_count=1,
        quality_issues=({"code": "OCR_RETRY_SCHEDULED"},),
        usage={"attempts": [{"usage": {"total_tokens": 123}}]},
    )
    live_job = {
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "source_outline": [],
        "_source_sha256": runtime_snapshot.source_sha256,
        "target": "C:/private/source.pdf",
        "status": "done",
        "quality_profile": "standard",
        "backend": "codex_cli",
        "model": "vision-test",
        "reasoning_effort": "low",
        "dpi": 200,
        "raw_ready": True,
        "raw_frozen": True,
        "compile_status": "COMPILED",
        "_v2_snapshot": runtime_snapshot,
        "current_concurrency_limit": 3,
        "pages": {
            1: {
                "status": "done",
                "attempts": 2,
                "image_size_pixels": [1200, 1800],
                "visual_input_sha256": image_sha,
                "visual_input_persisted": True,
            }
        },
    }

    frozen = srv._snapshot_ocr_bundle_job(live_job, v2_records=[record])
    manifest_page = srv._ocr_manifest_page_records(frozen)[0]

    assert frozen["performance_metrics"]["counts"]["success"] == 1
    assert frozen["ocr_run_snapshot"]["concurrency_limit"] == 3
    exported_telemetry = json.dumps({
        "run_snapshot": frozen["ocr_run_snapshot"],
        "performance_metrics": frozen["performance_metrics"],
        "page": manifest_page,
    }, ensure_ascii=False)
    assert "C:/private" not in exported_telemetry
    assert manifest_page["telemetry"] == {
        "page_id": "ocr-page-000001",
        "status": "SUCCESS",
        "task_index": 1,
        "dpi": 300,
        "model": "vision-test",
        "call_index": 2,
        "batch_call": False,
        "batch_id": "",
        "started_at": "2026-08-24T00:00:00Z",
        "ended_at": "2026-08-24T00:00:12Z",
        "elapsed_seconds": 12.0,
        "retry_count": 1,
        "raw_response_sha256": raw_response_sha,
        "tex_sha256": record.tex_sha256,
        "usage": {"attempts": [{"usage": {"total_tokens": 123}}]},
        "quality_issues": [{"code": "OCR_RETRY_SCHEDULED"}],
        "unresolved_regions": [],
        "terminal_error": "",
    }

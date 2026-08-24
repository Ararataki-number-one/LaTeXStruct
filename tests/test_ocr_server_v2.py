from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunStore,
    OcrStoreError,
    make_page_id,
    make_run_snapshot,
)
from latexstruct.core.ocr_baseline import OcrBaselineResult
from latexstruct.core.ocr_recovery import (
    AttemptOutcome,
    OcrRecoveryEvidenceStore,
    RecoveryImageInput,
    RecoveryImageRole,
    RecoveryStage,
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


def _persist_recovery_attempt(
    store: OcrRunStore,
    run_id: str,
    task_index: int,
    source_page: int,
    *,
    outcome: AttemptOutcome,
    total_tokens: int,
) -> Path:
    image = b"\x89PNG\r\n\x1a\n" + f"rendered-page-{source_page}".encode()
    recovery_root = store.run_dir(run_id) / "recovery-evidence"
    recovery = OcrRecoveryEvidenceStore(recovery_root)
    recovery.record_attempt(
        run_id=run_id,
        page_id=make_page_id(task_index),
        source_page=source_page,
        task_index=task_index,
        stage=RecoveryStage.INITIAL_READ,
        outcome=outcome,
        base_dpi=200,
        dpi=200,
        model="vision-test",
        backend="api",
        model_context_id=f"context-{task_index}",
        images=(RecoveryImageInput(
            role=RecoveryImageRole.FULL_PAGE,
            content=image,
            dpi=200,
            width_pixels=1200,
            height_pixels=1800,
        ),),
        raw_response=json.dumps({"page": source_page, "outcome": outcome.value}),
        duration_ms=10,
        usage={
            "prompt_tokens": total_tokens - 1,
            "completion_tokens": 1,
            "total_tokens": total_tokens,
        },
        error=("provider interrupted" if outcome is AttemptOutcome.FAILED else None),
        tex_sha256=(
            hashlib.sha256(f"Recovered page {source_page}.".encode()).hexdigest()
            if outcome is AttemptOutcome.PASSED else ""
        ),
    )
    return recovery_root


def test_status_reconstructs_partial_run_from_immutable_snapshot(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (4, 5))
    _persist_result(store, run_id, 1, 4, success=True)
    _persist_result(store, run_id, 2, 5, success=False)
    recovery_root = _persist_recovery_attempt(
        store, run_id, 1, 4,
        outcome=AttemptOutcome.PASSED,
        total_tokens=11,
    )
    _persist_recovery_attempt(
        store, run_id, 2, 5,
        outcome=AttemptOutcome.FAILED,
        total_tokens=13,
    )
    evidence_before = {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in recovery_root.rglob("*") if path.is_file()
    }
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
    assert state["usage"]["calls"] == 2
    assert state["usage"]["total_tokens"] == 24
    assert state["usage_revision"] == 2
    assert state["pages"]["4"]["recovery_attempt_count"] == 1
    assert state["pages"]["5"]["recovery_status"] == "FAILED"
    assert state["progress_metrics"]["attempt_progress"] == 1.0
    assert state["progress_metrics"]["recognition_progress"] == 0.5
    assert state["progress_metrics"]["merge_complete"] is False
    assert state["progress"] < 0.5
    assert state["progress"] < 1.0
    assert str(tmp_path) not in response.text
    assert evidence_before == {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in recovery_root.rglob("*") if path.is_file()
    }


def test_partial_raw_preview_does_not_unlock_merge_progress(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (4, 5))
    _persist_result(store, run_id, 1, 4, success=True)
    _persist_result(store, run_id, 2, 5, success=False)
    snapshot = store.load_snapshot(run_id)
    job = {
        "id": run_id,
        "status": "partial",
        "selected_pages": [4, 5],
        "pages": {
            4: {"status": "done", "task_index": 1},
            5: {"status": "error", "task_index": 2},
        },
        "raw_tex": "% Page 4\nRecovered page 4.",
        # This legacy field intentionally means a partial preview is available.
        "raw_ready": True,
        "raw_frozen": False,
        "_v2_store": store,
        "_v2_snapshot": snapshot,
        "current_concurrency_limit": 3,
    }

    state = srv._public_ocr_job(job)

    assert state["raw_ready"] is True
    assert state["progress_metrics"]["recognition_progress"] == 0.5
    assert state["progress_metrics"]["merge_complete"] is False
    assert state["progress"] < 0.5


def test_restart_resume_retries_only_failed_page_and_second_resume_freezes(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1, 2))
    _persist_result(store, run_id, 1, 1, success=True)
    _persist_result(store, run_id, 2, 2, success=False)
    recovery_root = _persist_recovery_attempt(
        store, run_id, 1, 1,
        outcome=AttemptOutcome.PASSED,
        total_tokens=17,
    )
    _persist_recovery_attempt(
        store, run_id, 2, 2,
        outcome=AttemptOutcome.FAILED,
        total_tokens=19,
    )
    original_chain = {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (recovery_root / run_id).rglob("*") if path.is_file()
    }
    successful_before = store.load_record(run_id, make_page_id(1)).to_dict()
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    calls: list[int] = []
    systems: list[str] = []

    class ResumeClient:
        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage = {}

        def chat_vision_json_bytes(self, system, user, _image, _schema, **_kwargs):
            request = json.loads(user)["page_requests"][0]
            source_page = int(request["source_page"])
            calls.append(source_page)
            systems.append(system)
            if len(calls) == 1:
                raise RuntimeError("synthetic permanent resume failure")
            usage = {
                "prompt_tokens": 22,
                "completion_tokens": 3,
                "total_tokens": 25,
            }
            self.last_usage = usage
            return ({"pages": [{
                "page_id": request["page_id"],
                "latex": "Recovered failed page two after the fixed prompt.\n\n2",
                "figures": [],
                "unresolved_regions": [],
            }]}, usage)

    client_instance = ResumeClient()

    def fake_render(_path, pages, _dpi):
        source_page = int(pages[0])
        yield source_page, b"\x89PNG\r\n\x1a\n" + bytes([source_page]) * 32

    baseline = OcrBaselineResult(
        tex="twice compiled resumed baseline",
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\nresumed compiled\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    fixed_prompt = "FIXED OCR PROMPT WITH CURRENT image_size_pixels"
    app = srv.create_app()
    http = TestClient(app)
    restored = http.get(f"/api/ocr/jobs/{run_id}").json()
    assert restored["usage"]["calls"] == 2
    assert restored["usage"]["total_tokens"] == 36

    with (
        patch.object(
            srv,
            "_build_ocr_client",
            return_value=(client_instance, "vision-test", "api"),
        ),
        patch.object(srv, "OCR_TRANSCRIPTION_SYSTEM_PROMPT", fixed_prompt),
        patch("latexstruct.ocr.iter_pdf_pages", fake_render),
        patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
        patch("latexstruct.server.app._prepare_page_formula_evidence", return_value=[]),
        patch("latexstruct.core.ocr_baseline.compile_ocr_baseline", return_value=baseline),
    ):
        first_resume = http.post(f"/api/ocr/jobs/{run_id}/resume")
        assert first_resume.status_code == 200, first_resume.text
        for _ in range(200):
            first_terminal = http.get(f"/api/ocr/jobs/{run_id}").json()
            if first_terminal["status"] == "partial" and first_terminal.get("terminal_epoch"):
                break
            time.sleep(0.01)
        assert first_terminal["status"] == "partial", first_terminal
        assert calls == [2], first_terminal
        assert first_terminal["pages"]["1"]["status"] == "done"

        second_resume = http.post(f"/api/ocr/jobs/{run_id}/resume")
        assert second_resume.status_code == 200, second_resume.text
        for _ in range(300):
            final = http.get(f"/api/ocr/jobs/{run_id}").json()
            if final["status"] == "done":
                break
            time.sleep(0.01)

    assert final["status"] == "done", final
    assert final["raw_frozen"] is True
    assert final["compile_status"] == "COMPILED"
    assert final["baseline_compile"]["successful_passes"] == 2
    assert final["usage"]["calls"] == 3
    assert final["usage"]["total_tokens"] == 61
    assert calls == [2, 2]
    assert systems == [fixed_prompt, fixed_prompt]
    assert store.load_record(run_id, make_page_id(1)).to_dict() == successful_before
    resumed_record = store.load_record(run_id, make_page_id(2))
    assert resumed_record.raw_tex.endswith("\n\n2")
    assert resumed_record.cleaned_tex == "Recovered failed page two after the fixed prompt."
    assert original_chain == {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (recovery_root / run_id).rglob("*") if path.is_file()
    }
    recovery_runs = [
        path for path in recovery_root.iterdir()
        if path.is_dir() and path.name != run_id
    ]
    assert len(recovery_runs) == 2


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


def test_analysis_entry_uses_only_hash_verified_twice_compiled_baseline(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    store.freeze_raw_ocr(run_id)
    store.save_compile_baseline(
        run_id,
        baseline_tex="Syntax repaired baseline.",
        compile_log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.7\ncompiled\n",
    )
    runtime = {
        "_v2_store": store,
        "_v2_snapshot": store.load_snapshot(run_id),
        "raw_tex": "uncompiled raw",
    }

    baseline, lineage = srv._verified_v2_baseline_for_analysis(runtime)

    assert baseline == "Syntax repaired baseline."
    assert lineage["verified"] is True
    assert lineage["successful_passes"] == 2
    assert lineage["source"] == "twice_compiled_syntax_baseline"
    baseline_path = store.run_dir(run_id) / "artifacts" / "baseline.tex"
    baseline_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        srv._verified_v2_baseline_for_analysis(runtime)


def test_restore_does_not_promote_missing_persisted_visual_evidence(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    for page_image in (store.run_dir(run_id) / "page-images").iterdir():
        page_image.unlink()
    store.freeze_raw_ocr(run_id)
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    state = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}").json()

    assert state["status"] == "partial"
    assert state["pages"]["1"]["visual_input_persisted"] is False
    assert state["quality_report"]["counts"]["missing_provenance_pages"] == 1
    assert state["quality_report"]["resources"]["source_pages"] == 0


def test_restart_keeps_needs_review_page_retryable_and_unfrozen(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    image = b"\x89PNG\r\n\x1a\nreview-page"
    record = store.load_record(run_id, make_page_id(1))
    record = record.transition(OcrPageStatus.RENDERING, dpi=300).transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=300,
        model="vision-test",
        call_index=2,
    )
    store.persist_record(run_id, record)
    store.persist_page_image(run_id, record, image)
    raw = {
        "page_id": record.page_id,
        "latex": "Visible content that still needs confirmation.",
        "figures": [],
        "unresolved_regions": [{
            "type": "formula",
            "reason": "operator is not legible",
            "bbox_normalized": [0.2, 0.2, 0.4, 0.3],
        }],
    }
    raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    record = record.transition(OcrPageStatus.VALIDATING).transition(
        OcrPageStatus.NEEDS_REVIEW,
        raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_tex=raw["latex"],
        cleaned_tex=raw["latex"],
        unresolved_regions=tuple(raw["unresolved_regions"]),
    )
    store.persist_record(run_id, record, raw_response=raw)
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    state = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}").json()

    assert state["status"] == "partial"
    assert state["raw_frozen"] is False
    assert state["pages"]["1"]["needs_review"] is True
    assert state["can_resume"] is True


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
        "recovery": {
            "run_id": "",
            "stage": "",
            "status": "",
            "attempt_count": 0,
            "evidence_chain_sha256": "",
        },
    }


def test_recovery_json_evidence_is_preserved_and_hash_verified_without_host_path(
    tmp_path: Path,
):
    root = tmp_path / "private-recovery-root"
    page = root / ("a" * 32) / "pages" / "ocr-page-000001"
    attempts = page / "attempts"
    attempts.mkdir(parents=True)
    attempt = {
        "schema_version": "latexstruct-ocr-recovery-attempt-v2",
        "record_sha256": "b" * 64,
    }
    (attempts / "000001-attempt01.json").write_text(
        json.dumps(attempt), encoding="utf-8"
    )
    (page / "state.json").write_text(
        json.dumps({"status": "SUCCESS"}), encoding="utf-8"
    )
    (root / ("a" * 32) / "blobs").mkdir()
    (root / ("a" * 32) / "blobs" / "secret").write_bytes(b"not packaged")

    project = tmp_path / "project"
    project.mkdir()
    rows = srv._preserve_ocr_recovery_evidence(
        {"_recovery_evidence_root": str(root)}, project
    )
    files = srv._verified_ocr_recovery_resource_bytes(
        project, {"recovery_evidence": rows}
    )

    assert len(rows) == 2
    assert all(str(tmp_path) not in json.dumps(row) for row in rows)
    assert all(path.startswith("evidence/ocr-recovery/") for path in files)
    assert not any("blobs" in path for path in files)
    tampered = project / Path(rows[0]["path"])
    tampered.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="校验失败"):
        srv._verified_ocr_recovery_resource_bytes(
            project, {"recovery_evidence": rows}
        )


def test_ocr_bundle_contains_recovery_journal_without_host_paths(tmp_path: Path):
    source = tmp_path / "中文原始输入.pdf"
    source.write_bytes(b"%PDF-1.7\nimmutable source\n")
    recovery_root = tmp_path / "private-recovery-root"
    page = recovery_root / ("d" * 32) / "pages" / "ocr-page-000001"
    attempts = page / "attempts"
    attempts.mkdir(parents=True)
    attempt_bytes = json.dumps({
        "schema_version": "latexstruct-ocr-recovery-attempt-v2",
        "record_sha256": "e" * 64,
    }).encode("utf-8")
    (attempts / "000001-attempt01.json").write_bytes(attempt_bytes)
    state_bytes = json.dumps({"status": "NEEDS_REVIEW"}).encode("utf-8")
    (page / "state.json").write_bytes(state_bytes)

    source_bytes = source.read_bytes()
    bundle, manifest = srv._ocr_bundle_bytes({
        "target": str(source),
        "_source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "_recovery_evidence_root": str(recovery_root),
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "pages": {},
        "status": "partial",
    }, "Recovered page 1.")

    assert len(manifest["recovery_evidence"]) == 2
    assert all(
        item["path"].startswith("evidence/ocr-recovery/")
        for item in manifest["recovery_evidence"]
    )
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        names = set(archive.namelist())
        for item in manifest["recovery_evidence"]:
            assert item["path"] in names
            assert hashlib.sha256(archive.read(item["path"])).hexdigest() == item["sha256"]
        manifest_bytes = archive.read("OCR-MANIFEST.json")
    assert str(tmp_path).encode("utf-8") not in bundle
    assert str(tmp_path).encode("utf-8") not in manifest_bytes


def test_ocr_bundle_manifest_redacts_historical_page_record_errors(tmp_path: Path):
    source = tmp_path / "source.pdf"
    source_bytes = b"%PDF-1.7\nimmutable source\n"
    source.write_bytes(source_bytes)
    runtime_snapshot = make_run_snapshot(
        source_bytes=source_bytes,
        source_type="pdf",
        original_filename="source.pdf",
        source_total_pages=1,
        selected_pages=(1,),
        ocr_model="vision-test",
        api_backend="api",
        app_version="2.0.0",
        run_id="f" * 32,
    )
    secret = "super-secret-token-123456"
    windows_path = r"C:\Users\ZQY\private\ocr.log"
    posix_path = "/home/zqy/private/ocr.log"
    unsafe = (
        f"Authorization: Bearer {secret} failed at {windows_path}; "
        f"trace {posix_path}"
    )
    record = OcrPageRecord(
        page_id=make_page_id(1),
        source_page=1,
        task_index=1,
        status=OcrPageStatus.FAILED,
        quality_issues=({
            "code": "OCR_CALL_FAILED",
            "message": unsafe,
            "Authorization": secret,
        },),
        unresolved_regions=({"reason": unsafe},),
        usage={"provider_error": unsafe, "api_key": secret},
        error_reason=unsafe,
    )
    frozen = srv._snapshot_ocr_bundle_job({
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "_source_sha256": runtime_snapshot.source_sha256,
        "target": str(source),
        "status": "partial",
        "backend": "api",
        "model": "vision-test",
        "_v2_snapshot": runtime_snapshot,
        "pages": {1: {"status": "error", "error": unsafe}},
    }, v2_records=[record])

    bundle, manifest = srv._ocr_bundle_bytes(frozen, "Recovered page.")

    manifest_text = json.dumps(manifest, ensure_ascii=False)
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        archived_manifest = archive.read("OCR-MANIFEST.json").decode("utf-8")
    for payload in (manifest_text, archived_manifest):
        assert secret not in payload
        assert windows_path not in payload
        assert posix_path not in payload
        assert "<REDACTED>" in payload
        assert "<LOCAL_PATH>" in payload

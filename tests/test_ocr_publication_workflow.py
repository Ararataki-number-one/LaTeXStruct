from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from latexstruct.server import app as server


_ONE_PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _terminal_job(job_id: str, *, low_conf: bool = False) -> dict:
    return {
        "id": job_id,
        "status": "done",
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "raw_tex": "\\documentclass{article}\\begin{document}ok\\end{document}",
        "raw_ready": True,
        "raw_revision": 1,
        "raw_chars": 60,
        "usage_revision": 0,
        "page_revision": 1,
        "state_revision": 1,
        "quality_profile": "publication",
        "_source_sha256": "c" * 64,
        "backend": "codex_cli",
        "model": "gpt-test",
        "reasoning_effort": "medium",
        "dpi": 300,
        "pages": {
            1: {
                "status": "done",
                "attempts": 1,
                "image_size_pixels": [1000, 1500],
                "visual_input_sha256": "b" * 64,
                "low_conf": low_conf,
                "needs_review": low_conf,
                "quality_flags": [],
                "figures": [],
                "text_hint_chars": 10,
                "text_hint_sha256": "a" * 64,
            },
        },
    }


def test_quality_endpoint_reports_evidence_gate_without_publication_claim():
    job_id = "a" * 32
    server._ocr_jobs[job_id] = _terminal_job(job_id)
    try:
        with TestClient(server.create_app()) as client:
            response = client.get(f"/api/ocr/jobs/{job_id}/quality")
        assert response.status_code == 200
        report = response.json()
        assert report["page_gate_passed"] is True
        assert report["publication_readiness"] == "not_established"
        assert report["accuracy_measurement"] == "not_performed"
    finally:
        server._ocr_jobs.pop(job_id, None)


def test_publication_start_validates_profile_and_minimum_dpi_before_spending():
    with TestClient(server.create_app()) as client:
        invalid = client.post(
            "/api/ocr/jobs/missing/start",
            data={"quality_profile": "publication;unsafe", "dpi": "300"},
        )
        blurry = client.post(
            "/api/ocr/jobs/missing/start",
            data={"quality_profile": "publication", "dpi": "150"},
        )

    assert invalid.status_code == 400
    assert "standard" in invalid.json()["detail"]
    assert blurry.status_code == 400
    assert "200 DPI" in blurry.json()["detail"]


def test_publication_import_blocks_known_review_page_but_keeps_snapshot():
    job_id = "b" * 32
    job = _terminal_job(job_id, low_conf=True)
    server._ocr_jobs[job_id] = job
    try:
        with TestClient(server.create_app()) as client:
            response = client.post(f"/api/ocr/jobs/{job_id}/import")
        assert response.status_code == 409
        assert "低置信" in response.json()["detail"]
        assert server._ocr_jobs[job_id]["raw_tex"] == job["raw_tex"]
        assert server._ocr_jobs[job_id].get("importing") is not True
    finally:
        server._ocr_jobs.pop(job_id, None)


def test_bundle_manifest_binds_source_processing_and_resource_quality(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"source-pdf-identity")
    job = _terminal_job("c" * 32)
    job["target"] = str(source)
    job["_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    job["selected_pages"] = []
    job["pages"][1]["png"] = ""

    data, manifest = server._ocr_bundle_bytes(job, job["raw_tex"])

    assert manifest["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest["processing"] == {
        "profile": "publication",
        "transcription_source": "full_page_visual_plus_bounded_pdf_evidence",
        "backend": "codex_cli",
        "model": "gpt-test",
        "reasoning_effort": "medium",
        "dpi": 300,
        "target_template": "faithfulbook",
    }
    assert manifest["quality_report"]["publication_readiness"] == "not_established"
    assert manifest["quality_report"]["resource_gate_passed"] is True
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        stored = json.loads(archive.read("OCR-MANIFEST.json"))
    assert stored == manifest


def test_original_ocr_pdf_is_preserved_as_hash_bound_project_evidence(tmp_path):
    source = tmp_path / "upload.pdf"
    source.write_bytes(b"%PDF-1.7\nimmutable-source-evidence")
    project = tmp_path / "project"
    project.mkdir()
    job = _terminal_job("d" * 32)
    job["target"] = str(source)
    job["_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()

    record = server._preserve_original_ocr_source(job, project)

    stored = project / "ocr-source.pdf"
    assert stored.read_bytes() == source.read_bytes()
    assert record["path"] == "ocr-source.pdf"
    assert record["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert record["source_pages"] == 1
    assert record["immutable_evidence"] is True


def test_original_source_rejects_changed_upload_before_project_copy(tmp_path):
    source = tmp_path / "upload.pdf"
    original = b"%PDF-1.7\noriginal"
    source.write_bytes(original)
    project = tmp_path / "project"
    project.mkdir()
    job = _terminal_job("e" * 32)
    job["target"] = str(source)
    job["_source_sha256"] = hashlib.sha256(original).hexdigest()
    source.write_bytes(b"%PDF-1.7\nchanged-after-ocr")

    with pytest.raises(RuntimeError, match="哈希|改变"):
        server._preserve_original_ocr_source(job, project)

    assert list(project.glob("ocr-source.*")) == []


def test_publication_bundle_revalidates_page_pixels_instead_of_trusting_job_fields(
    tmp_path,
):
    source = tmp_path / "source.png"
    page = tmp_path / "page-1.img"
    source.write_bytes(_ONE_PIXEL_PNG)
    page.write_bytes(_ONE_PIXEL_PNG)
    job = _terminal_job("f" * 32)
    job.update({
        "source_type": "image",
        "target": str(source),
        "_source_sha256": hashlib.sha256(_ONE_PIXEL_PNG).hexdigest(),
    })
    job["pages"][1].update({
        "png": str(page),
        "image_size_pixels": [1, 1],
        "visual_input_sha256": hashlib.sha256(_ONE_PIXEL_PNG).hexdigest(),
    })

    _data, valid = server._ocr_bundle_bytes(job, job["raw_tex"])
    assert valid["quality_report"]["workflow_gate_passed"] is True

    page.write_bytes(_ONE_PIXEL_PNG + b"changed")
    _data, changed = server._ocr_bundle_bytes(job, job["raw_tex"])
    assert changed["quality_report"]["page_gate_passed"] is False
    assert changed["pages"][0]["visual_input_sha256"] == ""
    assert changed["evidence_errors"]

    page.unlink()
    _data, missing = server._ocr_bundle_bytes(job, job["raw_tex"])
    assert missing["quality_report"]["workflow_gate_passed"] is False


def test_ocr_import_failure_is_atomic_and_second_attempt_really_starts(
    tmp_path, monkeypatch,
):
    source = tmp_path / "source.png"
    page = tmp_path / "page-1.img"
    source.write_bytes(_ONE_PIXEL_PNG)
    page.write_bytes(_ONE_PIXEL_PNG)
    job_id = "1" * 32
    job = _terminal_job(job_id)
    job.update({
        "source_type": "image",
        "target": str(source),
        "_source_sha256": hashlib.sha256(_ONE_PIXEL_PNG).hexdigest(),
        "output_template": "faithfulbook",
    })
    job["pages"][1].update({
        "png": str(page),
        "image_size_pixels": [1, 1],
        "visual_input_sha256": hashlib.sha256(_ONE_PIXEL_PNG).hexdigest(),
    })
    old_store = server._store
    server._process_jobs.clear()
    server._store = server.ProjectStore(str(tmp_path / "projects"))
    server._ocr_jobs[job_id] = job
    try:
        with monkeypatch.context() as local_patch:
            local_patch.setattr(
                server._process_jobs,
                "create",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("synthetic launch failure")
                ),
            )
            with TestClient(server.create_app(), raise_server_exceptions=False) as client:
                failed = client.post(
                    f"/api/ocr/jobs/{job_id}/import",
                    params={"mode": "rule"},
                )
        assert failed.status_code == 500
        assert server._store.list() == []
        assert not job.get("imported_project_id")
        assert job.get("importing") is False

        real_thread_start = server.threading.Thread.start

        def start_except_background_pipeline(thread):
            if str(thread.name).startswith("latexstruct-"):
                return None
            return real_thread_start(thread)

        with TestClient(server.create_app()) as client:
            with monkeypatch.context() as local_patch:
                local_patch.setattr(
                    server.threading.Thread,
                    "start",
                    start_except_background_pipeline,
                )
                retried = client.post(
                    f"/api/ocr/jobs/{job_id}/import",
                    params={"mode": "rule"},
                )
        assert retried.status_code == 200
        assert retried.json().get("reused") is not True
        assert retried.json()["process"]["pid"] == retried.json()["id"]
    finally:
        server._process_jobs.clear()
        server._ocr_jobs.pop(job_id, None)
        server._store = old_store


def test_ocr_project_packages_include_hash_verified_source_and_quality(
    tmp_path,
):
    old_store = server._store
    store = server.ProjectStore(str(tmp_path / "projects"))
    server._store = store
    try:
        pid = store.create(
            "\\documentclass{article}\\begin{document}ok\\end{document}",
            "evidence-package",
            "rule",
            kind="ocr",
        )
        project_dir = tmp_path / "projects" / pid
        source_bytes = b"%PDF-1.7\nimmutable-project-source"
        (project_dir / "ocr-source.pdf").write_bytes(source_bytes)
        meta = json.loads((project_dir / "meta.json").read_text(encoding="utf-8"))
        meta.update({
            "ocr_source": {
                "available": True,
                "path": "ocr-source.pdf",
                "bytes": len(source_bytes),
                "sha256": hashlib.sha256(source_bytes).hexdigest(),
                "source_type": "pdf",
                "source_pages": 1,
                "selected_start": 1,
                "selected_end": 1,
                "immutable_evidence": True,
            },
            "ocr_resources": {
                "assets": [],
                "source_pages": [],
                "unresolved": [],
                "errors": [],
            },
            "ocr_processing": {
                "profile": "publication",
                "backend": "codex_cli",
                "dpi": 300,
            },
            "ocr_quality": {
                "schema_version": 1,
                "profile": "publication",
                "workflow_gate_passed": True,
                "publication_readiness": "not_established",
            },
        })
        store._write_json(str(project_dir), "meta.json", meta)

        with TestClient(server.create_app()) as client:
            current = client.get(f"/api/projects/{pid}/export-current-package")
        assert current.status_code == 200
        with zipfile.ZipFile(io.BytesIO(current.content)) as archive:
            assert archive.read("ocr-source.pdf") == source_bytes
            quality = json.loads(archive.read("OCR-QUALITY.json"))
            assert quality["source"]["sha256"] == hashlib.sha256(source_bytes).hexdigest()
            assert quality["processing"]["profile"] == "publication"
            assert quality["quality"]["publication_readiness"] == "not_established"

        store.set_result(
            pid,
            "\\documentclass{article}\\begin{document}ok\\end{document}",
            "verified",
            [],
            {"verification": {"safe_to_export": True}},
        )
        with TestClient(server.create_app()) as client:
            committed = client.get(f"/api/projects/{pid}/export-package")
        assert committed.status_code == 200
        with zipfile.ZipFile(io.BytesIO(committed.content)) as archive:
            assert archive.read("ocr-source.pdf") == source_bytes
            assert "OCR-QUALITY.json" in archive.namelist()

        (project_dir / "ocr-source.pdf").write_bytes(source_bytes + b"tampered")
        with TestClient(server.create_app()) as client:
            rejected_current = client.get(f"/api/projects/{pid}/export-current-package")
            rejected_committed = client.get(f"/api/projects/{pid}/export-package")
        assert rejected_current.status_code == 409
        assert rejected_committed.status_code == 409
    finally:
        server._store = old_store

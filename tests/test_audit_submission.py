# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import time
import zipfile
from pathlib import Path

import pytest

from latexstruct.core.audit_schema import AuditSubmissionRequest
from latexstruct.core.audit_submission import (
    build_audit_submission,
    load_submission_summary,
    project_fingerprint,
    submission_package_path,
)
from latexstruct.core.preview import preview_storage_filename


class FakeStore:
    def __init__(self, root: Path):
        self.root = root

    def _dir(self, pid: str) -> str:
        return str(self.root / pid)

    def get(self, pid: str):
        path = self.root / pid
        if not path.is_dir():
            return None
        meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
        meta["has_result"] = (path / "result.tex").is_file()
        return meta

    def read_source(self, pid: str) -> str:
        return (self.root / pid / "source.tex").read_text(encoding="utf-8")

    def read_failed_attempt(self, pid: str):
        path = self.root / pid
        marker = path / "last-failure.json"
        draft = path / "last-failed-draft.tex"
        report = path / "last-failure-report.md"
        if not all(item.is_file() for item in (marker, draft, report)):
            return None
        data = json.loads(marker.read_text(encoding="utf-8"))
        return {
            **data,
            "draft": draft.read_text(encoding="utf-8"),
            "report": report.read_text(encoding="utf-8"),
        }


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def make_project(
    tmp_path: Path,
    *,
    pid: str = "abc123def456",
    kind: str = "",
    mode: str = "ai",
    template: str = "",
    source: str = "\\documentclass{article}\n\\begin{document}\nHello\n\\end{document}\n",
) -> tuple[FakeStore, str, Path]:
    root = tmp_path / "projects"
    project = root / pid
    project.mkdir(parents=True)
    meta = {
        "id": pid,
        "name": "中文 审计项目",
        "mode": mode,
        "template": template,
        "created": "2026-08-21 12:00:00",
    }
    if kind:
        meta["kind"] = kind
    write_json(project / "meta.json", meta)
    (project / "source.tex").write_text(source, encoding="utf-8")
    return FakeStore(root), pid, project


def add_success(project: Path, result: str | None = None, *, preview_status: str = "") -> None:
    source = (project / "source.tex").read_text(encoding="utf-8")
    result = result or source.replace("Hello", "\\section{Hello}\nHello")
    result_bytes = result.encode("utf-8")
    verification = {
        "safe_to_export": True,
        "compile_before": {"available": True, "ok": True, "engine": "xelatex", "log": "before"},
        "compile_after": {"available": True, "ok": True, "engine": "xelatex", "log": "after"},
        "failures": [],
    }
    if preview_status:
        payload = b"%PDF-1.4\n% test preview\n"
        digest = hashlib.sha256(payload).hexdigest()
        verification["compile_after"]["preview_status"] = preview_status
        verification["preview_artifact"] = {"status": preview_status, "sha256": digest}
        (project / preview_storage_filename(preview_status, digest)).write_bytes(payload)
    info = {
        "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "verification": verification,
        "items": [],
        "producer_identity": {
            "app_version": "1.2.6",
            "commit": "a" * 40,
            "build_id": "42",
            "prompt_version": "3.6",
        },
    }
    (project / "result.tex").write_bytes(result_bytes)
    (project / "report.md").write_text("# Report\n\nVerified.\n", encoding="utf-8")
    (project / "decisions.json").write_text("[]", encoding="utf-8")
    write_json(project / "verification.json", info)


def add_failure(project: Path, draft: str | None = None) -> None:
    source = (project / "source.tex").read_text(encoding="utf-8")
    draft = draft or source.replace("Hello", "\\textbf{Theorem 1.} Hello")
    report = "# Report\n\nUNVERIFIED.\n"
    details = {
        "verification": {
            "safe_to_export": False,
            "compile_before": {"available": True, "ok": False, "log": "! raw error"},
            "compile_after": {"available": True, "ok": False, "log": "! current error"},
            "failures": [{"id": "structure", "summary": "formal residual", "action": "fix"}],
        },
        "failures": [{"id": "structure", "summary": "formal residual", "action": "fix"}],
        "items": [{"candidate_id": "thm-1", "status": "ambiguous"}],
        "ambiguous": [{"candidate_id": "thm-1", "reason": "boundary unknown"}],
    }
    (project / "last-failed-draft.tex").write_text(draft, encoding="utf-8")
    (project / "last-failure-report.md").write_text(report, encoding="utf-8")
    write_json(project / "last-failure.json", {"created": "2026-08-21", "details": details})
    now = time.time() + 1
    for name in ("last-failure.json", "last-failed-draft.tex", "last-failure-report.md"):
        os.utime(project / name, (now, now))


def ocr_source_with_metadata() -> str:
    metadata = {
        "version": 1,
        "kind": "article",
        "pages": [1, 2],
        "outline": [{"level": 0, "title": "1. Introduction", "page": 1}],
    }
    encoded = base64.b64encode(json.dumps(metadata).encode("utf-8")).decode("ascii")
    return (
        "\\documentclass{article}\n\\begin{document}\n"
        f"% LaTeXStruct-OCR-Metadata: {encoded}\n"
        "OCR body\n\\end{document}\n"
    )


def read_zip(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def assert_sums(files: dict[str, bytes]) -> None:
    sums = files["audit/SHA256SUMS"].decode("utf-8").splitlines()
    for line in sums:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256(files[name]).hexdigest() == digest


def test_analysis_review_bundle_contains_prompts_and_recomputable_hashes(tmp_path):
    store, pid, project = make_project(tmp_path)
    add_success(project)
    result = build_audit_submission(
        store=store,
        pid=pid,
        request=AuditSubmissionRequest(),
        runtime_identity={"app_version": "1.2.6", "commit": "b" * 40, "build_id": "99"},
        latest_job={"status": "done"},
    )
    path = Path(result.package_path)
    assert path.is_file()
    files = read_zip(path)
    for name in (
        "00_README_FIRST.md",
        "01_PROMPT_SHORT.txt",
        "02_PROMPT_FULL.md",
        "submission_manifest.json",
        "stages/00_source.tex",
        "stages/30_current.tex",
        "audit/report.md",
        "audit/raw_to_current.diff",
        "audit/SHA256SUMS",
    ):
        assert name in files
    manifest = json.loads(files["submission_manifest.json"])
    assert manifest["workflow"]["type"] == "ANALYSIS_REVIEW_ONLY"
    assert manifest["workflow"]["verification_status"] == "VERIFIED"
    assert_sums(files)


def test_ocr_analysis_review_includes_source_pdf_outline_and_source_previews(tmp_path):
    store, pid, project = make_project(tmp_path, kind="ocr", source=ocr_source_with_metadata())
    pdf = b"%PDF-1.4\nsource\n"
    (project / "ocr-source.pdf").write_bytes(pdf)
    meta = json.loads((project / "meta.json").read_text(encoding="utf-8"))
    meta["ocr_source"] = {
        "available": True,
        "path": "ocr-source.pdf",
        "sha256": hashlib.sha256(pdf).hexdigest(),
        "bytes": len(pdf),
        "source_type": "pdf",
        "selected_start": 1,
        "selected_end": 2,
    }
    write_json(project / "meta.json", meta)
    add_failure(project)
    result = build_audit_submission(store=store, pid=pid, latest_job={"status": "blocked"})
    files = read_zip(Path(result.package_path))
    manifest = json.loads(files["submission_manifest.json"])
    assert manifest["workflow"]["type"] == "OCR_ANALYSIS_REVIEW"
    assert manifest["workflow"]["verification_status"] == "UNVERIFIED"
    assert "inputs/source.pdf" in files
    assert "stages/00_raw_ocr.tex" in files
    assert "evidence/outline.json" in files
    assert any(name.endswith("SOURCE_PREVIEW.pdf") for name in files)
    import pymupdf
    preview_bytes = files["previews/current_SOURCE_PREVIEW.pdf"]
    with pymupdf.open(stream=preview_bytes, filetype="pdf") as document:
        assert "NOT A LATEX COMPILED RESULT" in document[0].get_text()


@pytest.mark.parametrize(
    "kind,mode,template,job_status,expected",
    [
        ("", "ai", "", "error", "FAILED"),
        ("", "ai", "", "cancelled", "CANCELLED"),
        ("ocr", "ai", "", "done", "UNVERIFIED"),
        ("", "rule", "faithfulbook", "done", "UNVERIFIED"),
    ],
)
def test_terminal_statuses_and_workflows(tmp_path, kind, mode, template, job_status, expected):
    store, pid, _project = make_project(tmp_path, kind=kind, mode=mode, template=template)
    result = build_audit_submission(
        store=store,
        pid=pid,
        latest_job={"status": job_status},
        create_package=False,
    )
    assert result.manifest.snapshot.terminal_status.value == expected
    assert result.manifest.snapshot.verification_status == "UNVERIFIED"


def test_multifile_project_is_sanitized_and_preserves_chinese_paths(tmp_path):
    store, pid, project = make_project(tmp_path, kind="folder")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("章节/主文件.tex", "API_KEY=secret-value\n\\input{子.tex}\n")
        archive.writestr(".env", "TOKEN=should-not-leak")
    (project / "original-files.zip").write_bytes(buffer.getvalue())
    result = build_audit_submission(store=store, pid=pid)
    files = read_zip(Path(result.package_path))
    nested = zipfile.ZipFile(io.BytesIO(files["inputs/original-project.zip"]), "r")
    names = nested.namelist()
    assert "章节/主文件.tex" in names
    assert ".env" not in names
    assert b"<REDACTED>" in nested.read("章节/主文件.tex")
    manifest = json.loads(files["submission_manifest.json"])
    assert manifest["workflow"]["type"] == "MULTIFILE_PROJECT"


def test_dedup_records_aliases_instead_of_duplicate_bytes(tmp_path):
    source = "same content\n"
    store, pid, _project = make_project(tmp_path, source=source)
    result = build_audit_submission(store=store, pid=pid)
    files = read_zip(Path(result.package_path))
    manifest = json.loads(files["submission_manifest.json"])
    records = manifest["artifacts"]
    matching = [item for item in records if "stages/30_current.tex" in item.get("aliases", [])]
    assert matching
    assert "stages/30_current.tex" not in files


def test_partial_compiled_pdf_is_honest(tmp_path):
    store, pid, project = make_project(tmp_path)
    add_success(project, preview_status="PARTIAL_COMPILED")
    info = json.loads((project / "verification.json").read_text(encoding="utf-8"))
    info["verification"]["safe_to_export"] = False
    write_json(project / "verification.json", info)
    result = build_audit_submission(store=store, pid=pid)
    files = read_zip(Path(result.package_path))
    assert "previews/current_PARTIAL_COMPILED.pdf" in files
    manifest = json.loads(files["submission_manifest.json"])
    preview = next(item for item in manifest["artifacts"] if item["artifact_role"] == "partial_compiled_pdf")
    assert preview["preview_status"] == "PARTIAL_COMPILED"


def test_stale_detection_after_project_or_review_state_changes(tmp_path):
    store, pid, project = make_project(tmp_path)
    add_success(project)
    result = build_audit_submission(
        store=store,
        pid=pid,
        request={"reviewed_candidate_ids": ["a", "b"]},
    )
    current = load_submission_summary(
        store=store,
        pid=pid,
        reviewed_candidate_ids=("a", "b"),
    )
    assert current and current["stale"] is False
    changed_review = load_submission_summary(
        store=store,
        pid=pid,
        reviewed_candidate_ids=("a",),
    )
    assert changed_review and changed_review["stale"] is True
    (project / "source.tex").write_text("changed\n", encoding="utf-8")
    changed_source = load_submission_summary(
        store=store,
        pid=pid,
        reviewed_candidate_ids=("a", "b"),
    )
    assert changed_source and changed_source["stale"] is True
    assert submission_package_path(store, pid, result.submission_id).is_file()


def test_prompt_only_references_actual_canonical_paths(tmp_path):
    store, pid, project = make_project(tmp_path)
    add_failure(project)
    result = build_audit_submission(store=store, pid=pid)
    files = read_zip(Path(result.package_path))
    manifest = json.loads(files["submission_manifest.json"])
    prompt = files["02_PROMPT_FULL.md"].decode("utf-8")
    for artifact in manifest["artifacts"]:
        assert artifact["path"] in files
        assert artifact["path"] in prompt
    assert "stages/10_ai_analyzed.tex" not in prompt


def test_atomic_write_leaves_no_temporary_entries(tmp_path):
    store, pid, project = make_project(tmp_path)
    add_success(project)
    result = build_audit_submission(store=store, pid=pid)
    root = project / "audit-submissions"
    assert not [path for path in root.iterdir() if path.name.startswith(".tmp-")]
    assert Path(result.package_path).is_file()


def test_project_fingerprint_is_deterministic(tmp_path):
    _store, _pid, project = make_project(tmp_path)
    first = project_fingerprint(project, ("b", "a"))
    second = project_fingerprint(project, ("a", "b"))
    assert first == second
    (project / "source.tex").write_text("changed", encoding="utf-8")
    assert project_fingerprint(project, ("a", "b")) != first


def test_fastapi_routes_precede_static_mount_and_download(tmp_path, monkeypatch):
    import sys
    import types
    from contextlib import nullcontext

    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.testclient import TestClient

    store, pid, project = make_project(tmp_path)
    add_success(project)

    class Manager:
        def __init__(self):
            self.jobs = {}

        def active(self, _pid):
            return None

        def latest(self, _pid):
            return None

        def public(self, job):
            return dict(job)

        def get(self, jid):
            return self.jobs.get(jid)

        def complete(self, _jid, _result):
            return None

        def cancelled(self, _jid):
            return None

        def fail(self, _jid, _message):
            return None

    manager = Manager()
    stub = types.ModuleType("latexstruct.server.app")
    stub.get_store = lambda: store
    stub._process_jobs = manager
    stub._project_lock = lambda _pid: nullcontext()
    stub._runtime_provenance_identity = lambda _prompt: {
        "app_version": "1.2.6", "commit": "c" * 40, "build_id": "test",
        "prompt_version": "audit-submission-v1",
    }
    monkeypatch.setitem(sys.modules, "latexstruct.server.app", stub)
    import latexstruct.server as server_package
    monkeypatch.setattr(server_package, "app", stub, raising=False)

    from latexstruct.server.audit_submission_routes import register_audit_submission_routes

    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("static", encoding="utf-8")
    app = FastAPI()
    app.mount("/", StaticFiles(directory=static, html=True), name="static")
    register_audit_submission_routes(app)

    client = TestClient(app)
    created = client.post(
        f"/api/projects/{pid}/audit-submission",
        json={"profile": "standard", "reviewed_candidate_ids": ["a"]},
    )
    assert created.status_code == 200, created.text
    value = created.json()
    assert value["download_url"].startswith(f"/api/projects/{pid}/audit-submission/")
    latest = client.get(
        f"/api/projects/{pid}/audit-submission/latest?reviewed_candidate_id=a"
    )
    assert latest.status_code == 200
    assert latest.json()["stale"] is False
    downloaded = client.get(value["download_url"])
    assert downloaded.status_code == 200
    assert downloaded.content.startswith(b"PK")

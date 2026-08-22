# -*- coding: utf-8 -*-
"""FastAPI contract tests for AI-audit submission packages.

These tests deliberately use the deterministic rule pipeline and a fake TeX
compiler.  They exercise the HTTP/storage boundary without calling an AI
backend or depending on a local TeX installation.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath
from unittest.mock import patch


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        from starlette.testclient import TestClient

    import latexstruct.server.app as srv
    from latexstruct.core.audit_schema import (
        ArtifactRole,
        AuditWorkflow,
        RunSnapshot,
        TerminalStatus,
    )
    from latexstruct.core.audit_submission import make_audit_artifact
    from latexstruct.server.audit_store import AuditSubmissionStore
except ImportError:  # pragma: no cover - optional server dependencies
    sys.exit(0)


SAMPLE = (
    "\\documentclass{article}\n"
    "\\begin{document}\n"
    "Theorem 1. A statement used by the audit API test.\n"
    "\\end{document}\n"
)
CONTROL_FILES = {
    "00_README_FIRST.md",
    "01_PROMPT_SHORT.txt",
    "02_PROMPT_FULL.md",
    "submission_manifest.json",
}

_TESTS_DIR = Path(__file__).resolve().parent


class WorkspaceTmp:
    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="ls-audit-api-", dir=_TESTS_DIR)
        import latexstruct.config as configmod

        self.old_config_path = configmod.CONFIG_PATH
        configmod.CONFIG_PATH = os.path.join(self.path, "config.json")
        return self.path

    def __exit__(self, *exc):
        import latexstruct.config as configmod

        configmod.CONFIG_PATH = self.old_config_path
        shutil.rmtree(self.path, ignore_errors=True)


def _client(tmp: str, *, raise_server_exceptions: bool = True) -> TestClient:
    srv._process_jobs.clear()
    with srv._project_locks_guard:
        srv._project_locks.clear()
    srv._cancel_update_preparation()
    with srv._update_jobs_lock:
        srv._update_jobs.clear()
    srv._active_pipeline_runs = 0
    srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
    srv._config = None
    return TestClient(
        srv.create_app(),
        raise_server_exceptions=raise_server_exceptions,
    )


def _fake_compile(_text: str, **kwargs) -> dict:
    result = {
        "available": True,
        "ok": True,
        "pages": 1,
        "errors": [],
        "log": "deterministic fake compile log",
        "preview_status": "COMPILED",
        "process_status": "SUCCESS",
        "return_code": 0,
        "fatal_line": None,
        "timed_out": False,
        "passes_requested": 1,
        "passes_completed": 1,
    }
    if kwargs.get("include_pdf"):
        result["pdf_bytes"] = b"%PDF-audit-api-test"
    return result


def _create_processed_project(client: TestClient, *, name: str = "审计接口样本") -> str:
    created = client.post(
        "/api/projects",
        json={"text": SAMPLE, "name": name, "mode": "rule"},
    )
    assert created.status_code == 200, created.text
    pid = created.json()["id"]
    with patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile):
        processed = client.post(f"/api/projects/{pid}/process")
    assert processed.status_code == 200, processed.text
    assert processed.json()["ok"] is True
    return pid


def _assert_lightweight_controls(tmp: str, pid: str, summary: dict) -> None:
    relative = str(summary["relative_directory"])
    assert not Path(relative).is_absolute()
    assert ":" not in relative
    directory = (
        Path(srv.get_store()._dir(pid))
        / "audit-submissions"
        / PurePosixPath(relative)
    )
    assert directory.is_dir()
    assert CONTROL_FILES.issubset({item.name for item in directory.iterdir()})
    assert not list(directory.glob("*.zip"))

    manifest = json.loads(
        (directory / "submission_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["submission_id"] == summary["submission_id"]
    assert manifest["terminal_status"] == summary["terminal_status"]
    assert {item["path"] for item in manifest["artifacts"]} == CONTROL_FILES


def _assert_zip_checksums(archive: zipfile.ZipFile) -> None:
    names = set(archive.namelist())
    sums_path = "audit/SHA256SUMS"
    assert sums_path in names
    covered = {}
    for line in archive.read(sums_path).decode("utf-8").splitlines():
        digest, name = line.split("  ", 1)
        covered[name] = digest
    assert set(covered) == names - {sums_path}
    for name, expected in covered.items():
        assert hashlib.sha256(archive.read(name)).hexdigest() == expected


def _logical_manifest_paths(manifest: dict) -> set[str]:
    """Return physical paths plus byte-deduplicated logical aliases."""
    paths = set()
    for item in manifest["artifacts"]:
        paths.add(item["path"])
        paths.update(
            alias["path"]
            for alias in item.get("aliases", [])
            if alias.get("path")
        )
    return paths


def test_audit_submission_routes_publish_lightweight_then_standard_zip():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        created = client.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "尚未运行", "mode": "rule"},
        )
        pid = created.json()["id"]
        before = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert before.status_code == 200
        assert before.json() == {
            "available": False,
            "can_generate": True,
            "reason": "NO_TERMINAL_RUN",
            "latest": None,
            "history": [],
            "history_count": 0,
        }

        with patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile):
            processed = client.post(f"/api/projects/{pid}/process")
        assert processed.status_code == 200 and processed.json()["ok"] is True

        latest_response = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert latest_response.status_code == 200, latest_response.text
        latest_body = latest_response.json()
        assert latest_body["available"] is True
        assert latest_body["can_generate"] is True
        lightweight = latest_body["latest"]
        assert lightweight["state"] == "LIGHTWEIGHT"
        assert lightweight["bundle_state"] == "LIGHTWEIGHT"
        assert lightweight["terminal_status"] == "SUCCESS"
        assert lightweight["verification_status"] == "VERIFIED"
        assert lightweight["download_url"] is None
        _assert_lightweight_controls(tmp, pid, lightweight)

        downloads = Path(tmp) / "downloads" / "LaTeXStruct"
        with patch(
            "latexstruct.server.downloads.download_root",
            return_value=downloads,
        ):
            generated = client.post(
                f"/api/projects/{pid}/audit-submission",
                json={
                    "profile": "standard",
                    "audit_focus": "重点核对定理环境和目录。",
                    "include_source_files": True,
                    "include_compile_logs": True,
                    "include_verification_records": True,
                    "sanitize_sensitive": True,
                },
            )
        assert generated.status_code == 201, generated.text
        ready = generated.json()["submission"]
        assert ready["state"] == "READY"
        assert ready["bundle_state"] == "ZIP_READY"
        assert ready["profile"] == "standard"
        assert ready["stale"] is False
        assert ready["is_latest"] is True
        assert ready["historical"] is False
        assert ready["download_url"]
        assert (downloads / ready["filename"]).is_file()

        downloaded = client.get(ready["download_url"])
        assert downloaded.status_code == 200, downloaded.text
        assert downloaded.headers["x-latexstruct-submission-id"] == ready["submission_id"]
        assert downloaded.headers["x-latexstruct-stale"] == "false"
        with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
            names = set(archive.namelist())
            assert CONTROL_FILES.issubset(names)
            assert {
                "inputs/source.tex",
                "previews/current.pdf",
                "audit/report.md",
                "audit/verification.json",
                "audit/decisions.json",
                "audit/raw_to_current.diff",
                "audit/compile_current.log",
            }.issubset(names)
            _assert_zip_checksums(archive)

            manifest = json.loads(archive.read("submission_manifest.json"))
            assert manifest["workflow"] == "ANALYSIS_REVIEW_ONLY"
            assert manifest["terminal_status"] == "SUCCESS"
            assert manifest["verification_status"] == "VERIFIED"
            assert manifest["audit_focus"] == "重点核对定理环境和目录。"
            manifest_roles = {
                role
                for item in manifest["artifacts"]
                for role in [
                    item["artifact_role"],
                    *[alias["artifact_role"] for alias in item.get("aliases", [])],
                ]
            }
            assert "RULE_ANALYZED_TEX" in manifest_roles
            assert "AI_ANALYZED_TEX" not in manifest_roles
            assert {
                "inputs/source.tex",
                "stages/00_source.tex",
                "stages/30_current.tex",
            }.issubset(_logical_manifest_paths(manifest))
            packaged_paths = {item["path"] for item in manifest["artifacts"]}
            assert packaged_paths == names
            prompt = archive.read("02_PROMPT_FULL.md").decode("utf-8")
            assert "ANALYSIS_REVIEW_ONLY" in prompt
            assert "重点核对定理环境和目录" in prompt
            short = archive.read("01_PROMPT_SHORT.txt").decode("utf-8").strip()
            assert "00_README_FIRST.md" in short
            assert "submission_manifest.json" in short
            assert "02_PROMPT_FULL.md" in short
            assert len(short.splitlines()) == 1
            # Neither the manifest nor prompts may expose the temporary host root.
            controls = b"\n".join(
                archive.read(name)
                for name in CONTROL_FILES
            ).decode("utf-8")
            assert str(Path(tmp).resolve()) not in controls

        newest = client.get(f"/api/projects/{pid}/audit-submission/latest").json()
        assert newest["latest"]["submission_id"] == ready["submission_id"]
        assert newest["latest"]["bundle_state"] == "ZIP_READY"


def test_review_state_marks_ready_bundle_stale_and_regeneration_replaces_latest():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create_processed_project(client)
        downloads = Path(tmp) / "downloads" / "LaTeXStruct"
        with patch(
            "latexstruct.server.downloads.download_root",
            return_value=downloads,
        ):
            first_response = client.post(
                f"/api/projects/{pid}/audit-submission",
                json={"profile": "quick"},
            )
        assert first_response.status_code == 201, first_response.text
        first = first_response.json()["submission"]

        decisions = client.get(f"/api/projects/{pid}/decisions").json()["items"]
        candidate_id = next(
            str(item.get("candidate_id") or item.get("id"))
            for item in decisions
            if item.get("candidate_id") or item.get("id")
        )
        reviewed = client.post(
            f"/api/projects/{pid}/decisions/review-state",
            json={"accepted_ids": [candidate_id], "expected_revision": 0},
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["review_revision"] == 1

        stale_latest = client.get(
            f"/api/projects/{pid}/audit-submission/latest"
        ).json()["latest"]
        assert stale_latest["submission_id"] == first["submission_id"]
        assert stale_latest["stale"] is True
        assert "审阅" in stale_latest["stale_reason"]
        old_download = client.get(first["download_url"])
        assert old_download.status_code == 200
        assert old_download.headers["x-latexstruct-stale"] == "true"

        with patch(
            "latexstruct.server.downloads.download_root",
            return_value=downloads,
        ):
            regenerated_response = client.post(
                f"/api/projects/{pid}/audit-submission",
                json={"profile": "standard"},
            )
        assert regenerated_response.status_code == 201, regenerated_response.text
        regenerated = regenerated_response.json()["submission"]
        assert regenerated["submission_id"] != first["submission_id"]
        assert regenerated["stale"] is False
        current = client.get(
            f"/api/projects/{pid}/audit-submission/latest"
        ).json()["latest"]
        assert current["submission_id"] == regenerated["submission_id"]
        assert current["stale"] is False

        with patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile):
            rejected = client.post(
                f"/api/projects/{pid}/decisions/{candidate_id}/reject"
            )
        assert rejected.status_code == 200, rejected.text
        project = client.get(f"/api/projects/{pid}").json()
        assert candidate_id not in project.get("accepted_decision_ids", [])
        assert candidate_id in project.get("excludes", [])
        assert project["review_revision"] == 2
        old_after_reject = client.get(regenerated["download_url"])
        assert old_after_reject.headers["x-latexstruct-stale"] == "true"

        conflicting_accept = client.post(
            f"/api/projects/{pid}/decisions/review-state",
            json={"accepted_ids": [candidate_id], "expected_revision": 2},
        )
        assert conflicting_accept.status_code == 409
        after_conflict = client.get(f"/api/projects/{pid}").json()
        assert candidate_id not in after_conflict.get("accepted_decision_ids", [])
        assert candidate_id in after_conflict.get("excludes", [])
        assert after_conflict["review_revision"] == 2


def test_audit_submission_rejects_invalid_input_and_unknown_download():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create_processed_project(client, name="invalid-audit-request")

        invalid = client.post(
            f"/api/projects/{pid}/audit-submission",
            json={"profile": "not-a-depth"},
        )
        assert invalid.status_code == 400, invalid.text
        assert "AuditDepth" in invalid.json()["detail"]

        missing = client.get(
            f"/api/projects/{pid}/audit-submission/audit-does-not-exist/download"
        )
        assert missing.status_code == 404
        assert "不存在" in missing.json()["detail"]

        missing_pid = f"{pid[:-1]}{'0' if pid[-1] != '0' else '1'}"
        absent_project = client.get(
            f"/api/projects/{missing_pid}/audit-submission/latest"
        )
        assert absent_project.status_code == 404


def test_failed_run_keeps_partial_stage_error_and_can_generate_unverified_zip():
    partial = SAMPLE.replace(
        "Theorem 1.", "\\begin{theorem}[1]"
    ).replace(
        " A statement used by the audit API test.",
        " A statement used by the audit API test.\\end{theorem}",
    )

    def failing_pipeline(*_args, **kwargs):
        progress = kwargs.get("progress_callback")
        assert progress is not None
        progress(
            "analysis",
            0.45,
            "captured one partial stage",
            {
                "preview": partial,
                "preview_state": "SOURCE_PREVIEW",
                "audit_stage": {"role": "rule_analyzed", "text": partial},
            },
        )
        raise RuntimeError("simulated audit pipeline failure")

    with WorkspaceTmp() as tmp:
        client = _client(tmp, raise_server_exceptions=False)
        pid = client.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "failed-audit", "mode": "rule"},
        ).json()["id"]
        with patch.object(srv, "run_pipeline", side_effect=failing_pipeline):
            failed = client.post(f"/api/projects/{pid}/process")
        assert failed.status_code == 500

        latest_response = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert latest_response.status_code == 200, latest_response.text
        lightweight = latest_response.json()["latest"]
        assert lightweight["terminal_status"] == "FAILED"
        assert lightweight["verification_status"] == "UNVERIFIED"
        assert lightweight["state"] == "LIGHTWEIGHT"
        _assert_lightweight_controls(tmp, pid, lightweight)

        downloads = Path(tmp) / "downloads" / "LaTeXStruct"
        with patch(
            "latexstruct.server.downloads.download_root",
            return_value=downloads,
        ):
            generated = client.post(
                f"/api/projects/{pid}/audit-submission",
                json={"profile": "standard"},
            )
        assert generated.status_code == 201, generated.text
        downloaded = client.get(generated.json()["submission"]["download_url"])
        assert downloaded.status_code == 200
        with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
            names = set(archive.namelist())
            assert {
                "inputs/source.tex",
                "audit/error.log",
                "audit/report.md",
                "audit/verification.json",
            }.issubset(names)
            _assert_zip_checksums(archive)
            manifest = json.loads(archive.read("submission_manifest.json"))
            assert manifest["terminal_status"] == "FAILED"
            assert manifest["verification_status"] == "UNVERIFIED"
            assert {
                "inputs/source.tex",
                "stages/00_source.tex",
                "stages/10_rule_analyzed.tex",
                "stages/30_current.tex",
            }.issubset(_logical_manifest_paths(manifest))
            assert any(
                item["artifact_role"] == "ERROR_LOG"
                for item in manifest["artifacts"]
            )
            analyzed_record = next(
                item
                for item in manifest["artifacts"]
                if item["path"] == "stages/10_rule_analyzed.tex"
                or any(
                    alias.get("path") == "stages/10_rule_analyzed.tex"
                    for alias in item.get("aliases", [])
                )
            )
            assert archive.read(analyzed_record["path"]).decode("utf-8") == partial


def test_partial_ocr_only_snapshot_can_generate_while_child_analysis_is_running():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = client.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "OCR-only-partial", "mode": "rule"},
        ).json()["id"]
        source = make_audit_artifact(
            ArtifactRole.SOURCE_IMAGE,
            b"\x89PNG\r\n\x1a\nsource",
            filename="source.png",
            media_type="image/png",
        )
        raw = make_audit_artifact(
            ArtifactRole.RAW_OCR_TEX,
            SAMPLE.encode(),
            parent_artifact_ids=(source.artifact_id,),
        )
        snapshot = RunSnapshot(
            project_id=pid,
            run_id="ocr-only-partial",
            workflow=AuditWorkflow.OCR_ONLY,
            terminal_status=TerminalStatus.PARTIAL,
            captured_at="2026-08-22T02:00:00Z",
            artifacts=(source, raw),
            machine_verification={"safe_to_export": False},
            blockers=("部分页面尚未完成",),
        )
        audit_store = AuditSubmissionStore(srv.get_store()._dir(pid))
        audit_store.persist_terminal_snapshot(snapshot)
        active = srv._process_jobs.create(pid, SAMPLE)

        # Merely having an OCR_ONLY latest snapshot does not identify this as
        # its child.  A normal active task must remain blocked, including when
        # the client explicitly repeats the current snapshot ID.
        unbound = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert unbound.status_code == 200, unbound.text
        assert unbound.json()["can_generate"] is False
        assert unbound.json()["reason"] == "TASK_RUNNING"
        assert "_audit_parent_snapshot_id" not in srv._process_jobs.public(active)
        assert client.post(
            f"/api/projects/{pid}/audit-submission",
            json={"profile": "standard"},
        ).status_code == 409
        assert client.post(
            f"/api/projects/{pid}/audit-submission",
            json={"snapshot_id": snapshot.snapshot_id, "profile": "standard"},
        ).status_code == 409

        srv._process_jobs.bind_audit_parent_snapshot(
            active["id"],
            snapshot.snapshot_id,
        )

        latest = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert latest.status_code == 200, latest.text
        assert latest.json()["can_generate"] is True
        assert latest.json()["latest"]["workflow"] == "OCR_ONLY"
        assert latest.json()["latest"]["terminal_status"] == "PARTIAL"
        assert latest.json()["latest"]["stale"] is False

        downloads = Path(tmp) / "downloads" / "LaTeXStruct"
        with patch(
            "latexstruct.server.downloads.download_root",
            return_value=downloads,
        ):
            generated = client.post(
                f"/api/projects/{pid}/audit-submission",
                json={"profile": "standard"},
            )
        assert generated.status_code == 201, generated.text
        submission = generated.json()["submission"]
        assert submission["workflow"] == "OCR_ONLY"
        assert submission["terminal_status"] == "PARTIAL"
        assert submission["stale"] is False

        # Even a bound OCR child loses the exception if latest moves to a
        # different frozen OCR_ONLY snapshot.
        newer_raw = make_audit_artifact(
            ArtifactRole.RAW_OCR_TEX,
            (SAMPLE + "% newer OCR revision\n").encode(),
            parent_artifact_ids=(source.artifact_id,),
        )
        newer_snapshot = RunSnapshot(
            project_id=pid,
            run_id="ocr-only-newer",
            workflow=AuditWorkflow.OCR_ONLY,
            terminal_status=TerminalStatus.PARTIAL,
            captured_at="2026-08-22T02:01:00Z",
            artifacts=(source, newer_raw),
            machine_verification={"safe_to_export": False},
            blockers=("新 OCR 修订",),
        )
        audit_store.persist_terminal_snapshot(newer_snapshot)
        mismatched = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert mismatched.status_code == 200, mismatched.text
        assert mismatched.json()["can_generate"] is False
        assert mismatched.json()["reason"] == "TASK_RUNNING"
        assert client.post(
            f"/api/projects/{pid}/audit-submission",
            json={"profile": "standard"},
        ).status_code == 409


def test_post_reclassifies_zip_if_child_finishes_while_download_copy_is_paused():
    """A late terminal commit must win even after ZIP storage has committed."""
    from latexstruct.server import downloads as download_helpers

    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = client.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "OCR-download-race", "mode": "rule"},
        ).json()["id"]
        source = make_audit_artifact(
            ArtifactRole.SOURCE_PDF,
            b"%PDF-download-race",
            filename="source.pdf",
            media_type="application/pdf",
        )
        raw = make_audit_artifact(
            ArtifactRole.RAW_OCR_TEX,
            SAMPLE.encode(),
            parent_artifact_ids=(source.artifact_id,),
        )
        parent = RunSnapshot(
            project_id=pid,
            run_id="ocr-download-race-parent",
            workflow=AuditWorkflow.OCR_ONLY,
            terminal_status=TerminalStatus.PARTIAL,
            captured_at="2026-08-22T02:00:00Z",
            artifacts=(source, raw),
            machine_verification={"safe_to_export": False},
            blockers=("部分页面尚未完成",),
        )
        audit_store = AuditSubmissionStore(srv.get_store()._dir(pid))
        audit_store.persist_terminal_snapshot(parent)
        active = srv._process_jobs.create(pid, SAMPLE)
        srv._process_jobs.bind_audit_parent_snapshot(active["id"], parent.snapshot_id)

        download_copy_started = threading.Event()
        release_download_copy = threading.Event()
        response = {}
        errors = []
        original_save = download_helpers.save_unique_download

        def pause_download_copy(data, filename):
            download_copy_started.set()
            assert release_download_copy.wait(timeout=10)
            return original_save(data, filename)

        def generate_zip():
            try:
                response["value"] = client.post(
                    f"/api/projects/{pid}/audit-submission",
                    json={"profile": "standard"},
                )
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        downloads = Path(tmp) / "downloads" / "LaTeXStruct"
        with (
            patch(
                "latexstruct.server.downloads.save_unique_download",
                side_effect=pause_download_copy,
            ),
            patch(
                "latexstruct.server.downloads.download_root",
                return_value=downloads,
            ),
        ):
            thread = threading.Thread(target=generate_zip)
            thread.start()
            assert download_copy_started.wait(timeout=10)

            current = make_audit_artifact(
                ArtifactRole.CURRENT_TEX,
                (SAMPLE + "% child terminal\n").encode(),
                parent_artifact_ids=(raw.artifact_id,),
            )
            child = RunSnapshot(
                project_id=pid,
                run_id="ocr-download-race-child",
                workflow=AuditWorkflow.OCR_ANALYSIS_REVIEW,
                terminal_status=TerminalStatus.SUCCESS,
                captured_at="2026-08-22T02:01:00Z",
                artifacts=(source, raw, current),
                machine_verification={"safe_to_export": False},
                blockers=("等待人工复核",),
            )
            child_submission = audit_store.persist_terminal_snapshot(child)
            release_download_copy.set()
            thread.join(timeout=10)

        assert not thread.is_alive()
        assert errors == []
        generated = response["value"]
        assert generated.status_code == 201, generated.text
        submission = generated.json()["submission"]
        assert submission["stale"] is True
        assert submission["historical"] is True
        assert submission["is_latest"] is False
        assert audit_store.get_submission(submission["submission_id"]).stale is True
        assert audit_store.latest().submission_id == child_submission.submission_id


def test_overwritten_ocr_only_snapshot_remains_in_history_and_generates_exact_zip():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = client.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "OCR-history", "mode": "rule"},
        ).json()["id"]
        source = make_audit_artifact(
            ArtifactRole.SOURCE_IMAGE,
            b"\x89PNG\r\n\x1a\nsource",
            filename="source.png",
            media_type="image/png",
        )
        raw = make_audit_artifact(
            ArtifactRole.RAW_OCR_TEX,
            SAMPLE.encode(),
            parent_artifact_ids=(source.artifact_id,),
        )
        ocr_only = RunSnapshot(
            project_id=pid,
            run_id="ocr-only-history",
            workflow=AuditWorkflow.OCR_ONLY,
            terminal_status=TerminalStatus.PARTIAL,
            captured_at="2026-08-22T02:00:00Z",
            artifacts=(source, raw),
            machine_verification={"safe_to_export": False},
            blockers=("部分页面尚未完成",),
        )

        combined_current = make_audit_artifact(
            ArtifactRole.CURRENT_TEX,
            b"\\documentclass{article}\n\\begin{document}combined\\end{document}\n",
            parent_artifact_ids=(raw.artifact_id,),
        )
        combined = RunSnapshot(
            project_id=pid,
            run_id="ocr-analysis-review-history",
            workflow=AuditWorkflow.OCR_ANALYSIS_REVIEW,
            terminal_status=TerminalStatus.SUCCESS,
            captured_at="2026-08-22T03:00:00Z",
            artifacts=(source, raw, combined_current),
            machine_verification={"safe_to_export": False},
        )
        audit_store = AuditSubmissionStore(srv.get_store()._dir(pid))
        first = audit_store.persist_terminal_snapshot(ocr_only)
        second = audit_store.persist_terminal_snapshot(combined)
        assert audit_store.latest().submission_id == second.submission_id

        latest_response = client.get(f"/api/projects/{pid}/audit-submission/latest")
        assert latest_response.status_code == 200, latest_response.text
        body = latest_response.json()
        assert body["latest"]["snapshot_id"] == combined.snapshot_id
        assert body["latest"]["workflow"] == "OCR_ANALYSIS_REVIEW"
        assert body["history_count"] == 2
        history = {item["snapshot_id"]: item for item in body["history"]}
        assert history[combined.snapshot_id]["is_latest"] is True
        historical = history[ocr_only.snapshot_id]
        assert {
            "snapshot_id",
            "submission_id",
            "workflow",
            "terminal_status",
            "generated_at",
            "captured_at",
            "bundle_state",
            "stale",
            "is_latest",
            "can_generate_snapshot",
        }.issubset(historical)
        assert historical["submission_id"] == first.submission_id
        assert historical["workflow"] == "OCR_ONLY"
        assert historical["terminal_status"] == "PARTIAL"
        assert historical["is_latest"] is False
        assert historical["can_generate_snapshot"] is True

        # A damaged old ZIP/control record is not exposed as a selectable
        # snapshot and does not move the latest pointer away from the newer run.
        damaged = audit_store.generate_zip(
            ocr_only.snapshot_id,
            filename="damaged-history.zip",
        )
        damaged_manifest = (
            audit_store.root
            / PurePosixPath(damaged.relative_directory)
            / "submission_manifest.json"
        )
        damaged_manifest.write_text("tampered\n", encoding="utf-8")
        assert audit_store.latest().snapshot_id == combined.snapshot_id

        # A later child run may already be active.  Explicit history packaging
        # still reads only the immutable stored snapshot selected by its ID.
        srv._process_jobs.create(pid, SAMPLE)
        checked_history = client.get(
            f"/api/projects/{pid}/audit-submission/latest"
        ).json()["history"]
        checked_ocr = next(
            item for item in checked_history
            if item["snapshot_id"] == ocr_only.snapshot_id
        )
        assert checked_ocr["submission_id"] == first.submission_id
        downloads = Path(tmp) / "downloads" / "LaTeXStruct"
        with patch(
            "latexstruct.server.downloads.download_root",
            return_value=downloads,
        ):
            generated = client.post(
                f"/api/projects/{pid}/audit-submission",
                json={"snapshot_id": ocr_only.snapshot_id, "profile": "standard"},
            )
        assert generated.status_code == 201, generated.text
        submission = generated.json()["submission"]
        assert submission["snapshot_id"] == ocr_only.snapshot_id
        assert submission["workflow"] == "OCR_ONLY"
        assert submission["terminal_status"] == "PARTIAL"
        assert submission["historical"] is True
        assert submission["is_latest"] is False
        assert submission["stale"] is True

        downloaded = client.get(submission["download_url"])
        assert downloaded.status_code == 200
        assert downloaded.headers["x-latexstruct-stale"] == "true"
        with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
            _assert_zip_checksums(archive)
            manifest = json.loads(archive.read("submission_manifest.json"))
            assert manifest["snapshot_id"] == ocr_only.snapshot_id
            assert manifest["workflow"] == "OCR_ONLY"
            assert manifest["terminal_status"] == "PARTIAL"

        # Generating history must not promote it to the current/latest run.
        assert audit_store.latest().snapshot_id == combined.snapshot_id
        after = client.get(f"/api/projects/{pid}/audit-submission/latest").json()
        assert after["latest"]["snapshot_id"] == combined.snapshot_id
        history_after = {
            item["snapshot_id"]: item for item in after["history"]
        }
        assert history_after[ocr_only.snapshot_id]["bundle_state"] == "ZIP_READY"
        assert history_after[ocr_only.snapshot_id]["download_url"]

        unknown = client.post(
            f"/api/projects/{pid}/audit-submission",
            json={"snapshot_id": "snapshot-not-saved-by-host"},
        )
        assert unknown.status_code == 404

# -*- coding: utf-8 -*-
"""Service integration for immutable v2 analysis-run archives."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover
    from starlette.testclient import TestClient

import latexstruct.server.app as srv
from latexstruct.core.analysis_adapter import verify_frozen_analysis_run
from latexstruct.core.analysis_runtime import AnalysisQualityRuntime, CandidateRepository
from latexstruct.core.analysis_schema import AnalysisFinalStatus


SAMPLE = (
    "\\documentclass{article}\n"
    "\\begin{document}\n"
    "Theorem 1. A deterministic service integration sample.\n"
    "\\end{document}\n"
)


class WorkspaceTmp:
    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="ls-analysis-api-", dir=Path(__file__).parent)
        import latexstruct.config as configmod

        self.old_config_path = configmod.CONFIG_PATH
        configmod.CONFIG_PATH = os.path.join(self.path, "config.json")
        return self.path

    def __exit__(self, *exc):
        import latexstruct.config as configmod

        configmod.CONFIG_PATH = self.old_config_path
        shutil.rmtree(self.path, ignore_errors=True)


def _client(tmp: str) -> TestClient:
    srv._process_jobs.clear()
    with srv._project_locks_guard:
        srv._project_locks.clear()
    srv._cancel_update_preparation()
    srv._active_pipeline_runs = 0
    srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
    srv._config = None
    return TestClient(srv.create_app())


def _fake_compile(_text: str, **kwargs) -> dict:
    record = {
        "available": True,
        "ok": True,
        "pages": 1,
        "errors": [],
        "log": "host-produced deterministic compile log",
        "preview_status": "COMPILED",
        "process_status": "SUCCESS",
        "return_code": 0,
        "passes_completed": 1,
    }
    if kwargs.get("include_pdf"):
        record["pdf_bytes"] = b"%PDF-analysis-adapter-service-test"
    return record


def _create(client: TestClient) -> str:
    response = client.post(
        "/api/projects",
        json={"text": SAMPLE, "name": "analysis adapter", "mode": "rule"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _archive_directory(pid: str, summary: dict) -> Path:
    relative = str(summary["relative_path"])
    assert not Path(relative).is_absolute()
    assert ":" not in relative
    return Path(srv.get_store()._dir(pid)).joinpath(*PurePosixPath(relative).parts)


def test_sync_process_exposes_fail_closed_analysis_archive_without_changing_ok():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create(client)
        final_decision = AnalysisQualityRuntime.final_decision
        persist_candidate = CandidateRepository.persist
        with (
            patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile),
            patch.object(
                AnalysisQualityRuntime,
                "final_decision",
                autospec=True,
                side_effect=final_decision,
            ) as runtime_finalize,
            patch.object(
                CandidateRepository,
                "persist",
                autospec=True,
                side_effect=persist_candidate,
            ) as candidate_persist,
        ):
            response = client.post(f"/api/projects/{pid}/process")

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ok"] is True  # existing processing contract is unchanged
        summary = payload["analysis_archive"]
        assert summary["archive_status"] == "READY"
        assert summary["final_status"] == "COMPLETED_WITH_ISSUES"
        assert summary["verified"] is False
        assert summary["verification"]["status"] == "UNVERIFIED"
        assert "two_independent_reviews_missing" in summary["failures"]
        assert summary["quality_runtime"]["executed"] is True
        assert summary["quality_runtime"]["candidate_count"] >= 1
        assert summary["verification"]["evidence_source"].startswith("host-derived-")
        assert summary["verification"]["review_pass_count"] < 2
        assert runtime_finalize.call_count == 1
        assert candidate_persist.call_count == summary["quality_runtime"]["candidate_count"]

        directory = _archive_directory(pid, summary)
        assert verify_frozen_analysis_run(directory)
        final = json.loads(
            (directory / "audit" / "final_decision.json").read_text(encoding="utf-8")
        )
        assert final["legacy_safe_to_export"] is True
        assert final["verified"] is False
        assert final["status"] == "COMPLETED_WITH_ISSUES"
        evidence = json.loads(
            (directory / "audit" / "v2_verification_evidence.json").read_text(
                encoding="utf-8"
            )
        )
        assert evidence["candidate_hash"] == evidence["current_candidate_hash"]
        assert evidence["final_reviews"] == []


def test_background_result_uses_job_id_and_archive_failure_is_nonfatal():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create(client)
        with patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile):
            started = client.post(f"/api/projects/{pid}/process/start").json()
            deadline = time.time() + 8
            while time.time() < deadline:
                status = client.get(f"/api/projects/{pid}/process/status").json()
                if status["status"] in {"done", "error", "cancelled"}:
                    break
                time.sleep(0.01)
        assert status["status"] == "done", status
        summary = status["result"]["analysis_archive"]
        assert summary["run_id"] == started["id"]
        assert _archive_directory(pid, summary).name == started["id"]

        second_pid = _create(client)
        with (
            patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile),
            patch(
                "latexstruct.server.app.freeze_pipeline_analysis_run",
                side_effect=OSError("C:/private/path/archive denied"),
            ),
        ):
            response = client.post(f"/api/projects/{second_pid}/process")
        payload = response.json()
        assert payload["ok"] is True
        failed = payload["analysis_archive"]
        assert failed["archive_status"] == "FAILED"
        assert failed["final_status"] == "FAILED_BEST_RETAINED"
        assert failed["verified"] is False
        assert failed["relative_path"] is None
        assert "C:/private/path" not in failed["error"]


def test_archive_is_not_reported_ready_when_immediate_hash_recheck_fails():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create(client)
        with (
            patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile),
            patch(
                "latexstruct.server.app.verify_frozen_analysis_run",
                return_value=False,
            ) as verify_archive,
        ):
            response = client.post(f"/api/projects/{pid}/process")

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ok"] is True
        failed = payload["analysis_archive"]
        assert failed["archive_status"] == "FAILED"
        assert failed["final_status"] == "FAILED_BEST_RETAINED"
        assert failed["verified"] is False
        assert failed["relative_path"] is None
        assert failed["verification"]["status"] == "UNVERIFIED"
        assert verify_archive.call_count == 1


def test_server_never_reports_verified_archive_without_production_authority():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create(client)
        forged = SimpleNamespace(
            run_directory=Path(tmp) / "forged-analysis-archive",
            status=AnalysisFinalStatus.VERIFIED,
            verified=True,
        )
        with (
            patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile),
            patch(
                "latexstruct.server.app.freeze_pipeline_analysis_run",
                return_value=forged,
            ),
            patch(
                "latexstruct.server.app.verify_frozen_analysis_run",
                return_value=True,
            ),
        ):
            response = client.post(f"/api/projects/{pid}/process")

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ok"] is True
        summary = payload["analysis_archive"]
        assert summary["archive_status"] == "FAILED"
        assert summary["verified"] is False
        assert summary["verification"]["status"] == "UNVERIFIED"
        assert summary["verification"]["verified"] is False
        assert "safe_to_export" not in summary


def test_server_packages_authoritative_pipeline_fields_as_typed_archive_evidence():
    with WorkspaceTmp() as tmp:
        client = _client(tmp)
        pid = _create(client)
        run_pipeline = srv.run_pipeline
        authoritative_snapshot = object.__new__(srv.AnalysisRunSnapshot)
        object.__setattr__(authoritative_snapshot, "page_count", 1)
        object.__setattr__(authoritative_snapshot, "page_range", (1,))
        object.__setattr__(authoritative_snapshot, "models", ())
        object.__setattr__(authoritative_snapshot, "prompt_version", "production-v2")
        page_risk_admission = object()
        page_inputs = (object(),)
        page_route_closure = object()
        analysis_configuration = {"source": "production-pipeline"}
        analysis_configuration_sha256 = "a" * 64
        risk_preflight = (object(),)
        typed_evidence = object()

        def pipeline_with_authority(*args, **kwargs):
            result = run_pipeline(*args, **kwargs)
            result.analysis_v2_authoritative_snapshot = authoritative_snapshot
            result.analysis_v2_page_risk_admission = page_risk_admission
            result.analysis_v2_production_page_inputs = page_inputs
            result.analysis_v2_page_route_closure = page_route_closure
            result.analysis_v2_analysis_configuration = analysis_configuration
            result.analysis_v2_analysis_configuration_sha256 = (
                analysis_configuration_sha256
            )
            result.analysis_v2_typed_risk_preflight = risk_preflight
            result.analysis_v2_baseline_tex = SAMPLE
            result.analysis_v2_baseline_pdf = b"%PDF-production-baseline"
            return result

        with (
            patch("latexstruct.core.compilecheck.compile_latex", side_effect=_fake_compile),
            patch(
                "latexstruct.server.app.run_pipeline",
                side_effect=pipeline_with_authority,
            ),
            patch(
                "latexstruct.server.app.ProductionAnalysisArchiveEvidence",
                autospec=True,
                return_value=typed_evidence,
            ) as evidence_factory,
            patch(
                "latexstruct.server.app.freeze_pipeline_analysis_run",
                side_effect=OSError("controlled archive stop"),
            ) as freeze_archive,
        ):
            response = client.post(f"/api/projects/{pid}/process")

        assert response.status_code == 200, response.text
        summary = response.json()["analysis_archive"]
        assert summary["archive_status"] == "FAILED"
        assert summary["verified"] is False
        evidence_factory.assert_called_once_with(
            snapshot=authoritative_snapshot,
            page_risk_admission=page_risk_admission,
            page_inputs=page_inputs,
            page_route_closure=page_route_closure,
            analysis_configuration=analysis_configuration,
            analysis_configuration_sha256=analysis_configuration_sha256,
            risk_preflight=risk_preflight,
        )
        assert freeze_archive.call_count == 1
        freeze_kwargs = freeze_archive.call_args.kwargs
        assert freeze_kwargs["authoritative_snapshot"] is authoritative_snapshot
        assert freeze_kwargs["production_evidence"] is typed_evidence

# -*- coding: utf-8 -*-
"""本地整书编排器测试；全部使用假 API，绝不启动真实 Codex 模型。"""

import io
import json
import os
from pathlib import Path
import zipfile

import pytest

import tools.run_local_book as book_runner_module
from tools.run_local_book import ApiResponse, BookRunner, LocalApi, RunnerError, StateStore


class FakeApi:
    def __init__(self):
        self.calls = []
        self.ocr_statuses = [
            {
                "status": "running", "phase": "第 1 页", "done": 1, "total": 2,
                "page": 1, "raw_revision": 1, "state_revision": 2, "errors": [],
            },
            {
                "status": "partial", "phase": "等待重试", "done": 2, "total": 2,
                "page": 2, "raw_revision": 1, "state_revision": 3,
                "errors": [{"page": 2, "reason": "temporary timeout"}],
            },
            {
                "status": "running", "phase": "重试第 2 页", "done": 1, "total": 2,
                "page": 2, "raw_revision": 1, "state_revision": 4, "errors": [],
            },
            {
                "status": "done", "phase": "原始 OCR 已就绪", "done": 2, "total": 2,
                "page": 2, "raw_revision": 2, "state_revision": 5, "errors": [],
            },
        ]
        self.analysis_statuses = [
            {
                "status": "running", "phase": "review", "progress": 0.7,
                "message": "正在复查", "preview_revision": 1,
            },
            {
                "status": "blocked", "phase": "verification_failed", "progress": 1.0,
                "message": "编译检查未通过", "preview_revision": 2,
            },
        ]

    def upload(self, path, file_path, field="file"):
        self.calls.append(("UPLOAD", path, {"name": file_path.name, "field": field}))
        return {"id": "ocr-1", "total_pages": 20, "max_pages_per_job": 500}

    def json(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if path == "/api/codex/status":
            return {"ready": True, "authenticated": True, "message": "ready"}
        if path == "/api/config":
            payload = kwargs["payload"]
            return {
                "analysis_backend": payload["analysis_backend"],
                "codex_model": payload["codex_model"],
                "codex_reasoning_effort": payload["codex_reasoning_effort"],
            }
        if path == "/api/ocr/jobs/ocr-1/start":
            return {"id": "ocr-1", "status": "running"}
        if path == "/api/ocr/jobs/ocr-1":
            return self.ocr_statuses.pop(0)
        if path == "/api/ocr/jobs/ocr-1/retry-failed":
            return {"id": "ocr-1", "status": "running"}
        if path == "/api/ocr/jobs/ocr-1/save":
            return {"ok": True, "filename": "OCR.zip", "preserved": True}
        if path == "/api/ocr/jobs/ocr-1/import":
            return {"id": "project-1", "processed": False, "process": {"status": "running"}}
        if path == "/api/projects/project-1/process/status":
            return self.analysis_statuses.pop(0)
        raise AssertionError(f"unexpected JSON request: {method} {path}")

    def download(self, path, **kwargs):
        self.calls.append(("DOWNLOAD", path, kwargs))
        if path == "/api/ocr/jobs/ocr-1/preview":
            return ApiResponse(b"ocr preview", {})
        if path == "/api/ocr/jobs/ocr-1/result":
            return ApiResponse(b"ocr result", {})
        if path == "/api/ocr/jobs/ocr-1/package":
            return ApiResponse(b"ocr zip", {})
        if path == "/api/projects/project-1/process/preview":
            return ApiResponse(b"analysis preview", {})
        if path.endswith("/export-current-package"):
            return ApiResponse(b"current zip", {"x-latexstruct-verified": "false"})
        if path.endswith("/export-current-report"):
            return ApiResponse(b"current report", {"x-latexstruct-verified": "false"})
        if path.endswith("/export-current"):
            return ApiResponse(b"current tex", {"x-latexstruct-verified": "false"})
        raise AssertionError(f"unexpected download: {path}")


def _new_store(tmp_path: Path) -> StateStore:
    pdf = tmp_path / "book.pdf"
    pdf.write_bytes(b"%PDF-1.7\nfixture")
    store = StateStore(tmp_path / "run" / "run-state.json")
    store.initialize(
        pdf,
        {
            "start_page": 3,
            "end_page": 20,
            "dpi": 180,
            "ocr_retries": 2,
            "reasoning_effort": "medium",
            "codex_model": "",
            "name": "Bondy 前17章",
            "title": "Graph Theory",
        },
        "http://127.0.0.1:8080",
    )
    return store


def test_atomic_write_retries_transient_windows_permission_error(monkeypatch, tmp_path):
    destination = tmp_path / "run-state.json"
    destination.write_bytes(b"old state")
    real_replace = os.replace
    replace_calls = []
    sleeps = []

    def flaky_replace(source, target):
        replace_calls.append((Path(source), Path(target)))
        if len(replace_calls) < 3:
            raise PermissionError(13, "file is temporarily locked", str(target))
        real_replace(source, target)

    monkeypatch.setattr(book_runner_module.os, "replace", flaky_replace)
    monkeypatch.setattr(book_runner_module.time, "sleep", sleeps.append)
    monkeypatch.setattr(book_runner_module, "ATOMIC_REPLACE_RETRY_DELAYS", (0.01, 0.02))

    book_runner_module._atomic_write(destination, b"new state")

    assert destination.read_bytes() == b"new state"
    assert len(replace_calls) == 3
    assert sleeps == [0.01, 0.02]
    assert list(tmp_path.iterdir()) == [destination]


def test_atomic_write_does_not_overwrite_destination_created_during_retry(
    monkeypatch, tmp_path
):
    destination = tmp_path / "run-state.json"
    replace_calls = []

    def locked_then_foreign(_source, target):
        replace_calls.append(Path(target))
        Path(target).write_bytes(b"foreign state")
        raise PermissionError(13, "file is temporarily locked", str(target))

    monkeypatch.setattr(book_runner_module.os, "replace", locked_then_foreign)
    monkeypatch.setattr(book_runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(book_runner_module, "ATOMIC_REPLACE_RETRY_DELAYS", (0.0,))

    with pytest.raises(RunnerError, match="已被其他进程改动"):
        book_runner_module._atomic_write(destination, b"our state")

    assert replace_calls == [destination]
    assert destination.read_bytes() == b"foreign state"
    assert list(tmp_path.iterdir()) == [destination]


def test_atomic_write_exhaustion_preserves_old_destination_and_cleans_temp(
    monkeypatch, tmp_path
):
    destination = tmp_path / "run-state.json"
    destination.write_bytes(b"last durable state")
    replace_calls = []

    def always_locked(_source, target):
        replace_calls.append(Path(target))
        raise PermissionError(13, "still locked", str(target))

    monkeypatch.setattr(book_runner_module.os, "replace", always_locked)
    monkeypatch.setattr(book_runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(book_runner_module, "ATOMIC_REPLACE_RETRY_DELAYS", (0.0, 0.0))

    with pytest.raises(PermissionError, match="still locked"):
        book_runner_module._atomic_write(destination, b"new state")

    assert len(replace_calls) == 3
    assert destination.read_bytes() == b"last durable state"
    assert list(tmp_path.iterdir()) == [destination]


def test_runner_retries_ocr_and_exports_blocked_analysis(tmp_path):
    store = _new_store(tmp_path)
    api = FakeApi()
    runner = BookRunner(api, store, poll_seconds=0.05, sleep=lambda _seconds: None)

    result = runner.execute()

    assert result["phase"] == "complete"
    assert result["outcome"] == "unverified"
    assert result["process_status"] == "blocked"
    assert result["ocr"]["retry_rounds"] == 1
    assert result["applied_config"] == {
        "analysis_backend": "codex_cli",
        "codex_model": "",
        "codex_reasoning_effort": "medium",
    }
    assert set(result["artifacts"]) == {
        "ocr-preview.tex",
        "ocr-result.tex",
        "ocr-project.zip",
        "analysis-preview.tex",
        "current-project.zip",
        "analysis-report.md",
        "current.tex",
    }
    assert (store.output_dir / "current-project.zip").read_bytes() == b"current zip"
    assert (store.output_dir / "analysis-report.md").read_bytes() == b"current report"

    retry_calls = [call for call in api.calls if call[1].endswith("/retry-failed")]
    assert len(retry_calls) == 1
    config_call = next(call for call in api.calls if call[1] == "/api/config")
    assert config_call[2]["payload"] == {
        "analysis_backend": "codex_cli",
        "codex_reasoning_effort": "medium",
        "codex_model": "",
    }
    import_call = next(call for call in api.calls if call[1].endswith("/import"))
    assert import_call[2]["query"]["mode"] == "ai"
    assert import_call[2]["query"]["template"] == "faithfulbook"

    reloaded = StateStore(store.path).load()
    assert reloaded["phase"] == "complete"
    assert reloaded["artifacts"]["ocr-project.zip"]["sha256"]
    assert any(item["kind"] == "exports_saved" for item in reloaded["diagnostics"])


class PauseApi:
    def __init__(self):
        self.calls = []
        self.statuses = [{"status": "running"}, {"status": "pausing"}, {"status": "paused"}]

    def json(self, method, path, **kwargs):
        self.calls.append((method, path))
        if method == "POST":
            return {"status": "pausing"}
        return self.statuses.pop(0)


def test_pause_command_waits_for_safe_analysis_boundary_and_persists(tmp_path):
    store = _new_store(tmp_path)
    store.state["project_id"] = "project-2"
    store.phase("analysis_running", "analysis")
    api = PauseApi()
    runner = BookRunner(api, store, poll_seconds=0.05, sleep=lambda _seconds: None)

    result = runner.pause_active(timeout=2)

    assert result["phase"] == "paused"
    assert result["active_stage"] == "analysis"
    assert result["analysis"]["last_status"]["status"] == "paused"
    assert ("POST", "/api/projects/project-2/process/pause") in api.calls
    assert StateStore(store.path).load()["phase"] == "paused"


class ExportOnlyApi:
    """模拟提交后进程被杀：Codex 已离线，但落盘成果仍必须可以取回。"""

    def __init__(self):
        self.json_calls = []

    def json(self, method, path, **kwargs):
        self.json_calls.append((method, path))
        raise AssertionError("已知分析终态不应再次探测 Codex 或启动模型")

    def download(self, path, **_kwargs):
        if path.endswith("/export-current-package"):
            return ApiResponse(b"recovered zip", {"x-latexstruct-verified": "false"})
        if path.endswith("/export-current-report"):
            return ApiResponse(b"recovered report", {"x-latexstruct-verified": "false"})
        if path.endswith("/export-current"):
            return ApiResponse(b"recovered tex", {"x-latexstruct-verified": "false"})
        raise AssertionError(path)


def test_resume_exports_known_terminal_result_without_requiring_codex(tmp_path):
    store = _new_store(tmp_path)
    store.state["project_id"] = "project-finished"
    store.state["analysis"]["terminal_status"] = {"status": "blocked"}
    store.phase("analysis_terminal", "")
    api = ExportOnlyApi()

    result = BookRunner(api, store, sleep=lambda _seconds: None).execute(auto_resume=True)

    assert result["phase"] == "complete"
    assert result["process_status"] == "blocked"
    assert result["outcome"] == "unverified"
    assert api.json_calls == []
    assert (store.output_dir / "current-project.zip").read_bytes() == b"recovered zip"


class _LocalResponse:
    status = 200
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b"artifact"


def test_long_artifact_download_uses_separate_timeout_without_blind_retry(monkeypatch):
    calls = []

    def fake_urlopen(_request, timeout):
        calls.append(timeout)
        if len(calls) == 1:
            raise TimeoutError("slow zip")
        return _LocalResponse()

    monkeypatch.setattr(book_runner_module, "urlopen", fake_urlopen)
    api = LocalApi("http://127.0.0.1:8080", timeout=7, artifact_timeout=123)

    try:
        api.download("/api/projects/p/export-current-package", long_running=True)
    except Exception as exc:  # the exact user-facing wrapper is tested by the call count
        assert "slow zip" in str(exc)
    else:
        raise AssertionError("long artifact timeout must surface to explicit resume")
    assert calls == [123]

    response = api.download("/api/health")
    assert response.body == b"artifact"
    assert calls == [123, 7]


def test_runner_records_resource_limit_diagnostics_from_ocr_manifest(tmp_path):
    store = _new_store(tmp_path)
    runner = BookRunner(FakeApi(), store, sleep=lambda _seconds: None)
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "OCR-MANIFEST.json",
            json.dumps({
                "resources": {
                    "assets": [{"path": "images/p1-fig1.png"}],
                    "total_bytes": 95 * 1024 * 1024,
                    "unresolved": [],
                },
            }),
        )

    runner._record_ocr_resource_diagnostics(package.getvalue())

    assert store.state["ocr"]["resource_summary"] == {
        "assets": 1,
        "bytes": 95 * 1024 * 1024,
        "unresolved": 0,
    }
    assert store.state["diagnostics"][-1]["kind"] == "ocr_resource_near_limit"

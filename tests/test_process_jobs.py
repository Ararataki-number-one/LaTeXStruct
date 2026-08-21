# -*- coding: utf-8 -*-
"""后台处理任务暂停/继续/取消状态机测试。"""

import threading
import time

from latexstruct.server.process_jobs import ProcessJobManager, ProcessingCancelled


def _wait_status(manager, job, expected, timeout=1.0):
    end = time.time() + timeout
    while time.time() < end:
        if manager.public(job)["status"] == expected:
            return
        time.sleep(0.005)
    raise AssertionError(f"任务未进入 {expected}，当前 {manager.public(job)['status']}")


def test_pause_resume_at_safe_control_point():
    manager = ProcessJobManager()
    job = manager.create("project-1", "source")
    assert manager.active_count() == 1
    manager.request_pause(job)
    passed = threading.Event()

    def run_control():
        manager.control(job["id"])
        passed.set()

    thread = threading.Thread(target=run_control)
    thread.start()
    _wait_status(manager, job, "paused")
    assert not passed.is_set()
    manager.request_resume(job)
    thread.join(timeout=1)
    assert passed.is_set()
    assert manager.public(job)["status"] == "running"


def test_active_count_includes_paused_and_excludes_terminal_jobs():
    manager = ProcessJobManager()
    first = manager.create("project-a")
    second = manager.create("project-b")
    manager.request_pause(first)
    assert manager.active_count() == 2
    manager.complete(second["id"], {"ok": True})
    assert manager.active_count() == 1
    manager.cancelled(first["id"])
    assert manager.active_count() == 0


def test_preview_state_is_explicit_and_only_promoted_by_terminal_evidence():
    manager = ProcessJobManager()
    job = manager.create("project-preview", "source")
    assert manager.public(job)["preview_state"] == "SOURCE_PREVIEW"

    manager.complete(job["id"], {"ok": True, "preview_state": "COMPILED"})
    assert manager.public(job)["preview_state"] == "COMPILED"

    invalid = manager.create("project-invalid-preview", "source")
    manager.complete(invalid["id"], {"ok": False, "preview_state": "made-up"})
    assert manager.public(invalid)["preview_state"] == "SOURCE_PREVIEW"


def test_job_snapshot_exposes_only_allowlisted_analysis_backend():
    manager = ProcessJobManager()
    codex = manager.create("project-codex", analysis_backend="codex_cli")
    unknown = manager.create("project-unknown", analysis_backend="shell-command")
    assert manager.public(codex)["analysis_backend"] == "codex_cli"
    assert manager.public(unknown)["analysis_backend"] == "api"


def test_cancel_paused_task_wakes_worker_without_saving():
    manager = ProcessJobManager()
    job = manager.create("project-2", "draft")
    manager.request_pause(job)
    cancelled = threading.Event()

    def run_control():
        try:
            manager.control(job["id"])
        except ProcessingCancelled:
            cancelled.set()

    thread = threading.Thread(target=run_control)
    thread.start()
    _wait_status(manager, job, "paused")
    manager.request_cancel(job)
    thread.join(timeout=1)
    assert cancelled.is_set()
    manager.cancelled(job["id"])
    public = manager.public(job)
    assert public["status"] == "cancelled"
    assert manager.preview(job) == "draft"


def test_progress_is_monotonic_and_preview_is_private_from_status():
    manager = ProcessJobManager()
    job = manager.create("project-3", "source")
    initial = manager.public(job)
    assert initial["preview_revision"] == 1
    assert initial["preview_chars"] == len("source")
    manager.update(job["id"], "draft", 0.8, "草稿", {
        "preview": "new draft",
        "candidate_total": 12,
        "processed_candidates": 6,
    })
    manager.update(job["id"], "late", 0.4, "较晚回调")
    public = manager.public(job)
    assert public["progress"] == 0.8
    assert public["preview_ready"] is True
    assert public["preview_revision"] == 2
    assert public["preview_chars"] == len("new draft")
    assert public["candidate_total"] == 12
    assert public["processed_candidates"] == 6
    assert "preview" not in public
    assert manager.preview(job) == "new draft"

    manager.update(job["id"], "same", 0.9, "标签变化", {
        "preview": "new draft", "preview_label": "新标签",
    })
    assert manager.public(job)["preview_revision"] == 2

    manager.update(job["id"], "newer", 0.95, "正文变化", {"preview": "newer draft"})
    assert manager.preview_snapshot(job) == ("newer draft", 3)

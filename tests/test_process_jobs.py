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
    manager.update(job["id"], "draft", 0.8, "草稿", {"preview": "new draft"})
    manager.update(job["id"], "late", 0.4, "较晚回调")
    public = manager.public(job)
    assert public["progress"] == 0.8
    assert public["preview_ready"] is True
    assert "preview" not in public
    assert manager.preview(job) == "new draft"

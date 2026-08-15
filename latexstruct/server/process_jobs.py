# -*- coding: utf-8 -*-
"""结构化处理后台任务：进度、暂停、继续、取消与草稿预览。"""

from __future__ import annotations

import copy
import threading
import time
import uuid
from typing import Dict, Optional

from ..pricing import summarize_ai_usage


TERMINAL_STATUSES = {"done", "error", "cancelled"}
ACTIVE_STATUSES = {"running", "pausing", "paused", "cancelling", "committing"}


class ProcessingCancelled(Exception):
    """用户在安全暂停点取消任务。"""


class ProcessJobManager:
    def __init__(self, ttl_seconds: int = 24 * 60 * 60):
        self.ttl_seconds = ttl_seconds
        self._jobs: Dict[str, dict] = {}
        self._latest_by_pid: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)

    def clear(self):
        """仅供测试/应用重启清空内存态；不会删除任何项目文件。"""
        with self._changed:
            for job in self._jobs.values():
                job["cancel_requested"] = True
                job["pause_requested"] = False
            self._changed.notify_all()
            self._jobs.clear()
            self._latest_by_pid.clear()

    def cleanup(self, now: float = None):
        now = now or time.time()
        with self._changed:
            stale = [
                jid for jid, job in self._jobs.items()
                if job.get("status") in TERMINAL_STATUSES
                and now - job.get("updated", now) > self.ttl_seconds
            ]
            for jid in stale:
                pid = self._jobs[jid]["pid"]
                self._jobs.pop(jid, None)
                if self._latest_by_pid.get(pid) == jid:
                    self._latest_by_pid.pop(pid, None)

    def create(self, pid: str, source_preview: str = "") -> dict:
        self.cleanup()
        with self._changed:
            existing = self._active_locked(pid)
            if existing:
                return existing
            now = time.time()
            jid = uuid.uuid4().hex[:12]
            job = {
                "id": jid,
                "pid": pid,
                "status": "running",
                "phase": "queued",
                "phase_label": "已进入处理队列",
                "progress": 0.0,
                "message": "正在启动后台任务",
                "created": now,
                "updated": now,
                "started": now,
                "finished": None,
                "pause_requested": False,
                "cancel_requested": False,
                "preview": source_preview,
                "preview_label": "原始内容（尚未生成草稿）",
                "usage": {},
                "cost": summarize_ai_usage({}),
                "events": [{"at": now, "phase": "queued", "message": "任务已创建"}],
                "result": None,
                "error": "",
            }
            self._jobs[jid] = job
            self._latest_by_pid[pid] = jid
            return job

    def get(self, jid: str) -> Optional[dict]:
        with self._lock:
            return self._jobs.get(jid)

    def latest(self, pid: str) -> Optional[dict]:
        with self._lock:
            jid = self._latest_by_pid.get(pid)
            return self._jobs.get(jid) if jid else None

    def active(self, pid: str) -> Optional[dict]:
        with self._lock:
            return self._active_locked(pid)

    def _active_locked(self, pid: str) -> Optional[dict]:
        jid = self._latest_by_pid.get(pid)
        job = self._jobs.get(jid) if jid else None
        return job if job and job.get("status") in ACTIVE_STATUSES else None

    def public(self, job: dict) -> dict:
        with self._lock:
            payload = {
                key: value for key, value in job.items()
                if key not in {"preview", "pause_requested", "cancel_requested"}
            } | {
                "preview_ready": bool(job.get("preview")),
                "preview_lines": (job.get("preview") or "").count("\n") + 1,
                "can_pause": job.get("status") in {"running", "pausing"},
                "can_resume": job.get("status") == "paused",
                "can_cancel": job.get("status") in ACTIVE_STATUSES - {"committing"},
            }
            return copy.deepcopy(payload)

    def update(self, jid: str, phase: str, progress: float, message: str, data: dict = None):
        with self._changed:
            job = self._jobs.get(jid)
            if not job or job.get("status") in TERMINAL_STATUSES:
                return
            data = data or {}
            job["phase"] = phase
            job["phase_label"] = message
            job["message"] = message
            job["progress"] = round(max(job.get("progress", 0.0), min(1.0, progress)), 4)
            if isinstance(data.get("preview"), str):
                job["preview"] = data["preview"]
                job["preview_label"] = data.get("preview_label") or "处理中草稿"
            if isinstance(data.get("usage"), dict):
                job["usage"] = data["usage"]
                job["cost"] = summarize_ai_usage(data["usage"])
            for key in (
                "candidate_total", "decision_total", "completed_candidates", "ambiguous",
                "applied", "rejected", "review_findings", "safe_to_export",
            ):
                if key in data:
                    job[key] = data[key]
            now = time.time()
            job["updated"] = now
            last = job["events"][-1] if job["events"] else {}
            if last.get("phase") != phase or last.get("message") != message:
                job["events"].append({"at": now, "phase": phase, "message": message})
                job["events"] = job["events"][-40:]
            self._changed.notify_all()

    def control(self, jid: str):
        """流水线在阶段/批次边界调用；暂停时阻塞，取消时抛出专用异常。"""
        with self._changed:
            job = self._jobs.get(jid)
            if not job:
                raise ProcessingCancelled("任务已不存在")
            if job.get("cancel_requested"):
                raise ProcessingCancelled("用户取消了处理")
            if job.get("pause_requested"):
                job["status"] = "paused"
                job["message"] = "已安全暂停，可继续或取消"
                job["updated"] = time.time()
                self._changed.notify_all()
                while job.get("pause_requested") and not job.get("cancel_requested"):
                    self._changed.wait(timeout=1.0)
                if job.get("cancel_requested"):
                    raise ProcessingCancelled("用户取消了处理")
                job["status"] = "running"
                job["message"] = "已继续处理"
                job["updated"] = time.time()

    def request_pause(self, job: dict) -> dict:
        with self._changed:
            if job.get("status") not in {"running", "pausing"}:
                return job
            job["pause_requested"] = True
            job["status"] = "pausing"
            job["message"] = "正在完成当前步骤，随后安全暂停"
            job["updated"] = time.time()
            self._changed.notify_all()
            return job

    def request_resume(self, job: dict) -> dict:
        with self._changed:
            if job.get("status") not in {"paused", "pausing"}:
                return job
            job["pause_requested"] = False
            job["status"] = "running"
            job["message"] = "已继续处理"
            job["updated"] = time.time()
            self._changed.notify_all()
            return job

    def request_cancel(self, job: dict) -> dict:
        with self._changed:
            if job.get("status") in TERMINAL_STATUSES or job.get("status") == "committing":
                return job
            job["cancel_requested"] = True
            job["pause_requested"] = False
            job["status"] = "cancelling"
            job["message"] = "正在安全取消，不会保存未验证草稿"
            job["updated"] = time.time()
            self._changed.notify_all()
            return job

    def begin_commit(self, jid: str):
        """进入不可中断的原子保存窗口；到达这里的结果已经完成全部安全检查。"""
        with self._changed:
            job = self._jobs.get(jid)
            if not job or job.get("cancel_requested"):
                raise ProcessingCancelled("用户取消了处理")
            job["status"] = "committing"
            job["phase"] = "commit"
            job["phase_label"] = "正在保存已验证结果"
            job["message"] = "安全检查已完成，正在原子保存"
            job["progress"] = max(0.99, job.get("progress", 0.0))
            job["updated"] = time.time()
            self._changed.notify_all()

    def complete(self, jid: str, result: dict):
        with self._changed:
            job = self._jobs.get(jid)
            if not job:
                return
            job["status"] = "done"
            job["phase"] = "done"
            job["phase_label"] = "处理完成"
            job["message"] = "安全检查通过" if result.get("ok") else "安全检查未通过，已回退原文"
            job["progress"] = 1.0
            job["result"] = result
            if isinstance(result.get("usage"), dict):
                job["usage"] = result["usage"]
                job["cost"] = summarize_ai_usage(result["usage"])
            job["finished"] = job["updated"] = time.time()
            job["events"].append({"at": job["updated"], "phase": "done", "message": job["message"]})
            self._changed.notify_all()

    def cancelled(self, jid: str):
        with self._changed:
            job = self._jobs.get(jid)
            if not job:
                return
            job["status"] = "cancelled"
            job["phase"] = "cancelled"
            job["phase_label"] = "任务已取消"
            job["message"] = "未保存未验证草稿，原项目保持不变"
            job["finished"] = job["updated"] = time.time()
            job["events"].append({"at": job["updated"], "phase": "cancelled", "message": job["message"]})
            self._changed.notify_all()

    def fail(self, jid: str, message: str):
        with self._changed:
            job = self._jobs.get(jid)
            if not job:
                return
            job["status"] = "error"
            job["phase"] = "error"
            job["phase_label"] = "处理未完成"
            job["message"] = "处理未完成，原项目保持不变"
            job["error"] = (message or "未知错误")[:500]
            job["finished"] = job["updated"] = time.time()
            job["events"].append({"at": job["updated"], "phase": "error", "message": job["message"]})
            self._changed.notify_all()

    def preview(self, job: dict) -> str:
        with self._lock:
            return job.get("preview", "")

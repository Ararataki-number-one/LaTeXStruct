# -*- coding: utf-8 -*-
"""结构化处理后台任务：进度、暂停、继续、取消与草稿预览。"""

from __future__ import annotations

import copy
import hashlib
import threading
import time
import uuid
from typing import Dict, Optional

from ..pricing import summarize_ai_usage


TERMINAL_STATUSES = {"done", "blocked", "error", "cancelled"}
ACTIVE_STATUSES = {"running", "pausing", "paused", "cancelling", "committing"}
_AUDIT_PARENT_SNAPSHOT_FIELD = "_audit_parent_snapshot_id"


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

    def create(
        self,
        pid: str,
        source_preview: str = "",
        analysis_backend: str = "api",
    ) -> dict:
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
                "preview_revision": 1 if source_preview else 0,
                "preview_label": "原始内容（尚未生成草稿）",
                # This endpoint serves TeX source text.  Never let the UI infer
                # that a source snapshot is a rendered/compiled PDF preview.
                "preview_state": "SOURCE_PREVIEW",
                "usage": {},
                "cost": summarize_ai_usage({}),
                "analysis_backend": (
                    "codex_cli" if analysis_backend == "codex_cli" else "api"
                ),
                "events": [{"at": now, "phase": "queued", "message": "任务已创建"}],
                "result": None,
                "error": "",
                # Host-produced immutable stage snapshots.  They are kept out
                # of public polling payloads and are consumed only by the audit
                # submission builder after the task reaches a terminal state.
                "audit_stages": {},
                # Host-private lineage.  Only an OCR-import child is bound to
                # the immutable OCR_ONLY snapshot that existed at its launch.
                # Never expose this identifier through polling payloads.
                _AUDIT_PARENT_SNAPSHOT_FIELD: "",
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

    def audit_snapshot(self, job: dict) -> dict:
        """Return the private, host-captured evidence for one running task.

        Public polling deliberately omits stage bodies.  The audit finalizer
        uses this bounded copy after an exception/cancellation so the evidence
        can be persisted before the terminal state becomes visible to the UI.
        """
        with self._lock:
            return copy.deepcopy({
                "id": job.get("id"),
                "pid": job.get("pid"),
                "created": job.get("created"),
                "updated": job.get("updated"),
                "preview": job.get("preview") or "",
                "preview_state": job.get("preview_state") or "SOURCE_PREVIEW",
                "audit_stages": job.get("audit_stages") or {},
                "events": job.get("events") or [],
                "usage": job.get("usage") or {},
                "error": job.get("error") or "",
            })

    def active(self, pid: str) -> Optional[dict]:
        with self._lock:
            return self._active_locked(pid)

    def bind_audit_parent_snapshot(self, jid: str, snapshot_id: str) -> None:
        """Bind one job once to its host-frozen parent audit snapshot."""
        snapshot_id = str(snapshot_id or "").strip()
        if not snapshot_id or len(snapshot_id) > 128:
            raise ValueError("audit parent snapshot ID must be 1-128 characters")
        with self._changed:
            job = self._jobs.get(str(jid or ""))
            if job is None:
                raise KeyError("processing job no longer exists")
            existing = str(job.get(_AUDIT_PARENT_SNAPSHOT_FIELD) or "")
            if existing and existing != snapshot_id:
                raise ValueError("processing job audit parent snapshot is immutable")
            job[_AUDIT_PARENT_SNAPSHOT_FIELD] = snapshot_id
            self._changed.notify_all()

    def audit_parent_snapshot_id(self, job: dict) -> str:
        """Read private lineage from the manager-owned job, never its payload."""
        with self._lock:
            jid = str((job or {}).get("id") or "")
            stored = self._jobs.get(jid)
            if stored is None:
                return ""
            return str(stored.get(_AUDIT_PARENT_SNAPSHOT_FIELD) or "")

    def active_count(self) -> int:
        """返回所有项目的活动任务数，供更新/退出安全门使用。"""
        with self._lock:
            return sum(
                1 for job in self._jobs.values()
                if job.get("status") in ACTIVE_STATUSES
            )

    def _active_locked(self, pid: str) -> Optional[dict]:
        jid = self._latest_by_pid.get(pid)
        job = self._jobs.get(jid) if jid else None
        return job if job and job.get("status") in ACTIVE_STATUSES else None

    def public(self, job: dict) -> dict:
        with self._lock:
            payload = {
                key: value for key, value in job.items()
                if key not in {
                    "preview", "pause_requested", "cancel_requested", "audit_stages",
                    _AUDIT_PARENT_SNAPSHOT_FIELD,
                }
            } | {
                "preview_ready": bool(job.get("preview")),
                "preview_lines": (job.get("preview") or "").count("\n") + 1,
                "preview_chars": len(job.get("preview") or ""),
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
            previous_safe_to_export = job.get("safe_to_export")
            job["phase"] = phase
            job["phase_label"] = message
            job["message"] = message
            job["progress"] = round(max(job.get("progress", 0.0), min(1.0, progress)), 4)
            preserve_failed_draft = bool(
                (data.get("safe_to_export") is False or previous_safe_to_export is False)
                and phase in {"report", "ready"}
                and isinstance(job.get("preview"), str)
                and bool(job.get("preview"))
            )
            if isinstance(data.get("preview"), str) and not preserve_failed_draft:
                preview = data["preview"]
                if preview != job.get("preview", ""):
                    job["preview"] = preview
                    job["preview_revision"] = job.get("preview_revision", 0) + 1
                job["preview_label"] = data.get("preview_label") or "处理中草稿"
            elif preserve_failed_draft:
                job["preview_label"] = "未通过安全检查的结构化草稿（仅供检查，不能导出）"
            if isinstance(data.get("usage"), dict):
                job["usage"] = data["usage"]
                job["cost"] = summarize_ai_usage(data["usage"])
            audit_stage = data.get("audit_stage")
            if isinstance(audit_stage, dict):
                role = str(audit_stage.get("role") or "")
                text = audit_stage.get("text")
                allowed_roles = {
                    "ai_analyzed", "ai_reviewed", "rule_analyzed", "analyzed_current",
                }
                if role in allowed_roles and isinstance(text, str) and text:
                    stages = job.setdefault("audit_stages", {})
                    # A stage name is write-once inside one job.  This prevents
                    # a later progress callback from silently changing the
                    # evidence that a terminal RunSnapshot will freeze.
                    stages.setdefault(role, {
                        "text": text,
                        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "captured_at": time.time(),
                    })
            for key in (
                "candidate_total", "processed_candidates", "decision_total",
                "completed_candidates", "ambiguous", "applied", "rejected",
                "review_findings", "safe_to_export", "preview_state",
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
            passed = bool(result.get("ok"))
            job["status"] = "done" if passed else "blocked"
            job["phase"] = "done" if passed else "verification_failed"
            job["phase_label"] = "处理完成" if passed else "安全检查未通过"
            job["message"] = (
                "安全检查通过"
                if passed else str(result.get("failure_summary") or "安全检查未通过；失败草稿已保留供检查")[:500]
            )
            job["progress"] = 1.0
            job["result"] = result
            preview_state = str(result.get("preview_state") or "SOURCE_PREVIEW")
            job["preview_state"] = (
                preview_state
                if preview_state in {"COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"}
                else "SOURCE_PREVIEW"
            )
            if isinstance(result.get("usage"), dict):
                job["usage"] = result["usage"]
                job["cost"] = summarize_ai_usage(result["usage"])
            job["finished"] = job["updated"] = time.time()
            job["events"].append({
                "at": job["updated"],
                "phase": job["phase"],
                "message": job["message"],
            })
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

    def preview_snapshot(self, job: dict) -> tuple[str, int]:
        """在同一把锁内读取草稿及其版本，避免状态与正文跨版本。"""
        with self._lock:
            return job.get("preview", ""), int(job.get("preview_revision", 0))

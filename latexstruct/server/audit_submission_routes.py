# -*- coding: utf-8 -*-
"""FastAPI integration for one-click external AI audit submission bundles."""

from __future__ import annotations

import os
import subprocess
import threading
from functools import wraps
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.routing import Mount

from ..core.audit_schema import AuditSubmissionRequest
from ..core.audit_submission import (
    build_audit_submission,
    load_submission_summary,
    submission_directory,
    submission_package_path,
)


def _reviewed_ids(request: Request) -> tuple[str, ...]:
    values = request.query_params.getlist("reviewed_candidate_id")
    return tuple(sorted({str(item).strip() for item in values if str(item).strip()}))


def _reveal(path: Path) -> None:
    if os.name == "nt":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif os.sys.platform == "darwin":
        subprocess.Popen(["open", str(path)], close_fds=True)
    else:
        subprocess.Popen(["xdg-open", str(path)], close_fds=True)


def register_audit_submission_routes(app) -> None:
    """Register API routes before the catch-all static mount and install hooks."""
    if getattr(app.state, "latexstruct_audit_submission_registered", False):
        return

    from . import app as server_app

    store = server_app.get_store()
    manager = server_app._process_jobs
    project_lock = server_app._project_lock

    def runtime_identity() -> dict[str, str]:
        return server_app._runtime_provenance_identity("audit-submission-v1")

    def latest_job(pid: str):
        job = manager.latest(pid)
        return manager.public(job) if job else None

    def ensure(pid: str) -> None:
        if store.get(pid) is None:
            raise HTTPException(404, "项目不存在")

    initial_route_count = len(app.router.routes)

    @app.post("/api/projects/{pid}/audit-submission")
    async def create_audit_submission(pid: str, request: Request):
        ensure(pid)
        if manager.active(pid):
            raise HTTPException(409, "项目仍在处理中；请等待进入终态后再生成审计提交包")
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        options = AuditSubmissionRequest.from_mapping(body if isinstance(body, dict) else {})
        with project_lock(pid):
            if manager.active(pid):
                raise HTTPException(409, "项目仍在处理中；请等待进入终态后再生成审计提交包")
            result = build_audit_submission(
                store=store,
                pid=pid,
                request=options,
                runtime_identity=runtime_identity(),
                latest_job=latest_job(pid),
                create_package=True,
            )
        payload = result.to_public_dict()
        payload.update({
            "download_url": f"/api/projects/{pid}/audit-submission/{result.submission_id}/download",
            "open_folder_url": f"/api/projects/{pid}/audit-submission/open-folder",
        })
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    @app.get("/api/projects/{pid}/audit-submission/latest")
    def latest_audit_submission(pid: str, request: Request):
        ensure(pid)
        summary = load_submission_summary(
            store=store,
            pid=pid,
            reviewed_candidate_ids=_reviewed_ids(request),
        )
        if summary is None:
            raise HTTPException(404, "该项目还没有 AI 审计提交材料")
        if summary.get("package_ready"):
            summary["download_url"] = (
                f"/api/projects/{pid}/audit-submission/{summary['submission_id']}/download"
            )
        summary["open_folder_url"] = f"/api/projects/{pid}/audit-submission/open-folder"
        return JSONResponse(summary, headers={"Cache-Control": "no-store"})

    @app.get("/api/projects/{pid}/audit-submission/{submission_id}/download")
    def download_audit_submission(pid: str, submission_id: str):
        ensure(pid)
        try:
            path = submission_package_path(store, pid, submission_id)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from None
        return FileResponse(
            path,
            media_type="application/zip",
            filename=path.name,
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/projects/{pid}/audit-submission/open-folder")
    def open_audit_submission_folder(pid: str):
        ensure(pid)
        path = submission_directory(store, pid)
        try:
            _reveal(path)
        except OSError as exc:
            raise HTTPException(500, f"无法打开审计提交包目录：{exc}") from None
        return {"ok": True, "folder": "LaTeXStruct 项目 / audit-submissions"}

    # create_app mounts StaticFiles at '/'. Routes added afterwards must be moved
    # in front of that catch-all mount or Starlette will never reach them.
    new_routes = app.router.routes[initial_route_count:]
    del app.router.routes[initial_route_count:]
    mount_index = next(
        (index for index, route in enumerate(app.router.routes) if isinstance(route, Mount)),
        len(app.router.routes),
    )
    app.router.routes[mount_index:mount_index] = new_routes
    app.state.latexstruct_audit_submission_registered = True

    if getattr(manager, "_latexstruct_audit_submission_hook", False):
        return

    scheduled_jobs: set[str] = set()
    scheduled_jobs_lock = threading.Lock()

    def schedule_lightweight(job: dict | None) -> None:
        if not isinstance(job, dict) or not job.get("pid") or not job.get("id"):
            return
        jid = str(job["id"])
        with scheduled_jobs_lock:
            if jid in scheduled_jobs:
                return
            scheduled_jobs.add(jid)
        pid = str(job["pid"])

        def worker() -> None:
            try:
                with project_lock(pid):
                    build_audit_submission(
                        store=store,
                        pid=pid,
                        request=AuditSubmissionRequest(),
                        runtime_identity=runtime_identity(),
                        latest_job=manager.public(job),
                        create_package=False,
                    )
            except Exception:
                # Packaging evidence must never change the actual task result.
                return

        threading.Thread(
            target=worker,
            daemon=True,
            name=f"latexstruct-audit-light-{pid}",
        ).start()

    for method_name in ("complete", "cancelled", "fail"):
        original = getattr(manager, method_name)

        @wraps(original)
        def wrapped(*args, __original=original, **kwargs):
            result = __original(*args, **kwargs)
            jid = str(args[0]) if args else str(kwargs.get("jid") or "")
            schedule_lightweight(manager.get(jid) if jid else None)
            return result

        setattr(manager, method_name, wrapped)
    manager._latexstruct_audit_submission_hook = True

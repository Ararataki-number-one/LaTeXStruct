# -*- coding: utf-8 -*-
"""FastAPI 本地服务（127.0.0.1）。"""

from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import AppConfig, load_config, save_config
from ..core.pipeline import run_pipeline
from ..providers import list_provider_presets
from ..store import ProjectStore
from .process_jobs import ProcessJobManager, ProcessingCancelled

STATIC_DIR = Path(__file__).parent / "static"

_store: Optional[ProjectStore] = None
_config: Optional[AppConfig] = None
_ocr_jobs: Dict[str, dict] = {}
_ocr_jobs_lock = threading.RLock()
_process_jobs = ProcessJobManager()
_update_state_lock = threading.RLock()
_update_preparing = False
_update_jobs_lock = threading.RLock()
_update_jobs: Dict[str, dict] = {}


def _ocr_snapshot_preserved(job: dict) -> bool:
    """最新正文、逐页状态和计费状态是否由同一次保存/导入共同保全。"""
    raw_revision = int(job.get("raw_revision") or 0)
    if raw_revision <= 0:
        return False
    usage_revision = int(job.get("usage_revision") or 0)
    page_revision = int(job.get("page_revision") or 0)
    return any(
        raw_revision == int(job.get(f"{kind}_revision") or 0)
        and usage_revision == int(job.get(f"{kind}_usage_revision") or 0)
        and page_revision == int(job.get(f"{kind}_page_revision") or 0)
        for kind in ("downloaded", "imported")
    )


_active_pipeline_runs = 0


def _raise_if_update_preparing():
    if _update_preparing:
        raise HTTPException(
            409,
            "更新包正在准备，暂时不能启动新任务；应用重启后即可继续",
        )


def _begin_pipeline_run():
    global _active_pipeline_runs
    with _update_state_lock:
        _raise_if_update_preparing()
        _active_pipeline_runs += 1


def _end_pipeline_run():
    global _active_pipeline_runs
    with _update_state_lock:
        _active_pipeline_runs = max(0, _active_pipeline_runs - 1)


def _reserve_update_preparation():
    """原子阻止新任务，并拒绝打断任何正在运行/暂停/保存的工作。"""
    global _update_preparing
    with _update_state_lock:
        _raise_if_update_preparing()
        with _ocr_jobs_lock:
            active_ocr = 0
            unpreserved_ocr = 0
            for job in _ocr_jobs.values():
                if (
                    job.get("status") in {"starting", "running"}
                    or job.get("importing") or job.get("saving")
                ):
                    active_ocr += 1
                elif job.get("raw_ready") or bool(job.get("usage")):
                    if not _ocr_snapshot_preserved(job):
                        unpreserved_ocr += 1
        active_process = max(_active_pipeline_runs, _process_jobs.active_count())
        if active_process or active_ocr or unpreserved_ocr:
            parts = []
            if active_process:
                parts.append(f"{active_process} 个结构化任务")
            if active_ocr:
                parts.append(f"{active_ocr} 个 OCR 任务")
            if unpreserved_ocr:
                parts.append(f"{unpreserved_ocr} 个尚未保存的 OCR 结果")
            raise HTTPException(
                409,
                f"仍有{'、'.join(parts)}需要处理；请等待完成或安全取消后再更新，"
                "并先将已完成 OCR 导入项目或下载原始结果，以免丢失进度和 Token 消耗记录",
            )
        _update_preparing = True


def _cancel_update_preparation():
    global _update_preparing
    with _update_state_lock:
        _update_preparing = False


class _UpdateCancelled(Exception):
    """用户在安装器完成校验前取消了下载。"""


def _update_job_snapshot(job_id: str) -> dict:
    with _update_jobs_lock:
        job = _update_jobs.get(job_id)
        if not job:
            raise HTTPException(404, "更新任务不存在或已结束")
        return {
            key: deepcopy(value)
            for key, value in job.items()
            if key not in {"cancel_requested"}
        }


def _update_job_cancelled(job_id: str) -> bool:
    with _update_jobs_lock:
        job = _update_jobs.get(job_id)
        return not job or bool(job.get("cancel_requested"))


def _set_update_job(job_id: str, **values) -> None:
    with _update_jobs_lock:
        job = _update_jobs.get(job_id)
        if job:
            job.update(values)
            job["updated_at"] = time.time()


def _run_update_job(job_id: str, info) -> None:
    """后台下载并校验安装器；只在校验完成后安排退出与安装。"""
    from ..updater import (
        download_update,
        request_application_exit,
        schedule_installer_after_exit,
    )

    try:
        if _update_job_cancelled(job_id):
            raise _UpdateCancelled
        _set_update_job(
            job_id,
            status="downloading",
            latest=info.latest,
            notes=info.notes,
            total_bytes=max(0, int(info.size or 0)),
            message="正在下载安装包",
        )

        def on_progress(done: int, total: int) -> None:
            if _update_job_cancelled(job_id):
                raise _UpdateCancelled
            safe_total = max(0, int(total or info.size or 0))
            safe_done = max(0, int(done or 0))
            progress = min(1.0, safe_done / safe_total) if safe_total else 0.0
            _set_update_job(
                job_id,
                status="downloading",
                downloaded_bytes=safe_done,
                total_bytes=safe_total,
                progress=progress,
                message="正在下载安装包",
            )

        dest = download_update(info, progress=on_progress)
        if _update_job_cancelled(job_id):
            raise _UpdateCancelled
        _set_update_job(
            job_id,
            status="verifying",
            progress=1.0,
            downloaded_bytes=max(0, int(info.size or 0)),
            message="下载完成，安全校验已通过",
        )
        schedule_installer_after_exit(dest)
        _set_update_job(
            job_id,
            status="restarting",
            progress=1.0,
            message="即将关闭并安装，新版本会自动启动",
        )
        # 给前端至少一次轮询机会，以显示“校验完成 / 即将重启”。
        request_application_exit(delay=1.2)
    except _UpdateCancelled:
        _set_update_job(
            job_id,
            status="cancelled",
            message="更新下载已取消，当前应用保持运行",
            error="",
        )
        _cancel_update_preparation()
    except Exception:  # noqa: BLE001
        _set_update_job(
            job_id,
            status="error",
            message="更新没有安装，当前应用保持运行",
            error="更新包下载、校验或启动失败；请检查网络后重试",
        )
        _cancel_update_preparation()

MAX_FOLDER_FILES = 1000
MAX_FOLDER_FILE_BYTES = 25 * 1024 * 1024
MAX_FOLDER_TOTAL_BYTES = 100 * 1024 * 1024
MAX_OCR_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_OCR_PAGES_PER_JOB = 500
OCR_JOB_TTL_SECONDS = 24 * 60 * 60
MAX_ZIP_COMPRESSION_RATIO = 200

_CREDENTIAL_STORE_ERRORS = (
    (
        "系统凭据管理器不可用",
        "系统凭据管理器不可用；为避免密钥明文落盘，本次设置未保存",
    ),
    (
        "API Key 写入系统凭据管理器失败",
        "API Key 写入系统凭据管理器失败；配置文件未保存",
    ),
    (
        "API Key 从系统凭据管理器删除失败",
        "API Key 从系统凭据管理器删除失败；配置文件未保存",
    ),
)


def _os_error_content(exc: OSError) -> Dict[str, str]:
    message = str(exc)
    for prefix, safe_detail in _CREDENTIAL_STORE_ERRORS:
        if message.startswith(prefix):
            return {
                "detail": safe_detail,
                "action": (
                    "请重新启用并检查 Windows Credential Manager 服务与当前账户权限后重试；"
                    "系统不会降级为明文保存"
                ),
            }
    return {
        "detail": "无法读写本地文件；原文件未被覆盖",
        "action": "请检查磁盘空间、文件权限或是否被其他程序占用后重试",
    }


def _decode_folder_files(raw_files: dict) -> Dict[str, bytes]:
    """校验浏览器文件夹载荷，兼容旧版纯文本值与新版 Base64 二进制值。"""
    from ..core.project import safe_project_relpath

    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("未收到项目文件")
    if len(raw_files) > MAX_FOLDER_FILES:
        raise ValueError(f"项目文件过多（最多 {MAX_FOLDER_FILES} 个）")
    out: Dict[str, bytes] = {}
    total = 0
    for raw_rel, value in raw_files.items():
        rel = safe_project_relpath(raw_rel)
        if rel in out:
            raise ValueError(f"项目中存在重复路径：{rel}")
        if isinstance(value, str):
            data = value.encode("utf-8")
        elif isinstance(value, dict) and value.get("encoding") == "base64":
            encoded = value.get("data")
            if not isinstance(encoded, str):
                raise ValueError(f"文件内容格式无效：{rel}")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError):
                raise ValueError(f"文件 Base64 内容损坏：{rel}") from None
        else:
            raise ValueError(f"文件内容格式不受支持：{rel}")
        if len(data) > MAX_FOLDER_FILE_BYTES:
            raise ValueError(f"单个文件过大（上限 25 MB）：{rel}")
        total += len(data)
        if total > MAX_FOLDER_TOTAL_BYTES:
            raise ValueError("项目总大小超过 100 MB，请精简后重试")
        out[rel] = data
    return out


def _decode_zip_files(upload: bytes) -> Dict[str, bytes]:
    """安全解包浏览器上传的 ZIP，并自动去掉唯一的外层目录。"""
    from ..core.project import safe_project_relpath

    if not upload:
        raise ValueError("ZIP 文件为空")
    if len(upload) > MAX_FOLDER_TOTAL_BYTES:
        raise ValueError("ZIP 文件超过 100 MB，请精简后重试")
    try:
        with zipfile.ZipFile(io.BytesIO(upload), "r") as archive:
            members = archive.infolist()
            if len(members) > MAX_FOLDER_FILES + 200:
                raise ValueError(f"ZIP 内文件过多（最多 {MAX_FOLDER_FILES} 个）")
            raw: list[tuple[str, bytes]] = []
            total = 0
            seen = set()
            for member in members:
                rel = safe_project_relpath(member.filename)
                if member.is_dir():
                    continue
                parts = rel.split("/")
                if "__MACOSX" in parts or parts[-1] in {".DS_Store", "Thumbs.db"}:
                    continue
                if member.flag_bits & 0x1:
                    raise ValueError(f"ZIP 含加密文件，无法安全导入：{rel}")
                if member.file_size > MAX_FOLDER_FILE_BYTES:
                    raise ValueError(f"ZIP 内单个文件过大（上限 25 MB）：{rel}")
                total += member.file_size
                if total > MAX_FOLDER_TOTAL_BYTES:
                    raise ValueError("ZIP 解压后超过 100 MB，请精简后重试")
                if (
                    member.file_size > 1_000_000
                    and member.compress_size > 0
                    and member.file_size / member.compress_size > MAX_ZIP_COMPRESSION_RATIO
                ):
                    raise ValueError(f"ZIP 内文件压缩比异常，已阻止导入：{rel}")
                key = rel.casefold()
                if key in seen:
                    raise ValueError(f"ZIP 中存在重复或大小写冲突路径：{rel}")
                seen.add(key)
                raw.append((rel, archive.read(member)))
    except zipfile.BadZipFile:
        raise ValueError("ZIP 文件已损坏或格式不正确") from None
    if not raw:
        raise ValueError("ZIP 中没有可导入的项目文件")
    first = {rel.split("/", 1)[0].casefold() for rel, _ in raw}
    strip_wrapper = len(first) == 1 and all("/" in rel for rel, _ in raw)
    out = {}
    for rel, data in raw:
        clean = rel.split("/", 1)[1] if strip_wrapper else rel
        clean = safe_project_relpath(clean)
        if clean.casefold() in {key.casefold() for key in out}:
            raise ValueError(f"去除 ZIP 外层目录后出现重复路径：{clean}")
        out[clean] = data
    if len(out) > MAX_FOLDER_FILES:
        raise ValueError(f"项目文件过多（最多 {MAX_FOLDER_FILES} 个）")
    return out


def _safe_task_error(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    return re.sub(r"sk-(?:ws-|sp-)?[A-Za-z0-9._-]{8,}", "[已隐藏]", text)[:500]


def _cleanup_ocr_jobs(now: float = None):
    """清理已结束且超过 24 小时的 OCR 临时页；运行中的任务绝不触碰。"""
    now = now or time.time()
    expired = []
    with _ocr_jobs_lock:
        for jid, job in list(_ocr_jobs.items()):
            if (
                job.get("status") in ("running", "starting")
                or job.get("importing") or job.get("saving")
            ):
                continue
            if now - job.get("created", now) < OCR_JOB_TTL_SECONDS:
                continue
            if (
                (job.get("raw_ready") or bool(job.get("usage")))
                and not _ocr_snapshot_preserved(job)
            ):
                # 付费 OCR 或已生成正文的终态结果只能由用户明确保存、导入或放弃；
                # 不能因内存 TTL 在用户不知情时静默删除。
                continue
            expired.append(_ocr_jobs.pop(jid))
    for job in expired:
        tmpdir = job.get("dir")
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _decision_dict(decision) -> dict:
    return {
        "candidate_id": decision.candidate_id,
        "action": decision.action,
        "env": decision.env,
        "title_span": list(decision.title_span) if decision.title_span else None,
        "body_span": list(decision.body_span) if decision.body_span else None,
        "optional_arg": decision.optional_arg,
        "keep_title_text": decision.keep_title_text,
        "source": decision.source,
        "reason": decision.reason,
        "confidence": decision.confidence,
        "payload": decision.payload,
    }


def _decision_from_dict(data: dict):
    from ..core.patch import Decision

    return Decision(
        candidate_id=str(data.get("candidate_id", "")),
        action=str(data.get("action", "none")),
        env=str(data.get("env", "")),
        title_span=tuple(data["title_span"]) if data.get("title_span") else None,
        body_span=tuple(data["body_span"]) if data.get("body_span") else None,
        optional_arg=str(data.get("optional_arg", "")),
        keep_title_text=bool(data.get("keep_title_text", True)),
        source=str(data.get("source", "rule")),
        reason=str(data.get("reason", "")),
        confidence=float(data.get("confidence", 0.0)),
        payload=dict(data.get("payload") or {}),
    )


def get_store() -> ProjectStore:
    global _store
    if _store is None:
        _store = ProjectStore()
    return _store


def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config


class CreateRequest(BaseModel):
    text: str = ""
    name: str = ""
    mode: str = "rule"
    template: str = ""
    pack: str = ""


class FolderRequest(BaseModel):
    files: dict  # {相对路径: 内容}
    name: str = ""
    mode: str = "rule"
    template: str = ""
    pack: str = ""
    defer_process: bool = False


class BatchRejectRequest(BaseModel):
    cids: list = Field(default_factory=list)


class ConfigRequest(BaseModel):
    decide_base_url: Optional[str] = None
    decide_model: Optional[str] = None
    decide_api_key: Optional[str] = None
    review_base_url: Optional[str] = None
    review_model: Optional[str] = None
    review_api_key: Optional[str] = None
    review_enabled: Optional[bool] = None
    ocr_base_url: Optional[str] = None
    ocr_model: Optional[str] = None
    ocr_api_key: Optional[str] = None
    keyring: Optional[bool] = None


def _normalized_previous_version(value: str) -> str:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", (value or "").strip())
    if not match:
        return ""
    return ".".join(match.groups()[:3])


def create_app(updated_from: str = "") -> FastAPI:
    app = FastAPI(title="LaTeXStruct", docs_url="/api/docs")
    previous_version = _normalized_previous_version(updated_from)

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, exc: ValueError):
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc) or "输入内容无效", "action": "请检查输入后重试"},
        )

    @app.exception_handler(OSError)
    async def os_error(_request: Request, exc: OSError):
        return JSONResponse(
            status_code=500,
            content=_os_error_content(exc),
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_request: Request, _exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "detail": "操作未完成，已保留原始内容",
                "action": "请重试；若仍失败，请在汇报中查看安全检查并报告问题",
            },
        )

    @app.get("/api/health")
    def health():
        from .. import __version__

        return {"ok": True, "version": __version__}

    @app.get("/api/rulesets")
    def rulesets():
        from ..core.ruleset import list_builtin_packs

        return {"packs": list_builtin_packs(), "default": "bilingual"}

    @app.get("/api/templates")
    def templates():
        from ..core.template import ELEGANTBOOK, list_template_presets

        return {
            "templates": list_template_presets(),
            "default": ELEGANTBOOK,
            "ocr_default": ELEGANTBOOK,
            "export_default": ELEGANTBOOK,
            "fixed": True,
        }

    @app.get("/api/providers")
    def providers():
        """只返回公开预设；此接口永远不包含 API Key。"""
        return {"providers": list_provider_presets()}

    @app.get("/api/update/check")
    def update_check():
        from .. import UPDATE_REPO, __version__
        from ..updater import check_for_updates

        info = check_for_updates(UPDATE_REPO, __version__)
        return {
            "current": __version__,
            "available": info.available,
            "latest": info.latest,
            "url": info.url,
            "notes": info.notes,
            "size": info.size,
            "error": info.error,
        }

    @app.get("/api/update/result")
    def update_result():
        """安装器启动新版本时提供一次会话级成功提示；不包含任何本地路径。"""
        from .. import __version__

        return {
            "updated": bool(previous_version and previous_version != __version__),
            "previous": previous_version,
            "current": __version__,
        }

    @app.post("/api/update/install")
    def update_install():
        from .. import UPDATE_REPO, __version__
        from ..updater import check_for_updates

        _reserve_update_preparation()
        try:
            info = check_for_updates(UPDATE_REPO, __version__)
            if info.error and not info.url:
                raise HTTPException(502, info.error)
            if not info.available:
                raise HTTPException(409, "当前已经是最新版本，无需重复安装")
            if not info.url:
                raise HTTPException(502, "新版发布中没有可用的 Windows 安装包")
        except HTTPException:
            _cancel_update_preparation()
            raise
        except Exception:  # noqa: BLE001
            _cancel_update_preparation()
            raise HTTPException(
                502, "检查新版安装包失败；当前应用保持运行，请检查网络后重试"
            ) from None

        job_id = uuid.uuid4().hex
        now = time.time()
        with _update_jobs_lock:
            for old_id, old_job in list(_update_jobs.items()):
                if old_job.get("status") in {"cancelled", "error"}:
                    _update_jobs.pop(old_id, None)
            _update_jobs[job_id] = {
                "id": job_id,
                "status": "checking",
                "progress": 0.0,
                "downloaded_bytes": 0,
                "total_bytes": max(0, int(info.size or 0)),
                "latest": info.latest,
                "notes": info.notes,
                "message": "正在准备安全下载",
                "error": "",
                "cancel_requested": False,
                "created_at": now,
                "updated_at": now,
            }
        try:
            worker = threading.Thread(
                target=_run_update_job,
                args=(job_id, info),
                daemon=True,
                name=f"latexstruct-update-{job_id[:8]}",
            )
            worker.start()
        except Exception:  # noqa: BLE001
            with _update_jobs_lock:
                _update_jobs.pop(job_id, None)
            _cancel_update_preparation()
            raise HTTPException(
                500, "更新任务无法启动；当前应用保持运行，请稍后重试"
            ) from None
        return JSONResponse(status_code=202, content={
            "ok": True,
            "job_id": job_id,
            "note": "已开始安全下载；校验通过后应用会自动重启",
        })

    @app.get("/api/update/status/{job_id}")
    def update_status(job_id: str):
        return _update_job_snapshot(job_id)

    @app.post("/api/update/status/{job_id}/cancel")
    def update_cancel(job_id: str):
        with _update_jobs_lock:
            job = _update_jobs.get(job_id)
            if not job:
                raise HTTPException(404, "更新任务不存在或已结束")
            status = job.get("status")
            if status in {"cancelled", "error"}:
                return {"ok": True, "status": status}
            if status not in {"checking", "downloading", "cancelling"}:
                raise HTTPException(409, "安装包已完成校验，应用即将重启，不能再取消")
            job["cancel_requested"] = True
            job["status"] = "cancelling"
            job["message"] = "正在安全取消下载"
            job["updated_at"] = time.time()
        return {"ok": True, "status": "cancelling"}

    @app.get("/api/projects")
    def list_projects():
        projects = get_store().list()
        for project in projects:
            job = _process_jobs.latest(project["id"])
            if job:
                project["processing"] = {
                    "status": job["status"],
                    "progress": job.get("progress", 0),
                    "message": job.get("message", ""),
                    "error": job.get("error", ""),
                }
        return projects

    @app.post("/api/projects")
    def create_project(req: CreateRequest):
        from ..core.template import ELEGANTBOOK, normalize_template_id

        if not req.text.strip():
            raise HTTPException(400, "内容为空")
        normalize_template_id(req.template)
        pid = get_store().create(req.text, req.name, req.mode, ELEGANTBOOK, req.pack)
        return {"id": pid}

    def _import_project_files(files: Dict[str, bytes], name: str, mode: str,
                              template: str, pack: str, defer_process: bool):
        """统一的文件夹/ZIP 导入；原始资源逐字节保存在项目副本中。"""
        from ..core.project import discover_main, flatten_project, process_project
        from ..core.template import ELEGANTBOOK, normalize_template_id

        normalize_template_id(template)
        template = ELEGANTBOOK

        tmpdir = tempfile.mkdtemp(prefix="ls-folder-")
        pid = None
        try:
            for rel, content in files.items():
                p = Path(tmpdir) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)
            main_rel = discover_main(Path(tmpdir))
            if main_rel is None:
                raise ValueError("文件夹中未找到 .tex 主文件")
            mode = mode or "rule"
            if defer_process:
                flattened, graph_obj = flatten_project(Path(tmpdir), main_rel)
                pr = None
                per_file = None
            else:
                cfg = get_config()
                res = process_project(
                    Path(tmpdir), mode=mode, template=template or None,
                    template_context={"title": name},
                    ai_config=cfg.to_ai_config() if mode == "ai" else None,
                    pack=pack or None,
                )
                flattened, graph_obj = res.flattened, res.graph
                pr, per_file = res.pipeline, res.per_file
            # 项目源 = 展开文本（供 diff/决策审阅），原始文件另存本地 zip，导出时
            # 覆盖改动过的 .tex；图片/bib/sty 等二进制资源保持逐字节不变。
            pid = get_store().create(
                flattened, name, mode, template or "", pack or ""
            )
            project_dir = Path(get_store()._dir(pid))
            meta = json.loads((project_dir / "meta.json").read_text(encoding="utf-8"))
            meta["kind"] = "folder"
            meta["original_file_count"] = len(files)
            meta["graph"] = {
                "main_rel": graph_obj.main_rel,
                "files": graph_obj.files,
                "missing": graph_obj.missing,
                "cycles": graph_obj.cycles,
            }
            get_store()._write_json(str(project_dir), "meta.json", meta)
            with zipfile.ZipFile(project_dir / "original-files.zip", "w", zipfile.ZIP_DEFLATED) as zf:
                for rel, content in files.items():
                    zf.writestr(rel, content)
            if pr is not None:
                decisions = [_decision_dict(d) for d in pr.decisions]
                get_store().set_result(
                    pid, pr.export_text, pr.report_md, decisions, {
                        "verification": pr.verification,
                        "ambiguous": pr.ambiguous,
                        "applied": [],
                        "rejected": [],
                        "ai_notes": pr.ai_notes,
                        "review": {k: v for k, v in pr.review.items() if k != "decisions"},
                        "items": pr.decision_items,
                        "per_file": per_file,
                        "decision_cache": decisions,
                    }
                )
            return {
                "id": pid,
                "graph": meta["graph"],
                "processed": pr is not None,
                "ok": pr.ok if pr is not None else None,
                "applied": len(pr.applied) if pr is not None else 0,
                "ambiguous": len(pr.ambiguous) if pr is not None else 0,
            }
        except Exception:
            if pid is not None:
                get_store().delete(pid)
            raise
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @app.post("/api/projects/folder")
    def import_folder(req: FolderRequest):
        files = _decode_folder_files(req.files)
        return _import_project_files(
            files, req.name, req.mode, req.template, req.pack, req.defer_process
        )

    @app.post("/api/projects/archive")
    async def import_archive(
        file: UploadFile = File(...),
        name: str = Form(""),
        mode: str = Form("rule"),
        template: str = Form(""),
        pack: str = Form(""),
        defer_process: bool = Form(True),
    ):
        """ZIP 智能导入：安全解包、去外层目录、自动识别主文件。"""
        filename = file.filename or "project.zip"
        if Path(filename).suffix.lower() != ".zip":
            raise HTTPException(400, "请选择 .zip 项目压缩包")
        upload = await file.read(MAX_FOLDER_TOTAL_BYTES + 1)
        if len(upload) > MAX_FOLDER_TOTAL_BYTES:
            raise HTTPException(413, "ZIP 文件超过 100 MB，请精简后重试")
        files = _decode_zip_files(upload)
        project_name = name.strip() or Path(filename).stem
        return _import_project_files(
            files, project_name, mode, template, pack, defer_process
        )

    @app.get("/api/projects/{pid}/graph")
    def project_graph(pid: str):
        _ensure(pid)
        meta = json.loads((Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8"))
        return {"kind": meta.get("kind", "single"), "graph": meta.get("graph")}

    def _committed_record(pid: str):
        """读取与最终提交标记精确匹配的一组结果。"""
        _ensure(pid)
        d = Path(get_store()._dir(pid))
        target = d / "result.tex"
        info_path = d / "verification.json"
        if not target.exists() or not info_path.exists():
            raise HTTPException(409, "尚无完整且通过安全检查的结果，请重新处理项目")
        try:
            info = json.loads(info_path.read_text(encoding="utf-8"))
            result_bytes = target.read_bytes()
        except (OSError, ValueError, TypeError):
            raise HTTPException(409, "安全检查记录无法读取，已阻止导出；请重新处理项目") from None
        expected_hash = info.get("result_sha256") if isinstance(info, dict) else None
        actual_hash = hashlib.sha256(result_bytes).hexdigest()
        if not isinstance(expected_hash, str) or not hmac.compare_digest(expected_hash, actual_hash):
            raise HTTPException(409, "结果与安全检查记录不一致，已阻止导出；请重新处理项目")
        return info, result_bytes, d

    def _committed_export(pid: str):
        """只放行明确通过安全检查的、与提交标记一致的 TeX 结果。"""
        info, result_bytes, _directory = _committed_record(pid)
        verification = info.get("verification") if isinstance(info, dict) else None
        if not isinstance(verification, dict) or verification.get("safe_to_export") is not True:
            raise HTTPException(409, "安全检查未明确通过，已阻止导出；请查看汇报或重新处理")
        try:
            result_text = result_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(409, "结果不是有效 UTF-8 TEX，已阻止导出；请重新处理项目") from None
        from ..core.template import uses_elegantbook_class

        if not uses_elegantbook_class(result_text):
            raise HTTPException(
                409,
                "该结果不是当前固定的 ElegantBook 成品；请重新运行结构化整理后再导出",
            )
        return info, result_bytes

    def _committed_report(pid: str):
        """读取同一次提交的汇报；新提交还会校验独立 SHA-256。"""
        info, _result_bytes, directory = _committed_record(pid)
        report_path = directory / "report.md"
        try:
            report_bytes = report_path.read_bytes()
        except OSError:
            raise HTTPException(409, "汇报文件无法读取，请重新处理项目") from None
        expected_hash = info.get("report_sha256") if isinstance(info, dict) else None
        if expected_hash is not None:
            actual_hash = hashlib.sha256(report_bytes).hexdigest()
            if not isinstance(expected_hash, str) or not hmac.compare_digest(
                expected_hash, actual_hash
            ):
                raise HTTPException(409, "汇报与安全检查记录不一致，请重新处理项目")
        return report_bytes

    def _export_package_bytes(pid: str) -> bytes:
        """Build a portable ElegantBook package from the same committed result marker."""
        from ..core.project import safe_project_relpath
        from ..core.template import uses_elegantbook_class
        from ..elegantbook import elegantbook_bundle_assets

        info, result_bytes = _committed_export(pid)
        report_bytes = _committed_report(pid)
        assets = elegantbook_bundle_assets()
        reserved = {**assets, "LATEXSTRUCT-REPORT.md": report_bytes}
        meta = json.loads(
            (Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8")
        )
        per_file = info.get("per_file") if isinstance(info, dict) else None
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            if per_file:
                graph = meta.get("graph") or {}
                main_rel = safe_project_relpath(graph.get("main_rel", ""))
                main_text = str(per_file.get("", ""))
                if not uses_elegantbook_class(main_text):
                    raise HTTPException(
                        409,
                        "项目主文件不是 ElegantBook 成品，已阻止打包；请重新处理项目",
                    )
                processed = {main_rel} | {
                    safe_project_relpath(rel) for rel in per_file if rel
                }
                written = set()
                original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
                if original_zip.exists():
                    with zipfile.ZipFile(original_zip, "r") as source_zip:
                        for member in source_zip.infolist():
                            rel = safe_project_relpath(member.filename)
                            if member.is_dir() or rel in processed:
                                continue
                            data = source_zip.read(member)
                            if rel in reserved:
                                if data != reserved[rel]:
                                    raise HTTPException(
                                        409,
                                        f"原项目中的 {rel} 与固定工程资源冲突，已阻止打包",
                                    )
                            else:
                                zf.writestr(rel, data)
                            written.add(rel)
                zf.writestr(main_rel, main_text.encode("utf-8"))
                written.add(main_rel)
                for rel, content in per_file.items():
                    if not rel:
                        continue
                    safe_rel = safe_project_relpath(rel)
                    zf.writestr(safe_rel, str(content).encode("utf-8"))
                    written.add(safe_rel)
                expected = meta.get("original_file_count")
                if expected is not None and len(written) != expected:
                    raise HTTPException(
                        409,
                        f"文件数量安全检查未通过（原始 {expected}，导出 {len(written)}），已阻止导出。",
                    )
            else:
                zf.writestr("main.tex", result_bytes)
            existing = set(zf.namelist())
            for rel, data in reserved.items():
                if rel not in existing:
                    zf.writestr(rel, data)
        return buf.getvalue()

    @app.get("/api/projects/{pid}/export-package")
    def export_package(pid: str):
        data = _export_package_bytes(pid)
        return Response(
            content=data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{pid}-ElegantBook.zip"'},
        )

    @app.get("/api/projects/{pid}/export-folder")
    def export_folder(pid: str):
        """Backward-compatible alias for clients released before package export."""
        return export_package(pid)

    @app.post("/api/projects/upload")
    async def upload_project(file: bytes = None, name: str = "", mode: str = "rule"):
        # 简化 multipart：由前端读文件后走 /api/projects
        raise HTTPException(400, "请使用 /api/projects 提交文本")

    @app.get("/api/projects/{pid}")
    def get_project(pid: str):
        p = get_store().get(pid)
        if p is None:
            raise HTTPException(404, "项目不存在")
        return p

    @app.delete("/api/projects/{pid}")
    def delete_project(pid: str):
        if _process_jobs.active(pid):
            raise HTTPException(409, "项目正在处理；请先取消任务，待安全停止后再删除")
        get_store().delete(pid)
        return {"ok": True}

    @app.get("/api/projects/{pid}/source")
    def source(pid: str):
        _ensure(pid)
        return PlainTextResponse(get_store().read_source(pid))

    @app.get("/api/projects/{pid}/result")
    def result(pid: str):
        _ensure(pid)
        r = get_store().read_result(pid)
        if r is None:
            raise HTTPException(404, "尚未处理")
        return PlainTextResponse(r)

    @app.get("/api/projects/{pid}/report")
    def report(pid: str):
        _ensure(pid)
        r = get_store().read_report(pid)
        if r is None:
            raise HTTPException(404, "尚未处理")
        return PlainTextResponse(r, media_type="text/markdown")

    @app.get("/api/projects/{pid}/export-report")
    def export_report(pid: str):
        report_bytes = _committed_report(pid)
        return Response(
            content=report_bytes,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{pid}-report.md"'},
        )

    @app.get("/api/projects/{pid}/export")
    def export(pid: str):
        _info, result_bytes = _committed_export(pid)
        return Response(
            content=result_bytes,
            media_type="application/x-tex",
            headers={"Content-Disposition": f'attachment; filename="{pid}-structured.tex"'},
        )

    def _download_artifact(pid: str, artifact: str) -> tuple[bytes, str]:
        project = get_store().get(pid)
        if project is None:
            raise HTTPException(404, "项目不存在")
        project_name = str(project.get("name") or "LaTeXStruct")
        if artifact == "result":
            _info, data = _committed_export(pid)
            return data, f"{project_name}-ElegantBook.tex"
        if artifact == "report":
            return _committed_report(pid), f"{project_name}-report.md"
        if artifact in {"package", "folder"}:
            return _export_package_bytes(pid), f"{project_name}-ElegantBook-project.zip"
        raise HTTPException(404, "不支持的下载类型")

    @app.post("/api/projects/{pid}/exports/{artifact}/save")
    def save_export_to_downloads(pid: str, artifact: str):
        """桌面 WebView 下载被拦截时，可靠保存到固定的用户下载目录。"""
        from .downloads import save_unique_download

        data, filename = _download_artifact(pid, artifact)
        saved = save_unique_download(data, filename)
        return {
            "ok": True,
            "filename": saved.name,
            "folder": "下载/LaTeXStruct",
            "bytes": len(data),
        }

    @app.post("/api/exports/open-folder")
    def open_export_folder():
        """只打开应用固定下载目录，不接受任何路径参数。"""
        from .downloads import reveal_download_location

        reveal_download_location()
        return {"ok": True, "folder": "下载/LaTeXStruct"}

    def _run_project_impl(pid: str, exclude: set, reuse_decisions: bool = False,
                          progress_callback=None, control_callback=None, commit_callback=None):
        p = get_store().get(pid)
        text = get_store().read_source(pid)
        cfg = get_config()
        mode = p["mode"]
        from ..core.template import ELEGANTBOOK

        previous_template = str(p.get("template") or "")
        template = ELEGANTBOOK
        if previous_template != ELEGANTBOOK:
            # Existing projects migrate only when the user explicitly reruns processing.
            # Cached spans were produced against a different preamble, so they cannot be reused.
            get_store().set_template(pid, ELEGANTBOOK)
            p["template"] = ELEGANTBOOK
            reuse_decisions = False
        pack = (p.get("pack") or "") or None
        prior = {}
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if reuse_decisions and info_path.exists():
            prior = json.loads(info_path.read_text(encoding="utf-8"))
        cached = prior.get("decision_cache") if reuse_decisions else None
        overrides = [_decision_from_dict(item) for item in cached] if cached else None
        is_ocr_project = p.get("kind") == "ocr"
        # OCR is noisy enough to require an actual final compile when TeX is installed.
        # Ordinary imported TEX keeps the fast path; its report states that compile was not run.
        template_compile_guard = is_ocr_project
        res = run_pipeline(
            text, mode=mode, ai_config=cfg.to_ai_config() if mode == "ai" else None,
            template=template, pack=pack, exclude=exclude or None,
            template_context={"title": p.get("template_title") or p.get("name") or ""},
            decisions_override=overrides,
            ambiguous_override=prior.get("ambiguous") if overrides else None,
            ai_notes_override=prior.get("ai_notes") if overrides else None,
            progress_callback=progress_callback,
            control_callback=control_callback,
            compile_check=is_ocr_project or template_compile_guard,
            require_compile_when_available=is_ocr_project or template_compile_guard,
            resource_root=get_store()._dir(pid) if is_ocr_project else None,
            require_resources=is_ocr_project,
        )
        extra_verification = {}
        if p.get("kind") == "folder":
            from ..core.project import split_project

            graph = p.get("graph") or {}
            try:
                per_file = split_project(res.result)
                split_error = ""
            except ValueError as exc:
                per_file = {}
                split_error = str(exc)
            expected = {"", *(graph.get("files") or [])}
            project_ok = bool(
                not split_error
                and set(per_file) == expected
                and not graph.get("missing")
                and not graph.get("cycles")
            )
            project_check = {
                "ok": project_ok,
                "before_file_count": len(expected),
                "after_file_count": len(per_file),
                "file_set_equal": set(per_file) == expected,
                "missing_includes": graph.get("missing") or [],
                "cycles": graph.get("cycles") or [],
                "error": split_error,
            }
            res.verification["project"] = project_check
            res.verification.setdefault("checks", []).append(
                {"id": "project", "label": "项目文件与依赖完整", "ok": project_ok}
            )
            res.verification["safe_to_export"] = bool(
                res.verification.get("safe_to_export") and project_ok
            )
            res.verification["export_blocked"] = not res.verification["safe_to_export"]
            res.ok = bool(res.ok and project_ok)
            extra_verification["per_file"] = per_file
            if not project_ok:
                res.report_md += (
                    "\n\n## 项目安全检查\n\n"
                    "- ❌ 依赖图或文件集合不完整，已阻止导出。\n"
                    f"- 文件数量：{len(expected)} → {len(per_file)}\n"
                )
        decisions = [_decision_dict(d) for d in res.decisions]
        decision_cache = cached or decisions
        applied = [
            {
                "candidate_id": ap.decision.candidate_id,
                "action": ap.decision.action,
                "env": ap.decision.env,
                "reason": ap.decision.reason,
                "edits": [{"kind": e.kind, "line": e.line, "old": e.old, "new": e.new} for e in ap.edits],
            }
            for ap in res.applied
        ]
        if control_callback:
            control_callback()
        if commit_callback:
            commit_callback()
        get_store().set_result(
            pid, res.export_text, res.report_md, decisions, {
                "verification": res.verification,
                "ambiguous": res.ambiguous,
                "applied": applied,
                "rejected": [{"candidate_id": ap.decision.candidate_id, "error": ap.error} for ap in res.rejected],
                "ai_notes": res.ai_notes,
                "review": {k: v for k, v in res.review.items() if k != "decisions"},
                "items": res.decision_items,
                "decision_cache": decision_cache,
                **extra_verification,
            }
        )
        return {
            "ok": res.ok,
            "applied": len(res.applied),
            "rejected": len(res.rejected),
            "ambiguous": len(res.ambiguous),
            "degraded": res.verification.get("ai_degraded", False),
            "usage": res.verification.get("ai_usage", {}),
        }

    def _run_project(pid: str, exclude: set, reuse_decisions: bool = False,
                     progress_callback=None, control_callback=None, commit_callback=None):
        _begin_pipeline_run()
        try:
            return _run_project_impl(
                pid,
                exclude,
                reuse_decisions=reuse_decisions,
                progress_callback=progress_callback,
                control_callback=control_callback,
                commit_callback=commit_callback,
            )
        finally:
            _end_pipeline_run()

    @app.post("/api/projects/{pid}/process")
    def process(pid: str):
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "项目已有后台任务；请在进度卡片中暂停、继续或取消")
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        return _run_project(pid, set(meta.get("excludes", [])))

    @app.post("/api/projects/{pid}/process/start")
    def process_start(pid: str):
        """启动可暂停的后台处理；同一项目最多一个活动任务。"""
        _ensure(pid)
        with _update_state_lock:
            _raise_if_update_preparing()
            existing = _process_jobs.active(pid)
            if existing:
                return _process_jobs.public(existing) | {"already_running": True}
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            job = _process_jobs.create(pid, get_store().read_source(pid))
        jid = job["id"]

        def worker():
            try:
                processed = _run_project(
                    pid,
                    set(meta.get("excludes", [])),
                    progress_callback=lambda phase, progress, message, data: _process_jobs.update(
                        jid, phase, progress, message, data
                    ),
                    control_callback=lambda: _process_jobs.control(jid),
                    commit_callback=lambda: _process_jobs.begin_commit(jid),
                )
                _process_jobs.complete(jid, processed)
            except ProcessingCancelled:
                _process_jobs.cancelled(jid)
            except Exception as exc:  # noqa: BLE001
                _process_jobs.fail(jid, _safe_task_error(exc))

        threading.Thread(target=worker, daemon=True, name=f"latexstruct-{jid}").start()
        return _process_jobs.public(job)

    def _latest_process_job(pid: str):
        _ensure(pid)
        job = _process_jobs.latest(pid)
        if not job:
            raise HTTPException(404, "该项目还没有处理任务")
        return job

    @app.get("/api/projects/{pid}/process/status")
    def process_status(pid: str):
        _ensure(pid)
        job = _process_jobs.latest(pid)
        if not job:
            return {"pid": pid, "status": "idle", "progress": 0, "preview_ready": False}
        return _process_jobs.public(job)

    @app.get("/api/projects/{pid}/process/preview")
    def process_preview(pid: str):
        job = _latest_process_job(pid)
        preview, revision = _process_jobs.preview_snapshot(job)
        return PlainTextResponse(
            preview,
            headers={
                "X-LaTeXStruct-Task-Status": str(job.get("status", "")),
                "X-LaTeXStruct-Preview-Revision": str(revision),
                "Cache-Control": "no-store",
            },
        )

    @app.post("/api/projects/{pid}/process/pause")
    def process_pause(pid: str):
        return _process_jobs.public(_process_jobs.request_pause(_latest_process_job(pid)))

    @app.post("/api/projects/{pid}/process/resume")
    def process_resume(pid: str):
        return _process_jobs.public(_process_jobs.request_resume(_latest_process_job(pid)))

    @app.post("/api/projects/{pid}/process/cancel")
    def process_cancel(pid: str):
        return _process_jobs.public(_process_jobs.request_cancel(_latest_process_job(pid)))

    @app.get("/api/projects/{pid}/decisions")
    def decisions(pid: str):
        _ensure(pid)
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if not info_path.exists():
            return {"items": [], "excludes": get_store().get(pid).get("excludes", []),
                    "verification": None}
        info = json.loads(info_path.read_text(encoding="utf-8"))
        return {"items": info.get("items", []),
                "excludes": get_store().get(pid).get("excludes", []),
                "verification": info.get("verification")}

    @app.post("/api/projects/{pid}/decisions/{cid}/reject")
    def reject_decision(pid: str, cid: str):
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        excludes = set(meta.get("excludes", []))
        excludes.add(cid)
        meta["excludes"] = sorted(excludes)
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/{cid}/unreject")
    def unreject_decision(pid: str, cid: str):
        """撤销对某一项的拒绝：从排除清单移除并重跑（审阅台 Ctrl+Z 的后端）。"""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        excludes = set(meta.get("excludes", []))
        excludes.discard(cid)
        meta["excludes"] = sorted(excludes)
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/reject-batch")
    def reject_batch(pid: str, req: BatchRejectRequest):
        """批量拒绝（Accept-All-Similar 的逆操作：拒绝同类其余修改）。"""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        excludes = set(meta.get("excludes", [])) | set(req.cids)
        meta["excludes"] = sorted(excludes)
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/reset")
    def reset_decisions(pid: str):
        """撤销全部拒绝：清空 excludes 并重跑。"""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        meta["excludes"] = []
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, set(), reuse_decisions=True)

    @app.get("/api/projects/{pid}/diff")
    def diff(pid: str):
        _ensure(pid)
        old = get_store().read_source(pid).replace("\r\n", "\n").replace("\r", "\n").split("\n")
        new_text = get_store().read_result(pid)
        if new_text is None:
            raise HTTPException(404, "尚未处理")
        new = new_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        compact = len(old) + len(new) > 20_000
        sm = difflib.SequenceMatcher(a=old, b=new, autojunk=compact)
        rows = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                if compact and i2 - i1 > 6:
                    offsets = [0, 1, 2, i2 - i1 - 3, i2 - i1 - 2, i2 - i1 - 1]
                else:
                    offsets = range(i2 - i1)
                for k in offsets:
                    rows.append({"type": "same", "old": i1 + k + 1, "new": j1 + k + 1,
                                 "text": old[i1 + k]})
            elif tag == "replace":
                for k in range(i2 - i1):
                    rows.append({"type": "del", "old": i1 + k + 1, "new": None,
                                 "text": old[i1 + k]})
                for k in range(j2 - j1):
                    rows.append({"type": "ins", "old": None, "new": j1 + k + 1,
                                 "text": new[j1 + k]})
            elif tag == "delete":
                for k in range(i2 - i1):
                    rows.append({"type": "del", "old": i1 + k + 1, "new": None,
                                 "text": old[i1 + k]})
            elif tag == "insert":
                for k in range(j2 - j1):
                    rows.append({"type": "ins", "old": None, "new": j1 + k + 1,
                                 "text": new[j1 + k]})
        info = json.loads(
            (Path(get_store()._dir(pid)) / "verification.json").read_text(encoding="utf-8")
        )
        return {"rows": rows, "compact": compact, "applied": info.get("applied", []),
                "ambiguous": info.get("ambiguous", []),
                "verification": info.get("verification", {})}

    @app.get("/api/config")
    def get_cfg():
        return get_config().masked()

    @app.put("/api/config")
    def put_cfg(req: ConfigRequest):
        global _config
        # 在副本上验证/持久化；失败时绝不污染当前运行时缓存。
        cfg = deepcopy(get_config())
        updates = req.model_dump()
        secret_updates = {
            k: v for k, v in updates.items() if k.endswith("_api_key") and v is not None
        }
        for k, v in updates.items():
            if v is not None:
                setattr(cfg, k, v)
        save_config(cfg, secret_updates=secret_updates)
        _config = load_config()  # 重新解析（keyring 占位符 → 真实密钥 + 来源标记）
        return _config.masked()

    # ---- OCR ----

    async def _read_ocr_upload(file: UploadFile):
        suffix = Path(file.filename or "scan.pdf").suffix.lower()
        if suffix not in (".pdf", ".png", ".jpg", ".jpeg"):
            raise HTTPException(400, "仅支持 PDF/PNG/JPG")
        upload = await file.read(MAX_OCR_UPLOAD_BYTES + 1)
        if not upload:
            raise HTTPException(400, "上传文件为空")
        if len(upload) > MAX_OCR_UPLOAD_BYTES:
            raise HTTPException(413, "OCR 文件超过 100 MB，请拆分后重试")
        if suffix == ".pdf":
            if not upload.startswith(b"%PDF-"):
                raise HTTPException(400, "文件扩展名是 PDF，但内容不是有效 PDF")
            from ..core.ai import LLMError
            from ..ocr import pdf_document_info_bytes

            try:
                pdf_info = pdf_document_info_bytes(upload)
                source_total = int(pdf_info["pages"])
                source_outline = list(pdf_info.get("outline") or [])
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None
            except LLMError as exc:
                raise HTTPException(503, str(exc)) from None
        else:
            from ..core.ai import LLMError
            from ..ocr import image_mime_type

            try:
                image_mime_type(upload)
            except LLMError as exc:
                raise HTTPException(400, str(exc)) from None
            source_total = 1
            source_outline = []
        return suffix, upload, source_total, source_outline

    def _create_ocr_job(
        suffix: str,
        upload: bytes,
        source_total: int,
        status: str,
        source_outline: list[dict] = None,
    ):
        tmpdir = tempfile.mkdtemp(prefix="ls-ocr-")
        target = os.path.join(tmpdir, f"scan{suffix}")
        try:
            with open(target, "wb") as stream:
                stream.write(upload)
        except Exception:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise
        jid = uuid.uuid4().hex
        job = {
            "id": jid,
            "status": status,
            "source_type": "pdf" if suffix == ".pdf" else "image",
            "source_total": source_total,
            "source_outline": list(source_outline or []),
            "progress": 0.0,
            "total": 0,
            "done": 0,
            "page": 0,
            "current_index": 0,
            "phase": "已读取 PDF 页数" if suffix == ".pdf" else "准备图片",
            "raw_tex": "",
            "raw_ready": False,
            "raw_revision": 0,
            "raw_chars": 0,
            "usage_revision": 0,
            "page_revision": 0,
            "downloaded_revision": 0,
            "downloaded_usage_revision": 0,
            "downloaded_page_revision": 0,
            "imported_revision": 0,
            "imported_usage_revision": 0,
            "imported_page_revision": 0,
            "importing": False,
            "saving": False,
            "imported_project_id": "",
            "imported_processed": None,
            "error": "",
            "usage": {},
            "created": time.time(),
            "pages": {},
            "dir": tmpdir,
            "target": target,
            "suffix": suffix,
            "errors": [],
        }
        try:
            with _update_state_lock:
                _raise_if_update_preparing()
                with _ocr_jobs_lock:
                    _ocr_jobs[jid] = job
        except Exception:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise
        return job

    def _set_ocr_selection(job: dict, page_nos: list[int]):
        job["total"] = len(page_nos)
        job["selected_start"] = page_nos[0]
        job["selected_end"] = page_nos[-1]
        job["selected_pages"] = list(page_nos)
        job["pages"] = {
            page_no: {
                "status": "pending",
                "tex": "",
                "error": "",
                "png": os.path.join(job["dir"], f"page-{page_no}.img"),
                "low_conf": False,
                "attempts": 0,
                "task_index": index,
                "retrying": False,
            }
            for index, page_no in enumerate(page_nos, start=1)
        }

    def _launch_ocr_job(
        job: dict,
        page_nos: list[int],
        dpi: int,
        base_url: str,
        model: str,
        api_key: str,
    ):
        def _transcribe_one(job, client, page_no: int, png_path: str, max_attempts: int = 2):
            """转写单页并更新 job.pages；暂时性失败自动再试一次。"""
            from ..ocr import ocr_page_needs_retry, transcribe_page

            page = job["pages"][page_no]
            with _ocr_jobs_lock:
                page["status"] = "running"
                page["error"] = ""
            with open(png_path, "rb") as image_file:
                png = image_file.read()
            for attempt in range(1, max_attempts + 1):
                with _ocr_jobs_lock:
                    page["attempts"] = page.get("attempts", 0) + 1
                client.last_usage = {}
                try:
                    tex = transcribe_page(client, png, page_no)
                    low_conf = (
                        "[?]" in tex
                        or "% unsure" in tex
                        or len(tex.strip()) < 40
                        or ocr_page_needs_retry(tex)
                    )
                    with _ocr_jobs_lock:
                        page["tex"] = tex
                        page["status"] = "done"
                        page["error"] = ""
                        page["low_conf"] = low_conf
                        job["page_revision"] = int(job.get("page_revision") or 0) + 1
                    return True
                except Exception as exc:  # noqa: BLE001
                    message = _safe_task_error(exc)
                    with _ocr_jobs_lock:
                        page["error"] = message
                    if any(token in message.lower() for token in (
                        "未配置 api key", "http 401", "http 403", "http 400", "http 404",
                    )):
                        break
                    if attempt >= max_attempts:
                        break
                finally:
                    if client.last_usage:
                        from ..pricing import add_usage, summarize_ai_usage

                        with _ocr_jobs_lock:
                            add_usage(
                                job["usage"], client.last_usage,
                                getattr(client.cfg, "model", ""),
                            )
                            job["cost"] = summarize_ai_usage({"ocr": job["usage"]})
                            job["usage_revision"] = (
                                int(job.get("usage_revision") or 0) + 1
                            )
            with _ocr_jobs_lock:
                page["status"] = "error"
                page["low_conf"] = True
                job["page_revision"] = int(job.get("page_revision") or 0) + 1
            return False

        def _refresh_raw_preview(job):
            from ..ocr import merge_book

            with _ocr_jobs_lock:
                chunks = [
                    job["pages"][page_no]["tex"]
                    for page_no in job["selected_pages"]
                    if job["pages"][page_no]["status"] == "done"
                ]
                merged = merge_book(chunks, outline=job.get("source_outline"))
                job["raw_tex"] = merged
                job["raw_ready"] = bool(chunks)
                job["raw_chars"] = len(merged)
                job["raw_revision"] = int(job.get("raw_revision") or 0) + 1

        def _merge_job(job, complete_progress: bool = True):
            errors = []
            for page_no in job["selected_pages"]:
                page = job["pages"][page_no]
                if page["status"] != "done":
                    errors.append({
                        "page": page_no,
                        "task_index": page["task_index"],
                        "reason": page["error"] or page["status"],
                    })
            with _ocr_jobs_lock:
                job["errors"] = errors
                job["status"] = "done" if not errors else "partial"
                job["phase"] = "原始 OCR 已就绪" if not errors else "部分页面失败，等待重试"
                if complete_progress:
                    job["progress"] = 1.0

        job["_transcribe_one"] = _transcribe_one
        job["_refresh_raw_preview"] = _refresh_raw_preview
        job["_merge_job"] = _merge_job

        def worker():
            from ..core.ai import LLMClient, RoleConfig
            from ..ocr import iter_pdf_pages

            try:
                cfg = get_config()
                configured_role = cfg.to_ocr_config().role
                selected_base_url = base_url or configured_role.base_url
                selected_model = model or configured_role.model
                selected_key = api_key
                if (
                    not selected_key
                    and selected_base_url.rstrip("/") == configured_role.base_url.rstrip("/")
                ):
                    selected_key = configured_role.api_key
                client = LLMClient(RoleConfig(selected_base_url, selected_model, selected_key))
                job["client"] = client
                job["model"] = selected_model
                if job["source_type"] == "pdf":
                    rendered = iter_pdf_pages(job["target"], page_nos, dpi)
                else:
                    with open(job["target"], "rb") as image_file:
                        rendered = [(1, image_file.read())]
                job["phase"] = "逐页渲染与忠实转写"
                for index, (page_no, image_bytes) in enumerate(rendered, start=1):
                    page = job["pages"][page_no]
                    with open(page["png"], "wb") as stream:
                        stream.write(image_bytes)
                    job["page"] = page_no
                    job["current_index"] = index
                    job["phase"] = (
                        f"正在转写原 PDF 第 {page_no} 页"
                        if job["source_type"] == "pdf" else "正在转写图片"
                    )
                    job["progress"] = round((index - 1) / max(1, len(page_nos)), 3)
                    page_ok = _transcribe_one(job, client, page_no, page["png"])
                    if page_ok:
                        _refresh_raw_preview(job)
                    job["done"] = index
                    job["progress"] = round(index / max(1, len(page_nos)), 3)
                _merge_job(job)
            except Exception as exc:  # noqa: BLE001
                message = _safe_task_error(exc)
                if "No module named 'fitz'" in message:
                    message = "缺少 PDF 渲染组件 PyMuPDF，请重新安装完整版本后重试"
                if any(
                    page.get("status") == "done" for page in job.get("pages", {}).values()
                ):
                    _merge_job(job, complete_progress=False)
                    job["status"] = "partial"
                    job["phase"] = "后续页面处理失败，已保留完成页"
                    job["error"] = message
                else:
                    job["status"] = "error"
                    job["phase"] = "准备或渲染失败"
                    job["error"] = message

        threading.Thread(target=worker, daemon=True).start()

    @app.post("/api/ocr/inspect")
    async def ocr_inspect(file: UploadFile = File(...)):
        """上传一次 PDF/图片并创建不可猜测的待启动任务。"""
        _cleanup_ocr_jobs()
        suffix, upload, source_total, source_outline = await _read_ocr_upload(file)
        job = _create_ocr_job(
            suffix, upload, source_total, "ready", source_outline=source_outline
        )
        return {
            "id": job["id"],
            "source_type": job["source_type"],
            "total_pages": source_total,
            "max_pages_per_job": MAX_OCR_PAGES_PER_JOB,
        }

    @app.post("/api/ocr/jobs/{jid}/start")
    def ocr_start_inspected(
        jid: str,
        start_page: Optional[int] = Form(None),
        end_page: Optional[int] = Form(None),
        dpi: int = Form(150),
        base_url: str = Form(""),
        model: str = Form(""),
        api_key: str = Form(""),
    ):
        _cleanup_ocr_jobs()
        if not 72 <= dpi <= 300:
            raise HTTPException(400, "DPI 必须在 72-300 之间")
        if len(model) > 160 or len(base_url) > 500:
            raise HTTPException(400, "模型或 Base URL 输入过长")
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
            if job is None:
                raise HTTPException(404, "上传已过期，请重新选择文件")
            if job.get("status") != "ready":
                return {
                    "id": jid,
                    "reused": True,
                    "status": str(job.get("status") or "running"),
                }
        from ..ocr import select_page_interval

        try:
            page_nos = select_page_interval(
                job["source_total"], start_page, end_page, MAX_OCR_PAGES_PER_JOB
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_lock:
                if _ocr_jobs.get(jid) is not job:
                    raise HTTPException(404, "上传已过期，请重新选择文件")
                if job.get("status") != "ready":
                    return {
                        "id": jid,
                        "reused": True,
                        "status": str(job.get("status") or "running"),
                    }
                job["status"] = "starting"
                _set_ocr_selection(job, page_nos)
                job["status"] = "running"
        _launch_ocr_job(job, page_nos, dpi, base_url, model, api_key)
        return {"id": jid, "reused": False, "status": "running"}

    @app.delete("/api/ocr/jobs/{jid}")
    def ocr_discard_inspected(jid: str):
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_lock:
                job = _ocr_jobs.get(jid)
                if job is None:
                    return {"ok": True}
                if (
                    job.get("status") in {"starting", "running"}
                    or job.get("importing") or job.get("saving")
                ):
                    raise HTTPException(409, "运行中的 OCR 任务不能删除")
                _ocr_jobs.pop(jid, None)
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)
        return {"ok": True}

    @app.post("/api/ocr/jobs")
    async def ocr_start():
        """旧版一次上传即启动端点已停用；必须先 inspect 获取随机任务号。

        两阶段启动既能在响应丢失后安全重放，也避免任意网页通过跨站表单直接
        消耗本机已配置的视觉模型额度。
        """
        raise HTTPException(409, "请先上传并读取文件信息，再使用任务编号开始 OCR")

    @app.get("/api/ocr/jobs/{jid}")
    def ocr_status(jid: str):
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
            if job is None:
                raise HTTPException(404, "任务不存在")
            pages_summary = {
                str(n): {
                    "status": p["status"],
                    "low_conf": p["low_conf"],
                    "error": p["error"][:120],
                    "attempts": p.get("attempts", 0),
                    "task_index": p.get("task_index", 0),
                    "retrying": p.get("retrying", False),
                }
                for n, p in job.get("pages", {}).items()
            }
            public = {
                k: deepcopy(v)
                for k, v in job.items()
                if k not in (
                    "raw_tex", "pages", "client", "dir", "target", "suffix",
                    "_transcribe_one", "_refresh_raw_preview", "_merge_job",
                )
            }
            public["raw_revision"] = int(job.get("raw_revision") or 0)
            public["raw_chars"] = int(job.get("raw_chars") or len(job.get("raw_tex") or ""))
        return public | {"pages": pages_summary}

    @app.get("/api/ocr/jobs/{jid}/preview")
    def ocr_preview(jid: str):
        """返回当前已完成页的原子 LaTeX 草稿快照。"""
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
            if job is None:
                raise HTTPException(404, "任务不存在")
            raw_tex = str(job.get("raw_tex") or "")
            revision = int(job.get("raw_revision") or 0)
            raw_chars = int(job.get("raw_chars") or len(raw_tex))
        return PlainTextResponse(
            raw_tex,
            headers={
                "X-LaTeXStruct-OCR-Revision": str(revision),
                "X-LaTeXStruct-OCR-Chars": str(raw_chars),
                "Cache-Control": "no-store",
            },
        )

    @app.get("/api/ocr/jobs/{jid}/pages/{n}")
    def ocr_page_png(jid: str, n: int):
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not page or not os.path.exists(page.get("png", "")):
            raise HTTPException(404, "页面不存在")
        from ..ocr import image_mime_type

        media_type = image_mime_type(Path(page["png"]).read_bytes())
        return FileResponse(page["png"], media_type=media_type)

    @app.get("/api/ocr/jobs/{jid}/pages/{n}/tex")
    def ocr_page_tex(jid: str, n: int):
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not page:
            raise HTTPException(404, "页面不存在")
        return PlainTextResponse(page.get("tex", ""))

    @app.post("/api/ocr/jobs/{jid}/pages/{n}/retry")
    def ocr_page_retry(jid: str, n: int):
        """单页重试：重新转写该页并重合并。"""
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_lock:
                job = _ocr_jobs.get(jid)
                page = (job or {}).get("pages", {}).get(n)
                if not job or not page:
                    raise HTTPException(404, "页面不存在")
                if job.get("importing"):
                    raise HTTPException(409, "OCR 结果正在导入项目，暂时不能重试页面")
                if job.get("saving"):
                    raise HTTPException(409, "OCR 结果正在保存，完成后再重试页面")
                if job.get("status") == "running" or page.get("retrying"):
                    raise HTTPException(409, "该页正在处理，请勿重复点击重试")
                client = job.get("client")
                if client is None:
                    raise HTTPException(400, "任务尚未初始化")
                if not os.path.exists(page.get("png", "")):
                    raise HTTPException(409, "本页预览尚未准备好，暂时不能重试")
                page["retrying"] = True
                job["status"] = "running"
                job["page"] = n
                job["current_index"] = page.get("task_index", 0)
                job["phase"] = (
                    f"重试原 PDF 第 {n} 页"
                    if job.get("source_type") == "pdf" else "重试图片"
                )
        try:
            try:
                ok = job["_transcribe_one"](job, client, n, page["png"])
            except Exception as exc:  # noqa: BLE001
                ok = False
                with _ocr_jobs_lock:
                    page["status"] = "error"
                    page["low_conf"] = True
                    page["error"] = _safe_task_error(exc)
                    job["page_revision"] = int(job.get("page_revision") or 0) + 1
            if ok:
                job["_refresh_raw_preview"](job)
        finally:
            try:
                job["_merge_job"](job)
            finally:
                with _ocr_jobs_lock:
                    page["retrying"] = False
        return {
            "ok": ok,
            "page": n,
            "task_index": page.get("task_index", 0),
            "status": job["status"],
        }

    @app.get("/api/ocr/jobs/{jid}/result")
    def ocr_result(jid: str):
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
            if job is None or job.get("status") not in ("done", "partial"):
                raise HTTPException(404, "原始 OCR 尚未生成")
            raw_tex = job["raw_tex"]
            status = job["status"]
        return PlainTextResponse(
            raw_tex,
            headers={"X-LaTeXStruct-OCR-Complete": "true" if status == "done" else "false"},
        )

    @app.post("/api/ocr/jobs/{jid}/save")
    def save_ocr_result(jid: str):
        """可靠保存终态 OCR；成功落盘后才把该 revision 标记为已保全。"""
        from .downloads import save_unique_download

        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_lock:
                job = _ocr_jobs.get(jid)
                if job is None or job.get("status") not in ("done", "partial"):
                    raise HTTPException(409, "原始 OCR 尚未生成")
                if job.get("saving"):
                    raise HTTPException(409, "原始 OCR 正在保存，请勿重复点击")
                if job.get("importing"):
                    raise HTTPException(409, "OCR 结果正在导入项目，请等待完成")
                raw_tex = str(job.get("raw_tex") or "")
                if not raw_tex:
                    raise HTTPException(409, "原始 OCR 结果为空，请先重试失败页面")
                revision = int(job.get("raw_revision") or 0)
                usage_revision = int(job.get("usage_revision") or 0)
                page_revision = int(job.get("page_revision") or 0)
                status = str(job.get("status") or "")
                start = int(job.get("selected_start") or 1)
                end = int(job.get("selected_end") or start)
                source_type = str(job.get("source_type") or "image")
                job["saving"] = True
        range_label = f"-P{start}-{end}" if source_type == "pdf" else ""
        partial_label = "-partial" if status == "partial" else ""
        data = raw_tex.encode("utf-8")
        try:
            saved = save_unique_download(
                data,
                f"OCR{range_label}{partial_label}-{jid}.tex",
            )
            with _ocr_jobs_lock:
                current = _ocr_jobs.get(jid)
                preserved = bool(
                    current is not None
                    and int(current.get("raw_revision") or 0) == revision
                    and int(current.get("usage_revision") or 0) == usage_revision
                    and int(current.get("page_revision") or 0) == page_revision
                    and current.get("raw_tex") == raw_tex
                )
                if preserved:
                    current["downloaded_revision"] = revision
                    current["downloaded_usage_revision"] = usage_revision
                    current["downloaded_page_revision"] = page_revision
            if not preserved:
                raise HTTPException(
                    409,
                    f"保存期间 OCR 已更新；旧版 {saved.name} 已保留，请再次保存最新结果",
                )
            return {
                "ok": True,
                "filename": saved.name,
                "folder": "下载/LaTeXStruct",
                "bytes": len(data),
                "revision": revision,
                "usage_revision": usage_revision,
                "page_revision": page_revision,
                "preserved": True,
            }
        finally:
            with _ocr_jobs_lock:
                current = _ocr_jobs.get(jid)
                if current is not None:
                    current["saving"] = False

    @app.post("/api/ocr/jobs/{jid}/import")
    def ocr_import(
        jid: str,
        name: str = "OCR 转写项目",
        mode: str = "rule",
        template: str = "elegantbook",
        title: str = "",
    ):
        from ..core.template import ELEGANTBOOK, normalize_template_id

        mode = str(mode or "").strip().lower()
        if mode not in {"rule", "ai"}:
            raise HTTPException(400, "结构化整理方式只能是 AI 或规则")
        normalize_template_id(template)
        template = ELEGANTBOOK
        import_options = {
            "mode": mode,
            "template": template,
            "title": title.strip(),
            "name": name.strip(),
        }
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_lock:
                job = _ocr_jobs.get(jid)
                if job is None or job.get("status") != "done" or not job.get("raw_ready"):
                    raise HTTPException(409, "仍有失败页面；请逐页重试成功后再进入结构化审阅")
                if job.get("importing"):
                    raise HTTPException(409, "OCR 结果正在导入，请勿重复点击")
                if job.get("saving"):
                    raise HTTPException(409, "OCR 结果正在保存，请等待完成后再导入")
                revision = int(job.get("raw_revision") or 0)
                usage_revision = int(job.get("usage_revision") or 0)
                page_revision = int(job.get("page_revision") or 0)
                existing_pid = str(job.get("imported_project_id") or "")
                if (
                    existing_pid
                    and int(job.get("imported_revision") or 0) == revision
                    and int(job.get("imported_usage_revision") or 0) == usage_revision
                    and int(job.get("imported_page_revision") or 0) == page_revision
                    and job.get("imported_options", import_options) == import_options
                ):
                    return {
                        "id": existing_pid,
                        "processed": (
                            job.get("imported_processed")
                            if job.get("imported_processed") is not None else False
                        ),
                        "reused": True,
                    }
                job["importing"] = True
                raw_tex = job["raw_tex"]
        # 原始 OCR 永远作为 source.tex 保存；结构化结果单独写 result.tex，二者不混写。
        try:
            pid = get_store().create(
                raw_tex,
                name,
                mode,
                template,
                kind="ocr",
                template_title=title or name,
            )
            with _ocr_jobs_lock:
                current = _ocr_jobs.get(jid)
                if (
                    current is not None
                    and int(current.get("raw_revision") or 0) == revision
                    and int(current.get("usage_revision") or 0) == usage_revision
                    and int(current.get("page_revision") or 0) == page_revision
                    and current.get("raw_tex") == raw_tex
                ):
                    current["imported_revision"] = revision
                    current["imported_usage_revision"] = usage_revision
                    current["imported_page_revision"] = page_revision
                    current["imported_project_id"] = pid
                    current["imported_options"] = import_options
                    current["imported_processed"] = False
            # 立即进入工作台，再由标准后台任务提供进度、暂停与实时 TeX 草稿。
            process_job = process_start(pid)
            with _ocr_jobs_lock:
                current = _ocr_jobs.get(jid)
                if current is not None and current.get("imported_project_id") == pid:
                    current["imported_processed"] = False
            return {"id": pid, "processed": False, "process": process_job}
        finally:
            with _ocr_jobs_lock:
                current = _ocr_jobs.get(jid)
                if current is not None:
                    current["importing"] = False

    react_dir = STATIC_DIR.parent / "static-react"
    react_ready = (
        (react_dir / "index.html").is_file()
        and (react_dir / "assets").is_dir()
        and any((react_dir / "assets").iterdir())
    )
    if getattr(sys, "frozen", False) and not react_ready:
        # A release must never pretend to work by serving the obsolete fallback UI:
        # that page does not implement the current OCR/process APIs.
        raise RuntimeError(
            "发布包缺少 React 前端资源；请重新下载安装完整的 LaTeXStruct 安装包"
        )
    if react_ready:
        app.mount("/", StaticFiles(directory=str(react_dir), html=True), name="react")
    else:
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def _ensure(pid: str):
    if get_store().get(pid) is None:
        raise HTTPException(404, "项目不存在")

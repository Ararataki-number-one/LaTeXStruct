# -*- coding: utf-8 -*-
"""FastAPI 本地服务（127.0.0.1）。"""

from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import io
import json
import math
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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Dict, Literal, Optional
from weakref import WeakValueDictionary

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from ..config import AppConfig, load_config, save_config
from ..core.analysis_adapter import (
    AnalysisRunArtifacts,
    freeze_pipeline_analysis_run,
)
from ..core.analysis_schema import AnalysisFinalStatus, ModelBinding
from ..core.audit_schema import (
    ArtifactRole,
    AuditDepth,
    AuditSubmissionRequest,
    AuditWorkflow,
    RunSnapshot,
    TerminalStatus,
)
from ..core.audit_evidence import (
    build_metrics,
    build_outline_evidence,
    build_report_json,
    issues_csv_bytes,
    project_dependency_path,
    structured_blockers,
    template_manifest,
)
from ..core.audit_submission import make_audit_artifact
from ..core.audit_sanitize import sanitize_plain_text
from ..core.invariants import IMG_RE
from ..core.ocr_quality import (
    OCR_QUALITY_PUBLICATION,
    assess_ocr_quality,
    normalize_ocr_quality_profile,
)
from ..core.ocr_artifacts import available_ocr_artifacts, resolve_ocr_artifact
from ..core.ocr_runtime import (
    BoundedOcrExecutor,
    OcrErrorCategory,
    OcrPageRecord,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunPaused,
    OcrRunStore,
    OcrStoreError,
    OCR_TRANSCRIPTION_SYSTEM_PROMPT,
    make_page_id,
    make_run_snapshot,
    normalize_quality_tier,
    ocr_batch_output_schema,
    ocr_batch_request_payload,
    progress_metrics as ocr_progress_metrics,
    public_page_state,
    quality_tier_policy,
    thaw_json,
)
from ..core.ocr_sources import (
    MULTI_IMAGE_DERIVATION_ID,
    build_multi_image_source,
    extract_multi_image_bytes,
    verify_multi_image_source,
)
from ..core.parser import parse_latex
from ..core.pipeline import (
    IMAGE_TO_VISUAL_PDF_DERIVATION_ID,
    PDF_IDENTITY_VISUAL_DERIVATION_ID,
    VISUAL_SOURCE_PROVENANCE_SCHEMA,
    run_pipeline,
)
from ..core.prompts import PROMPT_VERSION
from ..core.provenance import (
    PROVENANCE_MANIFEST_NAME,
    RAW_ARTIFACT_PACKAGE_PATH,
    RAW_OCR_SCOPE,
    UNVERIFIED_SCOPE,
    VERIFIED_SCOPE,
    make_provenance_record,
    sha256_bytes,
    sha256_lf_normalized_text,
    stamp_tex_provenance,
)
from ..core.runbundle import (
    RUN_BUNDLE_NAMES,
    append_run_bundle,
    preview_state_from_verification,
    validate_archive_namespace,
)
from ..providers import list_provider_presets
from ..store import ProjectStore
from .audit_filename import build_audit_zip_filename
from .process_jobs import ProcessJobManager, ProcessingCancelled

STATIC_DIR = Path(__file__).parent / "static"

_store: Optional[ProjectStore] = None
_config: Optional[AppConfig] = None
_ocr_jobs: Dict[str, dict] = {}
_ocr_jobs_lock = threading.RLock()
_ocr_jobs_changed = threading.Condition(_ocr_jobs_lock)
_process_jobs = ProcessJobManager()
_update_state_lock = threading.RLock()
_update_preparing = False
_update_jobs_lock = threading.RLock()
_update_jobs: Dict[str, dict] = {}
_project_locks_guard = threading.Lock()
_project_locks: WeakValueDictionary[str, threading.RLock] = WeakValueDictionary()


def _project_lock(pid: str):
    """Return the stable per-project processing/review transaction lock.

    The registry lock protects lock creation only. Work for different projects
    therefore remains concurrent, while one project's meta/result files cannot
    be published by overlapping process or review requests. The weak registry
    does not retain a project forever: holders and waiters keep the returned
    lock strongly referenced until their transaction ends, after which an idle
    entry may be collected safely.
    """
    key = str(pid)
    with _project_locks_guard:
        lock = _project_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _project_locks[key] = lock
        return lock

OCR_ACTIVE_STATUSES = {"starting", "running", "pausing", "paused"}


def _bump_ocr_state(job: dict) -> None:
    """递增 OCR 公开快照版本，防止旧轮询响应覆盖新的控制状态。"""
    job["state_revision"] = int(job.get("state_revision") or 0) + 1
    job["updated"] = time.time()


def _ocr_error_is_retryable(message: str) -> bool:
    """仅对明确的暂时性/截断/空响应执行页面层重试。"""
    lower = (message or "").lower()
    return any(token in lower for token in (
        "暂时性", "临时", "网络错误", "连接失败", "timed out", "timeout",
        "connection", "temporarily", "temporary", "try again", "rate limit",
        "too many requests", "overloaded", "限流",
        "http 408", "http 409", "http 425", "http 429", "http 500", "http 502",
        "http 503", "http 504", "max_tokens", "被截断", "转写为空",
    ))


def _ocr_retry_wait(attempt: int) -> None:
    """页面层短指数退避；独立函数便于测试替换。"""
    time.sleep(min(4.0, 0.5 * (2 ** max(0, attempt - 1))))


def _build_ocr_client(
    cfg: AppConfig,
    base_url: str = "",
    model: str = "",
    api_key: str = "",
):
    """按全局后端创建视觉客户端；Codex 模式绝不接触或回退到 API 配置。"""
    from ..core.ai import LLMClient, LLMError, RoleConfig

    ocr_cfg = cfg.to_ocr_config()
    if ocr_cfg.backend == "codex_cli":
        from ..core.codex_cli import CodexCLIClient

        client = CodexCLIClient(
            model=ocr_cfg.codex_model,
            reasoning_effort=ocr_cfg.codex_reasoning_effort,
        )
        return client, client.cfg.model, "codex_cli"
    if ocr_cfg.backend != "api":
        raise LLMError(f"不支持的 OCR 后端：{ocr_cfg.backend}")
    configured_role = ocr_cfg.role
    selected_base_url = base_url or configured_role.base_url
    selected_model = model or configured_role.model
    selected_key = api_key
    if (
        not selected_key
        and selected_base_url.rstrip("/") == configured_role.base_url.rstrip("/")
    ):
        selected_key = configured_role.api_key
    return (
        LLMClient(RoleConfig(selected_base_url, selected_model, selected_key)),
        selected_model,
        "api",
    )


def _public_ocr_job(job: dict) -> dict:
    """在同一把锁中生成可供轮询/控制端点共用的完整快照。"""
    with _ocr_jobs_lock:
        job_busy = (
            job.get("status") in OCR_ACTIVE_STATUSES
            or bool(job.get("importing"))
            or bool(job.get("saving"))
        )
        retry_available = (
            not job_busy
            and job.get("client") is not None
            and (
                callable(job.get("_v2_retry_page"))
                or callable(job.get("_transcribe_one"))
            )
            and callable(job.get("_render_one"))
        )
        pages_summary = {
            str(n): {
                "status": page.get("status", "pending"),
                "page_id": str(page.get("page_id") or ""),
                "source_page": int(page.get("source_page") or n),
                "low_conf": bool(page.get("low_conf")),
                "needs_review": page.get("needs_review", False),
                "error": str(page.get("error") or "")[:120],
                "attempts": page.get("attempts", 0),
                "task_index": page.get("task_index", 0),
                "retrying": page.get("retrying", False),
                "can_retry": retry_available and not page.get("retrying", False),
                "preview_ready": os.path.isfile(str(
                    page.get("persisted_visual_path") or page.get("png") or ""
                )),
                "figure_count": len(page.get("figures") or []),
                "figure_bbox_ready": bool(page.get("figures")),
                "text_reference_chars": int(page.get("text_hint_chars") or 0),
                "quality_flag_count": len(page.get("quality_flags") or []),
                "visual_input_sha256": (
                    str(page.get("visual_input_sha256") or "").lower()
                    if re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(page.get("visual_input_sha256") or "").lower(),
                    )
                    else ""
                ),
                "visual_input_persisted": bool(
                    page.get("visual_input_persisted")
                ),
                "formula_visual_evidence": _bounded_formula_evidence(
                    page.get("formula_evidence") or []
                ),
                "formula_evidence_count": len(
                    _bounded_formula_evidence(page.get("formula_evidence") or [])
                ),
                "formula_evidence_attached": any(
                    item.get("attached")
                    for item in _bounded_formula_evidence(
                        page.get("formula_evidence") or []
                    )
                ),
            }
            for n, page in job.get("pages", {}).items()
        }
        public = {
            key: deepcopy(value)
            for key, value in job.items()
            if key not in (
                "raw_tex", "pages", "client", "dir", "target", "visual_target", "suffix",
                "pause_requested",
                "_transcribe_one", "_refresh_raw_preview", "_merge_job", "_render_one",
                "_mark_page_error",
                "_source_sha256", "_visual_source_sha256", "_v2_store", "_v2_snapshot",
                "_v2_retry_page", "_compatibility_single",
            )
        }
        public["raw_revision"] = int(job.get("raw_revision") or 0)
        public["raw_chars"] = int(job.get("raw_chars") or len(job.get("raw_tex") or ""))
        public["state_revision"] = int(job.get("state_revision") or 0)
        # 旧任务没有该字段时明确标为 unknown；绝不能拿当前设置替它猜测，
        # 否则切换后端后历史任务会显示错误的计费来源。
        public["backend"] = str(job.get("backend") or "unknown")
        public["can_pause"] = job.get("status") == "running"
        public["can_resume"] = job.get("status") in {"pausing", "paused"} or (
            job.get("status") == "partial"
            and job.get("_v2_snapshot") is not None
            and not bool(job.get("raw_frozen"))
        )
        public["can_cancel"] = False
        public["pages"] = pages_summary
        v2_store = job.get("_v2_store")
        v2_snapshot = job.get("_v2_snapshot")
        v2_records = None
        if isinstance(v2_store, OcrRunStore) and v2_snapshot is not None:
            try:
                records = v2_store.list_records(v2_snapshot.run_id)
                v2_records = records
                metrics = ocr_progress_metrics(
                    v2_snapshot,
                    records,
                    terminal_epoch=job.get("terminal_epoch"),
                    merge_complete=bool(job.get("raw_ready")),
                    raw_frozen=bool(job.get("raw_frozen")),
                    compile_status=job.get("compile_status") or None,
                    rate_limited=bool(job.get("rate_limited")),
                    concurrency_limit=int(job.get("current_concurrency_limit") or 0) or None,
                )
                counts = metrics.get("counts") or {}
                metrics.update({
                    "total_pages": counts.get("total", 0),
                    "pending_pages": counts.get("pending", 0),
                    "active_pages": counts.get("processing", 0),
                    "success_pages": counts.get("success", 0),
                    "needs_review_pages": counts.get("needs_review", 0),
                    "failed_pages": counts.get("failed", 0),
                    "auto_retry_pages": counts.get("automatic_retry_pages", 0),
                    "progress": metrics.get("overall_progress", 0),
                })
                public["progress_metrics"] = metrics
                public["progress"] = metrics["overall_progress"]
                public["elapsed_seconds"] = metrics["elapsed_seconds"]
                public["average_pages_per_minute"] = metrics[
                    "average_pages_per_minute"
                ]
                public["recent_pages_per_minute"] = metrics[
                    "recent_pages_per_minute"
                ]
                public["eta_seconds"] = metrics["eta_seconds"]
                public["current_pages"] = metrics["current_pages"]
                public["current_dpi"] = metrics["current_dpi"]
                public["current_concurrency"] = metrics["current_concurrency"]
                public["rate_limited"] = metrics["rate_limited"]
                for record in records:
                    legacy = pages_summary.get(str(record.source_page))
                    if legacy is not None:
                        legacy_attempts = int(legacy.get("attempts") or 0)
                        runtime_state = public_page_state(record)
                        runtime_state.pop("status", None)
                        runtime_state["attempts"] = max(
                            legacy_attempts, int(runtime_state.get("attempts") or 0)
                        )
                        legacy.update(runtime_state)
                        # Keep the old lower-case state for legacy consumers,
                        # while exposing the v2 state as final_status.
                        legacy["final_status"] = record.status.value
                available = available_ocr_artifacts(v2_store, v2_snapshot.run_id)
                artifact_urls = {}
                for public_name, role in {
                    "source_pdf": "source",
                    "source_images_manifest": "source-images-manifest",
                    "derived_visual_source_pdf": "visual-source",
                    "raw_ocr_tex": "raw-ocr",
                    "baseline_tex": "baseline-tex",
                    "baseline_pdf": "baseline-pdf",
                    "compile_log": "compile-log",
                    "run_snapshot": "snapshot",
                }.items():
                    evidence = available.get(role) or {}
                    artifact_urls[public_name] = {
                        "available": bool(evidence),
                        "download_url": f"/api/ocr/jobs/{job['id']}/artifacts/{role}",
                        **deepcopy(evidence),
                    }
                artifact_urls["baseline_pdf"]["preview_status"] = str(
                    job.get("compile_status") or ""
                )
                public["artifacts"] = artifact_urls
            except Exception:  # noqa: BLE001 - polling must survive a corrupt run
                public["persistence_error"] = "OCR 持久化记录需要恢复；已保留内存结果"
        public["quality_report"] = assess_ocr_quality(
            _snapshot_ocr_bundle_job(job, v2_records=v2_records)
        )
        return public


def _ocr_control(job: dict) -> None:
    """在页边界安全暂停；当前已发出的模型请求不被强行中断。"""
    with _ocr_jobs_changed:
        if not job.get("pause_requested"):
            if job.get("status") in {"pausing", "paused"}:
                job["status"] = "running"
                job["phase"] = "已继续 OCR"
                _bump_ocr_state(job)
                _ocr_jobs_changed.notify_all()
            return
        if job.get("status") != "paused":
            job["status"] = "paused"
            job["phase"] = "OCR 已安全暂停"
            _bump_ocr_state(job)
            _ocr_jobs_changed.notify_all()
        while job.get("pause_requested"):
            _ocr_jobs_changed.wait(timeout=1.0)
        if job.get("status") == "paused":
            job["status"] = "running"
            job["phase"] = "已继续 OCR"
            _bump_ocr_state(job)
            _ocr_jobs_changed.notify_all()

OCR_CANONICAL_IMAGE_PATH_RE = re.compile(
    r"images/page_(?P<page>\d+)_(?P<index>\d+)(?P<ext>\.(?:png|jpe?g))?",
    re.I,
)
MAX_PRESERVED_OCR_IMAGE_BYTES = 25 * 1024 * 1024
MAX_PRESERVED_OCR_ASSET_BYTES = 100 * 1024 * 1024
MAX_PRESERVED_SOURCE_PAGE_PREVIEWS = 8
OCR_SOURCE_PAGE_COUNT_SCHEMA = "latexstruct-ocr-source-page-count-v2"
OCR_LEGACY_PAGE_COUNT_REPAIR_ID = "pre-v1.2.9-import-snapshot-missing-source-total"
OCR_PAGE_BREAK_RE = re.compile(r"(?m)^\s*%===\s*PAGE BREAK\s*===.*$")
OCR_PAGE_MARKER_RE = re.compile(r"(?m)^\s*%\s*Page\s+(?P<page>\d+)\s*$", re.I)


def _strict_page_number(value: object) -> int:
    """Accept only a real positive integer or its canonical decimal spelling."""
    if isinstance(value, bool):
        raise ValueError("page number cannot be boolean")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        number = int(value)
    else:
        raise ValueError("page number must be a positive integer")
    if number < 1:
        raise ValueError("page number must be positive")
    return number


def _runtime_provenance_identity(prompt_version: str) -> dict[str, str]:
    """Return identity embedded in this executable, never mutable export-time env."""
    from .. import __version__
    from .._build import BUILD_COMMIT, BUILD_ID

    return {
        "app_version": __version__,
        "build_id": str(BUILD_ID or "unknown"),
        "commit": str(BUILD_COMMIT or "unknown"),
        "prompt_version": prompt_version,
    }


def _unknown_producer_identity() -> dict[str, str]:
    """Identity for legacy/source artifacts that never recorded their producer."""
    return {
        "app_version": "unknown",
        "build_id": "unknown",
        "commit": "unknown",
        "prompt_version": "unknown",
    }


def _stored_producer_identity(record: object) -> dict[str, str]:
    """Read only a processing-time identity; never substitute the current build."""
    if not isinstance(record, dict):
        return _unknown_producer_identity()
    stored = record.get("producer_identity")
    if not isinstance(stored, dict):
        return _unknown_producer_identity()
    return {
        key: str(stored.get(key) or "unknown")
        for key in ("app_version", "build_id", "commit", "prompt_version")
    }


def _ocr_prompt_version() -> str:
    from ..ocr import OCR_SYSTEM_PROMPT

    return "ocr-sha256-" + sha256_bytes(OCR_SYSTEM_PROMPT.encode("utf-8"))


def _provenance_json_bytes(record: dict[str, str]) -> bytes:
    return json.dumps(record, ensure_ascii=True, indent=2).encode("ascii")


def _canonical_image_extension(extension: str) -> str:
    extension = "." + str(extension or "").lower().lstrip(".")
    return ".jpg" if extension == ".jpeg" else extension


def _raster_extension(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    return ""


def _job_page_raster(job: dict, page_no: int) -> tuple[bytes, str] | None:
    pages = job.get("pages") or {}
    page = pages.get(page_no) or pages.get(str(page_no)) or {}
    page_path = Path(str(
        page.get("persisted_visual_path") or page.get("png") or ""
    ))
    try:
        data = page_path.read_bytes()
    except OSError:
        return None
    extension = _raster_extension(data)
    if not data or extension not in {".png", ".jpg"}:
        return None
    return data, extension


def _raster_for_reference(
    data: bytes,
    extension: str,
    requested_extension: str,
) -> tuple[bytes, str, bool]:
    """Return bytes whose real format matches an optional explicit TEX suffix."""
    requested_extension = str(requested_extension or "").lower()
    if not requested_extension:
        return data, extension, True
    if _canonical_image_extension(extension) == _canonical_image_extension(requested_extension):
        return data, requested_extension, True
    try:
        import fitz

        document = fitz.open(stream=data)
        try:
            pixmap = document[0].get_pixmap(alpha=False)
            output = "png" if requested_extension == ".png" else "jpg"
            converted = pixmap.tobytes(output)
        finally:
            document.close()
        if converted:
            return converted, requested_extension, True
    except Exception:  # noqa: BLE001 - caller records the conservative fallback
        pass
    # A real source-page image is still preferable to a dangling reference.  The
    # manifest marks the format mismatch so the review/export warning remains
    # honest on installations whose image converter is unavailable.
    return data, requested_extension, False


def _preserve_source_page_previews(
    job: dict,
    project_dir: Path,
    page_numbers,
    remaining_bytes: int,
) -> tuple[list[dict], int]:
    """Keep a bounded, hash-addressed sample of the actual OCR input pages."""
    previews = []
    used = 0
    seen = set()
    for raw_page in page_numbers:
        try:
            page_no = int(raw_page)
        except (TypeError, ValueError):
            continue
        if page_no in seen or len(previews) >= MAX_PRESERVED_SOURCE_PAGE_PREVIEWS:
            continue
        seen.add(page_no)
        raster = _job_page_raster(job, page_no)
        if raster is None:
            continue
        data, extension = raster
        if len(data) > MAX_PRESERVED_OCR_IMAGE_BYTES or used + len(data) > remaining_bytes:
            continue
        relative = f"source-pages/page_{page_no:04d}{extension}"
        target_path = (project_dir / Path(relative)).resolve()
        try:
            target_path.relative_to(project_dir)
        except ValueError:
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(data)
        previews.append({
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_page": page_no,
            "kind": "source_page_preview",
        })
        used += len(data)
    return previews, used


def _preserve_formula_crops(
    job: dict,
    project_dir: Path,
    remaining_bytes: int,
) -> tuple[list[dict], int]:
    """Freeze already-rendered formula crops; never re-run vision at export."""
    records = []
    used = 0
    for raw_page, page in sorted(
        (job.get("pages") or {}).items(), key=lambda item: int(item[0])
    ):
        try:
            page_no = int(raw_page)
        except (TypeError, ValueError):
            continue
        for evidence in page.get("formula_evidence") or []:
            if not isinstance(evidence, dict):
                continue
            public = _bounded_formula_evidence([evidence])
            source = Path(str(evidence.get("crop_path") or ""))
            if not public or source.is_symlink() or not source.is_file():
                continue
            try:
                data = source.read_bytes()
            except OSError:
                continue
            extension = _raster_extension(data)
            expected_hash = str(public[0].get("crop_sha256") or "")
            if (
                extension not in {".png", ".jpg"}
                or hashlib.sha256(data).hexdigest() != expected_hash
                or len(data) > MAX_PRESERVED_OCR_IMAGE_BYTES
                or used + len(data) > remaining_bytes
            ):
                continue
            evidence_id = str(public[0]["id"])
            relative = (
                f"formula-crops/page_{page_no:04d}-"
                f"{len(records) + 1:04d}{extension}"
            )
            target = (project_dir / Path(relative)).resolve()
            try:
                target.relative_to(project_dir)
            except ValueError:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
            try:
                with temporary.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    temporary.unlink()
            records.append({
                "path": relative,
                "bytes": len(data),
                "sha256": expected_hash,
                "source_page": page_no,
                "evidence_id": evidence_id,
                "kind": "formula_crop",
            })
            used += len(data)
    return records, used


def _ocr_image_references(text: str) -> tuple[list[dict], list[str]]:
    """Return canonical OCR image references and every unsupported active path.

    The shared invariant parser masks comments, inline ``\\verb`` and protected
    environments before ``IMG_RE`` runs.  This keeps examples in source text from
    blocking import while ensuring that *every* active ``\\includegraphics`` is
    either bound to a canonical OCR asset or reported unresolved.
    """
    references = []
    unsupported = []
    seen = set()
    unsupported_seen = set()
    document = parse_latex(text)
    # ``transcribe_page`` prepends the physical PDF page to every OCR chunk.  The
    # visual model may then copy the printed page number from the footer and may
    # also use that printed number in the suggested image filename.  Therefore
    # only the first Page marker in each PAGE BREAK chunk is authoritative.
    break_matches = list(OCR_PAGE_BREAK_RE.finditer(document.text))
    chunk_starts = [0, *(match.end() for match in break_matches)]
    chunk_ends = [*(match.start() for match in break_matches), len(document.text)]
    for chunk_start, chunk_end in zip(chunk_starts, chunk_ends):
        chunk = document.text[chunk_start:chunk_end]
        active_chunk = document.masked[chunk_start:chunk_end]
        page_marker = OCR_PAGE_MARKER_RE.search(chunk)
        for match in IMG_RE.finditer(active_chunk):
            raw_path = match.group(1)
            path = raw_path.replace("\\", "/").strip()
            canonical = OCR_CANONICAL_IMAGE_PATH_RE.fullmatch(path)
            if canonical is None:
                unresolved_path = path or raw_path
                if unresolved_path not in unsupported_seen:
                    unsupported_seen.add(unresolved_path)
                    unsupported.append(unresolved_path)
                continue
            if path in seen:
                continue
            seen.add(path)
            printed_page = int(canonical.group("page"))
            options_match = re.search(r"\[(?P<opts>[^\]]*)\]", match.group(0))
            options = options_match.group("opts") if options_match else ""
            width_match = re.search(
                r"\bwidth\s*=\s*(?P<width>\d+(?:\.\d+)?)\s*\\(?:line|text)width\b",
                options,
                re.I,
            )
            references.append({
                "path": path,
                "page": printed_page,
                "source_page": (
                    int(page_marker.group("page")) if page_marker else printed_page
                ),
                "index": int(canonical.group("index")),
                "ext": (canonical.group("ext") or "").lower(),
                "width_hint": float(width_match.group("width")) if width_match else None,
            })
    return references, unsupported


def _ocr_figure_bbox(job: dict, reference: dict) -> dict | None:
    """Return a secondarily validated bbox record for one exact TEX reference."""
    pages = job.get("pages") or {}
    page = pages.get(reference["source_page"]) or pages.get(
        str(reference["source_page"])
    ) or {}
    for figure in page.get("figures") or []:
        if not isinstance(figure, dict):
            continue
        path = str(figure.get("path") or "").replace("\\", "/").strip()
        if path != reference["path"] or figure.get("index") != reference["index"]:
            continue
        norm = figure.get("bbox_normalized")
        pixels = figure.get("bbox_pixels")
        size = figure.get("image_size_pixels") or page.get("image_size_pixels")
        if not all(isinstance(value, list) and len(value) == expected for value, expected in (
            (norm, 4), (pixels, 4), (size, 2),
        )):
            continue
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in [*norm, *pixels, *size]
        ):
            continue
        nx0, ny0, nx1, ny1 = [float(value) for value in norm]
        px0, py0, px1, py1 = [float(value) for value in pixels]
        image_width, image_height = [float(value) for value in size]
        if not (
            image_width > 0
            and image_height > 0
            and 0 <= nx0 < nx1 <= 1
            and 0 <= ny0 < ny1 <= 1
            and 0 <= px0 < px1 <= image_width
            and 0 <= py0 < py1 <= image_height
        ):
            continue
        box_width = nx1 - nx0
        box_height = ny1 - ny0
        if (
            box_width < 0.01
            or box_height < 0.01
            or box_width * box_height > 0.88
            or (box_width > 0.96 and box_height > 0.90)
        ):
            continue
        result = {
            "bbox_normalized": [nx0, ny0, nx1, ny1],
            "bbox_pixels": [int(round(value)) for value in (px0, py0, px1, py1)],
            "image_size_pixels": [int(image_width), int(image_height)],
            "bbox_source": str(figure.get("source") or "structured_vision"),
        }
        display_width = figure.get("display_width_ratio")
        if (
            not isinstance(display_width, bool)
            and isinstance(display_width, (int, float))
            and 0.25 <= float(display_width) <= 1.0
        ):
            result["display_width_ratio"] = round(float(display_width), 2)
        return result
    return None


_PDF_CAPTION_LINE_RE = re.compile(
    r"^\s*(?:fig(?:ure)?|table|plate|图|圖|表)\s*(?:[.：:]|\d|[ivxlcdm])",
    re.I,
)
_PDF_PURE_SUBFIGURE_LABEL_RE = re.compile(
    r"^\s*[（(]?\s*(?:[a-z]|\d{1,2}|[ivxlcdm]{1,5})\s*[)）.]?\s*$",
    re.I,
)


def _pdf_rect_distance(first, second) -> float:
    """Euclidean edge distance between two PyMuPDF rectangles."""
    horizontal = max(
        float(first.x0) - float(second.x1),
        float(second.x0) - float(first.x1),
        0.0,
    )
    vertical = max(
        float(first.y0) - float(second.y1),
        float(second.y0) - float(first.y1),
        0.0,
    )
    return (horizontal * horizontal + vertical * vertical) ** 0.5


def _pdf_sparse_figure_label(text: str, line_rect, page_rect, anchor_union) -> bool:
    """Accept node/math/subfigure labels while rejecting prose and captions."""
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    if not value or _PDF_CAPTION_LINE_RE.match(value):
        return False
    if _PDF_PURE_SUBFIGURE_LABEL_RE.fullmatch(value):
        return True
    # ``(a) description`` is a subcaption, not the pure panel marker.  Keeping
    # it in TEX separately avoids duplicated prose below the rasterized figure.
    if re.match(r"^\s*[（(][^）)]{1,8}[)）]\s*\S", value):
        return False
    if len(value) > 48:
        return False
    if float(line_rect.width) > max(
        float(page_rect.width) * 0.30,
        float(anchor_union.width) * 0.42,
    ):
        return False
    cjk_count = len(re.findall(r"[\u3400-\u9fff]", value))
    if cjk_count > 8:
        return False
    prose_words = re.findall(r"[A-Za-zÀ-ÖØ-öø-ÿ]{2,}", value)
    if len(prose_words) >= 4:
        return False
    # A short centered sentence immediately below the vector extent is a
    # caption even when it does not start with “Fig.”.  Formula/node labels use
    # mostly one-letter symbols and therefore do not hit this branch.
    below_anchor = float(line_rect.y0) >= float(anchor_union.y1) - 0.5
    if below_anchor and len(prose_words) >= 2 and sum(map(len, prose_words)) >= 9:
        return False
    return True


def _refine_pdf_figure_clip(page, bbox: dict):
    """Tighten a coarse visual bbox to PDF drawings plus sparse figure labels.

    Structured vision supplies the semantic seed.  Original-PDF vector paths
    (and genuine embedded image blocks) define the artwork extent; nearby short
    PDF text lines extend it only for node/math/panel labels.  Dense body lines
    and captions never expand the crop.  If the PDF exposes no reliable local
    artwork geometry, callers retain the validated visual bbox fallback.
    """
    import fitz

    page_rect = page.rect
    nx0, ny0, nx1, ny1 = bbox["bbox_normalized"]
    model = fitz.Rect(
        page_rect.x0 + nx0 * page_rect.width,
        page_rect.y0 + ny0 * page_rect.height,
        page_rect.x0 + nx1 * page_rect.width,
        page_rect.y0 + ny1 * page_rect.height,
    )
    page_area = max(1.0, float(page_rect.width * page_rect.height))
    drawing_pool = []
    try:
        drawings = page.get_drawings()
    except Exception:  # noqa: BLE001 - geometry refinement is optional
        drawings = []
    for drawing in drawings or []:
        raw_bbox = drawing.get("rect")
        if not raw_bbox:
            continue
        raw_rect = fitz.Rect(raw_bbox)
        if raw_rect.is_empty or raw_rect.is_infinite:
            continue
        raw_area = max(0.0, float(raw_rect.width * raw_rect.height))
        # Ignore page frames and long running rules.  A large genuine figure is
        # retained unless one path itself behaves like a page-wide decoration.
        if raw_area / page_area > 0.72:
            continue
        if (
            raw_rect.width > page_rect.width * 0.82
            and raw_rect.height > page_rect.height * 0.62
            and raw_rect.x0 < page_rect.x0 + page_rect.width * 0.10
            and raw_rect.x1 > page_rect.x1 - page_rect.width * 0.10
        ):
            continue
        stroke = drawing.get("width")
        stroke = float(stroke) if isinstance(stroke, (int, float)) else 0.0
        rect = fitz.Rect(raw_rect)
        rect.x0 -= max(0.5, stroke * 0.5)
        rect.y0 -= max(0.5, stroke * 0.5)
        rect.x1 += max(0.5, stroke * 0.5)
        rect.y1 += max(0.5, stroke * 0.5)
        if (
            max(rect.width, rect.height) > page_rect.width * 0.65
            and min(rect.width, rect.height) < 2.0
        ):
            continue
        drawing_pool.append(rect)

    anchors = [rect for rect in drawing_pool if rect.intersects(model)]
    # A structured bbox can stop in the middle of a logo assembled from
    # several independent vector paths.  Only when an accepted drawing already
    # touches the model's lower edge do we admit directly connected paths in a
    # small bounded strip below it.  Text captions are never part of this pool.
    boundary_slack = min(12.0, max(4.0, float(page_rect.height) * 0.018))
    if anchors and any(rect.y1 >= model.y1 - boundary_slack for rect in anchors):
        changed = True
        while changed:
            changed = False
            anchor_union = fitz.Rect(anchors[0])
            for rect in anchors[1:]:
                anchor_union.include_rect(rect)
            for rect in drawing_pool:
                if rect in anchors:
                    continue
                if (
                    rect.y0 < model.y1 - boundary_slack
                    or rect.y0 > model.y1 + boundary_slack * 2.0
                    or rect.y1 > model.y1 + boundary_slack * 2.5
                ):
                    continue
                horizontal_gap = max(
                    float(rect.x0) - float(anchor_union.x1),
                    float(anchor_union.x0) - float(rect.x1),
                    0.0,
                )
                if (
                    horizontal_gap <= boundary_slack
                    and _pdf_rect_distance(rect, anchor_union) <= boundary_slack
                ):
                    anchors.append(rect)
                    changed = True

    try:
        text_blocks = (page.get_text("dict") or {}).get("blocks", [])
    except Exception:  # noqa: BLE001
        text_blocks = []
    for block in text_blocks:
        if int(block.get("type", 0)) != 1 or not block.get("bbox"):
            continue
        rect = fitz.Rect(block["bbox"])
        area = max(0.0, float(rect.width * rect.height))
        if area / page_area > 0.72 or not rect.intersects(model):
            continue
        anchors.append(rect)

    line_records = []
    for block in text_blocks:
        if int(block.get("type", 0)) != 0:
            continue
        lines = [line for line in (block.get("lines") or []) if line.get("bbox")]
        for line in lines:
            line_rect = fitz.Rect(line["bbox"])
            if line_rect.is_empty or line_rect.is_infinite:
                continue
            text = "".join(
                str(span.get("text") or "") for span in (line.get("spans") or [])
            )
            line_records.append((line_rect, text, len(lines)))

    text_seed = False
    if not anchors:
        # Some publisher marks are encoded entirely as one custom-font glyph
        # run (for example a horse + wordmark whose extracted text is merely
        # “ABC”).  When the validated visual seed intersects such an isolated,
        # sparse line, its *complete* PDF glyph bbox is stronger evidence than
        # the model's clipped lower edge.  Multi-line body blocks and captions
        # are deliberately ineligible.
        for line_rect, text, block_line_count in line_records:
            if block_line_count != 1:
                continue
            if (
                line_rect.y1 <= page_rect.y0 + page_rect.height * 0.075
                or line_rect.y0 >= page_rect.y1 - page_rect.height * 0.055
            ):
                continue
            if _pdf_rect_distance(line_rect, model) > boundary_slack:
                continue
            horizontal_gap = max(
                float(line_rect.x0) - float(model.x1),
                float(model.x0) - float(line_rect.x1),
                0.0,
            )
            if horizontal_gap > boundary_slack:
                continue
            if not _pdf_sparse_figure_label(text, line_rect, page_rect, model):
                continue
            anchors.append(line_rect)
            text_seed = True

    if not anchors:
        return None
    anchor_union = fitz.Rect(anchors[0])
    for rect in anchors[1:]:
        anchor_union.include_rect(rect)
    # A single rule fragment is not enough evidence to override the model box.
    if (
        not text_seed
        and len(anchors) == 1
        and (anchor_union.width < 18.0 or anchor_union.height < 12.0)
    ):
        return None

    label_gap = min(18.0, max(10.0, float(page_rect.width) * 0.035))
    labels = []
    for line_rect, text, _block_line_count in line_records:
        # Printed running heads / folios are not figure labels, even when
        # a tall figure starts near the top of the body and happens to lie
        # within the generic label-distance threshold.
        if (
            line_rect.y1 <= page_rect.y0 + page_rect.height * 0.075
            or line_rect.y0 >= page_rect.y1 - page_rect.height * 0.055
        ):
            continue
        if not _pdf_sparse_figure_label(
            text, line_rect, page_rect, anchor_union,
        ):
            continue
        if min(_pdf_rect_distance(line_rect, rect) for rect in anchors) <= label_gap:
            labels.append(line_rect)

    clip = fitz.Rect(anchor_union)
    for label in labels:
        clip.include_rect(label)
    pad = min(3.0, max(1.5, float(page_rect.width) * 0.004))
    clip.x0 -= pad
    clip.y0 -= pad
    clip.x1 += pad
    clip.y1 += pad
    safe_top = page_rect.y0 + page_rect.height * 0.025
    safe_bottom = page_rect.y1 - page_rect.height * 0.025
    clip = fitz.Rect(
        max(page_rect.x0, clip.x0),
        max(safe_top, clip.y0),
        min(page_rect.x1, clip.x1),
        min(safe_bottom, clip.y1),
    )
    return clip if not clip.is_empty and not clip.is_infinite else None


def _pdf_clip_from_normalized_bbox(page, bbox: dict, *, dpi: int = 300):
    """Render only a validated figure region from the original PDF page."""
    import fitz

    page_rect = page.rect
    nx0, ny0, nx1, ny1 = bbox["bbox_normalized"]
    # Small page-relative padding protects vector labels while remaining far
    # from page headers/footers and body text outside the reported figure.
    pad_x = max(4.0, float(page_rect.width) * 0.008)
    pad_y = max(4.0, float(page_rect.height) * 0.008)
    # Printed running heads/folios normally live in the outer 2.5% bands.  A
    # figure crop never crosses those bands, even if the model bbox is loose.
    safe_top = page_rect.y0 + page_rect.height * 0.025
    safe_bottom = page_rect.y1 - page_rect.height * 0.025
    clip = _refine_pdf_figure_clip(page, bbox)
    if clip is None:
        clip = fitz.Rect(
            max(page_rect.x0, page_rect.x0 + nx0 * page_rect.width - pad_x),
            max(safe_top, page_rect.y0 + ny0 * page_rect.height - pad_y),
            min(page_rect.x1, page_rect.x0 + nx1 * page_rect.width + pad_x),
            min(safe_bottom, page_rect.y0 + ny1 * page_rect.height + pad_y),
        )
    clip_area = max(0.0, float(clip.width * clip.height))
    page_area = max(1.0, float(page_rect.width * page_rect.height))
    if clip.width <= 0 or clip.height <= 0 or clip_area / page_area > 0.92:
        return None, None
    pixmap = page.get_pixmap(clip=clip, dpi=max(240, int(dpi)), alpha=False)
    data = pixmap.tobytes("png")
    return (data, clip) if data else (None, None)


def _preserve_ocr_resources(job: dict, raw_tex: str, project_dir: Path) -> dict:
    """把 OCR ``includegraphics`` 占位绑定到原上传中的真实图片。

    Codex 结构化 bbox 是首选：它被映射回原 PDF 坐标并以高 DPI 重新栅格化，
    因此纯矢量图也能保留。无 bbox 的旧 API 输出只在版面候选或嵌入图数量
    能与引用唯一对应时才导入。源页只另存为审阅预览，绝不冒充局部插图。
    """
    references, unsupported = _ocr_image_references(raw_tex)
    result = {
        "assets": [],
        "source_pages": [],
        "formula_crops": [],
        "unresolved": list(unsupported),
        "errors": [],
        "page_records": _ocr_manifest_page_records(job),
    }
    project_dir = project_dir.resolve()
    formula_crops, formula_bytes = _preserve_formula_crops(
        job, project_dir, MAX_PRESERVED_OCR_ASSET_BYTES
    )
    result["formula_crops"] = formula_crops
    if not references:
        preview_pages = job.get("selected_pages") or sorted((job.get("pages") or {}).keys())
        previews, _used = _preserve_source_page_previews(
            job,
            project_dir,
            preview_pages,
            max(0, MAX_PRESERVED_OCR_ASSET_BYTES - formula_bytes),
        )
        result["source_pages"] = previews
        result["total_bytes"] = formula_bytes + _used
        return result
    source_type = str(job.get("source_type") or "")
    target = Path(str((
        job.get("visual_target")
        if source_type == "images"
        else job.get("target")
    ) or ""))
    if not target.is_file():
        result["errors"].append(
            "原始上传文件已不可用；源页预览仅供审阅，不会冒充插图"
        )

    extracted: dict[str, tuple[bytes, str, int]] = {}
    extracted_info: dict[str, dict] = {}
    if target.is_file() and job.get("source_type") == "image":
        # A page screenshot is still a page, not automatically the figure in it.
        # Crop it only when structured vision supplied a validated local bbox.
        if len(references) == 1 and references[0]["source_page"] == 1:
            reference = references[0]
            bbox = _ocr_figure_bbox(job, reference)
            image_document = None
            if bbox is not None:
                try:
                    import fitz

                    image_document = fitz.open(str(target))
                    data, clip = _pdf_clip_from_normalized_bbox(
                        image_document[0], bbox, dpi=300,
                    )
                    if data and clip is not None:
                        extracted[reference["path"]] = (data, ".png", 1)
                        extracted_info[reference["path"]] = {
                            "kind": "bbox_crop",
                            **bbox,
                            "render_dpi": 300,
                        }
                except Exception:  # noqa: BLE001 - unresolved is the safe result
                    pass
                finally:
                    if image_document is not None:
                        image_document.close()
    elif target.is_file() and source_type in {"pdf", "images"}:
        document = None
        try:
            import fitz

            document = fitz.open(str(target))
            by_page: dict[int, list[dict]] = {}
            for reference in references:
                by_page.setdefault(reference["source_page"], []).append(reference)
            for page_no, page_references in by_page.items():
                if page_no < 1 or page_no > int(document.page_count):
                    continue
                page = document[page_no - 1]
                # 1. 结构化 bbox 直接回到原 PDF 页面裁切；不依赖 xref，
                #    因而矢量线条、节点和文字标签都会被高 DPI 栅格化。
                for reference in page_references:
                    bbox = _ocr_figure_bbox(job, reference)
                    if bbox is None:
                        continue
                    try:
                        data, clip = _pdf_clip_from_normalized_bbox(page, bbox, dpi=300)
                    except Exception:  # noqa: BLE001
                        data, clip = None, None
                    if not data or clip is None:
                        continue
                    extracted[reference["path"]] = (
                        data, ".png", reference["index"],
                    )
                    extracted_info[reference["path"]] = {
                        "kind": "bbox_crop",
                        **bbox,
                        "pdf_clip_points": [
                            round(float(clip.x0), 3), round(float(clip.y0), 3),
                            round(float(clip.x1), 3), round(float(clip.y1), 3),
                        ],
                        "render_dpi": 300,
                    }

                remaining_references = [
                    reference for reference in page_references
                    if reference["path"] not in extracted
                ]
                if not remaining_references:
                    continue

                # 2. 旧视觉 API 没有 bbox 时，只接受与剩余引用数量完全一致的
                #    局部版面候选。任何整页背景、横跨正文的大框都被排除。
                clipped: list[tuple[bytes, object]] = []
                try:
                    page_rect = page.rect
                    page_area = max(1.0, float(page_rect.width * page_rect.height))
                    image_boxes = []
                    for block in (page.get_text("dict") or {}).get("blocks", []):
                        if int(block.get("type", 0)) == 1 and block.get("bbox"):
                            box = fitz.Rect(block["bbox"])
                            area = max(0.0, float(box.width * box.height))
                            if box.width < 36 or box.height < 24 or area < 1200:
                                continue
                            # 扫描版 PDF 往往只有一张整页背景图；它不能冒充
                            # OCR 生成的局部插图引用。
                            if area / page_area > 0.72:
                                continue
                            image_boxes.append(box)
                    drawing_boxes = []
                    cluster_drawings = getattr(page, "cluster_drawings", None)
                    if callable(cluster_drawings):
                        drawing_boxes.extend(fitz.Rect(box) for box in cluster_drawings())
                    filtered_drawings = []
                    for box in drawing_boxes:
                        area = max(0.0, float(box.width * box.height))
                        if box.width < 36 or box.height < 24 or area < 1200:
                            continue
                        # 扫描版 PDF 的整页背景不是“页面中的插图”，不能整页回填。
                        if area / page_area > 0.72:
                            continue
                        # 彩色提示框、整段 boxed text 等页面装饰不是插图。它们通常
                        # 横跨正文且高度也很大；之前会被误配给后面真正的图。
                        if (
                            box.width / max(1.0, float(page_rect.width)) > 0.68
                            and box.height / max(1.0, float(page_rect.height)) > 0.08
                        ):
                            continue
                        duplicate = False
                        for previous in filtered_drawings:
                            intersection = box & previous
                            union = area + previous.width * previous.height - (
                                intersection.width * intersection.height
                            )
                            if union > 0 and intersection.width * intersection.height / union > 0.75:
                                duplicate = True
                                break
                        if not duplicate:
                            filtered_drawings.append(box)

                    # 同一行的多个矢量图块既可能对应多个并排引用（0.4\linewidth
                    # + 0.4\linewidth），也可能共同组成一个宽图（0.8\linewidth）。
                    # 按引用的宽度提示保守决定逐个裁切还是合并裁切。
                    rows = []
                    for box in sorted(
                        filtered_drawings,
                        key=lambda item: (round(item.y0, 2), round(item.x0, 2)),
                    ):
                        placed = False
                        for row in rows:
                            row_y0 = min(item.y0 for item in row)
                            row_y1 = max(item.y1 for item in row)
                            overlap = max(0.0, min(row_y1, box.y1) - max(row_y0, box.y0))
                            if overlap >= 0.3 * min(row_y1 - row_y0, box.height):
                                row.append(box)
                                placed = True
                                break
                        if not placed:
                            rows.append([box])

                    box_groups = [([box], box.y0) for box in image_boxes]
                    box_groups.extend((row, min(box.y0 for box in row)) for row in rows)
                    box_groups.sort(key=lambda item: item[1])
                    selected_boxes = []
                    reference_offset = 0
                    for group, _y0 in box_groups:
                        if reference_offset >= len(remaining_references):
                            break
                        group.sort(key=lambda box: box.x0)
                        small_refs = 0
                        for reference in remaining_references[reference_offset:]:
                            hint = reference.get("width_hint")
                            if hint is None or hint > 0.55:
                                break
                            small_refs += 1
                        if len(group) > 1 and small_refs >= len(group):
                            selected_boxes.extend(group)
                            reference_offset += len(group)
                        else:
                            union = fitz.Rect(group[0])
                            for box in group[1:]:
                                union |= box
                            selected_boxes.append(union)
                            reference_offset += 1

                    for box in selected_boxes:
                        # 仅留小边距保护矢量标签，避免把附近正文带入插图。
                        padding = max(6.0, min(12.0, min(page_rect.width, page_rect.height) * 0.012))
                        box = fitz.Rect(
                            max(page_rect.x0, box.x0 - padding),
                            max(page_rect.y0, box.y0 - padding),
                            min(page_rect.x1, box.x1 + padding),
                            min(page_rect.y1, box.y1 + padding),
                        )
                        if box.width * box.height / page_area > 0.72:
                            continue
                        pixmap = page.get_pixmap(clip=box, dpi=300, alpha=False)
                        data = pixmap.tobytes("png")
                        if data:
                            clipped.append((data, box))
                except Exception:  # noqa: BLE001 - 老版 PyMuPDF 回退到 xref 提取
                    clipped = []
                if len(clipped) == len(remaining_references):
                    for reference, (data, box) in zip(remaining_references, clipped):
                        if not reference["ext"] or reference["ext"] == ".png":
                            extracted[reference["path"]] = (data, ".png", reference["index"])
                            extracted_info[reference["path"]] = {
                                "kind": "layout_crop",
                                "bbox_normalized": [
                                    round((box.x0 - page_rect.x0) / page_rect.width, 6),
                                    round((box.y0 - page_rect.y0) / page_rect.height, 6),
                                    round((box.x1 - page_rect.x0) / page_rect.width, 6),
                                    round((box.y1 - page_rect.y0) / page_rect.height, 6),
                                ],
                                "bbox_source": "pdf_layout_unique_match",
                                "render_dpi": 300,
                            }
                    continue

                # 3. 最后只在整页没有任何 bbox 裁图且 xref 与引用数严格相等
                #    时使用嵌入图；部分 zip 会把图错配给某个引用，因此禁止。
                xrefs = []
                for image in page.get_images(full=True):
                    try:
                        xref = int(image[0])
                    except (IndexError, TypeError, ValueError):
                        continue
                    if xref > 0 and xref not in xrefs:
                        xrefs.append(xref)
                if (
                    len(remaining_references) != len(page_references)
                    or len(xrefs) != len(remaining_references)
                ):
                    continue
                for reference, xref in zip(remaining_references, xrefs):
                    image = document.extract_image(xref) or {}
                    data = image.get("image")
                    extension = "." + str(image.get("ext") or "").lower().lstrip(".")
                    if not isinstance(data, bytes) or not data:
                        continue
                    if extension not in {".png", ".jpg", ".jpeg"}:
                        try:
                            data = fitz.Pixmap(document, xref).tobytes("png")
                            extension = ".png"
                        except Exception:  # noqa: BLE001 - 保守留给资源门报告
                            continue
                    if (
                        reference["ext"]
                        and _canonical_image_extension(reference["ext"])
                        != _canonical_image_extension(extension)
                    ):
                        # 不能只改扩展名伪装格式；当前提示生成的引用默认没有扩展名。
                        continue
                    extracted[reference["path"]] = (data, extension, xref)
                    extracted_info[reference["path"]] = {
                        "kind": "embedded_image_unique_match",
                    }
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(
                "无法从原 PDF 提取插图：" + type(exc).__name__
            )
        finally:
            if document is not None:
                document.close()

    total = formula_bytes
    for reference in references:
        hit = extracted.get(reference["path"])
        if hit is None:
            result["unresolved"].append(reference["path"])
            continue
        data, extension, source_index = hit
        data, extension, format_matches = _raster_for_reference(
            data, extension, reference["ext"]
        )
        if len(data) > MAX_PRESERVED_OCR_IMAGE_BYTES:
            result["unresolved"].append(reference["path"])
            result["errors"].append(f"插图过大，未导入：{reference['path']}")
            continue
        if total + len(data) > MAX_PRESERVED_OCR_ASSET_BYTES:
            result["unresolved"].append(reference["path"])
            result["errors"].append("OCR 插图总大小超过 100 MB，后续图片未导入")
            continue
        total += len(data)
        relative = reference["path"] if reference["ext"] else reference["path"] + extension
        target_path = (project_dir / Path(relative)).resolve()
        try:
            target_path.relative_to(project_dir)
        except ValueError:
            result["unresolved"].append(reference["path"])
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(data)
        asset = {
            "path": relative.replace("\\", "/"),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_page": reference["source_page"],
            "printed_page": reference["page"],
            "source_index": source_index,
            "kind": str((extracted_info.get(reference["path"]) or {}).get(
                "kind", "extracted",
            )),
            "format_matches_extension": format_matches,
        }
        asset.update({
            key: value
            for key, value in (extracted_info.get(reference["path"]) or {}).items()
            if key != "kind"
        })
        result["assets"].append(asset)
    preview_pages = [item["source_page"] for item in references]
    preview_pages.extend(job.get("selected_pages") or [])
    previews, preview_bytes = _preserve_source_page_previews(
        job,
        project_dir,
        preview_pages,
        max(0, MAX_PRESERVED_OCR_ASSET_BYTES - total),
    )
    result["source_pages"] = previews
    total += preview_bytes
    result["total_bytes"] = total
    result["unresolved"] = list(dict.fromkeys(
        str(path) for path in result["unresolved"] if str(path)
    ))
    if result["unresolved"]:
        result["errors"].append(
            f"{len(result['unresolved'])} 个插图缺少可验证的局部裁图，已标记 unresolved；"
            "OCR 源页预览仅供对照，不会冒充插图"
        )
    return result


def _ocr_bundle_bytes(job: dict, raw_tex: str) -> tuple[bytes, dict]:
    """Build a self-contained raw OCR snapshot without mutating project state."""
    verified_job = _verified_ocr_bundle_snapshot(job)
    with tempfile.TemporaryDirectory(prefix="ls-ocr-bundle-") as tmp:
        bundle_root = Path(tmp).resolve()
        resources = _preserve_ocr_resources(verified_job, raw_tex, bundle_root)
        source_sha256 = str(verified_job.get("_source_sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
            source_sha256 = ""
        raw_body = raw_tex.encode("utf-8")
        producer_identity = _stored_producer_identity(verified_job)
        exporter_identity = _runtime_provenance_identity("not-used")
        provenance = make_provenance_record(
            body=raw_body,
            verified=False,
            verification_scope=RAW_OCR_SCOPE,
            artifact_kind="raw-ocr-tex",
            app_version="unknown",
            source_sha256=source_sha256,
            raw_sha256=sha256_bytes(raw_body),
            result_sha256="unknown",
            producer_identity=producer_identity,
            exporter_identity=exporter_identity,
            raw_artifact_role="raw-ocr-tex",
            raw_artifact_path=RAW_ARTIFACT_PACKAGE_PATH,
            raw_bytes_sha256=sha256_bytes(raw_body),
            raw_normalized_text_sha256=sha256_lf_normalized_text(raw_body),
            raw_normalization_pipeline="decode-tex/newline-LF/encode-utf8",
        )
        stamped_raw = stamp_tex_provenance(raw_body, provenance)
        quality_report = assess_ocr_quality(verified_job, resources)
        source_type = str(verified_job.get("source_type") or "")
        source_total_raw = verified_job.get("source_total")
        source_total = (
            _strict_page_number(source_total_raw)
            if source_total_raw is not None
            else None
        )
        selected_start_raw = verified_job.get("selected_start")
        selected_end_raw = verified_job.get("selected_end")
        selected_start = (
            _strict_page_number(selected_start_raw)
            if selected_start_raw is not None
            else 1
        )
        selected_end = (
            _strict_page_number(selected_end_raw)
            if selected_end_raw is not None
            else selected_start
        )
        manifest = {
            "format": "latexstruct-ocr-bundle-v1",
            "source_type": source_type,
            # Very old in-memory result records did not retain this field.
            # Keep their unverified raw-result export usable without inventing
            # a PDF total; all new import snapshots require an exact integer.
            "source_total": source_total,
            "source_sha256": source_sha256,
            "status": str(verified_job.get("status") or ""),
            "selected_start": selected_start,
            "selected_end": selected_end,
            "raw_revision": int(verified_job.get("raw_revision") or 0),
            "usage_revision": int(verified_job.get("usage_revision") or 0),
            "page_revision": int(verified_job.get("page_revision") or 0),
            "pages": _ocr_manifest_page_records(verified_job),
            "run_snapshot": deepcopy(verified_job.get("ocr_run_snapshot") or {}),
            "performance_metrics": deepcopy(
                verified_job.get("performance_metrics") or {}
            ),
            "resources": resources,
            "evidence_errors": list(verified_job.get("evidence_errors") or []),
            "processing": {
                "profile": str(verified_job.get("quality_profile") or "standard"),
                "transcription_source": "full_page_visual_plus_bounded_pdf_evidence",
                "backend": str(verified_job.get("backend") or "unknown"),
                "model": str(verified_job.get("model") or ""),
                "reasoning_effort": str(verified_job.get("reasoning_effort") or ""),
                "dpi": int(verified_job.get("dpi") or 0),
                "quality_tier": str(
                    (verified_job.get("ocr_run_snapshot") or {}).get("quality_tier")
                    or verified_job.get("quality_tier")
                    or ""
                ),
                "batch_size": int(
                    (verified_job.get("ocr_run_snapshot") or {}).get("batch_size") or 0
                ),
                "concurrency_limit": int(
                    (verified_job.get("ocr_run_snapshot") or {}).get(
                        "concurrency_limit"
                    ) or 0
                ),
                "max_retries": int(
                    (verified_job.get("ocr_run_snapshot") or {}).get("max_retries") or 0
                ),
                "target_template": str(
                    verified_job.get("output_template") or "faithfulbook"
                ),
            },
            "quality_report": quality_report,
            "provenance": provenance,
        }
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ocr.tex", stamped_raw)
            archive.writestr(RAW_ARTIFACT_PACKAGE_PATH, raw_body)
            for item in [
                *(resources.get("assets") or []),
                *(resources.get("source_pages") or []),
            ]:
                relative = str(item.get("path") or "").replace("\\", "/")
                source = (bundle_root / Path(relative)).resolve()
                try:
                    source.relative_to(bundle_root)
                    data = source.read_bytes()
                except (ValueError, OSError):
                    continue
                archive.writestr(relative, data)
            archive.writestr(
                "OCR-MANIFEST.json",
                json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
            )
            archive.writestr(
                PROVENANCE_MANIFEST_NAME,
                _provenance_json_bytes(provenance),
            )
        return output.getvalue(), manifest


def _bounded_ocr_bbox(value, *, allow_line: bool = False) -> list[float]:
    """Return a finite normalized bbox or an empty list for manifest export."""
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return []
    result = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            return []
        number = float(item)
        if not math.isfinite(number) or not 0.0 <= number <= 1.0:
            return []
        result.append(round(number, 6))
    x0, y0, x1, y1 = result
    if allow_line:
        if x0 > x1 or y0 > y1 or (x0 == x1 and y0 == y1):
            return []
    elif x0 >= x1 or y0 >= y1:
        return []
    return result


def _bounded_formula_evidence(value) -> list[dict]:
    """Export at most four path-free, finite formula-crop evidence records."""
    def _points_bbox(raw) -> list[float]:
        if not isinstance(raw, (list, tuple)) or len(raw) != 4:
            return []
        values = []
        for item in raw:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                return []
            number = float(item)
            if not math.isfinite(number) or not -100_000.0 <= number <= 100_000.0:
                return []
            values.append(round(number, 3))
        if values[0] >= values[2] or values[1] >= values[3]:
            return []
        return values

    output = []
    for item in (value or [])[:4]:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("id") or "")
        target_bbox = _bounded_ocr_bbox(
            item.get("target_bbox_normalized_in_crop")
        )
        source_bbox = _points_bbox(item.get("source_bbox_points"))
        crop_bbox = _points_bbox(item.get("crop_bbox_points"))
        crop_sha256 = str(item.get("crop_sha256") or "").lower()
        dpi = item.get("dpi")
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", evidence_id)
            or not target_bbox
            or not source_bbox
            or not crop_bbox
            or source_bbox[0] < crop_bbox[0]
            or source_bbox[1] < crop_bbox[1]
            or source_bbox[2] > crop_bbox[2]
            or source_bbox[3] > crop_bbox[3]
            or not re.fullmatch(r"[0-9a-f]{64}", crop_sha256)
            or isinstance(dpi, bool)
            or not isinstance(dpi, int)
            or not 144 <= dpi <= 600
        ):
            continue
        record = {
            "id": evidence_id,
            "target_bbox_normalized_in_crop": target_bbox,
            "source_bbox_points": source_bbox,
            "crop_bbox_points": crop_bbox,
            "crop_sha256": crop_sha256,
            "dpi": dpi,
            "attached": bool(item.get("attached")),
        }
        size = item.get("image_size_pixels")
        if (
            isinstance(size, (list, tuple))
            and len(size) == 2
            and all(
                not isinstance(number, bool)
                and isinstance(number, int)
                and 1 <= number <= 100_000
                for number in size
            )
        ):
            record["image_size_pixels"] = [int(size[0]), int(size[1])]
        output.append(record)
    return output


def _prepare_page_formula_evidence(job: dict, page_no: int) -> list[dict]:
    """Detect/render publication PDF formula crops; failures intentionally propagate."""
    if (
        str(job.get("quality_profile") or "standard") != OCR_QUALITY_PUBLICATION
        or str(job.get("source_type") or "") != "pdf"
        or not callable(getattr(
            job.get("client"), "chat_vision_structured_images_bytes", None,
        ))
    ):
        return []
    from ..core.ocrformula import (
        DEFAULT_FORMULA_DPI,
        FormulaDetectionConfig,
        detect_pdf_formula_regions,
        render_pdf_formula_evidence,
        target_bbox_normalized,
    )

    source_sha256 = str(job.get("_source_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise RuntimeError("出版审校缺少可验证的源 PDF 哈希")
    regions = detect_pdf_formula_regions(
        job["target"],
        [page_no],
        config=FormulaDetectionConfig(max_regions_per_page=4),
    )
    if len(regions) > 4:
        raise RuntimeError(f"第 {page_no} 页公式局部证据超过 4 张上限")
    if not regions:
        return []
    evidence = render_pdf_formula_evidence(
        job["target"],
        source_sha256,
        regions,
        Path(job["dir"]) / "formula-evidence",
        dpi=DEFAULT_FORMULA_DPI,
    )
    if len(evidence) != len(regions) or len(evidence) > 4:
        raise RuntimeError(f"第 {page_no} 页公式局部证据生成不完整")
    return [
        {
            "id": item.region.region_id,
            "target_bbox_normalized_in_crop": list(target_bbox_normalized(item)),
            "source_bbox_points": list(item.region.bbox_points),
            "crop_bbox_points": list(item.crop_bbox_points),
            "crop_sha256": item.image_sha256,
            "dpi": int(item.dpi),
            "image_size_pixels": list(item.image_size_pixels),
            "crop_path": str(item.crop_path),
        }
        for item in evidence
    ]


def _ocr_manifest_page_records(job: dict) -> list[dict]:
    """Serialize only bounded OCR evidence metadata, never the text hint itself."""
    records = []
    for raw_page, page in sorted(
        (job.get("pages") or {}).items(),
        key=lambda item: int(item[0]),
    ):
        try:
            page_no = int(raw_page)
        except (TypeError, ValueError):
            continue
        figures = []
        for figure in page.get("figures") or []:
            if not isinstance(figure, dict):
                continue
            record = {
                "path": str(figure.get("path") or ""),
                "index": int(figure.get("index") or 0),
                "bbox_normalized": list(figure.get("bbox_normalized") or []),
                "bbox_pixels": list(figure.get("bbox_pixels") or []),
                "image_size_pixels": list(
                    figure.get("image_size_pixels")
                    or page.get("image_size_pixels")
                    or []
                ),
                "source": str(figure.get("source") or ""),
            }
            display_width = figure.get("display_width_ratio")
            if (
                not isinstance(display_width, bool)
                and isinstance(display_width, (int, float))
                and 0.25 <= float(display_width) <= 1.0
            ):
                record["display_width_ratio"] = round(float(display_width), 2)
            figures.append(record)
        quality_flags = []
        for flag in page.get("quality_flags") or []:
            if not isinstance(flag, dict):
                continue
            quality_record = {
                "type": str(flag.get("type") or "")[:80],
                "status": str(flag.get("status") or "")[:80],
                "needs_review": bool(flag.get("needs_review")),
                "left": str(flag.get("left") or "")[:80],
                "right": str(flag.get("right") or "")[:80],
                "reference_operator": str(flag.get("reference_operator") or "")[:8],
                "visual_operator": str(flag.get("visual_operator") or "")[:8],
                "initial_page_visual_operator": str(
                    flag.get("initial_page_visual_operator") or ""
                )[:8],
                "local_visual_operator": str(
                    flag.get("local_visual_operator") or ""
                )[:8],
                "evidence_id": str(flag.get("evidence_id") or "")[:100],
                "crop_bbox_normalized": list(
                    flag.get("crop_bbox_normalized") or []
                )[:4],
                "crop_size_pixels": list(flag.get("crop_size_pixels") or [])[:2],
                "crop_sha256": str(flag.get("crop_sha256") or "")[:64],
                "verifier": str(flag.get("verifier") or "")[:80],
            }
            for key in (
                "occurrence",
                "source_center_glyph_count",
                "source_left_rule_glyph_count",
                "source_right_rule_glyph_count",
                "active_wr_count",
                "active_rule_count",
            ):
                if key in flag:
                    quality_record[key] = max(0, int(flag.get(key) or 0))
            if "local_visual_status" in flag:
                quality_record["local_visual_status"] = str(
                    flag.get("local_visual_status") or ""
                )[:80]
            if "line_bbox_normalized" in flag:
                quality_record["line_bbox_normalized"] = list(
                    flag.get("line_bbox_normalized") or []
                )[:4]
            if "source" in flag:
                quality_record["source"] = str(flag.get("source") or "")[:80]
            if flag.get("type") == "equation_tag_integrity_evidence":
                quality_record["label"] = str(flag.get("label") or "")[:16]
                normalized = _bounded_ocr_bbox(flag.get("bbox_normalized"))
                if normalized:
                    quality_record["bbox_normalized"] = normalized
            if flag.get("type") == "framed_inset_vector_evidence":
                quality_record.update({
                    "title": str(flag.get("title") or "")[:160],
                    "position": str(flag.get("position") or "")[:20],
                    "environment": str(flag.get("environment") or "")[:40],
                    "title_font_evidence": str(
                        flag.get("title_font_evidence") or ""
                    )[:80],
                    "title_visible": bool(flag.get("title_visible", True)),
                })
                for key in (
                    "frame_bbox_normalized",
                    "model_bbox_normalized",
                    "model_bbox_pixels",
                    "title_bbox_normalized",
                ):
                    if key in flag:
                        quality_record[key] = list(flag.get(key) or [])[:4]
                edges = flag.get("edge_presence")
                if isinstance(edges, dict):
                    quality_record["edge_presence"] = {
                        edge: bool(edges.get(edge))
                        for edge in ("top", "left", "right", "bottom")
                    }
                stroke_width = flag.get("stroke_width_pt")
                if (
                    not isinstance(stroke_width, bool)
                    and isinstance(stroke_width, (int, float))
                    and 0.0 <= float(stroke_width) <= 20.0
                ):
                    quality_record["stroke_width_pt"] = round(
                        float(stroke_width), 4,
                    )
            if flag.get("type") == "footnote_structure_evidence":
                quality_record.update({
                    "marker": str(flag.get("marker") or "")[:16],
                    "rule_present": bool(flag.get("rule_present")),
                    "source_body_italic": bool(flag.get("source_body_italic")),
                    "active_body_italic": bool(flag.get("active_body_italic")),
                    "marker_font": str(flag.get("marker_font") or "")[:80],
                    "body_font": str(flag.get("body_font") or "")[:80],
                })
                for key in (
                    "source_reference_count",
                    "active_reference_count",
                    "active_body_count",
                    "body_chars",
                ):
                    if key in flag:
                        try:
                            quality_record[key] = min(
                                1_000_000, max(0, int(flag.get(key) or 0)),
                            )
                        except (TypeError, ValueError):
                            pass
                for key in ("marker_size_pt", "body_size_pt"):
                    value = flag.get(key)
                    if (
                        not isinstance(value, bool)
                        and isinstance(value, (int, float))
                        and math.isfinite(float(value))
                        and 0.0 <= float(value) <= 100.0
                    ):
                        quality_record[key] = round(float(value), 4)
                reference_bboxes = [
                    normalized
                    for normalized in (
                        _bounded_ocr_bbox(bbox)
                        for bbox in (flag.get("reference_bboxes_normalized") or [])[:8]
                    )
                    if normalized
                ]
                quality_record["reference_bboxes_normalized"] = reference_bboxes
                for source_key, target_key, allow_line in (
                    ("body_bbox_normalized", "body_bbox_normalized", False),
                    ("rule_bbox_normalized", "rule_bbox_normalized", True),
                    ("crop_bbox_normalized", "crop_bbox_normalized", False),
                ):
                    normalized = _bounded_ocr_bbox(
                        flag.get(source_key), allow_line=allow_line,
                    )
                    if normalized:
                        quality_record[target_key] = normalized
                    else:
                        quality_record.pop(target_key, None)
                body_hash = str(flag.get("body_sha256") or "").lower()
                if re.fullmatch(r"[0-9a-f]{64}", body_hash):
                    quality_record["body_sha256"] = body_hash
            quality_flags.append(quality_record)
        equation_tag_source_evidence = []
        for region in (page.get("equation_tag_regions") or [])[:32]:
            if not isinstance(region, dict):
                continue
            label = str(region.get("label_hint") or "")[:16]
            bbox = _bounded_ocr_bbox(region.get("bbox_normalized"))
            if not re.fullmatch(r"[0-9]{1,4}[A-Za-z]?", label) or not bbox:
                continue
            equation_tag_source_evidence.append({
                "evidence_id": str(region.get("evidence_id") or "")[:100],
                "label_hint": label,
                "bbox_normalized": bbox,
                "source": str(region.get("source") or "")[:80],
            })
        footnote_source_evidence = []
        for region in (page.get("footnote_regions") or [])[:8]:
            if not isinstance(region, dict):
                continue
            body_bbox = _bounded_ocr_bbox(region.get("definition_bbox_normalized"))
            references = [
                normalized
                for normalized in (
                    _bounded_ocr_bbox(bbox)
                    for bbox in (region.get("reference_bboxes_normalized") or [])[:8]
                )
                if normalized
            ]
            if not body_bbox or not references:
                continue
            font_evidence = (
                region.get("font_evidence")
                if isinstance(region.get("font_evidence"), dict) else {}
            )
            source_record = {
                "evidence_id": str(region.get("evidence_id") or "")[:100],
                "marker": str(region.get("marker_hint") or "")[:16],
                "source_reference_count": min(
                    12, max(0, int(region.get("reference_count") or 0)),
                ),
                "reference_bboxes_normalized": references,
                "body_bbox_normalized": body_bbox,
                "rule_present": bool(region.get("rule_present")),
                "body_italic": bool(font_evidence.get("body_italic")),
                "marker_font": ",".join(
                    str(item) for item in (font_evidence.get("reference_fonts") or [])[:8]
                )[:80],
                "body_font": ",".join(
                    str(item) for item in (font_evidence.get("note_fonts") or [])[:8]
                )[:80],
                "source": str(region.get("source") or "")[:80],
            }
            rule_bbox = _bounded_ocr_bbox(
                region.get("rule_bbox_normalized"), allow_line=True,
            )
            if rule_bbox:
                source_record["rule_bbox_normalized"] = rule_bbox
            for source_key, target_key in (
                ("reference_pt", "marker_size_pt"),
                ("note_body_pt", "body_size_pt"),
            ):
                value = font_evidence.get(source_key)
                if (
                    not isinstance(value, bool)
                    and isinstance(value, (int, float))
                    and math.isfinite(float(value))
                    and 0.0 <= float(value) <= 100.0
                ):
                    source_record[target_key] = round(float(value), 4)
            footnote_source_evidence.append(source_record)
        visual_sha256 = str(page.get("visual_input_sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", visual_sha256):
            visual_sha256 = ""
        telemetry = {
            "page_id": str(page.get("page_id") or "")[:80],
            "status": str(
                page.get("v2_status") or page.get("status") or "pending"
            )[:40],
            "task_index": max(0, int(page.get("task_index") or 0)),
            "dpi": max(0, int(page.get("dpi") or 0)),
            "model": str(page.get("model") or "")[:160],
            "call_index": max(0, int(page.get("call_index") or 0)),
            "batch_call": bool(page.get("batch_call")),
            "batch_id": str(page.get("batch_id") or "")[:80],
            "started_at": str(page.get("started_at") or "")[:80],
            "ended_at": str(page.get("ended_at") or "")[:80],
            "elapsed_seconds": page.get("elapsed_seconds"),
            "retry_count": max(0, int(page.get("retry_count") or 0)),
            "raw_response_sha256": str(
                page.get("raw_response_sha256") or ""
            )[:64],
            "tex_sha256": str(page.get("tex_sha256") or "")[:64],
            "usage": deepcopy(page.get("usage_v2") or {}),
            "quality_issues": deepcopy(page.get("quality_issues_v2") or [])[:32],
            "unresolved_regions": deepcopy(
                page.get("unresolved_regions_v2") or []
            )[:32],
            "terminal_error": str(page.get("terminal_error") or "")[:500],
        }
        if not isinstance(telemetry["elapsed_seconds"], (int, float)):
            telemetry["elapsed_seconds"] = None
        records.append({
            "source_page": page_no,
            "status": str(page.get("status") or "pending"),
            "attempts": int(page.get("attempts") or 0),
            "low_confidence": bool(page.get("low_conf")),
            "image_size_pixels": list(page.get("image_size_pixels") or []),
            "visual_input_sha256": visual_sha256,
            "transcription_source": "full_page_visual_plus_bounded_pdf_evidence",
            "reference_text": {
                "chars": int(page.get("text_hint_chars") or 0),
                "sha256": str(page.get("text_hint_sha256") or ""),
            },
            "figures": figures,
            "formula_visual_evidence": _bounded_formula_evidence(
                page.get("formula_evidence") or []
            ),
            "equation_tag_source_evidence": equation_tag_source_evidence,
            "equation_tag_extraction_status": str(
                page.get("equation_tag_extraction_status") or "unknown"
            )[:32],
            "footnote_source_evidence": footnote_source_evidence,
            "quality_flags": quality_flags,
            "needs_review": bool(
                page.get("needs_review")
                or any(flag.get("needs_review") for flag in quality_flags)
            ),
            "telemetry": telemetry,
        })
    return records


def _snapshot_ocr_bundle_job(
    job: dict,
    *,
    v2_records: list[OcrPageRecord] | None = None,
) -> dict:
    """Copy only immutable/bundle-relevant OCR fields while holding the job lock."""
    snapshot = {
        "source_type": str(job.get("source_type") or ""),
        # The original document total is distinct from selected_pages.  This
        # field was accidentally omitted before v1.2.9, causing every imported
        # multi-page PDF to be persisted as source_pages=1 even though the exact
        # hash-bound PDF and selected range were retained.
        # Keep the frozen value losslessly.  The persistence boundary below
        # validates type/range and must be able to reject ``True`` or a missing
        # total instead of silently turning either into a plausible page count.
        "source_total": deepcopy(job.get("source_total")),
        "source_outline": deepcopy(job.get("source_outline") or []),
        "_source_sha256": str(job.get("_source_sha256") or ""),
        "_visual_source_sha256": str(job.get("_visual_source_sha256") or ""),
        "source_images": deepcopy(job.get("source_images") or []),
        "target": str(job.get("target") or ""),
        "visual_target": str(job.get("visual_target") or ""),
        "status": str(job.get("status") or ""),
        "quality_profile": str(job.get("quality_profile") or "standard"),
        "backend": str(job.get("backend") or "unknown"),
        "model": str(job.get("model") or ""),
        "reasoning_effort": str(job.get("reasoning_effort") or ""),
        "created": job.get("created"),
        "producer_identity": deepcopy(
            job.get("producer_identity")
            if isinstance(job.get("producer_identity"), dict)
            else _unknown_producer_identity()
        ),
        "dpi": int(job.get("dpi") or 0),
        "output_template": str(job.get("output_template") or "faithfulbook"),
        "selected_start": deepcopy(job.get("selected_start")),
        "selected_end": deepcopy(job.get("selected_end")),
        "selected_pages": deepcopy(job.get("selected_pages") or []),
        "raw_revision": int(job.get("raw_revision") or 0),
        "usage_revision": int(job.get("usage_revision") or 0),
        "page_revision": int(job.get("page_revision") or 0),
        "pages": {
            page_no: {
                "png": str(
                    page.get("persisted_visual_path") or page.get("png") or ""
                ),
                "figures": deepcopy(page.get("figures") or []),
                "image_size_pixels": list(page.get("image_size_pixels") or []),
                "visual_input_sha256": str(page.get("visual_input_sha256") or ""),
                "visual_input_persisted": page.get("visual_input_persisted"),
                # Private import snapshot retains crop_path long enough to copy
                # exact bytes into the project.  Public manifests still pass
                # through _bounded_formula_evidence and never expose that path.
                "formula_evidence": deepcopy(page.get("formula_evidence") or []),
                "text_hint_chars": int(page.get("text_hint_chars") or 0),
                "text_hint_sha256": str(page.get("text_hint_sha256") or ""),
                "equation_tag_regions": deepcopy(
                    page.get("equation_tag_regions") or []
                ),
                "equation_tag_extraction_status": str(
                    page.get("equation_tag_extraction_status") or "unknown"
                ),
                "footnote_regions": deepcopy(page.get("footnote_regions") or []),
                "quality_flags": deepcopy(page.get("quality_flags") or []),
                "needs_review": bool(page.get("needs_review")),
                "status": str(page.get("status") or "pending"),
                "low_conf": bool(page.get("low_conf")),
                "error": str(page.get("error") or ""),
                "attempts": int(page.get("attempts") or 0),
            }
            for page_no, page in (job.get("pages") or {}).items()
        },
    }
    runtime_snapshot = job.get("_v2_snapshot")
    if runtime_snapshot is not None:
        runtime_source_hash = str(runtime_snapshot.source_sha256 or "").lower()
        if re.fullmatch(r"[0-9a-f]{64}", runtime_source_hash):
            snapshot["_source_sha256"] = runtime_source_hash
    if v2_records is None:
        runtime_store = job.get("_v2_store")
        if isinstance(runtime_store, OcrRunStore) and runtime_snapshot is not None:
            try:
                v2_records = runtime_store.list_records(runtime_snapshot.run_id)
            except (OcrStoreError, OSError, ValueError):
                v2_records = []
    for record in v2_records or []:
        page = snapshot["pages"].get(
            record.source_page,
            snapshot["pages"].get(str(record.source_page)),
        )
        if not isinstance(page, dict):
            continue
        page["attempts"] = max(
            int(page.get("attempts") or 0),
            int(record.call_index or 0),
        )
        if len(record.image_size_pixels) == 2:
            page["image_size_pixels"] = list(record.image_size_pixels)
        if re.fullmatch(r"[0-9a-f]{64}", str(record.image_sha256 or "")):
            page["visual_input_sha256"] = record.image_sha256
        page.update({
            "page_id": record.page_id,
            "v2_status": record.status.value,
            "task_index": record.task_index,
            "dpi": record.dpi,
            "model": record.model,
            "call_index": record.call_index,
            "batch_call": record.batch_call,
            "batch_id": record.batch_id,
            "raw_response_sha256": record.raw_response_sha256,
            "tex_sha256": record.tex_sha256,
            "started_at": record.started_at,
            "ended_at": record.ended_at,
            "elapsed_seconds": record.elapsed_seconds,
            "retry_count": record.retry_count,
            "quality_issues_v2": thaw_json(record.quality_issues),
            "unresolved_regions_v2": thaw_json(record.unresolved_regions),
            "usage_v2": thaw_json(record.usage),
            "terminal_error": record.error_reason,
        })
    if runtime_snapshot is not None:
        snapshot["ocr_run_snapshot"] = runtime_snapshot.to_dict()
        if v2_records is not None:
            snapshot["performance_metrics"] = ocr_progress_metrics(
                runtime_snapshot,
                v2_records,
                terminal_epoch=job.get("terminal_epoch"),
                merge_complete=bool(job.get("raw_ready")),
                raw_frozen=bool(job.get("raw_frozen")),
                compile_status=job.get("compile_status") or None,
                rate_limited=bool(job.get("rate_limited")),
                concurrency_limit=int(job.get("current_concurrency_limit") or 0) or None,
            )
    return snapshot


def _verified_ocr_bundle_snapshot(job: dict) -> dict:
    """Revalidate frozen source/page pixels before claiming OCR provenance.

    Page paths are deliberately kept private.  A missing or changed file clears
    the copied provenance hash so ``assess_ocr_quality`` fails publication mode,
    while the caller can still offer the raw, explicitly unverified snapshot.
    """
    from ..ocr import image_pixel_size

    snapshot = deepcopy(job)
    evidence_errors: list[str] = []
    expected_source_hash = str(snapshot.get("_source_sha256") or "").lower()
    source_path = Path(str(snapshot.get("target") or ""))
    try:
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_source_hash) is None
            or source_path.is_symlink()
            or not source_path.is_file()
        ):
            raise ValueError("source unavailable")
        actual_source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if not hmac.compare_digest(expected_source_hash, actual_source_hash):
            raise ValueError("source changed")
    except (OSError, ValueError):
        snapshot["_source_sha256"] = ""
        evidence_errors.append("原始 OCR 输入已丢失或与冻结哈希不一致")

    pages = snapshot.get("pages") if isinstance(snapshot.get("pages"), dict) else {}
    selected = snapshot.get("selected_pages") or list(pages)
    for raw_page_no in selected:
        try:
            page_no = int(raw_page_no)
        except (TypeError, ValueError):
            continue
        page = pages.get(page_no, pages.get(str(page_no)))
        if not isinstance(page, dict) or str(page.get("status") or "") != "done":
            continue
        expected_hash = str(page.get("visual_input_sha256") or "").lower()
        page_path = Path(str(page.get("png") or ""))
        try:
            if (
                re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
                or page_path.is_symlink()
                or not page_path.is_file()
            ):
                raise ValueError("page image unavailable")
            data = page_path.read_bytes()
            if _raster_extension(data) not in {".png", ".jpg"}:
                raise ValueError("page image format invalid")
            if not hmac.compare_digest(expected_hash, hashlib.sha256(data).hexdigest()):
                raise ValueError("page image changed")
            expected_size = [int(value) for value in (page.get("image_size_pixels") or [])]
            if len(expected_size) != 2 or list(image_pixel_size(data)) != expected_size:
                raise ValueError("page image dimensions changed")
        except (OSError, TypeError, ValueError):
            page["visual_input_sha256"] = ""
            page["visual_input_persisted"] = False
            evidence_errors.append(f"第 {page_no} 页视觉输入已丢失或被改变")
        else:
            page["visual_input_persisted"] = True
    snapshot["evidence_errors"] = evidence_errors[:100]
    return snapshot


def _preserve_original_ocr_source(job: dict, project_dir: Path) -> dict:
    """Atomically retain the immutable upload used by OCR for later audits."""
    source = Path(str(job.get("target") or ""))
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("原始 OCR 文件已不可用，无法建立可追溯项目")
    data = source.read_bytes()
    if not data or len(data) > MAX_OCR_UPLOAD_BYTES:
        raise RuntimeError("原始 OCR 文件为空或超过保存上限")
    actual_hash = hashlib.sha256(data).hexdigest()
    expected_hash = str(job.get("_source_sha256") or "").lower()
    has_frozen_hash = re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None
    if has_frozen_hash and not hmac.compare_digest(expected_hash, actual_hash):
        raise RuntimeError("原始 OCR 文件在识别后发生改变，哈希校验失败")
    if (
        not has_frozen_hash
        and str(job.get("quality_profile") or "") == OCR_QUALITY_PUBLICATION
    ):
        raise RuntimeError("原始 OCR 文件缺少启动时冻结的哈希，不能建立出版审校证据")
    source_type = str(job.get("source_type") or "")
    source_images: list[dict] = []
    visual_source_record: dict | None = None
    visual_data = b""
    if source_type == "pdf":
        if not data.startswith(b"%PDF-"):
            raise RuntimeError("原始 OCR PDF 内容已损坏")
        from ..core.ai import LLMError
        from ..ocr import pdf_page_count_bytes

        try:
            source_pages = pdf_page_count_bytes(data)
        except (LLMError, ValueError) as exc:
            raise RuntimeError("原始 OCR PDF 页数无法由冻结字节复算") from exc
        frozen_total = job.get("source_total")
        try:
            frozen_total = _strict_page_number(frozen_total)
        except ValueError:
            raise RuntimeError("原始 OCR PDF 缺少有效的冻结总页数") from None
        if frozen_total != source_pages:
            raise RuntimeError("原始 OCR PDF 页数与启动快照不一致")
        extension = ".pdf"
    elif source_type == "image":
        extension = _raster_extension(data)
        source_pages = 1
        frozen_total = job.get("source_total")
        try:
            frozen_total = _strict_page_number(frozen_total)
        except ValueError:
            raise RuntimeError("原始 OCR 图片缺少有效的冻结页数") from None
        if frozen_total != 1:
            raise RuntimeError("原始 OCR 图片冻结页数无效")
    elif source_type == "images":
        visual_path = Path(str(job.get("visual_target") or ""))
        if visual_path.is_symlink() or not visual_path.is_file():
            raise RuntimeError("多图片 OCR 的派生视觉 PDF 已不可用")
        visual_data = visual_path.read_bytes()
        expected_visual_hash = str(job.get("_visual_source_sha256") or "").lower()
        if (
            not visual_data.startswith(b"%PDF-")
            or re.fullmatch(r"[0-9a-f]{64}", expected_visual_hash) is None
            or not hmac.compare_digest(
                expected_visual_hash, hashlib.sha256(visual_data).hexdigest()
            )
        ):
            raise RuntimeError("多图片 OCR 的派生视觉 PDF 哈希校验失败")
        try:
            manifest = verify_multi_image_source(
                data,
                expected_images=job.get("source_images") or (),
                expected_visual_sha256=expected_visual_hash,
            )
            from ..ocr import pdf_page_count_bytes

            visual_pages = pdf_page_count_bytes(visual_data)
        except Exception as exc:
            raise RuntimeError("多图片 OCR 原始字节、顺序或派生关系校验失败") from exc
        source_images = [dict(item) for item in manifest.get("images") or ()]
        source_pages = len(source_images)
        frozen_total = job.get("source_total")
        try:
            frozen_total = _strict_page_number(frozen_total)
        except ValueError:
            raise RuntimeError("多图片 OCR 缺少有效的冻结总页数") from None
        if frozen_total != source_pages or visual_pages != source_pages:
            raise RuntimeError("多图片 OCR 页数与不可变来源清单不一致")
        extension = ".zip"
        visual_source_record = {
            "available": True,
            "path": "ocr-visual-source.pdf",
            "bytes": len(visual_data),
            "sha256": expected_visual_hash,
            "page_count": visual_pages,
            "is_original_upload": False,
            "derivation_id": MULTI_IMAGE_DERIVATION_ID,
            "derived_from_source_sha256": actual_hash,
        }
    else:
        raise RuntimeError("原始 OCR 文件类型未知")
    frozen_start = job.get("selected_start")
    frozen_end = job.get("selected_end")
    try:
        selected_start = _strict_page_number(frozen_start)
        selected_end = _strict_page_number(frozen_end)
    except ValueError:
        raise RuntimeError("原始 OCR 冻结页范围无效") from None
    if (
        selected_start < 1
        or selected_start > selected_end
        or selected_end > source_pages
    ):
        raise RuntimeError("原始 OCR 冻结页范围超出源文件")
    frozen_selected_pages = job.get("selected_pages")
    if not isinstance(frozen_selected_pages, (list, tuple)) or any(
        isinstance(page, bool) for page in frozen_selected_pages
    ):
        raise RuntimeError("原始 OCR 冻结页集合无效")
    try:
        selected_pages = [_strict_page_number(page) for page in frozen_selected_pages]
    except ValueError:
        raise RuntimeError("原始 OCR 冻结页集合无效") from None
    if selected_pages != list(range(selected_start, selected_end + 1)):
        raise RuntimeError("原始 OCR 冻结页集合与起止范围不一致")

    destination = (project_dir / f"ocr-source{extension}").resolve()
    destination.relative_to(project_dir.resolve())
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    visual_destination = (
        (project_dir / "ocr-visual-source.pdf").resolve()
        if visual_source_record is not None
        else None
    )
    visual_temporary = (
        visual_destination.with_name(
            f".{visual_destination.name}.{uuid.uuid4().hex}.tmp"
        )
        if visual_destination is not None
        else None
    )
    committed = False
    try:
        with open(temporary, "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        stored = destination.read_bytes()
        if stored != data:
            raise RuntimeError("原始 OCR 文件落盘校验失败")
        if visual_destination is not None and visual_temporary is not None:
            visual_destination.relative_to(project_dir.resolve())
            with open(visual_temporary, "xb") as stream:
                stream.write(visual_data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(visual_temporary, visual_destination)
            if visual_destination.read_bytes() != visual_data:
                raise RuntimeError("多图片 OCR 派生视觉 PDF 落盘校验失败")
        committed = True
    finally:
        if temporary.exists():
            temporary.unlink()
        if visual_temporary is not None and visual_temporary.exists():
            visual_temporary.unlink()
        if not committed and destination.exists():
            destination.unlink()
        if not committed and visual_destination is not None and visual_destination.exists():
            visual_destination.unlink()
    result = {
        "available": True,
        "path": destination.name,
        "bytes": len(data),
        "sha256": actual_hash,
        "source_type": source_type,
        "source_pages": source_pages,
        "page_count_schema": OCR_SOURCE_PAGE_COUNT_SCHEMA,
        "page_count_source": "host_reparsed_hash_bound_source",
        "selected_start": selected_start,
        "selected_end": selected_end,
        "immutable_evidence": has_frozen_hash,
        "reason": "" if has_frozen_hash else "legacy_job_without_frozen_hash",
    }
    if source_images:
        result["source_images"] = source_images
    if visual_source_record is not None:
        result["visual_source"] = visual_source_record
    return result


def _verified_ocr_source_bytes(
    project_dir: Path,
    source_info: dict,
    *,
    required: bool,
) -> tuple[str, bytes, dict] | None:
    """Return a hash-bound project OCR source, never an unchecked local path."""
    from ..core.project import safe_project_relpath

    if not isinstance(source_info, dict) or not source_info.get("available"):
        if required:
            raise ValueError("OCR 原始来源证据缺失，已阻止出版审校工程导出")
        return None
    if required and source_info.get("immutable_evidence") is not True:
        raise ValueError("OCR 原始来源未绑定启动时哈希，已阻止出版审校工程导出")
    rel = safe_project_relpath(str(source_info.get("path") or ""))
    if not rel.startswith("ocr-source."):
        raise ValueError("OCR 原始来源路径无效")
    root = project_dir.resolve()
    path = root / Path(rel)
    if path.is_symlink():
        raise ValueError("OCR 原始来源不能是符号链接")
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
        data = resolved.read_bytes()
    except (ValueError, OSError):
        raise ValueError("OCR 原始来源文件丢失") from None
    expected_size = source_info.get("bytes")
    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size != len(data)
    ):
        raise ValueError("OCR 原始来源大小校验失败")
    expected_hash = str(source_info.get("sha256") or "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None or not hmac.compare_digest(
        expected_hash,
        hashlib.sha256(data).hexdigest(),
    ):
        raise ValueError("OCR 原始来源哈希校验失败")
    source_type = str(source_info.get("source_type") or "")
    if source_type == "pdf":
        if not data.startswith(b"%PDF-") or not rel.lower().endswith(".pdf"):
            raise ValueError("OCR 原始 PDF 格式校验失败")
    elif source_type == "image":
        detected = _raster_extension(data)
        if detected not in {".png", ".jpg"} or _canonical_image_extension(
            Path(rel).suffix
        ) != detected:
            raise ValueError("OCR 原始图片格式校验失败")
    elif source_type == "images":
        if not rel.lower().endswith(".zip"):
            raise ValueError("OCR 多图片原始来源必须是清单化 ZIP")
        visual = source_info.get("visual_source")
        if not isinstance(visual, dict) or visual.get("is_original_upload") is not False:
            raise ValueError("OCR 多图片派生视觉来源记录缺失")
        visual_rel = safe_project_relpath(str(visual.get("path") or ""))
        visual_path = (root / Path(visual_rel)).resolve()
        try:
            visual_path.relative_to(root)
            visual_data = visual_path.read_bytes()
        except (OSError, ValueError):
            raise ValueError("OCR 多图片派生视觉 PDF 丢失") from None
        visual_sha = str(visual.get("sha256") or "").lower()
        if (
            visual_path.is_symlink()
            or not visual_data.startswith(b"%PDF-")
            or visual.get("bytes") != len(visual_data)
            or re.fullmatch(r"[0-9a-f]{64}", visual_sha) is None
            or not hmac.compare_digest(
                visual_sha, hashlib.sha256(visual_data).hexdigest()
            )
            or str(visual.get("derived_from_source_sha256") or "") != expected_hash
            or visual.get("is_original_upload") is not False
        ):
            raise ValueError("OCR 多图片派生视觉 PDF 校验失败")
        try:
            manifest = verify_multi_image_source(
                data,
                expected_images=source_info.get("source_images") or (),
                expected_visual_sha256=visual_sha,
            )
            from ..ocr import pdf_page_count_bytes

            visual_pages = pdf_page_count_bytes(visual_data)
        except Exception as exc:
            raise ValueError("OCR 多图片来源清单或派生关系校验失败") from exc
        if (
            source_info.get("source_pages") != len(manifest.get("images") or ())
            or visual.get("page_count") != visual_pages
            or visual_pages != source_info.get("source_pages")
        ):
            raise ValueError("OCR 多图片来源页数校验失败")
    else:
        raise ValueError("OCR 原始来源类型无效")
    public_record = {
        key: deepcopy(source_info.get(key))
        for key in (
            "available",
            "path",
            "bytes",
            "sha256",
            "source_type",
            "source_pages",
            "page_count_schema",
            "page_count_source",
            "legacy_page_count_repair",
            "selected_start",
            "selected_end",
            "immutable_evidence",
            "reason",
            "source_images",
            "visual_source",
        )
        if key in source_info
    }
    public_record["path"] = rel
    return rel, data, public_record


def _repair_legacy_ocr_source_page_count(
    project_dir: Path,
    project: dict,
) -> dict | None:
    """Return a repaired OCR source record only for the proven legacy defect.

    The old importer retained the exact PDF bytes, size, SHA-256 and page range,
    but dropped ``source_total`` while constructing its private import snapshot.
    ``_preserve_original_ocr_source`` then persisted the fallback value 1.  A
    repair is therefore allowed only for the legacy schema, the sentinel value
    1, a hash/size-verified PDF, and a *previously committed immutable* audit
    snapshot that independently records the same bytes as an N-page source.
    Every other mismatch remains fail-closed.
    """
    if project.get("kind") != "ocr":
        return None
    source_info = project.get("ocr_source")
    if not isinstance(source_info, dict):
        return None
    if (
        source_info.get("source_type") != "pdf"
        or source_info.get("immutable_evidence") is not True
        or "page_count_schema" in source_info
        or "legacy_page_count_repair" in source_info
    ):
        return None
    recorded = source_info.get("source_pages")
    raw_start = source_info.get("selected_start")
    raw_end = source_info.get("selected_end")
    try:
        recorded = _strict_page_number(recorded)
        selected_start = _strict_page_number(raw_start)
        selected_end = _strict_page_number(raw_end)
    except ValueError:
        return None
    if recorded != 1 or selected_start < 1 or selected_start > selected_end:
        return None

    verified = _verified_ocr_source_bytes(project_dir, source_info, required=True)
    if verified is None:  # pragma: no cover - required=True cannot return None
        return None
    _rel, source_bytes, verified_record = verified
    try:
        import pymupdf

        document = pymupdf.open(stream=source_bytes, filetype="pdf")
        try:
            actual_page_count = int(document.page_count)
        finally:
            document.close()
    except Exception:
        return None
    if actual_page_count <= 1 or selected_end > actual_page_count:
        return None

    # Do not infer a repair from mutable project metadata plus the current PDF.
    # The latest committed submission is loaded through the public store API,
    # which verifies its descriptor, control files, content-addressed blobs,
    # artifact identities and snapshot fingerprint before returning anything.
    latest_pointer = project_dir / "audit-submissions" / "latest.json"
    if latest_pointer.is_symlink() or not latest_pointer.is_file():
        return None
    try:
        from .audit_store import AuditSubmissionStore

        audit_store = AuditSubmissionStore(project_dir)
        latest = audit_store.latest()
        if latest is None:
            return None
        authority = audit_store.load_snapshot(latest.snapshot_id)
    except (KeyError, OSError, TypeError, ValueError):
        return None
    if (
        str(authority.project_id) != str(project.get("id") or "")
        or not hmac.compare_digest(
            authority.current_fingerprint,
            latest.snapshot_fingerprint,
        )
        or authority.workflow
        not in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}
        or str(authority.metadata.get("project_kind") or "") != "ocr"
        or authority.source_pdf is None
        or authority.source_pdf.page_count != actual_page_count
    ):
        return None
    authority_range = authority.source_pdf.selected_page_range
    expected_pages = tuple(range(selected_start, selected_end + 1))
    if (
        authority_range.start != selected_start
        or authority_range.end != selected_end
        or authority_range.pages != expected_pages
    ):
        return None
    source_artifacts = [
        artifact
        for artifact in authority.artifacts
        if artifact.artifact_role == ArtifactRole.SOURCE_PDF
    ]
    if len(source_artifacts) != 1:
        return None
    frozen_source = source_artifacts[0]
    if frozen_source.data != source_bytes:
        return None
    frozen_meta = frozen_source.metadata
    frozen_pages = frozen_meta.get("source_pages")
    frozen_start = frozen_meta.get("selected_start")
    frozen_end = frozen_meta.get("selected_end")
    frozen_bytes = frozen_meta.get("bytes")
    if isinstance(frozen_bytes, bool) or not isinstance(frozen_bytes, int):
        return None
    try:
        frozen_pages = _strict_page_number(frozen_pages)
        frozen_start = _strict_page_number(frozen_start)
        frozen_end = _strict_page_number(frozen_end)
    except ValueError:
        return None
    if (
        frozen_meta.get("source_type") != "pdf"
        or frozen_meta.get("immutable_evidence") is not True
        or "page_count_schema" in frozen_meta
        or "legacy_page_count_repair" in frozen_meta
        or frozen_pages != 1
        or frozen_start != selected_start
        or frozen_end != selected_end
        or frozen_bytes != len(source_bytes)
        or not hmac.compare_digest(
            str(frozen_meta.get("sha256") or "").lower(),
            verified_record["sha256"],
        )
    ):
        return None

    repaired = deepcopy(source_info)
    repaired.update({
        "source_pages": actual_page_count,
        "page_count_schema": OCR_SOURCE_PAGE_COUNT_SCHEMA,
        "page_count_source": "host_reparsed_hash_bound_pdf_and_immutable_run_snapshot",
        "legacy_page_count_repair": {
            "migration_id": OCR_LEGACY_PAGE_COUNT_REPAIR_ID,
            "from": 1,
            "to": actual_page_count,
            "source_sha256": verified_record["sha256"],
            "authority_snapshot_id": authority.snapshot_id,
        },
    })
    return repaired


def _quality_loop_inputs(
    project_dir: Path,
    project: dict,
    *,
    mode: str,
    provenance_out: dict | None = None,
) -> tuple[bool, bytes, tuple[int, int] | None]:
    """Bind an AI run to its immutable OCR PDF and recorded page range.

    A non-OCR project never receives PDF bytes, even if unrelated metadata is
    present.  AI OCR runs fail closed when the immutable source is unavailable;
    rule-only legacy runs may continue without visual evidence.
    """
    if provenance_out is not None:
        provenance_out.clear()
    quality_loop = mode == "ai"
    if project.get("kind") != "ocr":
        return quality_loop, b"", None

    verified = _verified_ocr_source_bytes(
        project_dir,
        project.get("ocr_source") or {},
        required=quality_loop,
    )
    if verified is None:
        return quality_loop, b"", None
    _rel, source_bytes, source_record = verified
    original_source_bytes = source_bytes

    def record_provenance(visual_pdf_bytes: bytes, *, derived: bool) -> None:
        if provenance_out is None:
            return
        source_type = str(source_record.get("source_type") or "").strip().lower()
        provenance_out.update({
            "schema": VISUAL_SOURCE_PROVENANCE_SCHEMA,
            "source_type": source_type,
            "original_upload_bytes": len(original_source_bytes),
            "original_upload_sha256": hashlib.sha256(
                original_source_bytes
            ).hexdigest(),
            "visual_pdf_bytes": len(visual_pdf_bytes),
            "visual_pdf_sha256": hashlib.sha256(visual_pdf_bytes).hexdigest(),
            "visual_pdf_is_derived": derived,
            "derivation_id": (
                IMAGE_TO_VISUAL_PDF_DERIVATION_ID
                if derived
                else PDF_IDENTITY_VISUAL_DERIVATION_ID
            ),
        })
    try:
        import pymupdf
    except ImportError:
        raise ValueError("PDF 视觉校验器不可用，已阻止 OCR 质量闭环") from None

    source_type = str(source_record.get("source_type") or "")
    if source_type == "images":
        from ..core.project import safe_project_relpath
        from ..ocr import pdf_page_count_bytes

        visual = source_record.get("visual_source")
        if not isinstance(visual, dict):
            raise ValueError("OCR 多图片派生视觉证据缺失，已阻止质量闭环")
        visual_rel = safe_project_relpath(str(visual.get("path") or ""))
        visual_path = (project_dir.resolve() / Path(visual_rel)).resolve()
        try:
            visual_path.relative_to(project_dir.resolve())
            visual_bytes = visual_path.read_bytes()
        except (OSError, ValueError):
            raise ValueError("OCR 多图片派生视觉 PDF 丢失，已阻止质量闭环") from None
        expected_visual_sha = str(visual.get("sha256") or "").lower()
        if (
            visual_path.is_symlink()
            or not visual_bytes.startswith(b"%PDF-")
            or visual.get("bytes") != len(visual_bytes)
            or not hmac.compare_digest(
                expected_visual_sha, hashlib.sha256(visual_bytes).hexdigest()
            )
            or pdf_page_count_bytes(visual_bytes) != source_record.get("source_pages")
        ):
            raise ValueError("OCR 多图片派生视觉 PDF 校验失败，已阻止质量闭环")
        selected_start = _strict_page_number(source_record.get("selected_start"))
        selected_end = _strict_page_number(source_record.get("selected_end"))
        if selected_start > selected_end or selected_end > source_record.get("source_pages"):
            raise ValueError("OCR 多图片页范围无效，已阻止质量闭环")
        record_provenance(visual_bytes, derived=True)
        if provenance_out is not None:
            provenance_out.update({
                "derivation_id": str(visual.get("derivation_id") or ""),
                "original_image_count": len(source_record.get("source_images") or ()),
                "source_images": [
                    {
                        "order": row.get("order"),
                        "original_filename": row.get("original_filename"),
                        "bytes": row.get("bytes"),
                        "sha256": row.get("sha256"),
                    }
                    for row in (source_record.get("source_images") or ())
                ],
                "derived_from_source_sha256": str(
                    visual.get("derived_from_source_sha256") or ""
                ),
            })
        return quality_loop, visual_bytes, (selected_start, selected_end)
    if source_type != "pdf":
        # A one-page image remains the immutable visual source.  Wrap its exact
        # bytes in an in-memory one-page PDF so the core can use one page-pair
        # protocol without pretending a SOURCE_PREVIEW was compiled output.
        image_document = None
        image_pixmap = None
        try:
            image_pixmap = pymupdf.Pixmap(source_bytes)
            if image_pixmap.width <= 0 or image_pixmap.height <= 0:
                raise ValueError
            image_document = pymupdf.open()
            image_page = image_document.new_page(
                width=float(image_pixmap.width),
                height=float(image_pixmap.height),
            )
            image_page.insert_image(image_page.rect, stream=source_bytes)
            source_bytes = image_document.tobytes(garbage=4, deflate=True)
        except Exception:
            raise ValueError(
                "OCR 原始图片无法建立不可变逐页视觉证据，已阻止质量闭环"
            ) from None
        finally:
            if image_document is not None:
                image_document.close()
            image_pixmap = None
        record_provenance(source_bytes, derived=True)
        return quality_loop, source_bytes, (1, 1)

    document = None
    try:
        document = pymupdf.open(stream=source_bytes, filetype="pdf")
        actual_page_count = int(document.page_count)
    except Exception:
        raise ValueError("OCR 原始 PDF 无法解析，已阻止质量闭环") from None
    finally:
        if document is not None:
            document.close()

    def page_number(field: str, label: str) -> int:
        raw = source_record.get(field)
        try:
            value = _strict_page_number(raw)
        except ValueError:
            raise ValueError(f"OCR {label}记录无效，已阻止质量闭环") from None
        return value

    recorded_page_count = page_number("source_pages", "总页数")
    if recorded_page_count != actual_page_count:
        raise ValueError("OCR 原始 PDF 页数与不可变快照不一致，已阻止质量闭环")
    selected_start = page_number("selected_start", "起始页")
    selected_end = page_number("selected_end", "结束页")
    if selected_start > selected_end or selected_end > actual_page_count:
        raise ValueError("OCR 页范围超出不可变原始 PDF，已阻止质量闭环")
    record_provenance(source_bytes, derived=False)
    return quality_loop, source_bytes, (selected_start, selected_end)


def _verified_ocr_resource_bytes(
    project_dir: Path,
    resource_info: dict,
    *,
    include_source_pages: bool = False,
    include_formula_crops: bool = False,
) -> dict[str, bytes]:
    """Read only manifest-listed, in-project OCR resources with matching hashes."""
    from ..core.project import safe_project_relpath

    project_dir = project_dir.resolve()
    groups = [resource_info.get("assets") or []]
    if include_source_pages:
        groups.append(resource_info.get("source_pages") or [])
    if include_formula_crops:
        groups.append(resource_info.get("formula_crops") or [])
    files: dict[str, bytes] = {}
    for item in [entry for group in groups for entry in group]:
        rel = safe_project_relpath(str(item.get("path") or ""))
        path = (project_dir / Path(rel)).resolve()
        try:
            path.relative_to(project_dir)
            data = path.read_bytes()
        except (ValueError, OSError):
            raise ValueError(f"OCR 图片丢失：{rel}") from None
        expected_size = item.get("bytes")
        if expected_size is not None and int(expected_size) != len(data):
            raise ValueError(f"OCR 图片大小校验失败：{rel}")
        expected_hash = str(item.get("sha256") or "")
        if not expected_hash or not hmac.compare_digest(
            expected_hash,
            hashlib.sha256(data).hexdigest(),
        ):
            raise ValueError(f"OCR 图片哈希校验失败：{rel}")
        detected_extension = _raster_extension(data)
        if (
            item.get("format_matches_extension") is False
            or detected_extension not in {".png", ".jpg"}
            or _canonical_image_extension(Path(rel).suffix) != detected_extension
        ):
            raise ValueError(f"OCR 图片格式与扩展名不一致：{rel}")
        previous = files.get(rel)
        if previous is not None and previous != data:
            raise ValueError(f"OCR 图片路径冲突：{rel}")
        files[rel] = data
    return files


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
                    job.get("status") in OCR_ACTIVE_STATUSES
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
        from .. import __version__

        schedule_installer_after_exit(
            dest,
            previous_version=__version__,
            expected_version=info.latest,
        )
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
MAX_OCR_PAGES_PER_JOB = 2000
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
    if "not JSON serializable" in text:
        return (
            "审阅结果保存格式异常；本次结果未保存，原项目和上一份已验证结果保持不变。"
            "请更新到最新版本后重新分析"
        )
    return re.sub(r"sk-(?:ws-|sp-)?[A-Za-z0-9._-]{8,}", "[已隐藏]", text)[:500]


def _cleanup_ocr_jobs(now: float = None):
    """清理已结束且超过 24 小时的 OCR 临时页；运行中的任务绝不触碰。"""
    now = now or time.time()
    expired = []
    with _ocr_jobs_lock:
        for jid, job in list(_ocr_jobs.items()):
            if (
                job.get("status") in OCR_ACTIVE_STATUSES
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


def _persisted_review_summary(review: dict) -> dict:
    """Return only the JSON review data needed after processing.

    ``run_review`` also returns runtime objects (Decision/AppliedPatch and the
    intermediate output lines) so the pipeline can keep applying patches.  Those
    values are deliberately not part of the on-disk project format.  Keeping an
    explicit allowlist here prevents a successful long-running AI job from
    failing only when ``verification.json`` is committed.
    """
    if not isinstance(review, dict):
        return {}
    summary = {}
    for key, expected_type in (
        ("findings", list),
        ("invalid", list),
        ("usage", dict),
        ("error", str),
        ("preserved_candidate_ids", list),
        ("preserved_findings", dict),
    ):
        value = review.get(key)
        if isinstance(value, expected_type):
            summary[key] = deepcopy(value)
    # Validate the persisted contract close to its boundary.  This is not a
    # ``default=str`` escape hatch: unsupported data must never be hidden in a
    # supposedly structured verification record.
    json.dumps(summary, ensure_ascii=False)
    return summary


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
    source_file: Optional[dict] = None
    name: str = ""
    mode: str = "ai"
    template: str = ""
    pack: str = ""


class FolderRequest(BaseModel):
    files: dict  # {相对路径: 内容}
    name: str = ""
    mode: str = "ai"
    template: str = ""
    pack: str = ""
    defer_process: bool = False


class BatchRejectRequest(BaseModel):
    cids: list = Field(default_factory=list)


class ReviewStateRequest(BaseModel):
    accepted_ids: list = Field(default_factory=list)
    expected_revision: Optional[int] = None


class AuditSubmissionBody(BaseModel):
    snapshot_id: str = Field(default="", max_length=128)
    profile: str = "standard"
    depth: str = ""
    audit_focus: str = Field(default="", max_length=4000)
    include_source_files: bool = True
    include_compile_logs: bool = True
    include_verification_records: bool = True
    include_verification_decisions: Optional[bool] = None
    include_page_images: Optional[bool] = None
    include_formula_crops: Optional[bool] = None
    include_page_images_formula_crops: Optional[bool] = None
    sanitize_sensitive: bool = True


class ConfigRequest(BaseModel):
    analysis_backend: Optional[str] = None
    codex_model: Optional[str] = None
    codex_reasoning_effort: Optional[str] = None
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


class ConfigConnectionTestRequest(BaseModel):
    """一次性 API 连通性探测；密钥只在本次请求内存中使用。"""

    role: Literal["decide", "review", "ocr"]
    base_url: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=256)
    api_key: Optional[SecretStr] = None


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

        identity = _runtime_provenance_identity("not-used")
        return {
            "ok": True,
            "version": __version__,
            "build_id": identity["build_id"],
            "commit": identity["commit"],
        }

    @app.get("/api/rulesets")
    def rulesets():
        from ..core.ruleset import list_builtin_packs

        return {"packs": list_builtin_packs(), "default": "bilingual"}

    @app.get("/api/templates")
    def templates():
        from ..core.template import FAITHFULBOOK, PRESERVE_SOURCE, list_template_presets

        return {
            "templates": list_template_presets(),
            "default": PRESERVE_SOURCE,
            "ocr_default": FAITHFULBOOK,
            "export_default": PRESERVE_SOURCE,
            "fixed": False,
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
        from ..core.project import decode_tex_bytes
        from ..core.template import normalize_template_id

        original_source = None
        source_format = None
        source_text = req.text
        if req.source_file is not None:
            original_source = _decode_folder_files(
                {"source.tex": req.source_file}
            )["source.tex"]
            decoded = decode_tex_bytes(original_source)
            source_text = decoded.text
            source_format = decoded.metadata()
        if not source_text.strip():
            raise HTTPException(400, "内容为空")
        template = normalize_template_id(req.template)
        pid = get_store().create(
            source_text,
            req.name,
            req.mode,
            template,
            req.pack,
            original_source=original_source,
            source_format=source_format,
        )
        return {"id": pid}

    def _import_project_files(files: Dict[str, bytes], name: str, mode: str,
                              template: str, pack: str, defer_process: bool):
        """统一的文件夹/ZIP 导入；原始资源逐字节保存在项目副本中。"""
        from ..core.project import (
            decode_tex_bytes,
            discover_main,
            flatten_project,
        )
        from ..core.template import normalize_template_id

        template = normalize_template_id(template)
        mode = mode or "ai"

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
            # Freeze the project before any model/compile work.  This gives a
            # failed immediate run a durable pid and lets the same terminal
            # snapshot path serve deferred and immediate folder processing.
            flattened, graph_obj = flatten_project(Path(tmpdir), main_rel)
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
            meta["text_formats"] = {
                rel: decode_tex_bytes(files[rel]).metadata()
                for rel in {graph_obj.main_rel, *graph_obj.files}
            }
            get_store()._write_json(str(project_dir), "meta.json", meta)
            with zipfile.ZipFile(project_dir / "original-files.zip", "w", zipfile.ZIP_DEFLATED) as zf:
                for rel, content in files.items():
                    zf.writestr(rel, content)
            processed = None
            processing_error = ""
            if not defer_process:
                try:
                    processed = _run_project(pid, set())
                except Exception as exc:  # noqa: BLE001
                    # _run_project has already frozen FAILED plus every stage
                    # available before the exception.  Keep the project visible
                    # so the user can generate/download that audit package.
                    processing_error = _safe_task_error(exc)
            return {
                "id": pid,
                "graph": meta["graph"],
                "processed": processed is not None or bool(processing_error),
                "ok": processed.get("ok") if processed is not None else (
                    False if processing_error else None
                ),
                "applied": int((processed or {}).get("applied") or 0),
                "ambiguous": int((processed or {}).get("ambiguous") or 0),
                "error": processing_error,
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
        mode: str = Form("ai"),
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
        info, result_bytes, directory = _committed_record(pid)
        verification = info.get("verification") if isinstance(info, dict) else None
        if not isinstance(verification, dict) or verification.get("safe_to_export") is not True:
            raise HTTPException(409, "安全检查未明确通过，已阻止导出；请查看汇报或重新处理")
        try:
            result_text = result_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(409, "结果不是有效 UTF-8 TEX，已阻止导出；请重新处理项目") from None
        meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        original_path = directory / "original-source.tex"
        if meta.get("kind") != "folder" and original_path.is_file():
            from ..core.project import encode_tex_like_original

            try:
                result_bytes = encode_tex_like_original(
                    result_text, original_path.read_bytes()
                )
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
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

    def _project_provenance_record(
        pid: str,
        body: bytes,
        *,
        verified: bool,
        attempt: str,
        result_sha256: str = "",
        artifact_kind: str = "project-tex",
        producer_identity: object = None,
    ) -> dict[str, str]:
        """Bind a downloaded TEX body to its frozen project inputs."""
        directory = Path(get_store()._dir(pid))
        try:
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            meta = {}
        raw_path = directory / "source.tex"
        try:
            raw_bytes = raw_path.read_bytes()
            raw_hash = sha256_bytes(raw_bytes)
        except OSError:
            raw_hash = "unknown"
            raw_normalized_hash = "unknown"
        else:
            try:
                raw_normalized_hash = sha256_lf_normalized_text(raw_bytes)
            except ValueError:
                # Preserve the exact byte identity even when a malformed TEX
                # encoding declaration makes canonical text unavailable.
                raw_normalized_hash = "unknown"

        source_hash = "unknown"
        if meta.get("kind") == "ocr":
            source_info = meta.get("ocr_source")
            if isinstance(source_info, dict):
                source_hash = str(source_info.get("sha256") or "unknown")
        elif meta.get("kind") == "folder":
            source_archive = directory / "original-files.zip"
            if source_archive.is_file():
                source_hash = sha256_bytes(source_archive.read_bytes())
        else:
            original_source = directory / "original-source.tex"
            source_path = original_source if original_source.is_file() else raw_path
            try:
                source_hash = sha256_bytes(source_path.read_bytes())
            except OSError:
                source_hash = "unknown"

        result_hash = str(result_sha256 or "")
        if not result_hash and attempt != "source":
            result_hash = sha256_bytes(body)
        raw_role = {
            "ocr": "ocr-analysis-input-tex",
            "folder": "flattened-project-analysis-input-tex",
        }.get(str(meta.get("kind") or ""), "analysis-input-tex")
        return make_provenance_record(
            body=body,
            verified=verified,
            verification_scope=VERIFIED_SCOPE if verified else UNVERIFIED_SCOPE,
            artifact_kind=artifact_kind,
            app_version="unknown",
            source_sha256=source_hash,
            raw_sha256=raw_hash,
            result_sha256=result_hash or "unknown",
            producer_identity=(
                producer_identity
                if isinstance(producer_identity, dict)
                else _unknown_producer_identity()
            ),
            exporter_identity=_runtime_provenance_identity("not-used"),
            raw_artifact_role=raw_role,
            raw_artifact_path=RAW_ARTIFACT_PACKAGE_PATH,
            raw_bytes_sha256=raw_hash,
            raw_normalized_text_sha256=raw_normalized_hash,
            raw_normalization_pipeline="decode-tex/newline-LF/encode-utf8",
        )

    def _stamp_project_tex(
        pid: str,
        body: bytes,
        *,
        verified: bool,
        attempt: str,
        result_sha256: str = "",
        artifact_kind: str = "project-tex",
        producer_identity: object = None,
    ) -> tuple[bytes, dict[str, str]]:
        record = _project_provenance_record(
            pid,
            body,
            verified=verified,
            attempt=attempt,
            result_sha256=result_sha256,
            artifact_kind=artifact_kind,
            producer_identity=producer_identity,
        )
        return stamp_tex_provenance(body, record), record

    def _project_raw_artifact_bytes(pid: str) -> bytes:
        """Return the exact internal analysis input named by provenance."""
        path = Path(get_store()._dir(pid)) / "source.tex"
        try:
            return path.read_bytes()
        except OSError:
            raise HTTPException(
                409, "内部原始分析输入缺失，无法生成可复算导出包"
            ) from None

    def _persist_compile_preview(pid: str, result) -> None:
        """Persist hash-bound current and raw-OCR PDFs beyond compiler temp dirs."""
        from ..core.preview import (
            COMPILED,
            PARTIAL_COMPILED,
            preview_artifact_path,
            preview_descriptor,
            preview_storage_filename,
        )

        allowed = {
            preview_descriptor(COMPILED).filename,
            preview_descriptor(PARTIAL_COMPILED).filename,
        }
        from ..core.compilecheck import build_compile_input_manifest

        specifications = (
            (
                "compiled_pdf",
                "compiled_pdf_name",
                "compiled_tex",
                "compiled_extra_files",
                "preview_artifact",
                "compile_after",
            ),
            (
                "raw_compiled_pdf",
                "raw_compiled_pdf_name",
                "raw_compiled_tex",
                "raw_compiled_extra_files",
                "raw_preview_artifact",
                "compile_before",
            ),
        )
        verification = getattr(result, "verification", {}) or {}
        for (
            payload_field,
            display_field,
            tex_field,
            extra_field,
            evidence_key,
            compile_key,
        ) in specifications:
            payload = getattr(result, payload_field, b"")
            if not isinstance(payload, (bytes, bytearray, memoryview)) or not payload:
                continue
            payload = bytes(payload)
            display_name = str(getattr(result, display_field, "") or "")
            if display_name not in allowed or not payload.startswith(b"%PDF-"):
                raise ValueError("编译预览工件格式无效，已阻止保存")
            evidence = verification.get(evidence_key)
            digest = sha256_bytes(payload)
            status = (
                str(evidence.get("status") or "")
                if isinstance(evidence, dict)
                else ""
            )
            if (
                not isinstance(evidence, dict)
                or evidence.get("sha256") != digest
                or evidence.get("pdf_sha256") != digest
                or evidence.get("display_filename") != display_name
                or evidence.get("filename") != preview_artifact_path(status, digest)
                or int(evidence.get("page_count") or 0) <= 0
            ):
                raise ValueError("编译预览工件与验证记录不一致，已阻止保存")
            compile_record = verification.get(compile_key)
            if not isinstance(compile_record, dict):
                raise ValueError("编译预览缺少机器编译记录，已阻止保存")
            for field_name in (
                "engine",
                "passes_attempted",
                "exit_code",
                "page_count",
                "pdf_sha256",
                "compile_input_sha256",
                "fatal_line",
                "fatal_error",
                "log_path",
            ):
                if evidence.get(field_name) != compile_record.get(field_name):
                    raise ValueError("编译预览元数据与机器编译记录不一致，已阻止保存")
            compiled_tex = str(getattr(result, tex_field, "") or "")
            if evidence.get("tex_sha256") != sha256_bytes(compiled_tex.encode("utf-8")):
                raise ValueError("编译预览工件与候选 TEX 不一致，已阻止保存")
            compile_inputs = build_compile_input_manifest(
                compiled_tex,
                dict(getattr(result, extra_field, {}) or {}),
            )
            if (
                evidence.get("compile_inputs") != compile_inputs
                or evidence.get("compile_input_sha256")
                != compile_inputs.get("manifest_sha256")
            ):
                raise ValueError("编译预览工件与完整编译输入集不一致，已阻止保存")
            storage_name = preview_storage_filename(status, digest)
            get_store()._atomic_write_bytes(
                get_store()._dir(pid), storage_name, payload
            )

    def _compile_preview_package_entry(
        pid: str,
        info: dict,
        result_bytes: bytes,
    ) -> tuple[str, bytes] | None:
        """Load a hash-bound compiled preview for inclusion in an export package."""
        from ..core.preview import (
            COMPILED,
            PARTIAL_COMPILED,
            preview_artifact_path,
            preview_storage_filename,
        )

        verification = info.get("verification") if isinstance(info, dict) else None
        evidence = (
            verification.get("preview_artifact")
            if isinstance(verification, dict)
            else None
        )
        if not isinstance(evidence, dict):
            return None
        allowed = {COMPILED, PARTIAL_COMPILED}
        status = str(evidence.get("status") or "")
        name = str(evidence.get("filename") or "")
        digest = str(evidence.get("sha256") or "")
        if (
            status not in allowed
            or preview_state_from_verification(verification) != status
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or name != preview_artifact_path(status, digest)
        ):
            raise HTTPException(409, "编译预览证据记录无效，已阻止打包")
        directory = Path(get_store()._dir(pid))
        try:
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            raise HTTPException(409, "项目元数据损坏，无法核对编译输入集") from None
        per_file = info.get("per_file") if isinstance(info, dict) else None
        compile_extra_files: dict[str, bytes] = {}
        if meta.get("kind") == "folder":
            if not isinstance(per_file, dict) or not isinstance(per_file.get(""), str):
                raise HTTPException(409, "多文件项目缺少候选文件集，已阻止打包")
            original_zip = directory / "original-files.zip"
            if not original_zip.is_file():
                raise HTTPException(409, "原始文件夹工程快照缺失，已阻止打包")
            from ..core.project import project_compile_inputs

            graph = meta.get("graph") if isinstance(meta.get("graph"), dict) else {}
            try:
                result_text, compile_extra_files = project_compile_inputs(
                    _decode_zip_files(original_zip.read_bytes()),
                    str(graph.get("main_rel") or ""),
                    per_file,
                )
            except (OSError, ValueError) as exc:
                raise HTTPException(409, f"无法重建编译输入集：{exc}") from None
        else:
            from ..core.project import decode_tex_bytes

            try:
                result_text = decode_tex_bytes(bytes(result_bytes)).text
            except ValueError as exc:
                raise HTTPException(
                    409, f"编译预览对应 TEX 无法无损解码：{exc}"
                ) from None
            if meta.get("kind") == "ocr":
                try:
                    compile_extra_files = _verified_ocr_resource_bytes(
                        directory, meta.get("ocr_resources") or {}
                    )
                except ValueError as exc:
                    raise HTTPException(409, str(exc)) from None
        normalized_result = result_text.replace("\r\n", "\n").replace("\r", "\n")
        tex_digest = str(evidence.get("tex_lf_normalized_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", tex_digest) or not hmac.compare_digest(
            sha256_bytes(normalized_result.encode("utf-8")), tex_digest
        ):
            raise HTTPException(409, "编译预览与当前 TEX 不匹配，已阻止打包")
        from ..core.compilecheck import build_compile_input_manifest

        # Pipeline candidates are compiled after newline normalization.  Keep
        # package bytes in their original encoding/newline form, but rebuild
        # the evidence manifest from the exact LF-normalized compile candidate.
        compile_inputs = build_compile_input_manifest(
            normalized_result, compile_extra_files
        )
        if evidence.get("compile_inputs") != compile_inputs:
            raise HTTPException(409, "编译预览与完整编译输入集不匹配，已阻止打包")
        path = Path(get_store()._dir(pid)) / preview_storage_filename(status, digest)
        try:
            payload = path.read_bytes()
        except OSError:
            raise HTTPException(409, "编译预览工件缺失，已阻止打包") from None
        if not payload.startswith(b"%PDF-") or not hmac.compare_digest(
            sha256_bytes(payload), digest
        ):
            raise HTTPException(409, "编译预览工件哈希不匹配，已阻止打包")
        return name, payload

    def _audit_iso_timestamp(value: object = None) -> str:
        try:
            timestamp = float(value) if value is not None else time.time()
        except (TypeError, ValueError):
            timestamp = time.time()
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")

    def _audit_json_bytes(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    def _audit_workflow(meta: dict, override: AuditWorkflow | None = None) -> AuditWorkflow:
        if override is not None:
            return override
        if meta.get("kind") == "folder":
            return AuditWorkflow.MULTIFILE_PROJECT
        if meta.get("kind") == "ocr":
            return AuditWorkflow.OCR_ANALYSIS_REVIEW
        if str(meta.get("template") or "").strip():
            return AuditWorkflow.TEMPLATE_CONVERSION
        return AuditWorkflow.ANALYSIS_REVIEW_ONLY

    def _review_state_payload(meta: dict) -> dict:
        accepted = sorted({
            str(item) for item in (meta.get("accepted_decision_ids") or [])
            if str(item).strip()
        })
        rejected = sorted({
            str(item) for item in (meta.get("excludes") or []) if str(item).strip()
        })
        return {
            "revision": max(0, int(meta.get("review_revision") or 0)),
            "accepted_ids": accepted,
            "rejected_ids": rejected,
        }

    def _audit_host_state_fingerprint(pid: str) -> str:
        """Hash the mutable host files that determine whether a bundle is current.

        This fingerprint is intentionally separate from ``RunSnapshot`` identity:
        a failed or cancelled run can freeze an in-memory stage without replacing
        the last committed project result.  Hashing the host state at the terminal
        boundary lets later TeX/PDF/review changes invalidate that snapshot without
        pretending the older committed result belonged to the failed run.
        """
        directory = Path(get_store()._dir(pid))
        names = (
            "meta.json",
            "source.tex",
            "original-source.tex",
            "result.tex",
            "report.md",
            "decisions.json",
            "verification.json",
            "last-failed-draft.tex",
            "last-failure-report.md",
            "last-failure.json",
            "ocr-source.pdf",
            "ocr-source.zip",
            "ocr-visual-source.pdf",
            "original-files.zip",
        )
        rows = []
        marker_payloads = []
        for name in names:
            path = directory / name
            try:
                payload = path.read_bytes()
            except FileNotFoundError:
                rows.append({"path": name, "present": False})
                continue
            rows.append({
                "path": name,
                "present": True,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            if name in {"verification.json", "last-failure.json"}:
                marker_payloads.append(payload)

        # Only the PDF named by a verification record is part of current state;
        # older immutable preview files may coexist and must not cause false stale.
        preview_names = set()
        from ..core.preview import COMPILED, PARTIAL_COMPILED, preview_storage_filename

        for payload in marker_payloads:
            for digest in re.findall(rb"[0-9a-f]{64}", payload):
                digest_text = digest.decode("ascii")
                for status in (COMPILED, PARTIAL_COMPILED):
                    candidate = preview_storage_filename(status, digest_text)
                    if (directory / candidate).is_file():
                        preview_names.add(candidate)
        for name in sorted(preview_names):
            payload = (directory / name).read_bytes()
            rows.append({
                "path": name,
                "present": True,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        try:
            meta_state = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, TypeError, ValueError):
            meta_state = {}
        resource_paths = {
            str(item.get("path") or "")
            for group in (meta_state.get("ocr_resources") or {}).values()
            if isinstance(group, list)
            for item in group
            if isinstance(item, dict) and str(item.get("path") or "")
        }
        from ..core.project import safe_project_relpath

        for raw_path in sorted(resource_paths):
            try:
                relative = safe_project_relpath(raw_path)
                candidate = (directory / Path(relative)).resolve()
                candidate.relative_to(directory.resolve())
                payload = candidate.read_bytes()
            except (OSError, ValueError):
                rows.append({"path": raw_path, "present": False})
                continue
            rows.append({
                "path": relative,
                "present": True,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        return hashlib.sha256(_audit_json_bytes(rows)).hexdigest()

    def _build_project_run_snapshot(
        pid: str,
        terminal_status: TerminalStatus,
        run_id: str,
        *,
        capture: Optional[dict] = None,
        error: str = "",
        workflow_override: AuditWorkflow | None = None,
    ) -> RunSnapshot:
        """Freeze one terminal project run without inferring any artifact role.

        This collector is the host authority boundary.  It receives the exact
        PipelineResult while it is still in memory; FAILED/CANCELLED runs use
        only their captured stages and never fall back to an older verified
        result as though it belonged to the new run.
        """
        capture = dict(capture or {})
        meta = get_store().get(pid) or {}
        directory = Path(get_store()._dir(pid))
        workflow = _audit_workflow(meta, workflow_override)
        source_text = get_store().read_source(pid)
        source_bytes = source_text.encode("utf-8")
        original_source = directory / "original-source.tex"
        input_tex_bytes = (
            original_source.read_bytes() if original_source.is_file() else source_bytes
        )
        artifacts = []

        def add_artifact(
            role: str,
            data: bytes | str,
            *,
            parents=(),
            path: str | None = None,
            media_type: str = "application/octet-stream",
            preview_status: str | None = None,
            index: int | None = None,
            filename: str | None = None,
            metadata: Optional[dict] = None,
        ):
            payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
            parent_ids = tuple(
                item.artifact_id for item in parents if item is not None
            )
            artifact = make_audit_artifact(
                role,
                payload,
                path=path,
                media_type=media_type,
                parent_artifact_ids=parent_ids,
                preview_status=preview_status,
                index=index,
                filename=filename,
                metadata=metadata,
            )
            artifacts.append(artifact)
            return artifact

        source_artifact = None
        raw_artifact = None
        ocr_source = None
        if meta.get("kind") == "ocr":
            try:
                ocr_source = _verified_ocr_source_bytes(
                    directory, meta.get("ocr_source") or {}, required=False
                )
            except ValueError:
                ocr_source = None
            if ocr_source is not None:
                source_rel, source_payload, source_record = ocr_source
                source_type = str(source_record.get("source_type") or "")
                if source_type == "images":
                    visual = source_record.get("visual_source") or {}
                    manifest_view = {
                        "images": source_record.get("source_images") or [],
                        "derived_visual_source": {
                            "sha256": visual.get("sha256"),
                        },
                    }
                    originals = extract_multi_image_bytes(source_payload, manifest_view)
                    original_artifacts = []
                    for row, payload in originals:
                        original_artifacts.append(add_artifact(
                            ArtifactRole.SOURCE_IMAGE,
                            payload,
                            media_type=str(row.get("media_type") or "application/octet-stream"),
                            index=int(row.get("order") or 0),
                            filename=str(row.get("original_filename") or ""),
                            metadata={
                                "order": row.get("order"),
                                "original_filename": row.get("original_filename"),
                                "source_bytes_sha256": row.get("sha256"),
                                "canonical_input": True,
                            },
                        ))
                    add_artifact(
                        ArtifactRole.PROJECT_FILE,
                        source_payload,
                        filename=source_rel,
                        media_type="application/zip",
                        metadata={
                            "kind": "CANONICAL_MULTI_IMAGE_SOURCE_BUNDLE",
                            "contains_original_bytes": True,
                            "image_count": len(original_artifacts),
                        },
                    )
                    visual_path = directory / Path(str(visual.get("path") or ""))
                    visual_payload = visual_path.read_bytes()
                    source_artifact = add_artifact(
                        ArtifactRole.SOURCE_PDF,
                        visual_payload,
                        parents=tuple(original_artifacts),
                        media_type="application/pdf",
                        filename=visual_path.name,
                        metadata={
                            **{key: value for key, value in visual.items() if key != "path"},
                            "source_type": "images",
                            "derived_visual_source": True,
                            "is_original_upload": False,
                        },
                    )
                else:
                    source_is_pdf = source_type == "pdf"
                    source_artifact = add_artifact(
                        (
                            ArtifactRole.SOURCE_PDF
                            if source_is_pdf
                            else ArtifactRole.SOURCE_IMAGE
                        ),
                        source_payload,
                        media_type=(
                            "application/pdf"
                            if source_is_pdf
                            else (
                                "image/png"
                                if source_payload.startswith(b"\x89PNG")
                                else "image/jpeg"
                            )
                        ),
                        filename=None if source_is_pdf else source_rel,
                        metadata={
                            key: value for key, value in source_record.items()
                            if key != "path"
                        },
                    )
            raw_artifact = add_artifact(
                ArtifactRole.RAW_OCR_TEX,
                source_bytes,
                parents=(source_artifact,),
                media_type="application/x-tex; charset=utf-8",
            )
        else:
            source_artifact = add_artifact(
                ArtifactRole.SOURCE_TEX,
                input_tex_bytes,
                media_type="application/x-tex",
            )
            raw_artifact = add_artifact(
                ArtifactRole.STAGE_SOURCE_TEX,
                source_bytes,
                parents=(source_artifact,),
                media_type="application/x-tex; charset=utf-8",
            )

        pipeline_result = capture.get("pipeline_result")
        captured_stages = capture.get("audit_stages") or {}

        def captured_stage_text(*names: str) -> str:
            for name in names:
                entry = captured_stages.get(name)
                if isinstance(entry, dict):
                    value = entry.get("text")
                else:
                    value = entry
                if isinstance(value, str) and value:
                    return value
            return ""

        analyzed_text = str(
            getattr(pipeline_result, "analyzed_tex", "") or ""
        ) or captured_stage_text("ai_analyzed", "rule_analyzed")
        analyzed_artifact = None
        if analyzed_text:
            analyzed_artifact = add_artifact(
                (
                    ArtifactRole.AI_ANALYZED_TEX
                    if meta.get("mode") == "ai"
                    else ArtifactRole.RULE_ANALYZED_TEX
                ),
                analyzed_text,
                parents=(raw_artifact,),
                media_type="application/x-tex; charset=utf-8",
                metadata={
                    "producer": "host-captured pipeline stage",
                    "mode": str(meta.get("mode") or ""),
                },
            )
        reviewed_text = str(
            getattr(pipeline_result, "reviewed_tex", "") or ""
        ) or captured_stage_text("ai_reviewed")
        review_verification = (
            getattr(pipeline_result, "verification", None)
            if pipeline_result is not None else None
        ) or capture.get("verification") or {}
        recorded_ai_review = (
            review_verification.get("ai_review")
            if isinstance(review_verification, dict) else None
        )
        review_output_authorized = bool(
            isinstance(recorded_ai_review, dict)
            and recorded_ai_review.get("checked") is True
        )
        if not review_output_authorized:
            reviewed_text = ""
        reviewed_artifact = None
        if reviewed_text and review_output_authorized:
            reviewed_artifact = add_artifact(
                ArtifactRole.AI_REVIEWED_TEX,
                reviewed_text,
                parents=(analyzed_artifact or raw_artifact,),
                media_type="application/x-tex; charset=utf-8",
            )

        pipeline_compiled_pdf = bytes(
            getattr(pipeline_result, "compiled_pdf", b"")
            if pipeline_result is not None
            else b""
        )
        if pipeline_result is not None:
            # When a real PDF exists, CURRENT_TEX must be the exact candidate
            # materialized for that PDF.  Export newline restoration is useful
            # for ordinary TEX downloads but is not the compile-input authority.
            if pipeline_compiled_pdf.startswith(b"%PDF-") and str(
                getattr(pipeline_result, "compiled_tex", "") or ""
            ):
                # The audit CURRENT_TEX is the exact main.tex materialized for
                # CURRENT_PREVIEW.  Ordinary TEX/project exports continue to use
                # export_text/result and are intentionally unchanged.
                current_text = str(pipeline_result.compiled_tex)
            elif terminal_status is TerminalStatus.SUCCESS:
                current_text = str(
                    getattr(pipeline_result, "export_text", "")
                    or getattr(pipeline_result, "result", "")
                    or source_text
                )
            else:
                current_text = str(
                    getattr(pipeline_result, "compiled_snapshot", "")
                    or getattr(pipeline_result, "compiled_tex", "")
                    or reviewed_text
                    or analyzed_text
                    or getattr(pipeline_result, "result", "")
                    or source_text
                )
        elif terminal_status in {TerminalStatus.FAILED, TerminalStatus.CANCELLED}:
            current_text = str(
                capture.get("preview") or reviewed_text or analyzed_text or source_text
            )
        else:
            try:
                current_text = _current_record(pid)["result"].decode("utf-8")
            except (HTTPException, UnicodeDecodeError, OSError):
                current_text = source_text
        current_artifact = add_artifact(
            ArtifactRole.CURRENT_TEX,
            current_text,
            parents=(reviewed_artifact or analyzed_artifact or raw_artifact,),
            media_type="application/x-tex; charset=utf-8",
            metadata={
                "terminal_capture": True,
                "partial": terminal_status in {
                    TerminalStatus.FAILED,
                    TerminalStatus.PARTIAL,
                    TerminalStatus.CANCELLED,
                },
            },
        )

        verification = deepcopy(
            getattr(pipeline_result, "verification", None) or capture.get("verification") or {}
        )
        # Verification status can only come from this captured machine record.
        if terminal_status is not TerminalStatus.SUCCESS:
            verification["safe_to_export"] = False
        verification.setdefault("safe_to_export", False)
        verification["audit_terminal_status"] = terminal_status.value

        compile_metadata_fields = (
            "engine",
            "passes_attempted",
            "exit_code",
            "page_count",
            "pdf_sha256",
            "compile_input_sha256",
            "fatal_line",
            "fatal_error",
            "log_path",
        )

        def preview_metadata(
            record_key: str,
            evidence_key: str,
            compile_input_manifest_path: str,
        ) -> dict:
            record = verification.get(record_key)
            evidence = verification.get(evidence_key)
            metadata = {}
            for field_name in compile_metadata_fields:
                if isinstance(evidence, dict) and field_name in evidence:
                    metadata[field_name] = deepcopy(evidence[field_name])
                elif isinstance(record, dict) and field_name in record:
                    metadata[field_name] = deepcopy(record[field_name])
            if metadata.get("compile_input_sha256"):
                metadata["compile_input_manifest_path"] = compile_input_manifest_path
            return metadata

        raw_compiled_pdf = b""
        if meta.get("kind") == "ocr":
            raw_preview_status = str(
                verification.get("raw_preview_state") or "SOURCE_PREVIEW"
            ).upper()
            if raw_preview_status not in {
                "COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"
            }:
                raw_preview_status = "SOURCE_PREVIEW"
            raw_compiled_pdf = bytes(
                getattr(pipeline_result, "raw_compiled_pdf", b"")
                if pipeline_result is not None
                else capture.get("raw_compiled_pdf") or b""
            )
            raw_evidence = verification.get("raw_preview_artifact")
            raw_digest = hashlib.sha256(raw_compiled_pdf).hexdigest()
            if (
                raw_preview_status in {"COMPILED", "PARTIAL_COMPILED"}
                and raw_compiled_pdf.startswith(b"%PDF-")
                and isinstance(raw_evidence, dict)
                and raw_evidence.get("sha256") == raw_digest
                and int(raw_evidence.get("page_count") or 0) > 0
            ):
                add_artifact(
                    ArtifactRole.RAW_OCR_PREVIEW,
                    raw_compiled_pdf,
                    parents=(raw_artifact,),
                    media_type="application/pdf",
                    preview_status=raw_preview_status,
                    metadata=preview_metadata(
                        "compile_before",
                        "raw_preview_artifact",
                        "audit/compile-input-raw-manifest.json",
                    ),
                )
            elif raw_preview_status == "SOURCE_PREVIEW":
                add_artifact(
                    ArtifactRole.RAW_OCR_PREVIEW,
                    source_bytes,
                    parents=(raw_artifact,),
                    path="previews/raw-ocr-source-preview.txt",
                    media_type="text/plain; charset=utf-8",
                    preview_status="SOURCE_PREVIEW",
                )
            # A declared compiled/partial preview with missing or mismatched bytes
            # intentionally has no fallback artifact.  The audit package gate can
            # then report the expected RAW_OCR_PREVIEW as missing instead of
            # misrepresenting a source rendering as the recorded compilation.

        preview_status = str(
            verification.get("preview_state")
            or capture.get("preview_state")
            or "SOURCE_PREVIEW"
        ).upper()
        if preview_status not in {"COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"}:
            preview_status = "SOURCE_PREVIEW"
        compiled_pdf = bytes(pipeline_compiled_pdf or capture.get("compiled_pdf") or b"")
        current_evidence = verification.get("preview_artifact")
        current_digest = hashlib.sha256(compiled_pdf).hexdigest()
        if (
            preview_status in {"COMPILED", "PARTIAL_COMPILED"}
            and compiled_pdf.startswith(b"%PDF-")
            and isinstance(current_evidence, dict)
            and current_evidence.get("sha256") == current_digest
            and int(current_evidence.get("page_count") or 0) > 0
        ):
            add_artifact(
                ArtifactRole.CURRENT_PREVIEW,
                compiled_pdf,
                parents=(current_artifact,),
                media_type="application/pdf",
                preview_status=preview_status,
                metadata=preview_metadata(
                    "compile_after",
                    "preview_artifact",
                    "audit/compile-input-manifest.json",
                ),
            )
        elif preview_status == "SOURCE_PREVIEW":
            add_artifact(
                ArtifactRole.CURRENT_PREVIEW,
                current_text,
                parents=(current_artifact,),
                path="previews/current-source-preview.txt",
                media_type="text/plain; charset=utf-8",
                preview_status=preview_status,
            )
        # As with raw OCR, a declared compiled/partial preview is never replaced
        # by SOURCE_PREVIEW merely because its immutable PDF is missing.  Omitting
        # the role preserves the discrepancy for the package completeness gate.

        # Freeze the exact raw/current non-system compile closures.  These
        # audit-only copies never change the ordinary TEX/project ZIP exports.
        from ..core.compilecheck import (
            build_compile_input_manifest,
            prepare_compile_inputs,
        )

        template_payload = None

        def capture_compile_closure(
            *,
            candidate_tex: str,
            extra_files: dict[str, bytes],
            main_artifact,
            preview_evidence: dict | None,
            manifest_role: str,
            manifest_path: str,
            scope: str,
        ) -> tuple[list, list[dict], bool]:
            if not candidate_tex:
                return [], [], False
            prepared_inputs = prepare_compile_inputs(candidate_tex, extra_files)
            base_manifest = build_compile_input_manifest(candidate_tex, extra_files)
            recorded_hash = str(
                (preview_evidence or {}).get("compile_input_sha256") or ""
            )
            complete = not recorded_hash or hmac.compare_digest(
                recorded_hash, str(base_manifest.get("manifest_sha256") or "")
            )
            completeness_reasons = [] if complete else [
                "captured compile closure hash does not match preview evidence"
            ]
            assets = []
            packaged_files: list[dict] = []
            for relative, payload in sorted(prepared_inputs.items()):
                digest = hashlib.sha256(payload).hexdigest()
                if relative == "main.tex":
                    packaged_files.append({
                        "path": relative,
                        "packaged_path": main_artifact.path,
                        "artifact_role": main_artifact.artifact_role,
                        "artifact_id": main_artifact.artifact_id,
                        "parent_artifact_ids": list(main_artifact.parent_artifact_ids),
                        "bytes": len(payload),
                        "bytes_sha256": digest,
                        "required_for_compile": True,
                        "source": f"host-captured {scope} compile candidate",
                    })
                    if digest != main_artifact.bytes_sha256:
                        complete = False
                        completeness_reasons.append(
                            "main artifact bytes differ from the captured compile candidate"
                        )
                    continue
                base_path = project_dependency_path(relative)
                if scope == "raw":
                    base_path = (
                        PurePosixPath("project")
                        / "raw"
                        / PurePosixPath(base_path).relative_to("project")
                    ).as_posix()
                asset = add_artifact(
                    ArtifactRole.PROJECT_FILE,
                    payload,
                    parents=(main_artifact,),
                    path=base_path,
                    media_type=(
                        "application/x-tex"
                        if Path(relative).suffix.lower()
                        in {".tex", ".ltx", ".bib", ".cls", ".sty"}
                        else "application/octet-stream"
                    ),
                    metadata={
                        "compile_scope": scope,
                        "compile_relative_path": relative,
                        "required_for_compile": True,
                        "source": f"captured {scope} compile input closure",
                    },
                )
                assets.append(asset)
                packaged_files.append({
                    "path": relative,
                    "packaged_path": base_path,
                    "artifact_path": base_path,
                    "artifact_role": ArtifactRole.PROJECT_FILE,
                    "artifact_id": asset.artifact_id,
                    "parent_artifact_ids": [main_artifact.artifact_id],
                    "bytes": len(payload),
                    "bytes_sha256": digest,
                    "required_for_compile": True,
                    "source": f"captured {scope} compile input closure",
                })
            manifest_payload = {
                **base_manifest,
                "compile_scope": scope,
                "main_artifact_id": main_artifact.artifact_id,
                "main_artifact_path": main_artifact.path,
                "preview_artifact_sha256": (
                    (preview_evidence or {}).get("sha256")
                ),
                "recorded_compile_input_sha256": recorded_hash or None,
                "packaged_files": packaged_files,
                "complete": complete,
                "completeness_reasons": completeness_reasons,
            }
            add_artifact(
                manifest_role,
                _audit_json_bytes(manifest_payload),
                parents=(main_artifact, *assets),
                path=manifest_path,
                media_type="application/json",
            )
            return assets, packaged_files, complete

        compiled_tex = str(
            getattr(pipeline_result, "compiled_tex", "") or ""
            if pipeline_result is not None else ""
        )
        compiled_extra_files = dict(
            getattr(pipeline_result, "compiled_extra_files", {}) or {}
            if pipeline_result is not None else {}
        )
        if not compiled_tex and isinstance(current_evidence, dict):
            normalized_current = current_text.replace("\r\n", "\n").replace("\r", "\n")
            expected_tex_hash = str(
                current_evidence.get("tex_lf_normalized_sha256") or ""
            )
            if expected_tex_hash and hmac.compare_digest(
                hashlib.sha256(normalized_current.encode("utf-8")).hexdigest(),
                expected_tex_hash,
            ):
                compiled_tex = normalized_current
                if meta.get("kind") == "ocr":
                    try:
                        compiled_extra_files = _verified_ocr_resource_bytes(
                            directory, meta.get("ocr_resources") or {}
                        )
                    except ValueError:
                        compiled_extra_files = {}

        current_assets, current_packaged_files, _current_closure_complete = (
            capture_compile_closure(
                candidate_tex=compiled_tex,
                extra_files=compiled_extra_files,
                main_artifact=current_artifact,
                preview_evidence=(
                    current_evidence if isinstance(current_evidence, dict) else None
                ),
                manifest_role=ArtifactRole.COMPILE_INPUT_MANIFEST,
                manifest_path="audit/compile-input-manifest.json",
                scope="current",
            )
        )

        raw_compiled_tex = str(
            getattr(pipeline_result, "raw_compiled_tex", "") or ""
            if pipeline_result is not None else ""
        )
        raw_extra_files = dict(
            getattr(pipeline_result, "raw_compiled_extra_files", {}) or {}
            if pipeline_result is not None else {}
        )
        raw_evidence = verification.get("raw_preview_artifact")
        if not raw_compiled_tex and isinstance(raw_evidence, dict):
            normalized_raw = source_text.replace("\r\n", "\n").replace("\r", "\n")
            expected_raw_hash = str(
                raw_evidence.get("tex_lf_normalized_sha256") or ""
            )
            if expected_raw_hash and hmac.compare_digest(
                hashlib.sha256(normalized_raw.encode("utf-8")).hexdigest(),
                expected_raw_hash,
            ):
                raw_compiled_tex = normalized_raw
                try:
                    raw_extra_files = _verified_ocr_resource_bytes(
                        directory, meta.get("ocr_resources") or {}
                    )
                except ValueError:
                    raw_extra_files = {}
        if raw_compiled_pdf.startswith(b"%PDF-"):
            capture_compile_closure(
                candidate_tex=raw_compiled_tex,
                extra_files=raw_extra_files,
                main_artifact=raw_artifact,
                preview_evidence=(raw_evidence if isinstance(raw_evidence, dict) else None),
                manifest_role=ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
                manifest_path="audit/compile-input-raw-manifest.json",
                scope="raw",
            )

        template_assets = [
            row
            for row in current_packaged_files
            if str(row.get("path", "")).lower().endswith(
                (".cls", ".sty", ".def", ".cfg", ".clo")
            )
        ]
        if template_assets:
            template_id = str(meta.get("template") or "none")
            template_version = None
            if any(row.get("path") == "elegantbook.cls" for row in template_assets):
                from ..elegantbook import (
                    ELEGANTBOOK_VERSION,
                    LICENSE_FILENAME,
                    elegantbook_license_bytes,
                )

                template_id = "elegantbook"
                template_version = ELEGANTBOOK_VERSION
                license_payload = elegantbook_license_bytes()
                license_path = f"project/LICENSES/{LICENSE_FILENAME}"
                license_artifact = add_artifact(
                    ArtifactRole.PROJECT_FILE,
                    license_payload,
                    parents=tuple(current_assets),
                    path=license_path,
                    media_type="text/plain; charset=utf-8",
                    metadata={
                        "required_for_compile": False,
                        "license_for": "elegantbook.cls",
                        "source": "vendored ElegantBook license",
                    },
                )
                current_assets.append(license_artifact)
                for row in template_assets:
                    if row.get("path") == "elegantbook.cls":
                        row["license_path"] = license_path
            template_payload = template_manifest(
                template_id=template_id,
                template_version=template_version,
                assets=template_assets,
            )
            add_artifact(
                ArtifactRole.TEMPLATE_MANIFEST,
                _audit_json_bytes(template_payload),
                parents=tuple(current_assets),
                path="audit/template-manifest.json",
                media_type="application/json",
            )

        info = capture.get("info") if isinstance(capture.get("info"), dict) else {}
        if pipeline_result is not None:
            decisions_payload = [
                _decision_dict(item) for item in getattr(pipeline_result, "decisions", [])
            ]
            decision_items = deepcopy(getattr(pipeline_result, "decision_items", []) or [])
            report_md = str(getattr(pipeline_result, "report_md", "") or "")
        else:
            decisions_payload = deepcopy(info.get("decision_cache") or [])
            decision_items = deepcopy(info.get("items") or [])
            report_md = str(capture.get("report_md") or "")

        safe_error = str(error or capture.get("error") or "").strip()
        ai_review = verification.get("ai_review")
        ai_review = ai_review if isinstance(ai_review, dict) else {}
        review_checked = ai_review.get("checked") is True
        requested_stages = {
            AuditWorkflow.ANALYSIS_REVIEW_ONLY: {"analysis", "review"},
            AuditWorkflow.OCR_ONLY: {"ocr"},
            AuditWorkflow.OCR_ANALYSIS_REVIEW: {"ocr", "analysis", "review"},
            AuditWorkflow.TEMPLATE_CONVERSION: {"analysis", "review", "template"},
            AuditWorkflow.MULTIFILE_PROJECT: {"analysis", "review"},
        }[workflow]

        def stage_record(name: str, completed: bool, *, checked=None) -> dict:
            if name not in requested_stages:
                return {"status": "NOT_REQUESTED"}
            if completed:
                return {
                    "status": "COMPLETED",
                    **({"checked": bool(checked)} if checked is not None else {}),
                }
            if name == "review" and ai_review.get("skipped") is True:
                return {
                    "status": "SKIPPED",
                    "checked": False,
                    "reason": str(ai_review.get("reason") or "AI review was skipped"),
                }
            if terminal_status is TerminalStatus.CANCELLED:
                return {
                    "status": "CANCELLED",
                    "reason": "source run was cancelled before this stage completed",
                }
            if terminal_status is TerminalStatus.FAILED:
                return {
                    "status": "FAILED",
                    "reason": safe_error or "source run failed before this stage completed",
                }
            return {
                "status": "SKIPPED",
                "reason": (
                    "AI review was not executed"
                    if name == "review"
                    else "host did not capture a completed stage output"
                ),
                **({"checked": False} if name == "review" else {}),
            }

        template_gate = verification.get("template")
        template_gate = template_gate if isinstance(template_gate, dict) else {}
        stages = {
            "ocr": stage_record("ocr", meta.get("kind") == "ocr"),
            "analysis": stage_record("analysis", analyzed_artifact is not None),
            "review": stage_record(
                "review", reviewed_artifact is not None and review_checked,
                checked=review_checked,
            ),
            "template": stage_record(
                "template",
                template_gate.get("applied") is True,
            ),
        }

        source_info = meta.get("ocr_source") or {}
        source_pdf_info = None
        if source_artifact is not None and source_artifact.artifact_role == ArtifactRole.SOURCE_PDF:
            recorded_page_count = int(source_info.get("source_pages") or 0)
            try:
                from ..ocr import pdf_page_count_bytes

                actual_page_count = pdf_page_count_bytes(source_artifact.data)
            except (ImportError, RuntimeError, ValueError):
                actual_page_count = recorded_page_count
            source_page_count = int(actual_page_count or recorded_page_count or 0)
            selected_start = int(source_info.get("selected_start") or 1)
            selected_end = int(
                source_info.get("selected_end")
                or source_page_count
                or selected_start
            )
            selected_pages = list(range(selected_start, selected_end + 1))
            source_pdf_info = {
                "page_count": source_page_count or None,
                "selected_page_range": {
                    "start": selected_start,
                    "end": selected_end,
                    "pages": selected_pages,
                },
            }

        outline = meta.get("ocr_outline")
        outline = outline if isinstance(outline, list) else []
        if source_pdf_info is not None:
            selected_outline_pages = set(
                source_pdf_info["selected_page_range"]["pages"]
            )

            def outline_is_selected(item: object) -> bool:
                if not isinstance(item, dict):
                    return False
                try:
                    return int(item.get("page") or 0) in selected_outline_pages
                except (TypeError, ValueError):
                    return False

            outline = [item for item in outline if outline_is_selected(item)]
        outline_evidence = build_outline_evidence(
            outline, current_text, verification
        )
        resource_info = meta.get("ocr_resources") or {}
        verified_resources: dict[str, bytes] = {}
        if meta.get("kind") == "ocr":
            try:
                verified_resources = _verified_ocr_resource_bytes(
                    directory,
                    resource_info,
                    include_source_pages=True,
                    include_formula_crops=True,
                )
            except ValueError as exc:
                verification["audit_resource_capture"] = {
                    "complete": False,
                    "error": str(exc),
                    "declared_source_pages": len(resource_info.get("source_pages") or []),
                    "declared_assets": len(resource_info.get("assets") or []),
                    "declared_formula_crops": len(resource_info.get("formula_crops") or []),
                }
            else:
                verification["audit_resource_capture"] = {
                    "complete": True,
                    "captured_files": len(verified_resources),
                }
        blocker_rows = structured_blockers(
            verification.get("failures") or (), error=safe_error
        )
        resource_capture = verification.get("audit_resource_capture")
        if (
            isinstance(resource_capture, dict)
            and resource_capture.get("complete") is False
        ):
            blocker_rows.extend(structured_blockers([{
                "id": "ocr-audit-resource-capture",
                "severity": "P1",
                "module": "evidence",
                "summary": "OCR 页图、图片或公式裁片未能按记录哈希完整冻结",
                "action": "恢复缺失资源并重新生成终态快照",
                "acceptance": "audit_resource_capture.complete == true",
            }]))
        if verification.get("safe_to_export") is not True and not blocker_rows:
            blocker_rows = structured_blockers([{
                "id": "machine-verification-not-passed",
                "severity": "P0",
                "module": "verification",
                "summary": "当前运行没有绑定完整通过的机器验证记录",
                "action": "重新运行并通过全部机器检查",
                "acceptance": "verification_status == VERIFIED",
            }])
        metrics_payload = build_metrics(
            source_pdf=source_pdf_info,
            outline_evidence=outline_evidence,
            verification=verification,
            current_tex=current_text,
        )
        if not report_md:
            report_md = (
                "# LaTeXStruct 运行审计记录\n\n"
                f"- 任务终态：**{terminal_status.value}**\n"
                "- 本记录保留终态前已经产生的材料；它不表示机器验证通过。\n"
            )
            if error:
                report_md += f"- 错误：{error}\n"
        report_artifact = add_artifact(
            ArtifactRole.REPORT,
            report_md,
            parents=(current_artifact,),
            media_type="text/markdown; charset=utf-8",
        )
        add_artifact(
            ArtifactRole.REPORT_JSON,
            _audit_json_bytes(build_report_json(
                source_run_status=terminal_status.value,
                verification_status=(
                    "VERIFIED"
                    if verification.get("safe_to_export") is True
                    else "UNVERIFIED"
                ),
                stages=stages,
                blockers=blocker_rows,
                metrics=metrics_payload,
            )),
            parents=(current_artifact, report_artifact),
            path="audit/report.json",
            media_type="application/json",
        )
        add_artifact(
            ArtifactRole.ISSUES_CSV,
            issues_csv_bytes(blocker_rows, decision_items),
            parents=(current_artifact, report_artifact),
            path="audit/issues.csv",
            media_type="text/csv; charset=utf-8",
        )
        add_artifact(
            ArtifactRole.METRICS,
            _audit_json_bytes(metrics_payload),
            parents=(current_artifact, report_artifact),
            path="audit/metrics.json",
            media_type="application/json",
        )
        add_artifact(
            ArtifactRole.VERIFICATION,
            _audit_json_bytes({
                "terminal_status": terminal_status.value,
                "verification": verification,
            }),
            parents=(current_artifact, report_artifact),
            media_type="application/json",
        )
        add_artifact(
            ArtifactRole.DECISIONS,
            _audit_json_bytes({
                "decisions": decisions_payload,
                "items": decision_items,
                "review_state": _review_state_payload(meta),
            }),
            parents=(current_artifact,),
            media_type="application/json",
        )
        diff_text = "".join(difflib.unified_diff(
            source_text.replace("\r\n", "\n").replace("\r", "\n").splitlines(True),
            current_text.replace("\r\n", "\n").replace("\r", "\n").splitlines(True),
            fromfile="raw/source.tex",
            tofile="current/current.tex",
        ))
        add_artifact(
            ArtifactRole.RAW_TO_CURRENT_DIFF,
            diff_text,
            parents=(raw_artifact, current_artifact),
            media_type="text/x-diff; charset=utf-8",
        )

        compile_after = verification.get("compile_after")
        if isinstance(compile_after, dict) and isinstance(compile_after.get("log"), str):
            add_artifact(
                ArtifactRole.COMPILE_CURRENT_LOG,
                compile_after.get("log") or "",
                parents=(current_artifact,),
                media_type="text/plain; charset=utf-8",
            )
        if meta.get("kind") == "ocr":
            # compile_before is run directly on the imported raw OCR TeX before
            # template conversion or structural edits.
            compile_before = verification.get("compile_before")
            if isinstance(compile_before, dict) and isinstance(compile_before.get("log"), str):
                add_artifact(
                    ArtifactRole.COMPILE_RAW_LOG,
                    compile_before.get("log") or "",
                    parents=(raw_artifact,),
                    media_type="text/plain; charset=utf-8",
                )
            if outline_evidence is not None:
                add_artifact(
                    ArtifactRole.OUTLINE,
                    _audit_json_bytes(outline_evidence),
                    parents=(source_artifact,),
                    media_type="application/json",
                )
            for index, item in enumerate(resource_info.get("source_pages") or [], 1):
                rel = str(item.get("path") or "")
                payload = verified_resources.get(rel)
                if payload:
                    add_artifact(
                        ArtifactRole.PAGE_IMAGE,
                        payload,
                        parents=(source_artifact,),
                        index=index,
                        filename=rel,
                        media_type=(
                            "image/png" if payload.startswith(b"\x89PNG") else "image/jpeg"
                        ),
                        metadata={"source_page": item.get("source_page") or index},
                    )
            for index, item in enumerate(resource_info.get("assets") or [], 1):
                rel = str(item.get("path") or "")
                payload = verified_resources.get(rel)
                if payload:
                    add_artifact(
                        ArtifactRole.EVIDENCE,
                        payload,
                        parents=(raw_artifact,),
                        filename=f"ocr-assets/asset-{index:04d}{Path(rel).suffix.lower()}",
                        media_type=(
                            "image/png" if payload.startswith(b"\x89PNG") else "image/jpeg"
                        ),
                        metadata={"evidence_kind": "ocr_figure_asset"},
                    )
            for index, item in enumerate(resource_info.get("formula_crops") or [], 1):
                rel = str(item.get("path") or "")
                payload = verified_resources.get(rel)
                if payload:
                    add_artifact(
                        ArtifactRole.FORMULA_CROP,
                        payload,
                        parents=(source_artifact, raw_artifact),
                        index=index,
                        filename=rel,
                        media_type=(
                            "image/png" if payload.startswith(b"\x89PNG") else "image/jpeg"
                        ),
                        metadata={
                            "source_page": item.get("source_page"),
                            "evidence_id": item.get("evidence_id"),
                        },
                    )
        if meta.get("kind") == "folder":
            original_zip = directory / "original-files.zip"
            if original_zip.is_file():
                try:
                    project_files = _decode_zip_files(original_zip.read_bytes())
                except (OSError, ValueError, zipfile.BadZipFile):
                    project_files = {}
                for rel, payload in sorted(project_files.items()):
                    add_artifact(
                        ArtifactRole.PROJECT_FILE,
                        payload,
                        parents=(source_artifact,),
                        filename=rel,
                        media_type=(
                            "application/x-tex" if rel.lower().endswith(".tex")
                            else "application/octet-stream"
                        ),
                    )

        if safe_error or terminal_status in {
            TerminalStatus.FAILED, TerminalStatus.CANCELLED, TerminalStatus.PARTIAL,
        }:
            add_artifact(
                ArtifactRole.ERROR_LOG,
                _audit_json_bytes({
                    "terminal_status": terminal_status.value,
                    "error": safe_error,
                    "events": capture.get("events") or [],
                }),
                parents=(current_artifact,),
                media_type="application/json",
            )

        cfg = capture.get("config_snapshot")
        ocr_processing = meta.get("ocr_processing")
        ocr_processing = ocr_processing if isinstance(ocr_processing, dict) else {}
        if workflow is AuditWorkflow.OCR_ONLY and str(
            ocr_processing.get("model") or ""
        ):
            model = str(ocr_processing["model"])
        elif meta.get("mode") != "ai":
            model = "rule-engine"
        elif cfg is not None:
            model = str(
                getattr(cfg, "codex_model", "")
                if getattr(cfg, "analysis_backend", "") == "codex_cli"
                else getattr(cfg, "decide_model", "")
            ) or "unknown"
        else:
            model = "unknown"
        page_range = (
            (
                f"{source_pdf_info['selected_page_range']['start']}-"
                f"{source_pdf_info['selected_page_range']['end']}"
            )
            if source_pdf_info is not None
            else "all"
        )

        def model_identity(role: str, stage_name: str) -> dict:
            stage_status = stages[stage_name]["status"]
            if role == "ocr":
                processing = ocr_processing
                backend = str(processing.get("backend") or "") or None
                role_model = str(processing.get("model") or "") or None
                provider = None
            elif meta.get("mode") != "ai":
                backend, provider, role_model = "rule-engine", "local", "rule-engine"
            elif cfg is not None:
                backend = str(getattr(cfg, "analysis_backend", "") or "") or None
                if backend == "codex_cli":
                    provider = "openai-codex"
                    role_model = str(getattr(cfg, "codex_model", "") or "") or None
                else:
                    from urllib.parse import urlsplit

                    base_url = str(
                        getattr(cfg, f"{role}_base_url", "") or ""
                    )
                    provider = urlsplit(base_url).hostname or None
                    role_model = str(
                        getattr(cfg, f"{role}_model", "") or ""
                    ) or None
            else:
                backend = provider = role_model = None
            invoked = stage_status == "COMPLETED"
            known = invoked and bool(backend or role_model)
            return {
                "backend": backend if known else None,
                "provider": provider if known else None,
                "model": role_model if known else None,
                "status": stage_status if known else "UNKNOWN",
                "stage_status": stage_status,
                **({
                    "configured_backend": backend,
                    "configured_provider": provider,
                    "configured_model": role_model,
                } if not known and (backend or provider or role_model) else {}),
                **({
                    "reason": (
                        "stage did not persist an invoked model identity"
                        if backend or role_model
                        else "legacy run did not persist model identity"
                    )
                } if not known else {}),
            }

        if isinstance(capture.get("producer_identity"), dict):
            producer_identity = {
                key: str(capture["producer_identity"].get(key) or "unknown")
                for key in ("app_version", "build_id", "commit", "prompt_version")
            }
        elif pipeline_result is not None:
            producer_identity = _runtime_provenance_identity(
                PROMPT_VERSION if meta.get("mode") == "ai" else "not-used"
            )
        else:
            producer_identity = _stored_producer_identity(info)
        producer_known = producer_identity.get("app_version") != "unknown"
        provenance = {
            "runtime": {
                "app_version": (
                    producer_identity.get("app_version") if producer_known else None
                ),
                "git_commit": (
                    producer_identity.get("commit")
                    if producer_identity.get("commit") != "unknown"
                    else None
                ),
                "build_id": (
                    producer_identity.get("build_id")
                    if producer_identity.get("build_id") != "unknown"
                    else None
                ),
                "dirty": None,
                "python_version": sys.version.split()[0] if producer_known else None,
                "platform": sys.platform if producer_known else None,
                "started_at": (
                    _audit_iso_timestamp(
                        capture.get("started")
                        if capture.get("started") is not None
                        else capture.get("created")
                    )
                    if capture.get("started") is not None
                    or capture.get("created") is not None
                    else None
                ),
                "finished_at": (
                    _audit_iso_timestamp(capture.get("finished"))
                    if capture.get("finished") is not None
                    else None
                ),
                "identity_status": "RECORDED" if producer_known else "UNKNOWN",
                **({
                    "reason": "legacy run did not persist producer identity"
                } if not producer_known else {}),
            },
            "models": {
                "ocr": model_identity("ocr", "ocr"),
                "decision": model_identity("decide", "analysis"),
                "review": model_identity("review", "review"),
            },
            "prompts": {
                "ocr_prompt_version": (
                    str((meta.get("ocr_processing") or {}).get("prompt_version") or "")
                    or None
                ),
                "decision_prompt_version": (
                    producer_identity.get("prompt_version")
                    if stages["analysis"]["status"] == "COMPLETED"
                    and producer_identity.get("prompt_version") != "unknown"
                    else None
                ),
                "review_prompt_version": (
                    producer_identity.get("prompt_version")
                    if stages["review"]["status"] == "COMPLETED"
                    and producer_identity.get("prompt_version") != "unknown"
                    else None
                ),
                "decision_schema_version": None,
                "review_schema_version": None,
            },
            "template": {
                "id": str(meta.get("template") or "none"),
                "version": (
                    template_payload.get("template_version")
                    if isinstance(template_payload, dict)
                    else None
                ),
                "asset_manifest_sha256": (
                    template_payload.get("asset_manifest_sha256")
                    if isinstance(template_payload, dict)
                    else None
                ),
            },
        }
        return RunSnapshot(
            project_id=pid,
            run_id=str(run_id),
            workflow=workflow,
            terminal_status=terminal_status,
            captured_at=_audit_iso_timestamp(capture.get("finished") or time.time()),
            artifacts=tuple(artifacts),
            machine_verification=verification,
            blockers=tuple(blocker_rows),
            model=model,
            app_version=str(producer_identity.get("app_version") or "unknown"),
            template=str(meta.get("template") or "none"),
            page_range=page_range,
            metadata={
                "project_kind": str(meta.get("kind") or "tex"),
                "mode": str(meta.get("mode") or ""),
                "review_revision": _review_state_payload(meta)["revision"],
                "preview_status": preview_status,
                "host_state_fingerprint": _audit_host_state_fingerprint(pid),
            },
            stages=stages,
            source_pdf=source_pdf_info,
            provenance=provenance,
        )

    def _project_audit_store(pid: str):
        from .audit_store import AuditSubmissionStore

        _ensure(pid)
        return AuditSubmissionStore(get_store()._dir(pid))

    def _persist_terminal_audit_snapshot(pid: str, snapshot: RunSnapshot):
        """Publish four lightweight files before a task terminal is exposed."""
        # The store commits the immutable snapshot, its four controls, the
        # latest pointer and staleness of prior snapshots under one root lock.
        # In particular, publishing a new terminal run must be able to repair a
        # previously corrupted latest control set instead of failing the main
        # processing task.
        return _project_audit_store(pid).persist_terminal_snapshot(snapshot)

    def _freeze_analysis_run_archive(
        pid: str,
        run_id: str,
        terminal_status: TerminalStatus,
        snapshot: RunSnapshot,
        capture: dict,
    ) -> dict:
        """Run the host-owned v2 evidence gate and freeze its immutable archive.

        Existing pipeline compile/visual/decision evidence is reused without a
        new model call.  The v2 runtime owns candidates, rollback and terminal
        status; legacy ``safe_to_export`` remains non-authoritative.
        """

        def artifact_for(*roles: str):
            wanted = set(roles)
            return next(
                (
                    artifact
                    for artifact in reversed(snapshot.artifacts)
                    if artifact.artifact_role in wanted
                ),
                None,
            )

        def artifact_text(*roles: str) -> str:
            artifact = artifact_for(*roles)
            if artifact is None:
                return ""
            try:
                return artifact.data.decode("utf-8")
            except UnicodeDecodeError:
                return ""

        def compiled_pdf_for(role: str) -> bytes:
            artifact = artifact_for(role)
            if (
                artifact is None
                or artifact.media_type != "application/pdf"
                or artifact.preview_status not in {"COMPILED", "PARTIAL_COMPILED"}
                or not artifact.data.startswith(b"%PDF-")
            ):
                return b""
            return bytes(artifact.data)

        verification = thaw_json(snapshot.machine_verification)
        if not isinstance(verification, dict):
            verification = {}
        pipeline_result = capture.get("pipeline_result")
        is_ocr = str(snapshot.metadata.get("project_kind") or "") == "ocr"

        source_pdf_artifact = artifact_for(ArtifactRole.SOURCE_PDF)
        source_pdf = bytes(source_pdf_artifact.data) if source_pdf_artifact else b""
        source_tex = artifact_text(ArtifactRole.SOURCE_TEX)
        raw_ocr_tex = artifact_text(ArtifactRole.RAW_OCR_TEX) if is_ocr else ""
        original_text = str(
            getattr(pipeline_result, "original", "") or raw_ocr_tex or source_tex
        )
        if not source_tex and not is_ocr:
            source_tex = original_text or artifact_text(ArtifactRole.STAGE_SOURCE_TEX)

        baseline_tex = str(
            getattr(pipeline_result, "raw_compiled_tex", "") or original_text
        )
        baseline_pdf = compiled_pdf_for(ArtifactRole.RAW_OCR_PREVIEW)
        compile_before = verification.get("compile_before")
        compile_before = compile_before if isinstance(compile_before, dict) else {}
        compile_after = verification.get("compile_after")
        compile_after = compile_after if isinstance(compile_after, dict) else {}

        pipeline_ok = bool(
            pipeline_result is not None and getattr(pipeline_result, "ok", False)
        )
        if pipeline_result is not None and not pipeline_ok:
            # A blocked run still has a useful *attempted* candidate when the
            # captured CURRENT_TEX and CURRENT_PREVIEW are hash-bound to the
            # exact compile evidence.  Preserve it in the immutable candidate
            # history so the v2 quality runtime can compare it with baseline
            # and continue from history-best.  It remains UNVERIFIED and never
            # replaces the ordinary project result merely because it compiled.
            attempted_tex = artifact_text(ArtifactRole.CURRENT_TEX)
            attempted_pdf = compiled_pdf_for(ArtifactRole.CURRENT_PREVIEW)
            preview_evidence = verification.get("preview_artifact")
            preview_evidence = (
                preview_evidence if isinstance(preview_evidence, dict) else {}
            )
            attempted_tex_hash = sha256_bytes(attempted_tex.encode("utf-8"))
            attempted_pdf_hash = sha256_bytes(attempted_pdf) if attempted_pdf else ""
            attempted_exact = bool(
                attempted_tex
                and attempted_pdf
                and preview_evidence.get("tex_sha256") == attempted_tex_hash
                and preview_evidence.get("pdf_sha256") == attempted_pdf_hash
            )
            if attempted_exact:
                current_tex = attempted_tex
                current_pdf = attempted_pdf
                current_compile_log = str(compile_after.get("log") or "")
            else:
                current_tex = str(
                    getattr(pipeline_result, "result", "") or original_text
                )
                raw_compiled_tex = str(
                    getattr(pipeline_result, "raw_compiled_tex", "") or ""
                )
                current_pdf = (
                    baseline_pdf
                    if raw_compiled_tex and raw_compiled_tex == current_tex
                    else b""
                )
                current_compile_log = str(
                    compile_before.get("log") or "" if current_pdf else ""
                )
        else:
            current_tex = artifact_text(ArtifactRole.CURRENT_TEX) or str(
                getattr(pipeline_result, "result", "") or original_text
            )
            current_pdf = compiled_pdf_for(ArtifactRole.CURRENT_PREVIEW)
            current_compile_log = str(compile_after.get("log") or "")

        source_info = snapshot.source_pdf
        if source_info is not None and source_info.page_count:
            page_count = int(source_info.page_count)
            selected_pages = tuple(source_info.selected_page_range.pages)
            page_range = selected_pages or tuple(range(1, page_count + 1))
        else:
            page_count = 1
            page_range = (1,)

        decision_items = [
            dict(item)
            for item in (getattr(pipeline_result, "decision_items", ()) or ())
            if isinstance(item, dict)
        ]
        # Page markers are immutable OCR output, so binding a decision line to
        # the most recent marker is a deterministic host operation, not an LLM
        # guess.  Single-page TEX inputs have the same unambiguous binding.
        marker_by_line: dict[int, int] = {}
        active_page = page_range[0] if len(page_range) == 1 else 0
        for line_number, line in enumerate(current_tex.splitlines(), 1):
            marker = re.match(r"^\s*%+\s*Page\s+(\d+)\b", line, re.IGNORECASE)
            if marker:
                active_page = int(marker.group(1))
            if active_page in page_range:
                marker_by_line[line_number] = active_page
        for item in decision_items:
            if any(
                item.get(key) not in {None, ""}
                for key in ("source_page_id", "source_page_number", "page_number", "pdf_page")
            ):
                continue
            try:
                line_number = int(item.get("line") or 0)
            except (TypeError, ValueError):
                line_number = 0
            bound_page = marker_by_line.get(line_number)
            if bound_page:
                item["source_page_number"] = bound_page

        provenance = snapshot.provenance.to_dict()
        model_rows = provenance.get("models") or {}
        role_names = {
            "ocr": ("OCR", ("vision", "transcription")),
            "decision": ("STRUCTURE_ANALYSIS", ("text", "structure")),
            "review": ("INDEPENDENT_REVIEW", ("text", "review")),
        }
        models = []
        for name, (role, capabilities) in role_names.items():
            record = model_rows.get(name)
            if not isinstance(record, dict):
                continue
            model_id = str(record.get("model") or "").strip()
            if model_id:
                models.append(ModelBinding(role, model_id, capabilities))
        if not models:
            models = [ModelBinding(
                "HOST_PIPELINE",
                str(snapshot.model or "unrecorded-model"),
                ("artifact-freeze",),
            )]

        prompt_rows = provenance.get("prompts") or {}
        prompt_version = next(
            (
                str(prompt_rows.get(name))
                for name in (
                    "review_prompt_version",
                    "decision_prompt_version",
                    "ocr_prompt_version",
                )
                if prompt_rows.get(name)
            ),
            "not-recorded",
        )
        elapsed = max(
            0.0,
            float(capture.get("finished") or time.time())
            - float(capture.get("started") or capture.get("created") or time.time()),
        )
        v2_evidence = verification.get("v2_verification_evidence")
        if not isinstance(v2_evidence, dict):
            v2_evidence = None
        rollback_history = []
        if verification.get("rolled_back") is True:
            rollback_history.append({
                "reason": "pipeline machine gates retained the prior/source best",
                "host_recorded": True,
            })

        try:
            archived = freeze_pipeline_analysis_run(
                project_dir=get_store()._dir(pid),
                run_id=run_id,
                project_id=pid,
                artifacts=AnalysisRunArtifacts(
                    source_pdf=source_pdf,
                    source_tex=source_tex,
                    raw_ocr_tex=raw_ocr_tex,
                    baseline_tex=baseline_tex,
                    baseline_pdf=baseline_pdf,
                    baseline_compile_log=str(compile_before.get("log") or ""),
                    current_tex=current_tex,
                    current_pdf=current_pdf,
                    current_compile_log=current_compile_log,
                    verification=verification,
                    decision_items=tuple(decision_items),
                    report_md=artifact_text(ArtifactRole.REPORT),
                    rollback_history=tuple(rollback_history),
                ),
                page_range=page_range,
                page_count=page_count,
                models=tuple(models),
                application_version=str(snapshot.app_version or "unknown"),
                verification_evidence=v2_evidence,
                processing_failed=terminal_status in {
                    TerminalStatus.FAILED,
                    TerminalStatus.CANCELLED,
                },
                prompt_version=prompt_version,
                started_at=str(
                    (provenance.get("runtime") or {}).get("started_at")
                    or snapshot.captured_at
                ),
                performance_metrics={
                    "available": True,
                    "elapsed_seconds": elapsed,
                    "source": "host pipeline timestamps",
                },
                config={
                    "workflow": snapshot.workflow.value,
                    "terminal_status": terminal_status.value,
                    "template": snapshot.template,
                    "page_range": snapshot.page_range,
                    "audit_snapshot_id": snapshot.snapshot_id,
                },
            )
            quality_path = archived.run_directory / "audit" / "quality_vector.json"
            quality = json.loads(quality_path.read_text(encoding="utf-8"))
            relative_path = PurePosixPath("analysis-runs", run_id).as_posix()
            failures = list(archived.failures)
            return {
                "archive_status": "READY",
                "run_id": run_id,
                "final_status": archived.status.value,
                "verified": archived.verified,
                "relative_path": relative_path,
                "snapshot_sha256": archived.snapshot_sha256,
                "artifact_count": archived.artifact_count,
                "failures": failures,
                "quality": {
                    "evidence_complete": bool(quality.get("evidence_complete")),
                    "unknown_fields": list(quality.get("unknown_fields") or ()),
                    "vector": quality.get("vector") or {},
                    "priority_key": list(quality.get("priority_key") or ()),
                },
                "quality_runtime": {
                    "executed": archived.runtime_executed,
                    "best_candidate_id": archived.best_candidate_id,
                    "candidate_count": archived.candidate_count,
                    "rollback_count": archived.rollback_count,
                },
                "verification": {
                    "status": "VERIFIED" if archived.verified else "UNVERIFIED",
                    "verified": archived.verified,
                    "failure_count": len(failures),
                    "failures": failures,
                    "evidence_source": archived.evidence_source,
                    "review_pass_count": archived.review_pass_count,
                },
            }
        except Exception as exc:
            failure = "analysis_archive_freeze_failed"
            return {
                "archive_status": "FAILED",
                "run_id": run_id,
                "final_status": AnalysisFinalStatus.FAILED_BEST_RETAINED.value,
                "verified": False,
                "relative_path": None,
                "snapshot_sha256": None,
                "artifact_count": 0,
                "failures": [failure],
                "quality": {
                    "evidence_complete": False,
                    "unknown_fields": ["analysis_archive_unavailable"],
                    "vector": {},
                    "priority_key": [],
                },
                "quality_runtime": {
                    "executed": False,
                    "best_candidate_id": "",
                    "candidate_count": 0,
                    "rollback_count": 0,
                },
                "verification": {
                    "status": "UNVERIFIED",
                    "verified": False,
                    "failure_count": 1,
                    "failures": [failure],
                    "evidence_source": "archive-failure",
                    "review_pass_count": 0,
                },
                "error": sanitize_plain_text(_safe_task_error(exc)),
            }

    def _current_record(pid: str) -> dict:
        """Return the newest hash-verified attempt, even when TEX validation failed."""
        _ensure(pid)
        directory = Path(get_store()._dir(pid))
        failure_paths = (
            directory / "last-failure.json",
            directory / "last-failed-draft.tex",
            directory / "last-failure-report.md",
        )
        failure_present = any(path.exists() for path in failure_paths)
        committed_marker = directory / "verification.json"
        # A successful commit clears the old failure triplet.  If cleanup itself
        # was interrupted, the newer committed marker still wins; otherwise a
        # stale diagnostic draft could shadow a later successful run forever.
        failure_is_current = failure_present and (
            not committed_marker.exists()
            or max(path.stat().st_mtime_ns for path in failure_paths if path.exists())
            > committed_marker.stat().st_mtime_ns
        )
        if failure_is_current:
            failed = get_store().read_failed_attempt(pid)
            if failed is None:
                raise HTTPException(
                    409,
                    "当前未验证草稿或汇报的哈希校验失败，已阻止导出；请重新分析",
                )
            return {
                "info": failed.get("details") or {},
                "result": str(failed.get("draft") or "").encode("utf-8"),
                "report": str(failed.get("report") or "").encode("utf-8"),
                "verified": False,
                "attempt": "blocked",
                "directory": directory,
            }

        result_path = directory / "result.tex"
        marker_path = directory / "verification.json"
        if result_path.exists() or marker_path.exists():
            info, result_bytes, _directory = _committed_record(pid)
            report_bytes = _committed_report(pid)
            verification = info.get("verification") if isinstance(info, dict) else None
            verified = bool(
                isinstance(verification, dict)
                and verification.get("safe_to_export") is True
            )
            if verified:
                _verified_info, result_bytes = _committed_export(pid)
            return {
                "info": info,
                "result": result_bytes,
                "report": report_bytes,
                "verified": verified,
                "attempt": "committed",
                "directory": directory,
            }

        # A task can fail before producing a structured draft (for example an AI
        # transport error).  The imported source is still a useful current TEX
        # artifact and remains exportable with an explicit unverified marker.
        original_source = directory / "original-source.tex"
        source_bytes = (
            original_source.read_bytes()
            if original_source.is_file()
            else get_store().read_source(pid).encode("utf-8")
        )
        report_bytes = (
            "# LaTeXStruct 当前导出\n\n"
            "本次分析尚未产生可校验的结构化草稿；此包保留原始导入 TEX。\n"
        ).encode("utf-8")
        return {
            "info": {},
            "result": source_bytes,
            "report": report_bytes,
            "verified": False,
            "attempt": "source",
            "directory": directory,
        }

    def _current_audit_capture(pid: str) -> dict:
        """Read current host files for stale checking or a legacy snapshot.

        Unlike a terminal capture, this intentionally has no fabricated AI
        stages.  It only reuses the committed/failed records already held by
        the project store and the hash-bound compiled preview when one exists.
        """
        record = _current_record(pid)
        directory = Path(record["directory"])
        info = deepcopy(record.get("info") or {})
        result_bytes = bytes(record.get("result") or b"")
        compiled_pdf = b""
        try:
            preview = _compile_preview_package_entry(pid, info, result_bytes)
        except HTTPException:
            preview = None
        if preview is not None:
            _name, compiled_pdf = preview
        verification = info.get("verification")
        if not isinstance(verification, dict):
            verification = {}
        raw_compiled_pdf = b""
        raw_evidence = verification.get("raw_preview_artifact")
        if isinstance(raw_evidence, dict):
            from ..core.preview import (
                COMPILED,
                PARTIAL_COMPILED,
                preview_storage_filename,
            )

            raw_status = str(raw_evidence.get("status") or "")
            raw_digest = str(raw_evidence.get("sha256") or "")
            if raw_status in {COMPILED, PARTIAL_COMPILED} and re.fullmatch(
                r"[0-9a-f]{64}", raw_digest
            ):
                candidate = directory / preview_storage_filename(
                    raw_status, raw_digest
                )
                try:
                    payload = candidate.read_bytes()
                except OSError:
                    payload = b""
                if (
                    payload.startswith(b"%PDF-")
                    and hmac.compare_digest(
                        hashlib.sha256(payload).hexdigest(), raw_digest
                    )
                ):
                    raw_compiled_pdf = payload
        return {
            "info": info,
            "verification": deepcopy(verification),
            "report_md": bytes(record.get("report") or b"").decode(
                "utf-8", errors="replace"
            ),
            "compiled_pdf": compiled_pdf,
            "raw_compiled_pdf": raw_compiled_pdf,
            "preview_state": str(
                verification.get("preview_state")
                or preview_state_from_verification(verification)
                or "SOURCE_PREVIEW"
            ),
            "preview": result_bytes.decode("utf-8", errors="replace"),
            "events": [],
        }

    def _current_audit_fingerprint(
        pid: str,
        terminal_status: TerminalStatus,
    ) -> str:
        latest = _project_audit_store(pid).latest()
        if latest is not None:
            frozen = _project_audit_store(pid).load_snapshot(latest.snapshot_id)
            expected_host_state = str(
                frozen.metadata.get("host_state_fingerprint") or ""
            )
            if expected_host_state and hmac.compare_digest(
                expected_host_state,
                _audit_host_state_fingerprint(pid),
            ):
                return latest.snapshot_fingerprint
        snapshot = _build_project_run_snapshot(
            pid,
            terminal_status,
            f"state-{uuid.uuid4().hex}",
            capture=_current_audit_capture(pid),
        )
        return snapshot.current_fingerprint

    def _write_ocr_package_resources(zf, pid: str, meta: dict, reserved: dict) -> None:
        resource_info = meta.get("ocr_resources") or {}
        project_dir = Path(get_store()._dir(pid)).resolve()
        processing = meta.get("ocr_processing") if isinstance(
            meta.get("ocr_processing"), dict
        ) else {}
        quality = meta.get("ocr_quality") if isinstance(
            meta.get("ocr_quality"), dict
        ) else {}
        profile = str(processing.get("profile") or quality.get("profile") or "standard")
        try:
            source_file = _verified_ocr_source_bytes(
                project_dir,
                meta.get("ocr_source") or {},
                required=profile == OCR_QUALITY_PUBLICATION,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        try:
            resource_files = _verified_ocr_resource_bytes(
                project_dir,
                resource_info,
                include_source_pages=True,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        existing = set(zf.namelist())
        if source_file is not None:
            source_rel, source_bytes, source_record = source_file
            if source_rel in reserved or source_rel in existing or source_rel == "main.tex":
                raise HTTPException(409, f"OCR 原始来源路径与工程文件冲突：{source_rel}")
            zf.writestr(source_rel, source_bytes)
            existing.add(source_rel)
            if source_record.get("source_type") == "images":
                visual = source_record.get("visual_source") or {}
                visual_rel = str(visual.get("path") or "")
                visual_path = (project_dir / Path(visual_rel)).resolve()
                try:
                    visual_path.relative_to(project_dir)
                    visual_bytes = visual_path.read_bytes()
                except (OSError, ValueError):
                    raise HTTPException(409, "OCR 多图片派生视觉 PDF 已丢失") from None
                if (
                    visual_rel in reserved
                    or visual_rel in existing
                    or not visual_bytes.startswith(b"%PDF-")
                    or not hmac.compare_digest(
                        str(visual.get("sha256") or "").lower(),
                        hashlib.sha256(visual_bytes).hexdigest(),
                    )
                ):
                    raise HTTPException(409, "OCR 多图片派生视觉 PDF 校验失败")
                zf.writestr(visual_rel, visual_bytes)
                existing.add(visual_rel)
        else:
            source_record = {
                "available": False,
                "immutable_evidence": False,
                "reason": "legacy_project_without_source",
            }
        for rel, data in resource_files.items():
            if rel in reserved or rel in existing or rel == "main.tex":
                raise HTTPException(409, f"OCR 图片路径与工程文件冲突：{rel}")
            zf.writestr(rel, data)
            existing.add(rel)
        for manifest_name in ("OCR-RESOURCES.json", "OCR-QUALITY.json"):
            if manifest_name in reserved or manifest_name in existing:
                raise HTTPException(409, f"OCR 证据清单与工程文件冲突：{manifest_name}")
        zf.writestr(
            "OCR-RESOURCES.json",
            json.dumps(resource_info, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        zf.writestr(
            "OCR-QUALITY.json",
            json.dumps(
                {
                    "format": "latexstruct-ocr-quality-v1",
                    "source": source_record,
                    "processing": deepcopy(processing),
                    "quality": deepcopy(quality),
                },
                ensure_ascii=False,
                indent=2,
            ).encode("utf-8"),
        )

    def _validate_project_package_namespace(
        pid: str,
        meta: dict,
        per_file: object,
        reserved_paths: object,
        *,
        allow_identical_paths: object = (),
    ) -> None:
        """Fail closed before a user path can shadow package evidence files."""
        from ..core.project import safe_project_relpath

        project_paths: set[str] = set()
        original_files: dict[str, bytes] = {}
        if meta.get("kind") == "folder":
            original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
            if not original_zip.is_file():
                raise HTTPException(409, "原始文件夹工程快照缺失，已阻止打包")
            try:
                original_files = _decode_zip_files(original_zip.read_bytes())
                project_paths.update(original_files)
            except (OSError, ValueError) as exc:
                raise HTTPException(409, f"原始工程命名空间无效：{exc}") from None
            graph = meta.get("graph") if isinstance(meta.get("graph"), dict) else {}
            project_paths.add(safe_project_relpath(str(graph.get("main_rel") or "")))
            if isinstance(per_file, dict):
                project_paths.update(
                    safe_project_relpath(str(rel))
                    for rel in per_file
                    if rel
                )
        else:
            project_paths.add("main.tex")

        reserved_map = dict(reserved_paths) if isinstance(reserved_paths, dict) else {
            str(path): b"" for path in reserved_paths
        }
        for path in allow_identical_paths:
            name = str(path)
            if (
                name in project_paths
                and name in original_files
                and name in reserved_map
                and original_files[name] == reserved_map[name]
            ):
                project_paths.remove(name)
        reserved = set(reserved_map)
        if meta.get("kind") == "ocr":
            reserved.update({"OCR-RESOURCES.json", "OCR-QUALITY.json"})
            source = meta.get("ocr_source")
            if isinstance(source, dict) and source.get("available"):
                project_paths.add(safe_project_relpath(str(source.get("path") or "")))
            resources = meta.get("ocr_resources")
            if isinstance(resources, dict):
                for group in ("assets", "source_pages"):
                    for item in resources.get(group) or []:
                        if isinstance(item, dict):
                            project_paths.add(
                                safe_project_relpath(str(item.get("path") or ""))
                            )
        reserved.update(RUN_BUNDLE_NAMES)
        try:
            validate_archive_namespace(
                [(path, False) for path in sorted(project_paths)],
                additions=tuple(sorted(reserved)),
            )
        except ValueError as exc:
            raise HTTPException(409, f"工程文件与导出保留路径冲突：{exc}") from None

    def _current_package_bytes(pid: str) -> tuple[bytes, bool]:
        """Build a portable package for the newest attempt without claiming it is valid."""
        from ..core.project import safe_project_relpath
        from ..core.template import uses_elegantbook_class
        from ..elegantbook import elegantbook_bundle_assets

        current = _current_record(pid)
        if current["verified"] and current["attempt"] == "committed":
            return _export_package_bytes(pid), True

        meta = json.loads(
            (Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8")
        )
        warning = (
            "This is the newest LaTeXStruct draft, exported at the user's request.\n"
            "It did not pass every verification/compile check. Read LATEXSTRUCT-REPORT.md.\n"
        ).encode("utf-8")
        try:
            current_text = current["result"].decode("utf-8")
        except UnicodeDecodeError:
            current_text = ""
        template_assets = (
            elegantbook_bundle_assets() if uses_elegantbook_class(current_text) else {}
        )
        info = current.get("info") or {}
        preview_entry = _compile_preview_package_entry(pid, info, current["result"])
        reserved = {
            **template_assets,
            "LATEXSTRUCT-REPORT.md": current["report"],
            "LATEXSTRUCT-UNVERIFIED.txt": warning,
            RAW_ARTIFACT_PACKAGE_PATH: _project_raw_artifact_bytes(pid),
            PROVENANCE_MANIFEST_NAME: b"",
        }
        if preview_entry is not None:
            reserved[preview_entry[0]] = preview_entry[1]
        per_file = info.get("per_file") if isinstance(info, dict) else None
        _validate_project_package_namespace(
            pid,
            meta,
            per_file,
            reserved,
            allow_identical_paths=template_assets,
        )
        provenance = None
        main_artifact = "main.tex"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            written = set()
            if meta.get("kind") == "folder" and not (
                isinstance(per_file, dict) and per_file
            ):
                original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
                if not original_zip.is_file():
                    raise HTTPException(409, "原始文件夹工程快照缺失，已阻止保真导出")
                graph = meta.get("graph") or {}
                main_rel = safe_project_relpath(str(graph.get("main_rel") or "main.tex"))
                main_artifact = main_rel
                with zipfile.ZipFile(original_zip, "r") as source_zip:
                    for member in source_zip.infolist():
                        if member.is_dir():
                            continue
                        rel = safe_project_relpath(member.filename)
                        data = source_zip.read(member)
                        if rel in reserved:
                            if rel in template_assets and data == reserved[rel]:
                                continue
                            raise HTTPException(
                                409, f"原项目中的 {rel} 与导出说明文件冲突"
                            )
                        if rel == main_rel:
                            data, provenance = _stamp_project_tex(
                                pid,
                                data,
                                verified=False,
                                attempt=current["attempt"],
                                artifact_kind="unverified-project-main-tex",
                                producer_identity=_stored_producer_identity(info),
                            )
                        zf.writestr(rel, data)
                        written.add(rel)
            elif meta.get("kind") == "folder":
                from ..core.project import encode_project_files

                graph = meta.get("graph") or {}
                main_rel = safe_project_relpath(str(graph.get("main_rel") or "main.tex"))
                main_artifact = main_rel
                original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
                if not original_zip.is_file():
                    raise HTTPException(409, "原始文件夹工程快照缺失，已阻止保真导出")
                original_files = _decode_zip_files(original_zip.read_bytes())
                try:
                    encoded_files = encode_project_files(
                        original_files, main_rel, per_file
                    )
                except ValueError as exc:
                    raise HTTPException(409, str(exc)) from None
                stamped_main, provenance = _stamp_project_tex(
                    pid,
                    encoded_files[main_rel],
                    verified=False,
                    attempt=current["attempt"],
                    artifact_kind="unverified-project-main-tex",
                    producer_identity=_stored_producer_identity(info),
                )
                zf.writestr(main_rel, stamped_main)
                written.add(main_rel)
                for rel, _content in per_file.items():
                    if not rel:
                        continue
                    safe_rel = safe_project_relpath(rel)
                    zf.writestr(safe_rel, encoded_files[safe_rel])
                    written.add(safe_rel)
            else:
                stamped_main, provenance = _stamp_project_tex(
                    pid,
                    current["result"],
                    verified=False,
                    attempt=current["attempt"],
                    artifact_kind="unverified-current-tex",
                    producer_identity=_stored_producer_identity(info),
                )
                zf.writestr("main.tex", stamped_main)
                written.add("main.tex")

            original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
            if original_zip.exists():
                with zipfile.ZipFile(original_zip, "r") as source_zip:
                    for member in source_zip.infolist():
                        rel = safe_project_relpath(member.filename)
                        if member.is_dir() or rel in written:
                            continue
                        data = source_zip.read(member)
                        if rel in reserved:
                            if rel in template_assets and data == reserved[rel]:
                                continue
                            raise HTTPException(
                                409,
                                f"原项目中的 {rel} 与固定工程资源冲突，已阻止打包",
                            )
                        zf.writestr(rel, data)
                        written.add(rel)
            if meta.get("kind") == "ocr":
                _write_ocr_package_resources(zf, pid, meta, reserved)
            if provenance is None:
                raise HTTPException(409, "项目主 TEX 缺失，无法生成可核验导出清单")
            reserved[PROVENANCE_MANIFEST_NAME] = _provenance_json_bytes(provenance)
            existing = set(zf.namelist())
            for rel, data in reserved.items():
                if rel not in existing:
                    zf.writestr(rel, data)
        try:
            bundled = append_run_bundle(
                output.getvalue(),
                info=info,
                provenance=provenance,
                terminal_status=current["attempt"],
                attempt=current["attempt"],
                main_path=main_artifact,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        return bundled, False

    def _export_package_bytes(pid: str) -> bytes:
        """Build a portable project package from the same committed result marker."""
        from ..core.project import safe_project_relpath
        from ..core.template import uses_elegantbook_class
        from ..elegantbook import elegantbook_bundle_assets

        info, result_bytes = _committed_export(pid)
        report_bytes = _committed_report(pid)
        from ..core.project import decode_tex_bytes

        result_text = decode_tex_bytes(result_bytes).text
        assets = elegantbook_bundle_assets() if uses_elegantbook_class(result_text) else {}
        reserved = {
            **assets,
            "LATEXSTRUCT-REPORT.md": report_bytes,
            RAW_ARTIFACT_PACKAGE_PATH: _project_raw_artifact_bytes(pid),
            PROVENANCE_MANIFEST_NAME: b"",
        }
        preview_entry = _compile_preview_package_entry(pid, info, result_bytes)
        if preview_entry is not None:
            reserved[preview_entry[0]] = preview_entry[1]
        meta = json.loads(
            (Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8")
        )
        per_file = info.get("per_file") if isinstance(info, dict) else None
        _validate_project_package_namespace(
            pid,
            meta,
            per_file,
            reserved,
            allow_identical_paths=assets,
        )
        provenance = None
        main_artifact = "main.tex"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            if per_file:
                from ..core.project import encode_project_files

                graph = meta.get("graph") or {}
                main_rel = safe_project_relpath(graph.get("main_rel", ""))
                main_artifact = main_rel
                processed = {main_rel} | {
                    safe_project_relpath(rel) for rel in per_file if rel
                }
                written = set()
                original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
                if not original_zip.is_file():
                    raise HTTPException(409, "原始文件夹工程快照缺失，已阻止保真导出")
                original_files = _decode_zip_files(original_zip.read_bytes())
                try:
                    encoded_files = encode_project_files(
                        original_files, main_rel, per_file
                    )
                except ValueError as exc:
                    raise HTTPException(409, str(exc)) from None
                if original_zip.exists():
                    with zipfile.ZipFile(original_zip, "r") as source_zip:
                        for member in source_zip.infolist():
                            rel = safe_project_relpath(member.filename)
                            if member.is_dir() or rel in processed:
                                continue
                            data = source_zip.read(member)
                            if rel in reserved:
                                if rel not in assets or data != reserved[rel]:
                                    raise HTTPException(
                                        409,
                                        f"原项目中的 {rel} 与固定工程资源冲突，已阻止打包",
                                    )
                            else:
                                zf.writestr(rel, data)
                            written.add(rel)
                stamped_main, provenance = _stamp_project_tex(
                    pid,
                    encoded_files[main_rel],
                    verified=True,
                    attempt="committed",
                    result_sha256=str(info.get("result_sha256") or ""),
                    artifact_kind="verified-project-main-tex",
                    producer_identity=_stored_producer_identity(info),
                )
                zf.writestr(main_rel, stamped_main)
                written.add(main_rel)
                for rel, _content in per_file.items():
                    if not rel:
                        continue
                    safe_rel = safe_project_relpath(rel)
                    zf.writestr(safe_rel, encoded_files[safe_rel])
                    written.add(safe_rel)
                expected = meta.get("original_file_count")
                if expected is not None and len(written) != expected:
                    raise HTTPException(
                        409,
                        f"文件数量安全检查未通过（原始 {expected}，导出 {len(written)}），已阻止导出。",
                    )
            else:
                stamped_main, provenance = _stamp_project_tex(
                    pid,
                    result_bytes,
                    verified=True,
                    attempt="committed",
                    result_sha256=str(info.get("result_sha256") or ""),
                    artifact_kind="verified-structured-tex",
                    producer_identity=_stored_producer_identity(info),
                )
                zf.writestr("main.tex", stamped_main)
                if meta.get("kind") == "ocr":
                    resource_info = meta.get("ocr_resources") or {}
                    unresolved = list(resource_info.get("unresolved") or [])
                    if unresolved:
                        raise HTTPException(
                            409,
                            "仍有 OCR 图片未能从原 PDF 可靠提取："
                            + "、".join(str(item) for item in unresolved[:5]),
                        )
                    _write_ocr_package_resources(zf, pid, meta, reserved)
            if provenance is None:
                raise HTTPException(409, "项目主 TEX 缺失，无法生成可核验导出清单")
            reserved[PROVENANCE_MANIFEST_NAME] = _provenance_json_bytes(provenance)
            existing = set(zf.namelist())
            for rel, data in reserved.items():
                if rel not in existing:
                    zf.writestr(rel, data)
        try:
            return append_run_bundle(
                buf.getvalue(),
                info=info,
                provenance=provenance,
                terminal_status="success",
                attempt="committed",
                main_path=main_artifact,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/projects/{pid}/export-package")
    def export_package(pid: str):
        data = _export_package_bytes(pid)
        return Response(
            content=data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{pid}-structured-project.zip"'},
        )

    @app.get("/api/projects/{pid}/export-folder")
    def export_folder(pid: str):
        """Backward-compatible alias for clients released before package export."""
        return export_package(pid)

    @app.post("/api/projects/upload")
    async def upload_project(file: bytes = None, name: str = "", mode: str = "ai"):
        # 简化 multipart：由前端读文件后走 /api/projects
        raise HTTPException(400, "请使用 /api/projects 提交文本")

    @app.get("/api/projects/{pid}")
    def get_project(pid: str):
        p = get_store().get(pid)
        if p is None:
            raise HTTPException(404, "项目不存在")
        return p

    def _legacy_audit_terminal_status(pid: str) -> TerminalStatus:
        job = _process_jobs.latest(pid)
        if job is not None:
            status = str(job.get("status") or "")
            if status == "error":
                return TerminalStatus.FAILED
            if status == "cancelled":
                return TerminalStatus.CANCELLED
            if status == "blocked":
                return TerminalStatus.UNVERIFIED
            if status == "done":
                return (
                    TerminalStatus.SUCCESS
                    if (job.get("result") or {}).get("ok") is True
                    else TerminalStatus.UNVERIFIED
                )
        record = _current_record(pid)
        return (
            TerminalStatus.SUCCESS
            if record.get("verified") is True
            else TerminalStatus.UNVERIFIED
        )

    def _audit_submission_summary(pid: str, stored, *, transient_stale: str = ""):
        audit_store = _project_audit_store(pid)
        snapshot = audit_store.load_snapshot(stored.snapshot_id)
        submission_directory = audit_store.root / Path(stored.relative_directory)
        short_path = submission_directory / "01_PROMPT_SHORT.txt"
        manifest_path = submission_directory / "submission_manifest.json"
        try:
            short_prompt = short_path.read_text(encoding="utf-8").strip()
        except OSError:
            short_prompt = ""
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            manifest = {}
        stale_reason = transient_stale or stored.stale_reason
        stale = bool(stored.stale or transient_stale)
        zip_filename = (
            Path(stored.zip_relative_path).name if stored.zip_relative_path else None
        )
        try:
            saved_filename = audit_store.saved_download_filename(
                stored.submission_id
            ) or None
        except (OSError, TypeError, ValueError):
            # The optional Downloads sidecar must never make the immutable
            # package unreadable.  Omit an untrusted local-copy claim instead.
            saved_filename = None
        preview_state = str(
            snapshot.metadata.get("preview_status") or "SOURCE_PREVIEW"
        )
        return {
            **stored.to_dict(),
            "captured_at": snapshot.captured_at,
            "run_terminal_status": stored.terminal_status,
            "preview_state": preview_state,
            "profile": stored.depth,
            "bundle_state": (
                "ZIP_READY" if stored.state == "READY" else "LIGHTWEIGHT"
            ),
            "artifact_count": len(manifest.get("artifacts") or []),
            "snapshot_artifact_count": len(snapshot.artifacts),
            "filename": saved_filename or zip_filename,
            "archive_filename": zip_filename,
            "saved_filename": saved_filename,
            "folder": "下载/LaTeXStruct" if saved_filename else None,
            "short_prompt": short_prompt,
            "download_url": (
                f"/api/projects/{pid}/audit-submission/"
                f"{stored.submission_id}/download"
                if zip_filename else None
            ),
            "stale": stale,
            "stale_reason": stale_reason,
            "stale_reasons": [stale_reason] if stale_reason else [],
        }

    def _stored_audit_submissions(pid: str):
        """Return only integrity-checked submissions committed by this project."""
        audit_store = _project_audit_store(pid)
        directory = audit_store.root / "submissions"
        if not directory.is_dir():
            return []
        stored = []
        for child in directory.iterdir():
            if not child.is_dir() or child.is_symlink():
                continue
            try:
                item = audit_store.get_submission(child.name)
                audit_store.load_snapshot(item.snapshot_id)
            except (KeyError, OSError, ValueError):
                # Incomplete temporary/tampered records are never offered as
                # client-selectable history.
                continue
            stored.append(item)
        return stored

    def _audit_snapshot_history(pid: str, latest=None) -> list[dict]:
        """Expose one best submission per immutable, host-saved snapshot."""
        best_by_snapshot = {}
        for item in _stored_audit_submissions(pid):
            previous = best_by_snapshot.get(item.snapshot_id)
            rank = (item.generated_at, item.state == "READY", item.submission_id)
            previous_rank = (
                (
                    previous.generated_at,
                    previous.state == "READY",
                    previous.submission_id,
                )
                if previous is not None else None
            )
            if previous_rank is None or rank > previous_rank:
                best_by_snapshot[item.snapshot_id] = item
        history = []
        for item in best_by_snapshot.values():
            summary = _audit_submission_summary(pid, item)
            summary["is_latest"] = bool(
                latest is not None and latest.submission_id == item.submission_id
            )
            summary["historical"] = not summary["is_latest"]
            summary["can_generate_snapshot"] = True
            history.append(summary)
        history.sort(
            key=lambda item: (
                str(item.get("captured_at") or ""),
                str(item.get("generated_at") or ""),
                str(item.get("snapshot_id") or ""),
            ),
            reverse=True,
        )
        return history

    def _saved_audit_snapshot_submission(pid: str, snapshot_id: str):
        """Resolve a client-selected ID only through host-committed records."""
        requested = str(snapshot_id or "").strip()
        if not requested:
            return None
        matches = [
            item
            for item in _stored_audit_submissions(pid)
            if item.snapshot_id == requested
        ]
        if not matches:
            raise HTTPException(404, "所选历史运行快照不存在或完整性校验未通过")
        return max(
            matches,
            key=lambda item: (
                item.generated_at,
                item.state == "READY",
                item.submission_id,
            ),
        )

    def _ensure_current_audit_snapshot(pid: str):
        audit_store = _project_audit_store(pid)
        latest = audit_store.latest()
        if latest is None:
            terminal = _legacy_audit_terminal_status(pid)
            snapshot = _build_project_run_snapshot(
                pid,
                terminal,
                f"legacy-{uuid.uuid4().hex}",
                capture=_current_audit_capture(pid),
            )
            latest = _persist_terminal_audit_snapshot(pid, snapshot)
            return latest
        terminal = TerminalStatus(latest.terminal_status)
        current_fingerprint = _current_audit_fingerprint(pid, terminal)
        if latest.snapshot_fingerprint != current_fingerprint:
            audit_store.mark_outdated_submissions(
                current_fingerprint,
                "current TeX/PDF/hash 或审阅记录已经改变",
            )
            snapshot = _build_project_run_snapshot(
                pid,
                terminal,
                f"state-{uuid.uuid4().hex}",
                capture=_current_audit_capture(pid),
            )
            latest = _persist_terminal_audit_snapshot(pid, snapshot)
        elif latest.stale:
            # An explicit review mutation can leave bytes unchanged except for
            # the host review state.  Freeze that state before regenerating.
            snapshot = _build_project_run_snapshot(
                pid,
                terminal,
                f"state-{uuid.uuid4().hex}",
                capture=_current_audit_capture(pid),
            )
            latest = _persist_terminal_audit_snapshot(pid, snapshot)
        return latest

    def _active_job_matches_latest_ocr_parent(audit_store, active, latest) -> bool:
        """Allow live packaging only for the OCR child bound by the host."""
        if active is None or latest is None:
            return False
        parent_snapshot_id = _process_jobs.audit_parent_snapshot_id(active)
        if not parent_snapshot_id or parent_snapshot_id != latest.snapshot_id:
            return False
        try:
            frozen = audit_store.load_snapshot(parent_snapshot_id)
        except (KeyError, OSError, TypeError, ValueError):
            return False
        return frozen.workflow is AuditWorkflow.OCR_ONLY

    @app.get("/api/projects/{pid}/audit-submission/latest")
    def latest_audit_submission(pid: str):
        _ensure(pid)
        audit_store = _project_audit_store(pid)
        latest = audit_store.latest()
        active = _process_jobs.active(pid)
        if latest is None:
            history = _audit_snapshot_history(pid)
            return {
                "available": False,
                "can_generate": active is None,
                "reason": "TASK_RUNNING" if active is not None else "NO_TERMINAL_RUN",
                "latest": None,
                "history": history,
                "history_count": len(history),
            }
        terminal = TerminalStatus(latest.terminal_status)
        active_ocr_snapshot = _active_job_matches_latest_ocr_parent(
            audit_store,
            active,
            latest,
        )
        if active is None:
            current_fingerprint = _current_audit_fingerprint(pid, terminal)
            if current_fingerprint != latest.snapshot_fingerprint:
                audit_store.mark_outdated_submissions(
                    current_fingerprint,
                    "current TeX/PDF/hash 或审阅记录已经改变",
                )
                latest = audit_store.latest()
            transient = ""
        elif active_ocr_snapshot:
            # The OCR-only terminal snapshot is already immutable.  Let users
            # package it while the child analysis run proceeds independently.
            transient = ""
        else:
            transient = "新的处理任务仍在运行"
        history = _audit_snapshot_history(pid, latest)
        return {
            "available": True,
            "can_generate": active is None or active_ocr_snapshot,
            "reason": (
                "TASK_RUNNING"
                if active is not None and not active_ocr_snapshot
                else None
            ),
            "latest": _audit_submission_summary(
                pid, latest, transient_stale=transient
            ),
            "history": history,
            "history_count": len(history),
        }

    def _generate_audit_zip_from_snapshot(
        pid: str,
        body: AuditSubmissionBody,
        latest,
        *,
        frozen_snapshot: bool = False,
    ):
        audit_store = _project_audit_store(pid)
        depth = AuditDepth(str(body.depth or body.profile or "standard"))
        combined_evidence = body.include_page_images_formula_crops
        include_verification = (
            body.include_verification_records
            if body.include_verification_decisions is None
            else body.include_verification_decisions
        )
        request_options = AuditSubmissionRequest(
            depth=depth,
            audit_focus=body.audit_focus,
            include_source_files=body.include_source_files,
            include_compile_logs=body.include_compile_logs,
            include_verification=include_verification,
            include_page_images=(
                body.include_page_images
                if body.include_page_images is not None
                else combined_evidence
            ),
            include_formula_crops=(
                body.include_formula_crops
                if body.include_formula_crops is not None
                else combined_evidence
            ),
            sanitize_sensitive=body.sanitize_sensitive,
        )
        project = get_store().get(pid) or {}
        snapshot = audit_store.load_snapshot(latest.snapshot_id)
        filename = build_audit_zip_filename(
            project_name=project.get("name") or pid,
            workflow=snapshot.workflow,
            run_id=snapshot.run_id,
            source_status=snapshot.terminal_status,
        )
        current_fingerprint = (
            latest.snapshot_fingerprint
            if frozen_snapshot
            else _current_audit_fingerprint(
                pid, TerminalStatus(latest.terminal_status)
            )
        )
        stored = audit_store.generate_submission_zip(
            latest.snapshot_id,
            request_options,
            filename=filename,
            current_fingerprint=current_fingerprint,
        )
        canonical_zip = audit_store.download_path(stored.submission_id)
        from .downloads import save_unique_download

        saved = save_unique_download(canonical_zip.read_bytes(), canonical_zip.name)
        audit_store.record_saved_download(stored.submission_id, saved.name)
        # Saving the user-facing copy can overlap the OCR child's terminal
        # commit.  Re-read both records under the store's commit lock so the
        # response cannot publish a now-historic ZIP as the current package.
        stored, newest = audit_store.submission_freshness(stored.submission_id)
        summary = _audit_submission_summary(pid, stored)
        is_latest = bool(
            newest is not None and newest.submission_id == stored.submission_id
        )
        # A terminal run may win the race after this ZIP started building.  The
        # store already marks that ZIP stale; make the POST response equally
        # explicit so the client never replaces the true latest card with it.
        summary["is_latest"] = is_latest
        summary["historical"] = not is_latest
        summary["archive_filename"] = canonical_zip.name
        summary["saved_filename"] = saved.name
        summary["filename"] = saved.name
        summary["folder"] = "下载/LaTeXStruct"
        summary["effective_options"] = {
            "profile": depth.value,
            "include_source_files": body.include_source_files,
            "include_compile_logs": body.include_compile_logs,
            "include_verification_records": include_verification,
            "include_page_images": request_options.effective_page_images,
            "include_formula_crops": request_options.effective_formula_crops,
            "sanitize_sensitive": body.sanitize_sensitive,
        }
        return {"ok": True, "submission": summary}

    @app.post("/api/projects/{pid}/audit-submission", status_code=201)
    def create_audit_submission(pid: str, body: AuditSubmissionBody):
        _ensure(pid)
        active = _process_jobs.active(pid)
        audit_store = _project_audit_store(pid)
        latest = audit_store.latest()
        selected = _saved_audit_snapshot_submission(pid, body.snapshot_id)
        active_ocr_snapshot = _active_job_matches_latest_ocr_parent(
            audit_store,
            active,
            latest,
        )
        if selected is not None:
            # Every selected snapshot is immutable and was first committed by
            # the host at a terminal boundary.  It is safe to package while a
            # newer run proceeds because no live project files are consulted.
            selected_is_latest = bool(
                latest is not None and selected.snapshot_id == latest.snapshot_id
            )
            if active is not None and selected_is_latest and not active_ocr_snapshot:
                raise HTTPException(
                    409,
                    "任务仍在运行；请等待终态快照冻结后再生成审计包",
                )
            response = _generate_audit_zip_from_snapshot(
                pid,
                body,
                selected,
                frozen_snapshot=True,
            )
            return response
        if active is not None and not active_ocr_snapshot:
            raise HTTPException(409, "任务仍在运行；请等待终态快照冻结后再生成审计包")
        if active_ocr_snapshot:
            return _generate_audit_zip_from_snapshot(
                pid,
                body,
                latest,
                frozen_snapshot=True,
            )
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "任务仍在运行；请等待终态快照冻结后再生成审计包")
            latest = _ensure_current_audit_snapshot(pid)
            return _generate_audit_zip_from_snapshot(pid, body, latest)

    @app.get(
        "/api/projects/{pid}/audit-submission/{submission_id}/download"
    )
    def download_audit_submission(pid: str, submission_id: str):
        _ensure(pid)
        audit_store = _project_audit_store(pid)
        try:
            stored = audit_store.get_submission(submission_id)
            path = audit_store.download_path(submission_id)
        except KeyError:
            raise HTTPException(404, "审计提交包不存在或尚未生成 ZIP") from None
        stale = stored.stale
        return FileResponse(
            path,
            media_type="application/zip",
            filename=path.name,
            headers={
                "Cache-Control": "no-store",
                "X-LaTeXStruct-Submission-ID": stored.submission_id,
                "X-LaTeXStruct-Snapshot-SHA256": stored.snapshot_fingerprint,
                "X-LaTeXStruct-Stale": "true" if stale else "false",
            },
        )

    @app.delete("/api/projects/{pid}")
    def delete_project(pid: str):
        if _process_jobs.active(pid):
            raise HTTPException(409, "项目正在处理；请先取消任务，待安全停止后再删除")
        with _project_lock(pid):
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

    @app.get("/api/projects/{pid}/failed-draft")
    def failed_draft(pid: str):
        """读取哈希校验通过的最近失败草稿；该接口永不参与正式导出。"""
        _ensure(pid)
        failed = get_store().read_failed_attempt(pid)
        if failed is None:
            # 文件缺失、marker 损坏和内容被改写都统一 fail closed，避免 UI 把
            # 不完整/被篡改的诊断草稿当成本次真实处理结果。
            raise HTTPException(404, "没有可恢复的失败草稿")
        return JSONResponse(
            {
                "attempt": "blocked",
                "created": failed.get("created"),
                "draft": failed.get("draft", ""),
                "report": failed.get("report", ""),
                "details": failed.get("details") or {},
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/projects/{pid}/report")
    def report(pid: str):
        _ensure(pid)
        failed = get_store().read_failed_attempt(pid)
        r = failed.get("report") if failed is not None else get_store().read_report(pid)
        if r is None:
            raise HTTPException(404, "尚未处理")
        headers = {"X-LaTeXStruct-Attempt": "blocked"} if failed is not None else None
        return PlainTextResponse(r, media_type="text/markdown", headers=headers)

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
        info, result_bytes = _committed_export(pid)
        stamped, _provenance = _stamp_project_tex(
            pid,
            result_bytes,
            verified=True,
            attempt="committed",
            result_sha256=str(info.get("result_sha256") or ""),
            artifact_kind="verified-structured-tex",
            producer_identity=_stored_producer_identity(info),
        )
        return Response(
            content=stamped,
            media_type="application/x-tex",
            headers={"Content-Disposition": f'attachment; filename="{pid}-structured.tex"'},
        )

    @app.get("/api/projects/{pid}/export-current")
    def export_current(pid: str):
        current = _current_record(pid)
        verified = bool(current["verified"])
        suffix = "" if verified else "-UNVERIFIED"
        info = current.get("info") or {}
        stamped, _provenance = _stamp_project_tex(
            pid,
            current["result"],
            verified=verified,
            attempt=str(current.get("attempt") or "source"),
            result_sha256=str(info.get("result_sha256") or ""),
            artifact_kind=(
                "verified-structured-tex" if verified else "unverified-current-tex"
            ),
            producer_identity=_stored_producer_identity(info),
        )
        return Response(
            content=stamped,
            media_type="application/x-tex",
            headers={
                "Content-Disposition": f'attachment; filename="{pid}-current{suffix}.tex"',
                "X-LaTeXStruct-Verified": "true" if verified else "false",
            },
        )

    @app.get("/api/projects/{pid}/export-current-report")
    def export_current_report(pid: str):
        current = _current_record(pid)
        verified = bool(current["verified"])
        suffix = "" if verified else "-UNVERIFIED"
        return Response(
            content=current["report"],
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{pid}-current-report{suffix}.md"',
                "X-LaTeXStruct-Verified": "true" if verified else "false",
            },
        )

    @app.get("/api/projects/{pid}/export-current-package")
    def export_current_package(pid: str):
        data, verified = _current_package_bytes(pid)
        suffix = "" if verified else "-UNVERIFIED"
        return Response(
            content=data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{pid}-current{suffix}.zip"',
                "X-LaTeXStruct-Verified": "true" if verified else "false",
            },
        )

    def _download_artifact(pid: str, artifact: str) -> tuple[bytes, str, bool]:
        project = get_store().get(pid)
        if project is None:
            raise HTTPException(404, "项目不存在")
        project_name = str(project.get("name") or "LaTeXStruct")
        if artifact == "result":
            info, data = _committed_export(pid)
            stamped, _provenance = _stamp_project_tex(
                pid,
                data,
                verified=True,
                attempt="committed",
                result_sha256=str(info.get("result_sha256") or ""),
                artifact_kind="verified-structured-tex",
                producer_identity=_stored_producer_identity(info),
            )
            return stamped, f"{project_name}-structured.tex", True
        if artifact == "report":
            return _committed_report(pid), f"{project_name}-report.md", True
        if artifact in {"package", "folder"}:
            return _export_package_bytes(pid), f"{project_name}-structured-project.zip", True
        if artifact == "current":
            current = _current_record(pid)
            verified = bool(current["verified"])
            marker = "" if verified else "-UNVERIFIED"
            info = current.get("info") or {}
            stamped, _provenance = _stamp_project_tex(
                pid,
                current["result"],
                verified=verified,
                attempt=str(current.get("attempt") or "source"),
                result_sha256=str(info.get("result_sha256") or ""),
                artifact_kind=(
                    "verified-structured-tex" if verified else "unverified-current-tex"
                ),
                producer_identity=_stored_producer_identity(info),
            )
            return stamped, f"{project_name}-current{marker}.tex", verified
        if artifact == "current-report":
            current = _current_record(pid)
            verified = bool(current["verified"])
            marker = "" if verified else "-UNVERIFIED"
            return current["report"], f"{project_name}-current-report{marker}.md", verified
        if artifact == "current-package":
            data, verified = _current_package_bytes(pid)
            marker = "" if verified else "-UNVERIFIED"
            return data, f"{project_name}-current{marker}.zip", verified
        raise HTTPException(404, "不支持的下载类型")

    @app.post("/api/projects/{pid}/exports/{artifact}/save")
    def save_export_to_downloads(pid: str, artifact: str):
        """桌面 WebView 下载被拦截时，可靠保存到固定的用户下载目录。"""
        from .downloads import save_unique_download

        data, filename, verified = _download_artifact(pid, artifact)
        saved = save_unique_download(data, filename)
        return {
            "ok": True,
            "filename": saved.name,
            "folder": "下载/LaTeXStruct",
            "bytes": len(data),
            "verified": verified,
        }

    @app.post("/api/exports/open-folder")
    def open_export_folder():
        """只打开应用固定下载目录，不接受任何路径参数。"""
        from .downloads import reveal_download_location

        reveal_download_location()
        return {"ok": True, "folder": "下载/LaTeXStruct"}

    def _run_project_impl(pid: str, exclude: set, reuse_decisions: bool = False,
                          progress_callback=None, control_callback=None, commit_callback=None,
                          config_snapshot: Optional[AppConfig] = None,
                          audit_capture: Optional[dict] = None):
        def preflight_progress(progress: float, message: str) -> None:
            if audit_capture is not None:
                audit_capture.setdefault("events", []).append({
                    "at": time.time(),
                    "phase": "preflight",
                    "message": message,
                })
                audit_capture["events"] = audit_capture["events"][-80:]
            if progress_callback:
                progress_callback("preflight", progress, message, {})

        preflight_progress(0.01, "正在核对不可变输入快照")
        if control_callback:
            control_callback()
        p = get_store().get(pid)
        project_dir = Path(get_store()._dir(pid))
        repaired_source = _repair_legacy_ocr_source_page_count(project_dir, p)
        if repaired_source is not None:
            meta_path = project_dir / "meta.json"
            stored_meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if stored_meta.get("ocr_source") != p.get("ocr_source"):
                raise ValueError("OCR 项目元数据在页数迁移期间发生改变，已阻止处理")
            stored_meta["ocr_source"] = repaired_source
            _project_audit_store(pid).invalidate_before_state_change(
                lambda: get_store()._write_json(
                    str(project_dir),
                    "meta.json",
                    stored_meta,
                ),
                "OCR 原始 PDF 页数记录已由不可变快照迁移",
            )
            p = get_store().get(pid)
            preflight_progress(0.015, "已按不可变审计快照修复旧版页数记录")
        text = get_store().read_source(pid)
        # Background tasks receive the complete settings snapshot captured when the
        # user started them.  A later settings save must not change either their
        # billing backend or their model halfway through the launch boundary.
        cfg = config_snapshot if config_snapshot is not None else get_config()
        mode = p["mode"]
        producer_identity = _runtime_provenance_identity(
            PROMPT_VERSION if mode == "ai" else "not-used"
        )
        from ..core.template import normalize_template_id

        template = normalize_template_id(p.get("template") or "")
        pack = (p.get("pack") or "") or None
        prior = {}
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if reuse_decisions and info_path.exists():
            prior = json.loads(info_path.read_text(encoding="utf-8"))
        cached = prior.get("decision_cache") if reuse_decisions else None
        overrides = [_decision_from_dict(item) for item in cached] if cached else None
        is_ocr_project = p.get("kind") == "ocr"
        # OCR 必须在编译器可用时成功；普通 TEX 至少比较处理前后，避免结构补丁
        # 引入新的编译错误却仍被标为安全。
        template_compile_guard = is_ocr_project
        compile_extra_files = None
        compile_project_main_rel = None
        if is_ocr_project:
            compile_extra_files = _verified_ocr_resource_bytes(
                Path(get_store()._dir(pid)),
                p.get("ocr_resources") or {},
            )
        elif p.get("kind") == "folder":
            original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
            if not original_zip.is_file():
                raise ValueError("原始文件夹工程快照缺失，无法执行可靠的编译比较")
            compile_extra_files = _decode_zip_files(original_zip.read_bytes())
            graph = p.get("graph") or {}
            compile_project_main_rel = str(graph.get("main_rel") or "")
            if not compile_project_main_rel:
                raise ValueError("文件夹工程主文件记录缺失，无法执行可靠的编译比较")
        source_visual_provenance = {}
        quality_loop, source_pdf_bytes, source_pdf_page_range = _quality_loop_inputs(
            Path(get_store()._dir(pid)),
            p,
            mode=mode,
            provenance_out=source_visual_provenance,
        )
        visual_client = None
        if quality_loop and source_pdf_bytes:
            visual_client, _visual_model, _visual_backend = _build_ocr_client(cfg)
        latest_draft = {"text": ""}

        def capture_progress(phase, progress, message, data):
            event_data = data or {}
            if isinstance(event_data.get("preview"), str):
                latest_draft["text"] = event_data["preview"]
                if audit_capture is not None:
                    audit_capture["preview"] = event_data["preview"]
                    audit_capture["preview_state"] = str(
                        event_data.get("preview_state")
                        or audit_capture.get("preview_state")
                        or "SOURCE_PREVIEW"
                    )
            audit_stage = event_data.get("audit_stage")
            if audit_capture is not None and isinstance(audit_stage, dict):
                role = str(audit_stage.get("role") or "")
                stage_text = audit_stage.get("text")
                if role and isinstance(stage_text, str) and stage_text:
                    audit_capture.setdefault("audit_stages", {}).setdefault(
                        role,
                        {
                            "text": stage_text,
                            "sha256": hashlib.sha256(
                                stage_text.encode("utf-8")
                            ).hexdigest(),
                            "captured_at": time.time(),
                        },
                    )
            if audit_capture is not None:
                audit_capture.setdefault("events", []).append({
                    "at": time.time(),
                    "phase": str(phase),
                    "message": str(message)[:500],
                })
                audit_capture["events"] = audit_capture["events"][-80:]
            if progress_callback:
                progress_callback(phase, progress, message, data)

        res = run_pipeline(
            text, mode=mode, ai_config=cfg.to_ai_config() if mode == "ai" else None,
            template=template, pack=pack, exclude=exclude or None,
            template_context={"title": p.get("template_title") or p.get("name") or ""},
            decisions_override=overrides,
            ambiguous_override=prior.get("ambiguous") if overrides else None,
            ai_notes_override=prior.get("ai_notes") if overrides else None,
            progress_callback=capture_progress,
            control_callback=control_callback,
            # 普通 TEX 也要比较处理前后编译结果；否则语义错误的环境变更可能在
            # “正文可逆”检查下被误标为安全。未安装 TeX 时仍由静态检查接管。
            compile_check=True,
            require_compile_when_available=is_ocr_project or template_compile_guard,
            resource_root=get_store()._dir(pid) if is_ocr_project else None,
            require_resources=is_ocr_project,
            compile_extra_files=compile_extra_files,
            compile_project_main_rel=compile_project_main_rel,
            capture_compile_artifact=True,
            source_pdf_bytes=source_pdf_bytes,
            source_pdf_page_range=source_pdf_page_range,
            source_visual_provenance=source_visual_provenance or None,
            quality_loop=quality_loop,
            visual_client=visual_client,
            # ``kind`` is immutable host state.  The core must not infer away
            # OCR semantics merely because a damaged/raw TEX lost its marker.
            ocr_project=is_ocr_project,
        )
        extra_verification = {}
        encoding_error = ""
        if p.get("kind") != "folder":
            original_source = Path(get_store()._dir(pid)) / "original-source.tex"
            if original_source.is_file():
                from ..core.project import encode_tex_like_original

                try:
                    encode_tex_like_original(res.result, original_source.read_bytes())
                except ValueError as exc:
                    encoding_error = str(exc)
        if p.get("kind") == "folder":
            from ..core.project import encode_project_files, split_project

            graph = p.get("graph") or {}
            try:
                per_file = split_project(res.result)
                split_error = ""
            except ValueError as exc:
                per_file = {}
                split_error = str(exc)
            if not split_error:
                try:
                    encode_project_files(
                        compile_extra_files or {},
                        str(graph.get("main_rel") or ""),
                        per_file,
                    )
                except ValueError as exc:
                    encoding_error = str(exc)
            expected = {"", *(graph.get("files") or [])}
            project_ok = bool(
                not split_error
                and set(per_file) == expected
                and not graph.get("missing")
                and not graph.get("cycles")
                and not encoding_error
            )
            project_check = {
                "ok": project_ok,
                "before_file_count": len(expected),
                "after_file_count": len(per_file),
                "file_set_equal": set(per_file) == expected,
                "missing_includes": graph.get("missing") or [],
                "cycles": graph.get("cycles") or [],
                "error": split_error,
                "encoding_error": encoding_error,
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
        encoding_checked = bool(
            p.get("kind") == "folder"
            or (Path(get_store()._dir(pid)) / "original-source.tex").is_file()
        )
        encoding_ok = not encoding_error
        res.verification["source_encoding"] = {
            "checked": encoding_checked,
            "ok": encoding_ok,
            "error": encoding_error,
        }
        res.verification.setdefault("checks", []).append({
            "id": "source-encoding",
            "label": "源文件编码、BOM 与换行可保真写回",
            "ok": encoding_ok,
            "skipped": not encoding_checked,
        })
        if encoding_error:
            res.verification["safe_to_export"] = False
            res.verification["export_blocked"] = True
            res.ok = False
            res.report_md += (
                "\n\n## 源文件编码安全检查\n\n"
                f"- ❌ {encoding_error}\n"
                "- 原始文件字节保持不变；本次修改仅作为未验证草稿保留。\n"
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
        from ..core.verify import verification_failures

        failures = verification_failures(res.verification)
        final_safe_to_export = bool(
            res.ok
            and res.verification.get("safe_to_export") is True
            and not failures
        )
        res.verification["safe_to_export"] = final_safe_to_export
        res.verification["export_blocked"] = not final_safe_to_export
        res.ok = final_safe_to_export
        res.verification["failures"] = failures
        # The core report is produced before host-only project/encoding gates.
        # Reconcile its front-page claim only after those gates and their
        # persisted failure list are final, so the Markdown shipped in the ZIP
        # cannot say VERIFIED while verification.json blocks export.
        from ..core.report import reconcile_report_status

        final_terminal_status = (
            "SUCCESS" if final_safe_to_export else "UNVERIFIED"
        )
        res.report_md = reconcile_report_status(
            res.report_md,
            res.verification,
            terminal_status=final_terminal_status,
        )
        if audit_capture is not None:
            audit_capture["pipeline_result"] = res
            audit_capture["verification"] = deepcopy(res.verification)
            audit_capture["config_snapshot"] = cfg
            audit_capture["preview_state"] = str(
                res.verification.get("preview_state") or "SOURCE_PREVIEW"
            )
        _persist_compile_preview(pid, res)
        if not res.ok:
            failed_checks = [item["id"] for item in failures]
            failure_summary = "；".join(item["summary"] for item in failures[:3])
            if not failure_summary:
                failure_summary = "安全检查未通过；原项目和上一次安全结果均未覆盖"
            report_lines = [
                "",
                "## 为什么没有保存本次结果",
                "",
                "本次结构化草稿未通过安全检查，已作为诊断草稿保留；"
                "原项目和上一次通过检查的结果均未覆盖。",
                "",
            ]
            for item in failures:
                report_lines.extend([
                    f"- ❌ **{item['label']}**：{item['summary']}",
                    f"  - 下一步：{item['action']}",
                ])
            res.report_md += "\n".join(report_lines)
            failed_draft = (
                str(getattr(res, "compiled_snapshot", "") or "")
                or res.compiled_tex
                or latest_draft["text"]
                or res.result
                or text
            )
            if p.get("kind") == "folder" and getattr(
                res, "compiled_snapshot", ""
            ):
                from ..core.project import split_project

                extra_verification["per_file"] = split_project(
                    res.compiled_snapshot
                )
            get_store().record_failed_attempt(
                pid,
                failed_draft,
                res.report_md,
                {
                    "verification": res.verification,
                    "failures": failures,
                    "items": res.decision_items,
                    "ambiguous": res.ambiguous,
                    "decision_cache": decision_cache,
                    "applied": applied,
                    "producer_identity": producer_identity,
                    **extra_verification,
                },
            )
            return {
                "ok": False,
                "safe_to_export": False,
                "applied": len(res.applied),
                "rejected": len(res.rejected),
                "ambiguous": len(res.ambiguous),
                "degraded": res.verification.get("ai_degraded", False),
                "usage": res.verification.get("ai_usage", {}),
                "failed_checks": failed_checks,
                "failure_summary": failure_summary,
                "failures": failures,
                "preview_preserved": True,
                "preview_state": res.verification.get(
                    "preview_state", "SOURCE_PREVIEW"
                ),
            }
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
                "review": _persisted_review_summary(res.review),
                "items": res.decision_items,
                "decision_cache": decision_cache,
                "producer_identity": producer_identity,
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
            "preview_state": res.verification.get(
                "preview_state", "SOURCE_PREVIEW"
            ),
        }

    def _run_project(pid: str, exclude: set, reuse_decisions: bool = False,
                     progress_callback=None, control_callback=None, commit_callback=None,
                     config_snapshot: Optional[AppConfig] = None,
                     audit_run_id: str = ""):
        # Includes the final store commit. RLock is required because review
        # routes hold this transaction while updating meta.json before rerunning.
        with _project_lock(pid):
            _begin_pipeline_run()
            run_id = str(audit_run_id or f"run-{uuid.uuid4().hex}")
            audit_capture = {
                "run_id": run_id,
                "started": time.time(),
                "preview": get_store().read_source(pid),
                "preview_state": "SOURCE_PREVIEW",
                "audit_stages": {},
                "events": [],
                "config_snapshot": config_snapshot,
            }
            try:
                result = _run_project_impl(
                    pid,
                    exclude,
                    reuse_decisions=reuse_decisions,
                    progress_callback=progress_callback,
                    control_callback=control_callback,
                    commit_callback=commit_callback,
                    config_snapshot=config_snapshot,
                    audit_capture=audit_capture,
                )
                audit_capture["finished"] = time.time()
                terminal = (
                    TerminalStatus.SUCCESS
                    if result.get("ok") is True
                    else TerminalStatus.UNVERIFIED
                )
                snapshot = _build_project_run_snapshot(
                    pid, terminal, run_id, capture=audit_capture
                )
                result["analysis_archive"] = _freeze_analysis_run_archive(
                    pid, run_id, terminal, snapshot, audit_capture
                )
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        0.99,
                        "正在冻结终态并生成 AI 审计轻量材料",
                        {"scope": "finalization"},
                    )
                _persist_terminal_audit_snapshot(pid, snapshot)
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        1.0,
                        "终态审计材料已保存",
                        {"scope": "finalization"},
                    )
                return result
            except ProcessingCancelled as exc:
                audit_capture["finished"] = time.time()
                audit_capture["error"] = str(exc)
                snapshot = _build_project_run_snapshot(
                    pid,
                    TerminalStatus.CANCELLED,
                    run_id,
                    capture=audit_capture,
                    error=str(exc),
                )
                if audit_capture.get("pipeline_result") is not None:
                    audit_capture["analysis_archive"] = _freeze_analysis_run_archive(
                        pid,
                        run_id,
                        TerminalStatus.CANCELLED,
                        snapshot,
                        audit_capture,
                    )
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        0.99,
                        "正在保存取消前已有阶段和错误记录",
                        {"scope": "finalization"},
                    )
                _persist_terminal_audit_snapshot(pid, snapshot)
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        1.0,
                        "取消任务审计材料已保存",
                        {"scope": "finalization"},
                    )
                raise
            except Exception as exc:
                audit_capture["finished"] = time.time()
                audit_capture["error"] = _safe_task_error(exc)
                snapshot = _build_project_run_snapshot(
                    pid,
                    TerminalStatus.FAILED,
                    run_id,
                    capture=audit_capture,
                    error=audit_capture["error"],
                )
                if audit_capture.get("pipeline_result") is not None:
                    audit_capture["analysis_archive"] = _freeze_analysis_run_archive(
                        pid,
                        run_id,
                        TerminalStatus.FAILED,
                        snapshot,
                        audit_capture,
                    )
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        0.99,
                        "正在保存失败前已有阶段和错误记录",
                        {"scope": "finalization"},
                    )
                _persist_terminal_audit_snapshot(pid, snapshot)
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        1.0,
                        "失败任务审计材料已保存",
                        {"scope": "finalization"},
                    )
                raise
            finally:
                _end_pipeline_run()

    @app.post("/api/projects/{pid}/process")
    def process(pid: str):
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "项目已有后台任务；请在进度卡片中暂停、继续或取消")
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "项目已有后台任务；请在进度卡片中暂停、继续或取消")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            return _run_project(pid, set(meta.get("excludes", [])))

    @app.post("/api/projects/{pid}/process/start")
    def process_start(pid: str):
        """启动可暂停的后台处理；同一项目最多一个活动任务。"""
        _ensure(pid)
        existing = _process_jobs.active(pid)
        if existing:
            return _process_jobs.public(existing) | {"already_running": True}
        # Keep lock order project -> update state, matching _run_project.
        with _project_lock(pid):
            with _update_state_lock:
                _raise_if_update_preparing()
                existing = _process_jobs.active(pid)
                if existing:
                    return _process_jobs.public(existing) | {"already_running": True}
                meta = json.loads(
                    Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
                )
                launch_cfg = deepcopy(get_config()) if meta.get("mode") == "ai" else None
                job = _process_jobs.create(
                    pid,
                    get_store().read_source(pid),
                    analysis_backend=(
                        launch_cfg.analysis_backend
                        if launch_cfg is not None
                        else "api"
                    ),
                )
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
                    config_snapshot=launch_cfg,
                    audit_run_id=jid,
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
        failed = get_store().read_failed_attempt(pid)
        if failed is not None:
            details = failed.get("details") or {}
            return {
                "items": details.get("items", []),
                "excludes": get_store().get(pid).get("excludes", []),
                "verification": details.get("verification"),
                "attempt": "blocked",
                "failures": details.get("failures", []),
            }
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if not info_path.exists():
            return {"items": [], "excludes": get_store().get(pid).get("excludes", []),
                    "verification": None}
        info = json.loads(info_path.read_text(encoding="utf-8"))
        return {"items": info.get("items", []),
                "excludes": get_store().get(pid).get("excludes", []),
                "verification": info.get("verification")}

    def _commit_review_state(
        pid: str,
        meta: dict,
        *,
        accepted_ids,
        rejected_ids,
        stale_reason: str,
    ) -> tuple[dict, bool]:
        """Persist one disjoint host-authoritative review state and stale all old bundles."""
        previous = _review_state_payload(meta)
        accepted_set = {str(item) for item in accepted_ids if str(item).strip()}
        rejected_set = {str(item) for item in rejected_ids if str(item).strip()}
        # Repair any legacy overlap deterministically.  Callers that perform an
        # explicit acceptance remove that ID from rejected_set first; otherwise
        # rejection wins because it changes the generated current TeX.
        accepted_set.difference_update(rejected_set)
        accepted = sorted(accepted_set)
        rejected = sorted(rejected_set)
        changed = (
            accepted != previous["accepted_ids"]
            or rejected != previous["rejected_ids"]
        )
        if not changed:
            return meta, False
        meta["accepted_decision_ids"] = accepted
        meta["excludes"] = rejected
        meta["review_revision"] = previous["revision"] + 1
        directory = Path(get_store()._dir(pid))
        get_store()._write_json(str(directory), "meta.json", meta)
        audit_store = _project_audit_store(pid)
        latest = audit_store.latest()
        if latest is not None:
            current_fingerprint = _current_audit_fingerprint(
                pid,
                TerminalStatus(latest.terminal_status),
            )
            audit_store.mark_outdated_submissions(
                current_fingerprint,
                stale_reason,
            )
        return meta, True

    @app.post("/api/projects/{pid}/decisions/review-state")
    def set_decision_review_state(pid: str, req: ReviewStateRequest):
        """Persist confirmation choices so stale detection is host-authoritative."""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再确认审阅结论")
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再确认审阅结论")
            directory = Path(get_store()._dir(pid))
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
            revision = max(0, int(meta.get("review_revision") or 0))
            if req.expected_revision is not None and req.expected_revision != revision:
                raise HTTPException(
                    409,
                    "审阅状态已在其他操作中改变；请刷新后重试",
                )
            requested = sorted({
                str(item) for item in req.accepted_ids if str(item).strip()
            })
            if len(requested) > 100_000 or any(len(item) > 256 for item in requested):
                raise HTTPException(400, "确认项列表过大或候选 ID 无效")
            failed = get_store().read_failed_attempt(pid)
            if failed is not None:
                info = failed.get("details") or {}
            else:
                info_path = directory / "verification.json"
                info = (
                    json.loads(info_path.read_text(encoding="utf-8"))
                    if info_path.is_file() else {}
                )
            allowed = {
                str(item.get("candidate_id") or item.get("id") or "")
                for item in (info.get("items") or [])
                if isinstance(item, dict)
            }
            allowed.update(
                str(item.get("candidate_id") or "")
                for item in (info.get("decision_cache") or [])
                if isinstance(item, dict)
            )
            allowed.discard("")
            unknown = [item for item in requested if item not in allowed]
            if unknown:
                raise HTTPException(400, f"存在不属于当前运行的确认项：{unknown[0]}")
            rejected = {
                str(item) for item in (meta.get("excludes") or [])
                if str(item).strip()
            }
            rejected_acceptances = sorted(rejected.intersection(requested))
            if rejected_acceptances:
                # Accepting a rejected patch without rebuilding result.tex would
                # make the decision authority disagree with the current TeX.
                # Keep this endpoint metadata-only and require the existing
                # unreject operation, which reruns the pipeline, first.
                raise HTTPException(
                    409,
                    "该审阅项当前已被拒绝；请先撤销拒绝并完成重跑，再接受该项",
                )
            meta, _changed = _commit_review_state(
                pid,
                meta,
                accepted_ids=requested,
                rejected_ids=rejected,
                stale_reason="用户接受、撤销或调整了审阅项",
            )
            return {
                "ok": True,
                "review_revision": int(meta.get("review_revision") or revision),
                "accepted_ids": requested,
            }

    @app.post("/api/projects/{pid}/decisions/{cid}/reject")
    def reject_decision(pid: str, cid: str):
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            excludes = set(meta.get("excludes", []))
            excludes.add(cid)
            accepted = set(meta.get("accepted_decision_ids") or [])
            accepted.discard(cid)
            _commit_review_state(
                pid,
                meta,
                accepted_ids=accepted,
                rejected_ids=excludes,
                stale_reason="用户拒绝了审阅项",
            )
            return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/{cid}/unreject")
    def unreject_decision(pid: str, cid: str):
        """撤销对某一项的拒绝：从排除清单移除并重跑（审阅台 Ctrl+Z 的后端）。"""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            excludes = set(meta.get("excludes", []))
            excludes.discard(cid)
            _commit_review_state(
                pid,
                meta,
                accepted_ids=meta.get("accepted_decision_ids") or [],
                rejected_ids=excludes,
                stale_reason="用户撤销了审阅项拒绝状态",
            )
            return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/reject-batch")
    def reject_batch(pid: str, req: BatchRejectRequest):
        """批量拒绝（Accept-All-Similar 的逆操作：拒绝同类其余修改）。"""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            rejected_now = {str(item) for item in req.cids if str(item).strip()}
            excludes = set(meta.get("excludes", [])) | rejected_now
            accepted = set(meta.get("accepted_decision_ids") or []) - rejected_now
            _commit_review_state(
                pid,
                meta,
                accepted_ids=accepted,
                rejected_ids=excludes,
                stale_reason="用户批量拒绝了审阅项",
            )
            return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/reset")
    def reset_decisions(pid: str):
        """撤销全部拒绝：清空 excludes 并重跑。"""
        _ensure(pid)
        if _process_jobs.active(pid):
            raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            _commit_review_state(
                pid,
                meta,
                accepted_ids=meta.get("accepted_decision_ids") or [],
                rejected_ids=(),
                stale_reason="用户撤销了全部拒绝状态",
            )
            return _run_project(pid, set(), reuse_decisions=True)

    @app.get("/api/projects/{pid}/diff")
    def diff(pid: str):
        _ensure(pid)
        old = get_store().read_source(pid).replace("\r\n", "\n").replace("\r", "\n").split("\n")
        failed = get_store().read_failed_attempt(pid)
        new_text = failed.get("draft") if failed is not None else get_store().read_result(pid)
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
        if failed is not None:
            info = failed.get("details") or {}
        else:
            info = json.loads(
                (Path(get_store()._dir(pid)) / "verification.json").read_text(encoding="utf-8")
            )
        return {"rows": rows, "compact": compact, "applied": info.get("applied", []),
                "ambiguous": info.get("ambiguous", []),
                "verification": info.get("verification", {}),
                "attempt": "blocked" if failed is not None else "committed"}

    @app.get("/api/config")
    def get_cfg():
        return get_config().masked()

    @app.get("/api/codex/status")
    def get_codex_status():
        """只探测 runtime 与 ChatGPT 登录类型，不发送模型请求。"""
        from ..core.codex_cli import codex_status

        return codex_status()

    @app.post("/api/config/test-connection")
    def test_config_connection(req: ConfigConnectionTestRequest):
        """用最小模型请求验证地址、密钥和模型，且绝不持久化请求内容。"""
        from ..config import _api_authority
        from ..core.ai import LLMClient, LLMError, RoleConfig

        role = req.role
        base_url = req.base_url.strip().rstrip("/")
        model = req.model.strip()
        requested_authority = _api_authority(base_url, allow_loopback_http=True)
        if requested_authority is None:
            raise HTTPException(
                400,
                "API Base URL 必须是有效的 HTTPS 地址（仅本机 loopback 允许 HTTP）",
            )
        if not model:
            raise HTTPException(400, "请选择要测试的模型")

        cfg = get_config()
        if role == "ocr":
            saved_role = cfg.to_ocr_config().role
        else:
            ai_config = cfg.to_ai_config()
            saved_role = ai_config.decide if role == "decide" else ai_config.review
        saved_base_url = str(saved_role.base_url or "").strip()
        saved_authority = _api_authority(saved_base_url, allow_loopback_http=True)
        supplied_key = req.api_key.get_secret_value().strip() if req.api_key else ""
        # 前端展示用占位符永远不能被当成真实凭据发给供应商。
        if supplied_key in {"已配置", "已配置(系统凭据)"}:
            supplied_key = ""
        selected_key = supplied_key
        if not selected_key:
            if not saved_authority or requested_authority != saved_authority:
                raise HTTPException(
                    400,
                    f"{role} 的 API 地址已改变，请先填写该地址对应的新 API Key",
                )
            # Use the exact same safe, same-authority fallback as real OCR and
            # analysis runs.  AppConfig never reuses a credential across API
            # authorities, and the requested endpoint was checked above.
            selected_key = str(saved_role.api_key or "").strip()
        if not selected_key:
            raise HTTPException(400, f"{role} 尚未配置可用于测试的 API Key")

        client = LLMClient(
            RoleConfig(
                base_url=base_url,
                model=model,
                api_key=selected_key,
                timeout=20.0,
                max_tokens=16,
                max_retries=0,
                retry_delay=0.0,
            )
        )
        try:
            client.chat_json(
                "You are a connection probe. Return only one valid JSON object.",
                'Return exactly {"ok":true}.',
            )
        except LLMError as exc:
            # LLMClient 已执行供应商错误脱敏；这里再按本次实际密钥做最后一道清理，
            # 也覆盖测试替身或未来客户端实现直接抛出密钥的情况。
            detail = str(exc).replace(selected_key, "[已隐藏]")
            detail = re.sub(
                r"sk-(?:ws-|sp-)?[A-Za-z0-9._-]{8,}", "[已隐藏]", detail
            ).strip()[:400]
            raise HTTPException(502, detail or "模型连接测试失败") from None

        message = "连接成功；API 地址、密钥和模型均可用"
        if role == "ocr":
            message += "（本次仅验证基础请求，实际 OCR 仍要求模型支持图片输入）"
        return {
            "ok": True,
            "role": role,
            "model": model,
            "message": message,
            "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

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

    async def _read_ocr_upload(files: list[UploadFile]):
        uploads = list(files or ())
        if not uploads:
            raise HTTPException(400, "请选择 PDF 或图片")
        if len(uploads) > MAX_OCR_PAGES_PER_JOB:
            raise HTTPException(400, f"单次最多选择 {MAX_OCR_PAGES_PER_JOB} 张图片")
        suffixes = [Path(item.filename or "").suffix.lower() for item in uploads]
        if any(suffix not in (".pdf", ".png", ".jpg", ".jpeg") for suffix in suffixes):
            raise HTTPException(400, "仅支持 PDF/PNG/JPG")
        if len(uploads) > 1 and any(suffix == ".pdf" for suffix in suffixes):
            raise HTTPException(400, "请选择一个 PDF，或按顺序选择多张 PNG/JPG；不能混合上传")

        payloads: list[bytes] = []
        total_bytes = 0
        for item in uploads:
            remaining = MAX_OCR_UPLOAD_BYTES - total_bytes
            payload = await item.read(max(0, remaining) + 1)
            if not payload:
                raise HTTPException(400, f"图片 {Path(item.filename or '').name or len(payloads) + 1} 为空")
            total_bytes += len(payload)
            if total_bytes > MAX_OCR_UPLOAD_BYTES:
                raise HTTPException(413, "OCR 文件合计超过 100 MB，请拆分后重试")
            payloads.append(payload)

        suffix = suffixes[0]
        upload = payloads[0]
        if len(uploads) == 1 and suffix == ".pdf":
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
            return (
                suffix, upload, source_total, source_outline, "pdf",
                Path(uploads[0].filename or "scan.pdf").name,
                b"", (),
            )

        if len(uploads) == 1:
            from ..core.ai import LLMError
            from ..ocr import image_mime_type

            try:
                image_mime_type(upload)
            except LLMError as exc:
                raise HTTPException(400, str(exc)) from None
            return (
                suffix, upload, 1, [], "image",
                Path(uploads[0].filename or f"scan{suffix}").name,
                b"", (),
            )

        try:
            collection = build_multi_image_source([
                (Path(item.filename or f"image-{index:06d}{suffixes[index - 1]}").name, payload)
                for index, (item, payload) in enumerate(zip(uploads, payloads), 1)
            ])
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from None
        if len(collection.bundle_bytes) > MAX_OCR_UPLOAD_BYTES:
            raise HTTPException(413, "多图片不可变源包超过 100 MB，请减少图片后重试")
        return (
            ".zip",
            collection.bundle_bytes,
            len(payloads),
            [],
            "images",
            f"multi-images-{len(payloads)}.zip",
            collection.visual_pdf_bytes,
            tuple(collection.image_entries),
        )

    def _create_ocr_job(
        suffix: str,
        upload: bytes,
        source_total: int,
        status: str,
        source_outline: list[dict] = None,
        original_filename: str = "",
        source_type: str = "",
        visual_source: bytes = b"",
        source_images: tuple[dict, ...] = (),
    ):
        tmpdir = tempfile.mkdtemp(prefix="ls-ocr-")
        target = os.path.join(tmpdir, f"scan{suffix}")
        visual_target = os.path.join(tmpdir, "visual-source.pdf") if visual_source else ""
        try:
            with open(target, "wb") as stream:
                stream.write(upload)
            if visual_source:
                with open(visual_target, "wb") as stream:
                    stream.write(visual_source)
        except Exception:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise
        jid = uuid.uuid4().hex
        job = {
            "id": jid,
            "status": status,
            "source_type": source_type or ("pdf" if suffix == ".pdf" else "image"),
            "original_filename": Path(original_filename or f"scan{suffix}").name,
            "source_total": source_total,
            "source_outline": list(source_outline or []),
            "_source_sha256": hashlib.sha256(upload).hexdigest(),
            "_visual_source_sha256": (
                hashlib.sha256(visual_source).hexdigest() if visual_source else ""
            ),
            "source_images": [deepcopy(item) for item in source_images],
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
            "backend": "unknown",
            "quality_profile": "standard",
            "quality_tier": "recommended",
            "output_template": "",
            "reasoning_effort": "",
            "created": time.time(),
            "updated": time.time(),
            "state_revision": 1,
            "pause_requested": False,
            "retrying_failed": False,
            "pages": {},
            "dir": tmpdir,
            "target": target,
            "visual_target": visual_target,
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
                "page_id": make_page_id(index),
                "source_page": page_no,
                "status": "pending",
                "tex": "",
                "error": "",
                "png": os.path.join(job["dir"], f"page-{page_no}.img"),
                "persisted_visual_path": "",
                "low_conf": False,
                "needs_review": False,
                "attempts": 0,
                "task_index": index,
                "retrying": False,
                "figures": [],
                "image_size_pixels": [],
                "visual_input_sha256": "",
                "visual_input_persisted": False,
                "formula_evidence_inputs": [],
                "formula_evidence": [],
                "text_hint": "",
                "text_hint_chars": 0,
                "text_hint_sha256": "",
                "italic_terms": [],
                "relation_regions": [],
                "divider_regions": [],
                "framed_inset_regions": [],
                "equation_tag_regions": [],
                "equation_tag_extraction_status": "pending",
                "footnote_regions": [],
                "quality_flags": [],
            }
            for index, page_no in enumerate(page_nos, start=1)
        }
        # A single-image OCR job already has an exact visual source at inspect
        # time.  Publish a private, fsync'd preview copy before the asynchronous
        # provider/bootstrap work begins.  This makes preview availability a
        # fact about durable bytes, not an accidental side effect of a later
        # model call (which may fail before rendering).
        if str(job.get("source_type") or "") == "image" and page_nos == [1]:
            source_path = Path(str(job.get("target") or ""))
            page_path = Path(str(job["pages"][1]["png"]))
            source_bytes = source_path.read_bytes()
            if not source_bytes:
                raise ValueError("上传图片为空，无法建立预览")
            tmp_path = page_path.with_name(
                f"{page_path.name}.{uuid.uuid4().hex}.tmp"
            )
            try:
                with open(tmp_path, "wb") as stream:
                    stream.write(source_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp_path, page_path)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()

    def _restore_persisted_ocr_job(jid: str) -> dict | None:
        """Rebuild a read-safe job from its immutable snapshot after restart."""
        if re.fullmatch(r"[0-9a-f]{32}", str(jid or "")) is None:
            return None
        with _ocr_jobs_lock:
            existing = _ocr_jobs.get(jid)
            if existing is not None:
                return existing
        store = OcrRunStore(Path(get_store().root).parent / "ocr-runs")
        try:
            snapshot = store.load_snapshot(jid)
            source_path = store.verify_source(jid)
            visual_source_path = (
                store.verify_visual_source(jid)
                if snapshot.source_type == "images"
                else None
            )
            records = store.recover(jid)
        except (OcrStoreError, OSError, ValueError):
            return None
        tmpdir = tempfile.mkdtemp(prefix="ls-ocr-recovered-")
        suffix = source_path.suffix.lower() or ".bin"
        started_epoch = time.time()
        try:
            started_epoch = datetime.fromisoformat(
                snapshot.started_at.replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            pass
        job = {
            "id": jid,
            "status": "partial",
            "source_type": snapshot.source_type,
            "original_filename": snapshot.original_filename,
            "source_total": snapshot.source_total_pages,
            "source_outline": list(thaw_json(snapshot.bookmarks)),
            "_source_sha256": snapshot.source_sha256,
            "_visual_source_sha256": snapshot.visual_source_sha256,
            "source_images": list(thaw_json(snapshot.source_images)),
            "progress": 0.0,
            "total": len(snapshot.selected_pages),
            "done": 0,
            "page": 0,
            "current_index": 0,
            "phase": "已从不可变快照恢复；可继续失败页",
            "raw_tex": "",
            "raw_ready": False,
            "raw_frozen": False,
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
            "backend": snapshot.api_backend,
            "model": snapshot.ocr_model,
            "quality_profile": (
                OCR_QUALITY_PUBLICATION
                if snapshot.quality_tier.value == "high" else "standard"
            ),
            "quality_tier": snapshot.quality_tier.value,
            "output_template": "",
            "reasoning_effort": "",
            "created": started_epoch,
            "updated": time.time(),
            "state_revision": 1,
            "pause_requested": False,
            "retrying_failed": False,
            "provider_blocked": False,
            "selected_pages": list(snapshot.selected_pages),
            "selected_start": snapshot.selected_pages[0],
            "selected_end": snapshot.selected_pages[-1],
            "dpi": snapshot.initial_dpi,
            "current_concurrency_limit": snapshot.concurrency_limit,
            "rate_limited": False,
            "pages": {},
            "dir": tmpdir,
            "target": str(source_path),
            "visual_target": str(visual_source_path) if visual_source_path else "",
            "suffix": suffix,
            "errors": [],
            "_v2_store": store,
            "_v2_snapshot": snapshot,
            "recovered_after_restart": True,
        }
        for record in records:
            is_done = record.status in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW}
            is_error = record.status in {OcrPageStatus.FAILED, OcrPageStatus.CANCELLED}
            persisted_visual = False
            persisted_visual_path = os.path.join(
                tmpdir, f"page-{record.source_page}.img"
            )
            if record.image_sha256:
                try:
                    persisted_visual_path = str(
                        store.verify_page_image(snapshot.run_id, record)
                    )
                    persisted_visual = True
                except (OcrStoreError, OSError, ValueError):
                    pass
            job["pages"][record.source_page] = {
                "page_id": record.page_id,
                "source_page": record.source_page,
                "status": "done" if is_done else ("error" if is_error else "pending"),
                "tex": record.cleaned_tex,
                "error": record.error_reason,
                "png": os.path.join(tmpdir, f"page-{record.source_page}.img"),
                "persisted_visual_path": (
                    persisted_visual_path if persisted_visual else ""
                ),
                "low_conf": record.status == OcrPageStatus.NEEDS_REVIEW or is_error,
                "needs_review": record.status == OcrPageStatus.NEEDS_REVIEW,
                "attempts": max(record.call_index, record.retry_count),
                "task_index": record.task_index,
                "retrying": False,
                "figures": [],
                "image_size_pixels": (
                    list(record.image_size_pixels) if persisted_visual else []
                ),
                "visual_input_sha256": (
                    record.image_sha256 if persisted_visual else ""
                ),
                "visual_input_persisted": persisted_visual,
                "formula_evidence_inputs": [],
                "formula_evidence": [],
                "text_hint": "",
                "text_hint_chars": 0,
                "text_hint_sha256": "",
                "italic_terms": [],
                "relation_regions": [],
                "divider_regions": [],
                "framed_inset_regions": [],
                "equation_tag_regions": [],
                "equation_tag_extraction_status": "pending",
                "footnote_regions": [],
                "quality_flags": list(thaw_json(record.quality_issues)),
            }
            if is_error or not is_done:
                job["errors"].append({
                    "page": record.source_page,
                    "task_index": record.task_index,
                    "reason": record.error_reason or record.status.value,
                })
        job["done"] = sum(page["status"] in {"done", "error"} for page in job["pages"].values())
        try:
            raw_artifact = resolve_ocr_artifact(store, jid, "raw-ocr")
        except (OcrStoreError, OSError, ValueError):
            raw_artifact = None
        if raw_artifact is not None:
            raw_tex = raw_artifact.path.read_text(encoding="utf-8")
            job.update({
                "raw_tex": raw_tex,
                "raw_ready": True,
                "raw_frozen": True,
                "raw_revision": 1,
                "raw_chars": len(raw_tex),
            })
        try:
            baseline_manifest = json.loads(
                resolve_ocr_artifact(store, jid, "baseline-manifest").path.read_text(
                    encoding="utf-8"
                )
            )
        except (OcrStoreError, OSError, ValueError, json.JSONDecodeError):
            baseline_manifest = {}
        if baseline_manifest:
            job["compile_status"] = str(baseline_manifest.get("preview_status") or "")
            job["baseline_compile"] = baseline_manifest
        terminal_timestamp = str(baseline_manifest.get("created_at") or "")
        if not terminal_timestamp and records and all(
            record.status in {
                OcrPageStatus.SUCCESS,
                OcrPageStatus.NEEDS_REVIEW,
                OcrPageStatus.FAILED,
                OcrPageStatus.CANCELLED,
            }
            for record in records
        ):
            terminal_timestamp = max(
                (str(record.ended_at or "") for record in records),
                default="",
            )
        if terminal_timestamp:
            try:
                job["terminal_epoch"] = datetime.fromisoformat(
                    terminal_timestamp.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                pass
        if all(page["status"] == "done" for page in job["pages"].values()) and job["raw_frozen"]:
            job["status"] = "done"
            job["phase"] = "OCR 已从不可变快照完整恢复"
        with _ocr_jobs_lock:
            concurrent = _ocr_jobs.get(jid)
            if concurrent is not None:
                shutil.rmtree(tmpdir, ignore_errors=True)
                return concurrent
            _ocr_jobs[jid] = job
        return job

    def _launch_ocr_job(
        job: dict,
        page_nos: list[int],
        dpi: int,
        base_url: str,
        model: str,
        api_key: str,
        quality_profile: str = "standard",
    ):
        # 启动时冻结后端选择；后续设置变化不应改变本任务的重试/计费身份。
        launch_cfg = deepcopy(get_config())
        quality_tier = normalize_quality_tier(
            job.get("quality_tier") or quality_profile
        )
        tier_policy = quality_tier_policy(quality_tier)
        dpi = tier_policy.initial_dpi
        quality_profile = normalize_ocr_quality_profile(quality_profile)
        if (
            quality_profile == OCR_QUALITY_PUBLICATION
            and launch_cfg.analysis_backend == "codex_cli"
            and launch_cfg.codex_reasoning_effort == "low"
        ):
            # 出版审校优先稳定性；只把 low 提升到 medium，不覆盖用户显式 high。
            launch_cfg.codex_reasoning_effort = "medium"
        with _ocr_jobs_lock:
            job["backend"] = str(launch_cfg.analysis_backend or "api")
            job["quality_profile"] = quality_profile
            job["quality_tier"] = quality_tier.value
            job["dpi"] = dpi
            job["current_concurrency_limit"] = tier_policy.concurrency_limit
            job["rate_limited"] = False
            job["terminal_epoch"] = None
            job["reasoning_effort"] = (
                str(launch_cfg.codex_reasoning_effort or "")
                if launch_cfg.analysis_backend == "codex_cli" else ""
            )
            _bump_ocr_state(job)
        def _transcribe_one(job, client, page_no: int, png_path: str, max_attempts: int = 2):
            """转写单页；非空结果始终保留，仅明确暂时性失败自动重试。"""
            from ..ocr import (
                ocr_page_needs_retry,
                ocr_page_needs_review,
                transcribe_page_result,
            )

            if job.get("quality_profile") == OCR_QUALITY_PUBLICATION:
                max_attempts = max(max_attempts, 3)
            page = job["pages"][page_no]
            with _ocr_jobs_lock:
                page["status"] = "running"
                page["error"] = ""
                page["needs_review"] = False
                page["quality_flags"] = []
                _bump_ocr_state(job)
            with open(png_path, "rb") as image_file:
                png = image_file.read()
            correction_feedback = ""
            quality_retry_state = {}
            for attempt in range(1, max_attempts + 1):
                if attempt > 1:
                    # 上一次模型调用期间收到暂停请求时，不继续消耗下一次调用。
                    _ocr_control(job)
                with _ocr_jobs_lock:
                    page["attempts"] = page.get("attempts", 0) + 1
                    _bump_ocr_state(job)
                client.last_usage = {}
                try:
                    transcription = transcribe_page_result(
                        client,
                        png,
                        page_no,
                        reference_text=str(page.get("text_hint") or ""),
                        reference_italic_terms=list(page.get("italic_terms") or []),
                        correction_feedback=correction_feedback,
                        quality_retry_state=quality_retry_state,
                        reference_relation_regions=deepcopy(
                            page.get("relation_regions") or []
                        ),
                        reference_divider_regions=deepcopy(
                            page.get("divider_regions") or []
                        ),
                        reference_framed_insets=deepcopy(
                            page.get("framed_inset_regions") or []
                        ),
                        reference_equation_tag_regions=deepcopy(
                            page.get("equation_tag_regions") or []
                        ),
                        reference_footnote_regions=deepcopy(
                            page.get("footnote_regions") or []
                        ),
                        reference_formula_evidence=deepcopy(
                            page.get("formula_evidence_inputs") or []
                        ),
                    )
                    tex = transcription.tex
                    quality_flags = deepcopy(transcription.quality_flags or [])
                    needs_review = ocr_page_needs_review(tex) or any(
                        bool(flag.get("needs_review"))
                        for flag in quality_flags
                        if isinstance(flag, dict)
                    )
                    low_conf = (
                        "[?]" in tex
                        or "% unsure" in tex
                        or len(tex.strip()) < 40
                        or ocr_page_needs_retry(tex)
                        or needs_review
                    )
                    with _ocr_jobs_lock:
                        page["tex"] = tex
                        page["status"] = "done"
                        page["error"] = ""
                        page["low_conf"] = low_conf
                        page["needs_review"] = needs_review
                        page["figures"] = deepcopy(transcription.figures)
                        page["image_size_pixels"] = list(
                            transcription.image_size_pixels or []
                        )
                        page["quality_flags"] = quality_flags
                        page["formula_evidence"] = _bounded_formula_evidence(
                            transcription.formula_evidence or []
                        )
                        job["page_revision"] = int(job.get("page_revision") or 0) + 1
                        _bump_ocr_state(job)
                    return True
                except Exception as exc:  # noqa: BLE001
                    message = _safe_task_error(exc)
                    retry_instruction = str(
                        getattr(exc, "retry_instruction", "") or ""
                    )[:1600]
                    if retry_instruction:
                        correction_feedback = retry_instruction
                        state = getattr(exc, "retry_state", {})
                        quality_retry_state = dict(state) if isinstance(state, dict) else {}
                    with _ocr_jobs_lock:
                        page["error"] = message
                        _bump_ocr_state(job)
                    if (
                        attempt >= max_attempts
                        or not (retry_instruction or _ocr_error_is_retryable(message))
                    ):
                        break
                    _ocr_retry_wait(attempt)
                finally:
                    usage = client.last_usage if isinstance(client.last_usage, dict) else {}
                    if usage:
                        from ..pricing import add_usage, summarize_ai_usage

                        with _ocr_jobs_lock:
                            add_usage(
                                job["usage"], usage,
                                getattr(client.cfg, "model", ""),
                            )
                            job["cost"] = summarize_ai_usage({"ocr": job["usage"]})
                            job["usage_revision"] = (
                                int(job.get("usage_revision") or 0) + 1
                            )
                            _bump_ocr_state(job)
            with _ocr_jobs_lock:
                page["status"] = "error"
                page["low_conf"] = True
                job["page_revision"] = int(job.get("page_revision") or 0) + 1
                _bump_ocr_state(job)
            return False

        def _render_one(job, page_no: int) -> str:
            """渲染单页到原有页面路径，供首轮与失败页重试共用。"""
            from ..ocr import (
                image_pixel_size,
                iter_pdf_pages,
                pdf_page_italic_terms,
                pdf_page_divider_regions,
                pdf_page_equation_tag_regions,
                pdf_page_framed_insets,
                pdf_page_footnote_regions,
                pdf_page_relation_regions,
                pdf_page_text_hint,
            )

            page = job["pages"][page_no]
            source_type = str(job.get("source_type") or "")
            if source_type in {"pdf", "images"}:
                visual_path = (
                    job["target"] if source_type == "pdf" else job.get("visual_target")
                )
                if not visual_path:
                    raise RuntimeError("多图片任务缺少已记录的派生视觉 PDF")
                rendered = iter(iter_pdf_pages(
                    visual_path, [page_no], int(job.get("dpi") or dpi),
                ))
                try:
                    rendered_page, image_bytes = next(rendered)
                except StopIteration:
                    label = "原 PDF" if source_type == "pdf" else "派生视觉页源"
                    raise RuntimeError(f"{label}第 {page_no} 页未生成图像") from None
                if int(rendered_page) != page_no:
                    raise RuntimeError(f"第 {page_no} 页渲染结果页码不一致")
                if source_type == "images":
                    # Original image names/bytes/hashes are the source
                    # authority.  The derived PDF contains no trusted text or
                    # semantic geometry, so none is invented here.
                    text_hint = ""
                    italic_terms = []
                    relation_regions = []
                    divider_regions = []
                    equation_tag_regions = []
                    equation_tag_extraction_status = "not_applicable"
                    framed_inset_regions = []
                    footnote_regions = []
                    formula_evidence_inputs = []
                else:
                    # Text extraction is an optional, bounded spelling reference.
                    # It must never prevent the visual OCR path from running.
                    try:
                        text_hint = pdf_page_text_hint(job["target"], page_no)
                    except Exception:  # noqa: BLE001
                        text_hint = ""
                    try:
                        italic_terms = pdf_page_italic_terms(job["target"], page_no)
                    except Exception:  # noqa: BLE001
                        italic_terms = []
                    try:
                        relation_regions = pdf_page_relation_regions(job["target"], page_no)
                    except Exception:  # noqa: BLE001
                        relation_regions = []
                    try:
                        divider_regions = pdf_page_divider_regions(job["target"], page_no)
                    except Exception:  # noqa: BLE001
                        divider_regions = []
                    try:
                        equation_tag_regions = pdf_page_equation_tag_regions(
                            job["target"], page_no,
                        )
                        equation_tag_extraction_status = "ok"
                    except Exception:  # noqa: BLE001 - optional born-digital geometry
                        equation_tag_regions = []
                        equation_tag_extraction_status = "error"
                    try:
                        framed_inset_regions = pdf_page_framed_insets(job["target"], page_no)
                    except Exception:  # noqa: BLE001
                        framed_inset_regions = []
                    try:
                        footnote_regions = pdf_page_footnote_regions(job["target"], page_no)
                    except Exception as exc:  # noqa: BLE001 - footnotes fail closed
                        raise RuntimeError(
                            f"第 {page_no} 页脚注源证据提取失败：{str(exc)[:180]}"
                        ) from None
                    formula_evidence_inputs = _prepare_page_formula_evidence(job, page_no)
            else:
                if page_no != 1:
                    raise RuntimeError("单张图片任务仅有第 1 页")
                with open(job["target"], "rb") as image_file:
                    image_bytes = image_file.read()
                text_hint = ""
                italic_terms = []
                relation_regions = []
                divider_regions = []
                equation_tag_regions = []
                equation_tag_extraction_status = "not_applicable"
                framed_inset_regions = []
                footnote_regions = []
                formula_evidence_inputs = []
            if not image_bytes:
                raise RuntimeError(f"第 {page_no} 页渲染结果为空")
            try:
                pixel_size = image_pixel_size(image_bytes)
            except Exception:  # noqa: BLE001 - legacy API validates only MIME magic
                # Historical compatible-API clients do not need dimensions.
                # Codex re-validates a real PNG/JPEG before its structured call,
                # so a malformed raster still fails closed on that backend.
                pixel_size = ()
            tmp_path = f"{page['png']}.{uuid.uuid4().hex}.tmp"
            try:
                with open(tmp_path, "wb") as stream:
                    stream.write(image_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp_path, page["png"])
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            with _ocr_jobs_lock:
                page["text_hint"] = text_hint
                page["text_hint_chars"] = len(text_hint)
                page["text_hint_sha256"] = (
                    hashlib.sha256(text_hint.encode("utf-8")).hexdigest()
                    if text_hint else ""
                )
                page["italic_terms"] = list(italic_terms)
                page["relation_regions"] = deepcopy(relation_regions)
                page["divider_regions"] = deepcopy(divider_regions)
                page["equation_tag_regions"] = deepcopy(equation_tag_regions)
                page["equation_tag_extraction_status"] = (
                    equation_tag_extraction_status
                )
                page["framed_inset_regions"] = deepcopy(framed_inset_regions)
                page["footnote_regions"] = deepcopy(footnote_regions)
                page["image_size_pixels"] = list(pixel_size)
                page["visual_input_sha256"] = hashlib.sha256(image_bytes).hexdigest()
                page["visual_input_persisted"] = False
                page["persisted_visual_path"] = ""
                page["formula_evidence_inputs"] = deepcopy(formula_evidence_inputs)
                page["formula_evidence"] = [
                    {
                        **item,
                        "attached": False,
                    }
                    for item in _bounded_formula_evidence(formula_evidence_inputs)
                ]
                _bump_ocr_state(job)
            return page["png"]

        def _mark_page_error(job, page_no: int, exc: Exception | str):
            message = _safe_task_error(exc) if isinstance(exc, Exception) else str(exc)[:500]
            if "No module named 'fitz'" in message:
                message = "缺少 PDF 渲染组件 PyMuPDF，请重新安装完整版本后重试"
            with _ocr_jobs_lock:
                page = job["pages"][page_no]
                page["status"] = "error"
                page["low_conf"] = True
                page["needs_review"] = False
                page["error"] = message
                job["page_revision"] = int(job.get("page_revision") or 0) + 1
                _bump_ocr_state(job)
            return message

        def _refresh_raw_preview(job):
            from ..ocr import merge_book, verified_equation_tag_evidence

            with _ocr_jobs_lock:
                completed = [
                    (page_no, job["pages"][page_no])
                    for page_no in job["selected_pages"]
                    if job["pages"][page_no]["status"] == "done"
                ]
                chunks = [
                    f"% Page {page_no}\n{page['tex']}"
                    for page_no, page in completed
                ]
                evidence = verified_equation_tag_evidence([
                    {
                        "page": page_no,
                        "quality_flags": deepcopy(page.get("quality_flags") or []),
                    }
                    for page_no, page in completed
                ])
                merged = merge_book(
                    chunks,
                    outline=job.get("source_outline"),
                    equation_tag_evidence=evidence,
                )
                previous = str(job.get("raw_tex") or "")
                job["raw_tex"] = merged
                job["raw_ready"] = bool(chunks)
                job["raw_chars"] = len(merged)
                if merged != previous:
                    job["raw_revision"] = int(job.get("raw_revision") or 0) + 1
                _bump_ocr_state(job)

        def _merge_job(job, complete_progress: bool = True):
            with _ocr_jobs_lock:
                errors = []
                for page_no in job["selected_pages"]:
                    page = job["pages"][page_no]
                    if page["status"] != "done":
                        errors.append({
                            "page": page_no,
                            "task_index": page["task_index"],
                            "reason": page["error"] or page["status"],
                        })
                job["errors"] = errors
                if job.get("pause_requested"):
                    job["status"] = "pausing"
                    job["phase"] = "正在完成当前步骤，随后安全暂停"
                else:
                    job["status"] = "done" if not errors else "partial"
                    job["phase"] = "原始 OCR 已就绪" if not errors else "部分页面失败，等待重试"
                job["error"] = "" if not errors else str(errors[0]["reason"])
                if not job.get("pause_requested"):
                    job["pause_requested"] = False
                if complete_progress:
                    job["progress"] = 1.0
                if not job.get("pause_requested"):
                    # Freeze only after the caller has completed merge/freeze and
                    # baseline compilation.  Page OCR timestamps remain untouched.
                    job["terminal_epoch"] = time.time()
                _bump_ocr_state(job)
                _ocr_jobs_changed.notify_all()

        with _ocr_jobs_lock:
            job["_transcribe_one"] = _transcribe_one
            job["_refresh_raw_preview"] = _refresh_raw_preview
            job["_merge_job"] = _merge_job
            job["_render_one"] = _render_one
            job["_mark_page_error"] = _mark_page_error
            job["dpi"] = dpi
            _bump_ocr_state(job)

        def _iso_now() -> str:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        def _record_v2_usage(client, usage: dict) -> None:
            if not isinstance(usage, dict) or not usage:
                usage = client.last_usage if isinstance(client.last_usage, dict) else {}
            if not usage:
                return
            from ..pricing import add_usage, summarize_ai_usage

            with _ocr_jobs_lock:
                add_usage(job["usage"], usage, getattr(client.cfg, "model", ""))
                job["cost"] = summarize_ai_usage({"ocr": job["usage"]})
                job["usage_revision"] = int(job.get("usage_revision") or 0) + 1
                _bump_ocr_state(job)

        def _v2_model_call(client, requests):
            expected = [request.page_id for request in requests]
            prompt = ocr_batch_request_payload(requests)
            schema = ocr_batch_output_schema(expected)
            _ocr_control(job)
            client.last_usage = {}
            if len(requests) == 1:
                generic_single = getattr(client, "chat_vision_json_bytes", None)
                configured_key = str(getattr(getattr(client, "cfg", None), "api_key", "") or "")
                active_backend = str(job.get("backend") or "api")
                if callable(generic_single) and (
                    active_backend == "codex_cli" or configured_key
                ):
                    response, usage = generic_single(
                        OCR_TRANSCRIPTION_SYSTEM_PROMPT,
                        prompt,
                        requests[0].image_bytes,
                        schema,
                    )
                else:
                    # Compatibility path for old provider adapters used by
                    # existing installations/tests.  It remains a real visual
                    # OCR call and is wrapped in the host-owned page_id schema.
                    from ..ocr import transcribe_page_result

                    legacy_page = job["pages"][requests[0].source_page]
                    transcription = transcribe_page_result(
                        client,
                        requests[0].image_bytes,
                        requests[0].source_page,
                        reference_text=requests[0].text_layer_hint,
                        correction_feedback=requests[0].correction_instruction,
                        quality_retry_state=thaw_json(requests[0].retry_state),
                        reference_italic_terms=list(
                            legacy_page.get("italic_terms") or []
                        ),
                        reference_relation_regions=deepcopy(
                            legacy_page.get("relation_regions") or []
                        ),
                        reference_divider_regions=deepcopy(
                            legacy_page.get("divider_regions") or []
                        ),
                        reference_framed_insets=deepcopy(
                            legacy_page.get("framed_inset_regions") or []
                        ),
                        reference_equation_tag_regions=deepcopy(
                            legacy_page.get("equation_tag_regions") or []
                        ),
                        reference_footnote_regions=deepcopy(
                            legacy_page.get("footnote_regions") or []
                        ),
                        reference_formula_evidence=deepcopy(
                            legacy_page.get("formula_evidence_inputs") or []
                        ),
                    )
                    legacy_tex = re.sub(
                        r"(?mi)^\s*%\s*Page\s+\d+\s*$",
                        "",
                        transcription.tex,
                    ).strip()
                    response = {"pages": [{
                        "page_id": requests[0].page_id,
                        "latex": legacy_tex,
                        "figures": transcription.figures,
                        "host_quality_flags": deepcopy(transcription.quality_flags or []),
                        "unresolved_regions": [
                            {"type": "legacy_quality_flag", **deepcopy(flag)}
                            for flag in (transcription.quality_flags or [])
                            if isinstance(flag, dict) and flag.get("needs_review")
                        ],
                    }]}
                    usage = client.last_usage if isinstance(client.last_usage, dict) else {}
            else:
                generic_batch = getattr(client, "chat_vision_json_images_bytes", None)
                configured_key = str(getattr(getattr(client, "cfg", None), "api_key", "") or "")
                active_backend = str(job.get("backend") or "api")
                if not callable(generic_batch) or (
                    active_backend == "api" and not configured_key
                ):
                    raise RuntimeError("batch unsupported by this provider adapter")
                response, usage = generic_batch(
                    OCR_TRANSCRIPTION_SYSTEM_PROMPT,
                    prompt,
                    [request.image_bytes for request in requests],
                    schema,
                )
            _record_v2_usage(client, usage)
            # Keep bounded, per-page telemetry next to the immutable page
            # record.  A multi-image provider reports one shared usage object;
            # record that relationship instead of dividing tokens by guesswork.
            if isinstance(usage, dict) and usage:
                with _ocr_jobs_lock:
                    telemetry = job.setdefault("_v2_page_usage", {})
                    for request in requests:
                        telemetry.setdefault(request.page_id, []).append({
                            "call_index": int(
                                job["pages"][request.source_page].get("attempts") or 0
                            ),
                            "batch_shared": len(requests) > 1,
                            "batch_page_count": len(requests),
                            "usage": deepcopy(usage),
                        })
                    _bump_ocr_state(job)
            return response

        def _prepare_v2_request(
            store,
            snapshot,
            record,
            *,
            retry: bool = False,
            correction_instruction: str = "",
            retry_state: dict | None = None,
        ):
            from ..ocr import make_host_ocr_page_request

            page_no = record.source_page
            page = job["pages"][page_no]
            if (
                retry
                and record.status != OcrPageStatus.RETRYING
                and record.status != OcrPageStatus.PENDING
            ):
                record = record.transition(
                    OcrPageStatus.RETRYING,
                    retry_count=record.retry_count + 1,
                    error_reason="自动提高到 300 DPI 并进行单页重试",
                )
                store.persist_record(snapshot.run_id, record)
            render_dpi = tier_policy.retry_dpi if retry else snapshot.initial_dpi
            with _ocr_jobs_lock:
                job["dpi"] = render_dpi
                job["page"] = page_no
                job["current_index"] = record.task_index
                job["phase"] = (
                    f"正在以 {render_dpi} DPI 重试第 {page_no} 页"
                    if retry else f"正在渲染并识别第 {page_no} 页"
                )
                page["retrying"] = retry
                _bump_ocr_state(job)
            record = record.transition(OcrPageStatus.RENDERING, dpi=render_dpi)
            store.persist_record(snapshot.run_id, record)
            _render_one(job, page_no)
            image_bytes = Path(page["png"]).read_bytes()
            with _ocr_jobs_lock:
                page["status"] = "running"
                _bump_ocr_state(job)
            record = record.transition(
                OcrPageStatus.OCR_RUNNING,
                image_sha256=hashlib.sha256(image_bytes).hexdigest(),
                image_size_pixels=tuple(page.get("image_size_pixels") or ()),
                dpi=render_dpi,
                model=snapshot.ocr_model,
                call_index=record.call_index + 1,
                started_at=_iso_now(),
                error_reason="",
            )
            store.persist_record(snapshot.run_id, record)
            with _ocr_jobs_lock:
                page["attempts"] = max(
                    int(page.get("attempts") or 0),
                    int(record.call_index or 0),
                )
                _bump_ocr_state(job)
            return make_host_ocr_page_request(
                image_bytes,
                page_no,
                record.task_index,
                dpi=render_dpi,
                text_layer_hint=str(page.get("text_hint") or ""),
                correction_instruction=correction_instruction,
                retry_state=retry_state,
            )

        def _commit_v2_result(store, snapshot, execution, *, exhausted=False):
            request = execution.request
            record = store.load_record(snapshot.run_id, request.page_id)
            page = job["pages"][request.source_page]
            persisted_visual_path = store.persist_page_image(
                snapshot.run_id,
                record,
                request.image_bytes,
            )
            with _ocr_jobs_lock:
                page["persisted_visual_path"] = str(persisted_visual_path)
                page["attempts"] = max(
                    int(page.get("attempts") or 0),
                    int(record.call_index or 0),
                )
                page["image_size_pixels"] = list(record.image_size_pixels)
                page["visual_input_sha256"] = record.image_sha256
                page["visual_input_persisted"] = True
                _bump_ocr_state(job)
            if execution.page is None:
                failure_issue = {
                    "code": "OCR_CALL_FAILED",
                    "severity": "error",
                    "category": (
                        execution.error_category.value
                        if execution.error_category is not None
                        else OcrErrorCategory.UNKNOWN.value
                    ),
                    "message": (execution.error or "OCR 未返回可验证页面结果")[:500],
                }
                record = record.transition(
                    OcrPageStatus.FAILED,
                    ended_at=_iso_now(),
                    error_reason=execution.error or "OCR 未返回可验证页面结果",
                    quality_issues=tuple(record.quality_issues) + (failure_issue,),
                    usage={
                        "attempts": deepcopy(
                            (job.get("_v2_page_usage") or {}).get(request.page_id) or []
                        )
                    },
                )
                store.persist_record(snapshot.run_id, record)
                _mark_page_error(job, request.source_page, record.error_reason)
                return False
            validated = execution.page
            raw_object = thaw_json(validated.raw_object)
            raw_bytes = json.dumps(
                raw_object,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            needs_review = bool(validated.needs_review or (validated.needs_retry and exhausted))
            final_status = (
                OcrPageStatus.NEEDS_REVIEW if needs_review else OcrPageStatus.SUCCESS
            )
            elapsed = None
            try:
                started = datetime.fromisoformat(record.started_at.replace("Z", "+00:00"))
                elapsed = max(
                    0.0,
                    (datetime.now(timezone.utc) - started).total_seconds(),
                )
            except (TypeError, ValueError):
                pass
            record = record.transition(OcrPageStatus.VALIDATING)
            record = record.transition(
                final_status,
                batch_call=bool(execution.used_batch),
                batch_id=execution.batch_id,
                raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                raw_tex=validated.latex,
                cleaned_tex=validated.latex,
                ended_at=_iso_now(),
                elapsed_seconds=elapsed,
                quality_issues=(
                    tuple(record.quality_issues)
                    + tuple(issue.to_dict() for issue in validated.issues)
                ),
                unresolved_regions=tuple(thaw_json(validated.unresolved_regions)),
                usage={
                    "attempts": deepcopy(
                        (job.get("_v2_page_usage") or {}).get(request.page_id) or []
                    )
                },
                error_reason=(
                    "自动重试已用尽；该页需要人工确认" if needs_review else ""
                ),
            )
            store.persist_record(snapshot.run_id, record, raw_response=raw_object)
            with _ocr_jobs_lock:
                page["tex"] = validated.latex
                page["status"] = "done"
                page["error"] = record.error_reason
                page["low_conf"] = needs_review
                page["needs_review"] = needs_review
                page["retrying"] = False
                page["figures"] = list(thaw_json(validated.figures))
                runtime_flags = [
                    {
                        "type": "v2_ocr_validation",
                        **issue.to_dict(),
                        "needs_review": needs_review,
                    }
                    for issue in validated.issues
                ]
                legacy_flags = [
                    deepcopy(flag)
                    for flag in (raw_object.get("host_quality_flags") or [])
                    if isinstance(flag, dict)
                ]
                page["quality_flags"] = legacy_flags or runtime_flags
                job["page_revision"] = int(job.get("page_revision") or 0) + 1
                _bump_ocr_state(job)
            _refresh_raw_preview(job)
            return True

        def _retry_v2_execution(store, snapshot, client, execution):
            current = execution
            attempts = 0
            while (
                (current.page is None or current.page.needs_retry)
                and attempts < snapshot.max_retries
            ):
                if (
                    current.page is None
                    and not current.retry_instruction
                    and current.error_category not in {
                        OcrErrorCategory.TRANSIENT,
                        OcrErrorCategory.RATE_LIMIT,
                    }
                ):
                    break
                attempts += 1
                record = store.load_record(snapshot.run_id, current.request.page_id)
                if record.status == OcrPageStatus.OCR_RUNNING:
                    retry_issue = {
                        "code": "OCR_RETRY_SCHEDULED",
                        "severity": "warning",
                        "category": (
                            current.error_category.value
                            if current.error_category is not None
                            else OcrErrorCategory.UNKNOWN.value
                        ),
                        "message": (
                            current.error
                            or current.retry_instruction
                            or "页面质量门要求重新识别"
                        )[:500],
                    }
                    record = record.transition(
                        OcrPageStatus.RETRYING,
                        retry_count=record.retry_count + 1,
                        error_reason=current.error or "页面质量门要求重新识别",
                        quality_issues=tuple(record.quality_issues) + (retry_issue,),
                    )
                    store.persist_record(snapshot.run_id, record)
                if current.error_category in {
                    OcrErrorCategory.TRANSIENT,
                    OcrErrorCategory.RATE_LIMIT,
                }:
                    _ocr_retry_wait(attempts)
                request = _prepare_v2_request(
                    store,
                    snapshot,
                    record,
                    retry=True,
                    correction_instruction=current.retry_instruction,
                    retry_state=thaw_json(current.retry_state),
                )
                current = BoundedOcrExecutor(batch_size=1, concurrency_limit=1).run(
                    [request],
                    single_call=lambda item: _v2_model_call(client, [item]),
                )[0]
            return current, bool(
                current.page is not None and current.page.needs_retry
            )

        def _finalize_v2_ocr(store, snapshot):
            from ..core.ocr_baseline import compile_ocr_baseline
            from ..ocr import merge_book

            with _ocr_jobs_lock:
                job["phase"] = "正在冻结不可变 OCR 原稿"
                _bump_ocr_state(job)
            raw_manifest = store.freeze_raw_ocr(
                snapshot.run_id,
                document_builder=lambda fragments: merge_book(
                    fragments,
                    outline=job.get("source_outline"),
                ),
                model_usage=job.get("usage") or {},
                merge_version="2.0.0",
            )
            artifact_dir = store.run_dir(snapshot.run_id) / "artifacts"
            raw_tex = (artifact_dir / "raw-ocr.tex").read_text(encoding="utf-8")
            with _ocr_jobs_lock:
                previous = str(job.get("raw_tex") or "")
                job["raw_tex"] = raw_tex
                job["raw_ready"] = True
                job["raw_frozen"] = True
                job["raw_chars"] = len(raw_tex)
                if raw_tex != previous:
                    job["raw_revision"] = int(job.get("raw_revision") or 0) + 1
                job["phase"] = "正在真实编译 OCR 基线（两次）"
                _bump_ocr_state(job)
            if job.get("_compatibility_single"):
                # Old no-key provider adapters are retained only for backward
                # compatibility and unit-level fakes.  They cannot establish
                # the v2 structured-provider contract, so record an explicit
                # source preview instead of pretending a compile occurred.
                manifest = store.save_compile_baseline(
                    snapshot.run_id,
                    baseline_tex=raw_tex,
                    compile_log=(
                        "SOURCE_PREVIEW：这不是 LaTeX 编译结果；旧兼容适配器未执行基线编译。"
                    ),
                    preview_status=OcrPreviewStatus.SOURCE_PREVIEW,
                    exit_code=1,
                    successful_passes=0,
                    pdf_bytes=b"",
                    preview_filename="source-preview.pdf",
                )
                with _ocr_jobs_lock:
                    job["compile_status"] = OcrPreviewStatus.SOURCE_PREVIEW.value
                    job["baseline_compile"] = manifest
                    job["baseline_tex_sha256"] = manifest.get("baseline_tex_sha256")
                    job["raw_ocr_sha256"] = raw_manifest.get("raw_ocr_sha256")
                    _bump_ocr_state(job)
                return
            baseline = compile_ocr_baseline(raw_tex)
            manifest = store.save_compile_baseline(
                snapshot.run_id,
                baseline_tex=baseline.tex,
                compile_log=baseline.log,
                preview_status=baseline.preview_status,
                exit_code=baseline.exit_code,
                successful_passes=baseline.successful_passes,
                pdf_bytes=baseline.pdf_bytes,
                syntax_repairs=baseline.syntax_repairs,
                error_lines=baseline.error_lines,
                preview_filename="source-preview.pdf",
            )
            with _ocr_jobs_lock:
                job["compile_status"] = baseline.preview_status.value
                job["baseline_compile"] = manifest
                job["baseline_tex_sha256"] = manifest.get("baseline_tex_sha256")
                job["raw_ocr_sha256"] = raw_manifest.get("raw_ocr_sha256")
                job["phase"] = (
                    "OCR 基线已真实编译"
                    if baseline.preview_status == OcrPreviewStatus.COMPILED
                    else "OCR 已完成；基线编译需检查"
                )
                _bump_ocr_state(job)

        def _retry_v2_page(page_no: int) -> bool:
            """Retry one non-final page against the same immutable run identity."""
            store = job.get("_v2_store")
            snapshot = job.get("_v2_snapshot")
            client = job.get("client")
            if not isinstance(store, OcrRunStore) or snapshot is None or client is None:
                raise OcrStoreError("OCR 运行证据尚未初始化")
            if job.get("provider_blocked"):
                retry_cfg = deepcopy(get_config())
                retry_cfg.analysis_backend = snapshot.api_backend
                refreshed, selected_model, selected_backend = _build_ocr_client(
                    retry_cfg, "", snapshot.ocr_model, ""
                )
                if selected_model != snapshot.ocr_model or selected_backend != snapshot.api_backend:
                    raise OcrStoreError("当前模型设置与不可变 OCR 任务不一致")
                client = refreshed
                with _ocr_jobs_lock:
                    job["client"] = refreshed
                    job["provider_blocked"] = False
            records = store.recover(snapshot.run_id)
            record = next((item for item in records if item.source_page == page_no), None)
            if record is None:
                raise OcrStoreError("页面不属于本次不可变页范围")
            if record.status == OcrPageStatus.SUCCESS:
                raise OcrStoreError("成功页已经冻结；如需重做请创建新的 OCR 任务")
            if job.get("raw_frozen"):
                raise OcrStoreError("OCR 原稿已经冻结；如需重做请创建新的 OCR 任务")
            request = _prepare_v2_request(store, snapshot, record, retry=True)
            execution = BoundedOcrExecutor(batch_size=1, concurrency_limit=1).run(
                [request],
                single_call=lambda item: _v2_model_call(client, [item]),
            )[0]
            final, exhausted = _retry_v2_execution(store, snapshot, client, execution)
            ok = _commit_v2_result(store, snapshot, final, exhausted=exhausted)
            remaining = store.list_records(snapshot.run_id)
            if all(item.status in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW} for item in remaining):
                _finalize_v2_ocr(store, snapshot)
            _merge_job(job)
            return ok

        def worker():
            try:
                client, selected_model, backend = _build_ocr_client(
                    launch_cfg, base_url, model, api_key,
                )
                from .. import __version__

                source_bytes = Path(job["target"]).read_bytes()
                visual_source_bytes = (
                    Path(job["visual_target"]).read_bytes()
                    if job.get("source_type") == "images" and job.get("visual_target")
                    else b""
                )
                store = OcrRunStore(Path(get_store().root).parent / "ocr-runs")
                snapshot_path = store.run_dir(job["id"]) / "run-snapshot.json"
                if snapshot_path.is_file():
                    snapshot = store.load_snapshot(job["id"])
                    if (
                        snapshot.source_sha256 != hashlib.sha256(source_bytes).hexdigest()
                        or snapshot.selected_pages != tuple(page_nos)
                        or snapshot.ocr_model != selected_model
                        or snapshot.api_backend != backend
                        or (
                            snapshot.source_type == "images"
                            and snapshot.visual_source_sha256
                            != hashlib.sha256(visual_source_bytes).hexdigest()
                        )
                    ):
                        raise OcrStoreError("恢复设置与不可变 OCR 任务不一致")
                    store.verify_source(snapshot.run_id)
                    if snapshot.source_type == "images":
                        store.verify_visual_source(snapshot.run_id)
                else:
                    snapshot = make_run_snapshot(
                        source_bytes=source_bytes,
                        source_type=job["source_type"],
                        original_filename=job.get("original_filename") or f"scan{job['suffix']}",
                        source_total_pages=int(job["source_total"]),
                        selected_pages=tuple(page_nos),
                        ocr_model=selected_model,
                        api_backend=backend,
                        app_version=__version__,
                        quality_tier=quality_tier,
                        bookmarks=tuple(job.get("source_outline") or ()),
                        source_images=tuple(job.get("source_images") or ()),
                        visual_source_bytes=visual_source_bytes,
                        runtime_options={
                            "initial_dpi": tier_policy.initial_dpi,
                            "max_retries": tier_policy.max_retries,
                            "batch_size": tier_policy.batch_size,
                            "concurrency_limit": tier_policy.concurrency_limit,
                            "retry_dpi": tier_policy.retry_dpi,
                        },
                        run_id=job["id"],
                    )
                    store.initialize(
                        snapshot,
                        source_bytes,
                        visual_source_bytes=visual_source_bytes,
                    )
                records = store.recover(snapshot.run_id)
                with _ocr_jobs_lock:
                    job["client"] = client
                    job["model"] = selected_model
                    job["backend"] = backend
                    job["_v2_store"] = store
                    job["_v2_snapshot"] = snapshot
                    job["_v2_retry_page"] = _retry_v2_page
                    job["started_at"] = snapshot.started_at
                    job["phase"] = "三页批处理 OCR；失败页自动提高清晰度重试"
                    _bump_ocr_state(job)
                configured_key = str(
                    getattr(getattr(client, "cfg", None), "api_key", "") or ""
                )
                compatibility_single = backend == "api" and not configured_key
                with _ocr_jobs_lock:
                    job["_compatibility_single"] = compatibility_single
                executor = BoundedOcrExecutor(
                    batch_size=1 if compatibility_single else snapshot.batch_size,
                    concurrency_limit=(
                        1 if compatibility_single else snapshot.concurrency_limit
                    ),
                )
                pending = [
                    record for record in records
                    if record.status in {
                        OcrPageStatus.PENDING,
                        OcrPageStatus.RETRYING,
                        OcrPageStatus.FAILED,
                    }
                ]
                effective_batch_size = executor.batch_size
                for offset in range(0, len(pending), effective_batch_size):
                    _ocr_control(job)
                    batch_records = pending[offset:offset + effective_batch_size]
                    requests = []
                    for record in batch_records:
                        try:
                            requests.append(_prepare_v2_request(
                                store,
                                snapshot,
                                record,
                                retry=record.status in {
                                    OcrPageStatus.RETRYING,
                                    OcrPageStatus.FAILED,
                                },
                            ))
                        except Exception as exc:  # noqa: BLE001
                            failed = store.load_record(snapshot.run_id, record.page_id)
                            if failed.status in {
                                OcrPageStatus.RENDERING,
                                OcrPageStatus.OCR_RUNNING,
                                OcrPageStatus.RETRYING,
                            }:
                                failed = failed.transition(
                                    OcrPageStatus.FAILED,
                                    error_reason=_safe_task_error(exc),
                                    ended_at=_iso_now(),
                                )
                                store.persist_record(snapshot.run_id, failed)
                            _mark_page_error(job, record.source_page, exc)
                    if not requests:
                        continue
                    results = executor.run(
                        requests,
                        single_call=lambda request: _v2_model_call(client, [request]),
                        # Codex CLI process startup is independently bounded by
                        # its role-aware global gate.  Three parallel single-page
                        # calls make the configured OCR concurrency real, while
                        # API providers retain their lower-overhead three-image
                        # batch transport.
                        batch_call=(
                            None
                            if backend == "codex_cli"
                            else lambda items: _v2_model_call(client, items)
                        ),
                    )
                    for execution in results:
                        final, exhausted = _retry_v2_execution(
                            store, snapshot, client, execution
                        )
                        _commit_v2_result(
                            store, snapshot, final, exhausted=exhausted
                        )
                    with _ocr_jobs_lock:
                        job["done"] = sum(
                            page.get("status") in {"done", "error"}
                            for page in job["pages"].values()
                        )
                        _bump_ocr_state(job)
                errors = [
                    record for record in store.list_records(snapshot.run_id)
                    if record.status in {OcrPageStatus.FAILED, OcrPageStatus.CANCELLED}
                ]
                if not errors:
                    _finalize_v2_ocr(store, snapshot)
                _merge_job(job)
                with _ocr_jobs_lock:
                    job["dpi"] = snapshot.initial_dpi
                    _bump_ocr_state(job)
            except OcrRunPaused as exc:
                message = _safe_task_error(exc)
                store = job.get("_v2_store")
                snapshot = job.get("_v2_snapshot")
                if isinstance(store, OcrRunStore) and snapshot is not None:
                    try:
                        records_to_fail = store.list_records(snapshot.run_id)
                    except (OcrStoreError, OSError):
                        records_to_fail = []
                    for record in records_to_fail:
                        if record.status in {
                            OcrPageStatus.RENDERING,
                            OcrPageStatus.QUEUED,
                            OcrPageStatus.OCR_RUNNING,
                            OcrPageStatus.VALIDATING,
                            OcrPageStatus.RETRYING,
                        }:
                            try:
                                failed = record.transition(
                                    OcrPageStatus.FAILED,
                                    ended_at=_iso_now(),
                                    error_reason=message,
                                )
                                store.persist_record(snapshot.run_id, failed)
                            except (OcrStoreError, OSError):
                                pass
                            _mark_page_error(job, record.source_page, message)
                with _ocr_jobs_lock:
                    job["status"] = "partial"
                    job["provider_blocked"] = True
                    job["pause_requested"] = False
                    job["phase"] = "识别服务暂停；已完成页面均已保存"
                    job["error"] = message
                    job["terminal_epoch"] = time.time()
                    if not job.get("errors"):
                        job["errors"] = [{
                            "page": int(job.get("page") or 0),
                            "task_index": int(job.get("current_index") or 0),
                            "reason": job["error"],
                        }]
                    _bump_ocr_state(job)
            except Exception as exc:  # noqa: BLE001
                message = _safe_task_error(exc)
                if "No module named 'fitz'" in message:
                    message = "缺少 PDF 渲染组件 PyMuPDF，请重新安装完整版本后重试"
                with _ocr_jobs_lock:
                    unfinished = [
                        page_no for page_no, page in job.get("pages", {}).items()
                        if page.get("status") in {"pending", "running"}
                    ]
                for page_no in unfinished:
                    _mark_page_error(job, page_no, message)
                has_done = any(
                    page.get("status") == "done" for page in job.get("pages", {}).values()
                )
                _merge_job(job, complete_progress=False)
                with _ocr_jobs_lock:
                    job["status"] = "partial" if has_done else "error"
                    job["phase"] = (
                        "后续页面处理失败，已保留完成页"
                        if has_done else "准备、识别或基线编译失败"
                    )
                    job["error"] = message
                    _bump_ocr_state(job)

        threading.Thread(
            target=worker, daemon=True, name=f"latexstruct-ocr-{job['id'][:12]}",
        ).start()

    @app.post("/api/ocr/inspect")
    async def ocr_inspect(file: list[UploadFile] = File(...)):
        """上传一次 PDF/图片并创建不可猜测的待启动任务。"""
        _cleanup_ocr_jobs()
        (
            suffix,
            upload,
            source_total,
            source_outline,
            source_type,
            original_filename,
            visual_source,
            source_images,
        ) = await _read_ocr_upload(file)
        job = _create_ocr_job(
            suffix,
            upload,
            source_total,
            "ready",
            source_outline=source_outline,
            original_filename=original_filename,
            source_type=source_type,
            visual_source=visual_source,
            source_images=source_images,
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
        dpi: int = Form(200),
        base_url: str = Form(""),
        model: str = Form(""),
        api_key: str = Form(""),
        quality_profile: str = Form("standard"),
        quality_tier: Optional[str] = Form(None),
        output_template: str = Form(""),
    ):
        _cleanup_ocr_jobs()
        if not 72 <= dpi <= 300:
            raise HTTPException(400, "DPI 必须在 72-300 之间")
        if len(model) > 160 or len(base_url) > 500:
            raise HTTPException(400, "模型或 Base URL 输入过长")
        try:
            legacy_profile = normalize_ocr_quality_profile(quality_profile)
            if legacy_profile == OCR_QUALITY_PUBLICATION and dpi < 200:
                raise ValueError("出版审校工作流要求至少 200 DPI")
            explicit_tier = str(quality_tier or "").strip()
            # v2 callers own the three-tier selection.  A legacy publication
            # profile may imply ``high`` only when no explicit v2 tier was
            # supplied; otherwise a visible "recommended" choice must never be
            # silently promoted after the job starts.
            tier_input = explicit_tier or (
                "high" if legacy_profile == OCR_QUALITY_PUBLICATION else "recommended"
            )
            normalized_tier = normalize_quality_tier(
                tier_input
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        policy = quality_tier_policy(normalized_tier)
        quality_profile = (
            OCR_QUALITY_PUBLICATION
            if normalized_tier.value == "high"
            else "standard"
        )
        # v2 OCR quality is tier-driven.  The request field remains accepted
        # for old clients, but all tiers start from the frozen 200-DPI policy.
        dpi = policy.initial_dpi
        from ..core.template import normalize_template_id

        try:
            output_template = normalize_template_id(output_template)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
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
                job["output_template"] = output_template
                job["quality_tier"] = normalized_tier.value
                job["quality_profile"] = quality_profile
                # Freeze the build/prompt that will produce this OCR text.  A
                # later application update may export the task, but must never
                # rewrite its producer identity as the newer exporter.
                job["producer_identity"] = _runtime_provenance_identity(
                    _ocr_prompt_version()
                )
                job["status"] = "running"
                _bump_ocr_state(job)
        _launch_ocr_job(
            job, page_nos, dpi, base_url, model, api_key, quality_profile,
        )
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
                    job.get("status") in OCR_ACTIVE_STATUSES
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
            job = _restore_persisted_ocr_job(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        return _public_ocr_job(job)

    @app.get("/api/ocr/jobs/{jid}/artifacts/{role}")
    def ocr_artifact(jid: str, role: str):
        """Download a manifest/hash-verified immutable OCR artifact by role."""
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
        if job is None:
            job = _restore_persisted_ocr_job(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        with _ocr_jobs_lock:
            store = job.get("_v2_store")
            snapshot = job.get("_v2_snapshot")
        if not isinstance(store, OcrRunStore) or snapshot is None:
            raise HTTPException(404, "该任务没有 2.0.0 OCR 证据")
        try:
            artifact = resolve_ocr_artifact(store, snapshot.run_id, role)
        except ValueError:
            raise HTTPException(404, "OCR 产物角色不存在") from None
        except (OcrStoreError, OSError) as exc:
            raise HTTPException(409, _safe_task_error(exc)) from None
        return FileResponse(
            artifact.path,
            media_type=artifact.media_type,
            filename=artifact.filename,
            headers={
                "X-LaTeXStruct-SHA256": artifact.sha256,
                "Cache-Control": "no-store",
            },
        )

    @app.get("/api/ocr/jobs/{jid}/quality")
    def ocr_quality(jid: str):
        """Return the live evidence gate without claiming measured accuracy."""
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
        if job is None:
            job = _restore_persisted_ocr_job(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        return assess_ocr_quality(job)

    @app.post("/api/ocr/jobs/{jid}/pause")
    def ocr_pause(jid: str):
        """请求在渲染后或当前页面完成后的安全边界暂停。"""
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_changed:
                job = _ocr_jobs.get(jid)
                if job is None:
                    raise HTTPException(404, "任务不存在")
                status = str(job.get("status") or "")
                if status == "running":
                    job["pause_requested"] = True
                    job["status"] = "pausing"
                    job["phase"] = "正在完成当前步骤，随后安全暂停"
                    _bump_ocr_state(job)
                    _ocr_jobs_changed.notify_all()
                elif status not in {"pausing", "paused"}:
                    raise HTTPException(409, "当前 OCR 任务不在运行，不能暂停")
                return _public_ocr_job(job)

    @app.post("/api/ocr/jobs/{jid}/resume")
    def ocr_resume(jid: str):
        """继续一个正在安全暂停或已经暂停的 OCR 任务。"""
        job = _ocr_jobs.get(jid) or _restore_persisted_ocr_job(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        relaunch = False
        snapshot = job.get("_v2_snapshot")
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_changed:
                status = str(job.get("status") or "")
                if status in {"pausing", "paused"}:
                    job["pause_requested"] = False
                    job["status"] = "running"
                    job["phase"] = "已继续 OCR"
                    _bump_ocr_state(job)
                    _ocr_jobs_changed.notify_all()
                elif (
                    status == "partial"
                    and snapshot is not None
                    and not job.get("raw_frozen")
                ):
                    job["pause_requested"] = False
                    job["status"] = "running"
                    job["phase"] = "正在从不可变页记录继续失败页"
                    job["error"] = ""
                    relaunch = True
                    _bump_ocr_state(job)
                elif status != "running":
                    raise HTTPException(409, "当前 OCR 任务没有暂停")
        if relaunch:
            _launch_ocr_job(
                job,
                list(snapshot.selected_pages),
                snapshot.initial_dpi,
                "",
                snapshot.ocr_model,
                "",
                str(job.get("quality_profile") or "standard"),
            )
        return _public_ocr_job(job)

    @app.get("/api/ocr/jobs/{jid}/preview")
    def ocr_preview(jid: str):
        """返回当前已完成页的原子 LaTeX 草稿快照。"""
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
        if job is None:
            job = _restore_persisted_ocr_job(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        with _ocr_jobs_lock:
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
        # ``preview_ready`` in the polling response is derived from this same
        # durable file check.  Keep a not-yet-rendered page distinct from an
        # unknown page: callers must wait for preview_ready rather than infer
        # availability from an OCR state such as ``running`` or ``error``.
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
            page = (job or {}).get("pages", {}).get(n)
            if not page:
                raise HTTPException(404, "页面不存在")
            page_path = str(
                page.get("persisted_visual_path") or page.get("png") or ""
            )
            preview_ready = os.path.isfile(page_path)
        if not preview_ready:
            raise HTTPException(409, "页面预览尚未持久化，请等待 preview_ready")
        from ..ocr import image_mime_type

        media_type = image_mime_type(Path(page_path).read_bytes())
        return FileResponse(page_path, media_type=media_type)

    @app.get("/api/ocr/jobs/{jid}/pages/{n}/tex")
    def ocr_page_tex(jid: str, n: int):
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not page:
            raise HTTPException(404, "页面不存在")
        return PlainTextResponse(page.get("tex", ""))

    @app.post("/api/ocr/jobs/{jid}/pages/{n}/retry")
    def ocr_page_retry(jid: str, n: int):
        """单页重试；若页面预览缺失，先从原 PDF 按原 DPI 重渲染。"""
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
                if job.get("status") in OCR_ACTIVE_STATUSES or page.get("retrying"):
                    raise HTTPException(409, "该页正在处理，请勿重复点击重试")
                client = job.get("client")
                if client is None:
                    raise HTTPException(400, "任务尚未初始化")
                v2_retry = job.get("_v2_retry_page")
                if not callable(v2_retry):
                    required = (
                        "_transcribe_one", "_refresh_raw_preview", "_merge_job",
                        "_render_one", "_mark_page_error",
                    )
                    if not all(callable(job.get(name)) for name in required):
                        raise HTTPException(409, "OCR 任务版本过旧，请重新上传后再试")
                page["retrying"] = True
                job["status"] = "running"
                job["terminal_epoch"] = None
                job["pause_requested"] = False
                job["page"] = n
                job["current_index"] = page.get("task_index", 0)
                job["phase"] = (
                    f"重试原 PDF 第 {n} 页"
                    if job.get("source_type") == "pdf" else "重试图片"
                )
                _bump_ocr_state(job)
        ok = False
        if callable(v2_retry):
            try:
                ok = v2_retry(n)
            except OcrStoreError as exc:
                with _ocr_jobs_lock:
                    page["retrying"] = False
                    job["status"] = "done" if job.get("raw_frozen") else "partial"
                    _bump_ocr_state(job)
                raise HTTPException(409, _safe_task_error(exc)) from None
            except Exception as exc:  # noqa: BLE001
                job["_mark_page_error"](job, n, exc)
                job["_merge_job"](job)
            finally:
                with _ocr_jobs_lock:
                    page["retrying"] = False
                    _bump_ocr_state(job)
            snapshot = _public_ocr_job(job)
            snapshot["ok"] = ok
            snapshot["retried_page"] = n
            return snapshot
        try:
            try:
                if not os.path.isfile(str(page.get("png") or "")):
                    job["_render_one"](job, n)
                _ocr_control(job)
                ok = job["_transcribe_one"](job, client, n, page["png"])
            except Exception as exc:  # noqa: BLE001
                job["_mark_page_error"](job, n, exc)
            if ok:
                job["_refresh_raw_preview"](job)
        finally:
            with _ocr_jobs_lock:
                page["retrying"] = False
                _bump_ocr_state(job)
            job["_merge_job"](job)
        snapshot = _public_ocr_job(job)
        snapshot["ok"] = ok
        snapshot["retried_page"] = n
        return snapshot

    @app.post("/api/ocr/jobs/{jid}/retry-failed")
    def ocr_retry_failed(jid: str):
        """后台顺序重试全部失败页，并立即返回可轮询的完整任务快照。"""
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_lock:
                job = _ocr_jobs.get(jid)
                if job is None:
                    raise HTTPException(404, "任务不存在")
                if job.get("importing"):
                    raise HTTPException(409, "OCR 结果正在导入项目，暂时不能批量重试")
                if job.get("saving"):
                    raise HTTPException(409, "OCR 结果正在保存，完成后再批量重试")
                if job.get("status") in OCR_ACTIVE_STATUSES or job.get("retrying_failed"):
                    raise HTTPException(409, "OCR 任务正在处理，请勿重复启动批量重试")
                client = job.get("client")
                if client is None:
                    raise HTTPException(400, "任务尚未初始化")
                required = (
                    "_transcribe_one", "_refresh_raw_preview", "_merge_job",
                    "_render_one", "_mark_page_error",
                )
                if not all(callable(job.get(name)) for name in required):
                    raise HTTPException(409, "OCR 任务版本过旧，请重新上传后再试")
                v2_retry = job.get("_v2_retry_page")
                targets = [
                    page_no for page_no in job.get("selected_pages", [])
                    if job["pages"][page_no].get("status") != "done"
                ]
                if not targets:
                    return _public_ocr_job(job)
                job["retrying_failed"] = True
                job["retry_total"] = len(targets)
                job["retry_done"] = 0
                job["status"] = "running"
                job["terminal_epoch"] = None
                job["pause_requested"] = False
                job["phase"] = f"准备顺序重试 {len(targets)} 个失败页面"
                job["error"] = ""
                for page_no in targets:
                    job["pages"][page_no]["retrying"] = True
                completed = sum(
                    page.get("status") == "done" for page in job["pages"].values()
                )
                job["done"] = completed
                job["progress"] = round(completed / max(1, len(job["pages"])), 3)
                _bump_ocr_state(job)

        def retry_failed_worker():
            current_page = None
            try:
                for retry_index, page_no in enumerate(targets, start=1):
                    current_page = page_no
                    _ocr_control(job)
                    page = job["pages"][page_no]
                    with _ocr_jobs_lock:
                        job["page"] = page_no
                        job["current_index"] = page.get("task_index", 0)
                        job["phase"] = (
                            f"批量重试原 PDF 第 {page_no} 页"
                            if job.get("source_type") == "pdf" else "批量重试图片"
                        )
                        _bump_ocr_state(job)
                    try:
                        if callable(v2_retry):
                            ok = v2_retry(page_no)
                        else:
                            if not os.path.isfile(str(page.get("png") or "")):
                                job["_render_one"](job, page_no)
                            # 暂停若发生在渲染期间，不再继续发出新的视觉模型请求。
                            _ocr_control(job)
                            ok = job["_transcribe_one"](
                                job, client, page_no, page["png"]
                            )
                            if ok:
                                job["_refresh_raw_preview"](job)
                    except Exception as exc:  # noqa: BLE001
                        job["_mark_page_error"](job, page_no, exc)
                    finally:
                        with _ocr_jobs_lock:
                            page["retrying"] = False
                            job["retry_done"] = retry_index
                            completed = sum(
                                item.get("status") == "done"
                                for item in job["pages"].values()
                            )
                            job["done"] = completed
                            job["progress"] = round(
                                completed / max(1, len(job["pages"])), 3
                            )
                            _bump_ocr_state(job)
                    if retry_index < len(targets):
                        _ocr_control(job)
            except Exception as exc:  # noqa: BLE001
                message = _safe_task_error(exc)
                if current_page is not None:
                    current = job["pages"].get(current_page)
                    if current and current.get("status") in {"pending", "running"}:
                        job["_mark_page_error"](job, current_page, message)
                with _ocr_jobs_lock:
                    job["error"] = message
                    _bump_ocr_state(job)
            finally:
                with _ocr_jobs_lock:
                    for page_no in targets:
                        job["pages"][page_no]["retrying"] = False
                    job["retrying_failed"] = False
                    _bump_ocr_state(job)
                job["_merge_job"](job)

        threading.Thread(
            target=retry_failed_worker,
            daemon=True,
            name=f"latexstruct-ocr-retry-{jid[:12]}",
        ).start()
        return _public_ocr_job(job)

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
            headers={
                "X-LaTeXStruct-OCR-Complete": "true" if status == "done" else "false",
                "X-LaTeXStruct-Publication-Ready": "false",
            },
        )

    @app.get("/api/ocr/jobs/{jid}/package")
    def ocr_package(jid: str):
        """Download raw OCR TEX together with its real images and hash manifest."""
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
            if job is None or job.get("status") not in ("done", "partial"):
                raise HTTPException(404, "原始 OCR 尚未生成")
            raw_tex = str(job.get("raw_tex") or "")
            if not raw_tex:
                raise HTTPException(409, "原始 OCR 结果为空，请先重试失败页面")
            snapshot = _snapshot_ocr_bundle_job(job)
        data, _manifest = _ocr_bundle_bytes(snapshot, raw_tex)
        status = snapshot["status"]
        partial_label = "-partial" if status == "partial" else ""
        return Response(
            content=data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="OCR{partial_label}-{jid}.zip"',
                "X-LaTeXStruct-OCR-Complete": "true" if status == "done" else "false",
                "X-LaTeXStruct-Publication-Ready": "false",
            },
        )

    @app.post("/api/ocr/jobs/{jid}/save")
    def save_ocr_result(jid: str):
        """可靠保存终态 OCR 工程包；成功落盘后才标记 revision 已保全。"""
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
                snapshot = _snapshot_ocr_bundle_job(job)
                job["saving"] = True
        range_label = f"-P{start}-{end}" if source_type == "pdf" else ""
        partial_label = "-partial" if status == "partial" else ""
        try:
            data, manifest = _ocr_bundle_bytes(snapshot, raw_tex)
            saved = save_unique_download(
                data,
                f"OCR{range_label}{partial_label}-{jid}.zip",
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
                "assets": len((manifest.get("resources") or {}).get("assets") or []),
                "source_pages": len(
                    (manifest.get("resources") or {}).get("source_pages") or []
                ),
                "unresolved": list(
                    (manifest.get("resources") or {}).get("unresolved") or []
                ),
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
        mode: str = "ai",
        template: str = "faithfulbook",
        title: str = "",
    ):
        from ..core.template import FAITHFULBOOK, normalize_template_id

        mode = str(mode or "").strip().lower()
        if mode not in {"rule", "ai"}:
            raise HTTPException(400, "结构化整理方式只能是 AI 或规则")
        requested_template = normalize_template_id(template)
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
                # 新任务在启动前冻结成品版式；旧任务沿用请求值，并以
                # faithfulbook 作为缺失字段的兼容默认值。
                template = normalize_template_id(
                    job.get("output_template", requested_template or FAITHFULBOOK)
                )
                if "output_template" not in job and not template:
                    template = FAITHFULBOOK
                import_options = {
                    "mode": mode,
                    "template": template,
                    "title": title.strip(),
                    "name": name.strip(),
                }
                import_snapshot = _snapshot_ocr_bundle_job(job)
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
        pid = ""
        process_started = False
        try:
            # Hashing hundreds of rendered pages can take noticeable time.  It
            # must happen after the immutable snapshot/importing flag is frozen,
            # but outside the global OCR lock so other jobs can still poll,
            # pause, and finish their current page.
            verified_snapshot = _verified_ocr_bundle_snapshot(import_snapshot)
            quality_report = assess_ocr_quality(verified_snapshot)
            if (
                import_snapshot.get("quality_profile") == OCR_QUALITY_PUBLICATION
                and not quality_report.get("page_gate_passed")
            ):
                blocker = (quality_report.get("blockers") or [{}])[0]
                message = str(blocker.get("message") or "出版审校质量门尚未通过")
                raise HTTPException(
                    409,
                    f"{message}；请检查并重试标记页面，原始 OCR 工程仍可保存。",
                )
            pid = get_store().create(
                raw_tex,
                name,
                mode,
                template,
                kind="ocr",
                template_title=title or name,
            )
            project_dir = Path(get_store()._dir(pid))
            source_evidence = {
                "available": False,
                "immutable_evidence": False,
                "reason": "legacy_job_without_source",
            }
            if Path(str(import_snapshot.get("target") or "")).is_file():
                try:
                    source_evidence = _preserve_original_ocr_source(
                        import_snapshot, project_dir
                    )
                except Exception:
                    get_store().delete(pid)
                    raise
            elif import_snapshot.get("quality_profile") == OCR_QUALITY_PUBLICATION:
                get_store().delete(pid)
                raise HTTPException(409, "原始 PDF 证据已不可用，出版审校项目不能继续导入")
            resource_result = _preserve_ocr_resources(import_snapshot, raw_tex, project_dir)
            unresolved = [
                str(path) for path in (resource_result.get("unresolved") or []) if str(path)
            ]
            if unresolved:
                # Never open the analysis/review workspace with dangling image
                # references.  This project was created only for this import, so
                # remove the incomplete staging directory and leave the OCR job
                # intact for retry or bundle download.
                get_store().delete(pid)
                preview = "、".join(unresolved[:5])
                suffix = "……" if len(unresolved) > 5 else ""
                raise HTTPException(
                    409,
                    f"仍有 {len(unresolved)} 个 OCR 图片资源未能保存（{preview}{suffix}）；"
                    "请先重试对应页面或保存 OCR 工程 ZIP，未进入分析与审阅。",
                )
            meta = json.loads((project_dir / "meta.json").read_text(encoding="utf-8"))
            meta["ocr_source"] = source_evidence
            meta["ocr_resources"] = resource_result
            meta["ocr_outline"] = deepcopy(import_snapshot.get("source_outline") or [])
            final_quality = assess_ocr_quality(verified_snapshot, resource_result)
            if (
                import_snapshot.get("quality_profile") == OCR_QUALITY_PUBLICATION
                and not final_quality.get("workflow_gate_passed")
            ):
                get_store().delete(pid)
                blocker = (final_quality.get("blockers") or [{}])[0]
                raise HTTPException(
                    409,
                    str(blocker.get("message") or "OCR 出版审校证据未通过完整性校验"),
                )
            meta["ocr_quality"] = final_quality
            meta["ocr_processing"] = {
                "profile": str(import_snapshot.get("quality_profile") or "standard"),
                "transcription_source": "full_page_visual_plus_bounded_pdf_evidence",
                "backend": str(import_snapshot.get("backend") or "unknown"),
                "model": str(import_snapshot.get("model") or ""),
                "reasoning_effort": str(import_snapshot.get("reasoning_effort") or ""),
                "dpi": int(import_snapshot.get("dpi") or 0),
                "target_template": template,
                "prompt_version": str(
                    (import_snapshot.get("producer_identity") or {}).get(
                        "prompt_version"
                    )
                    or ""
                ),
            }
            get_store()._write_json(str(project_dir), "meta.json", meta)
            ocr_terminal = (
                TerminalStatus.PARTIAL
                if str(import_snapshot.get("status") or "").lower() == "partial"
                else TerminalStatus.SUCCESS
            )
            ocr_snapshot = _build_project_run_snapshot(
                pid,
                ocr_terminal,
                f"ocr-{jid}",
                workflow_override=AuditWorkflow.OCR_ONLY,
                capture={
                    "producer_identity": deepcopy(
                        import_snapshot.get("producer_identity") or {}
                    ),
                    "created": import_snapshot.get("created"),
                    "verification": {
                        "safe_to_export": False,
                        "ocr_quality": final_quality,
                        "ocr_source_preserved": bool(source_evidence.get("available")),
                        "preview_state": "SOURCE_PREVIEW",
                    },
                    "report_md": (
                        "# OCR 终态审计记录\n\n"
                        "原始 OCR 转写、来源证据和可用页图已由宿主冻结；"
                        "尚未执行结构分析与审阅，因此机器验证状态保持 UNVERIFIED。\n"
                    ),
                    "preview": raw_tex,
                    "preview_state": "SOURCE_PREVIEW",
                    "events": [{
                        "at": time.time(),
                        "phase": "ocr_terminal",
                        "message": "OCR 原始转写已冻结",
                    }],
                    "finished": time.time(),
                },
            )
            ocr_submission = _persist_terminal_audit_snapshot(pid, ocr_snapshot)
            # 立即进入工作台，再由标准后台任务提供进度、暂停与实时 TeX 草稿。
            process_job = process_start(pid)
            process_started = True
            _process_jobs.bind_audit_parent_snapshot(
                process_job["id"],
                ocr_submission.snapshot_id,
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
            return {"id": pid, "processed": False, "process": process_job}
        except Exception as exc:
            if pid and not process_started and get_store().get(pid) is not None:
                active = _process_jobs.active(pid)
                if active is not None:
                    _process_jobs.fail(active["id"], "项目处理任务未能启动")
                # Once the OCR-only terminal snapshot exists, never delete the
                # project merely because its child analysis task failed to
                # launch.  Freeze a FAILED child-run record and make the pid
                # reusable so the preserved audit material remains reachable.
                audit_store = _project_audit_store(pid)
                if audit_store.latest() is not None:
                    failure_snapshot = _build_project_run_snapshot(
                        pid,
                        TerminalStatus.FAILED,
                        f"ocr-analysis-start-{jid}-{uuid.uuid4().hex[:8]}",
                        workflow_override=AuditWorkflow.OCR_ANALYSIS_REVIEW,
                        capture={
                            "preview": raw_tex,
                            "preview_state": "SOURCE_PREVIEW",
                            "events": [{
                                "at": time.time(),
                                "phase": "analysis_start",
                                "message": "OCR 后续分析任务未能启动",
                            }],
                            "finished": time.time(),
                        },
                        error=_safe_task_error(exc),
                    )
                    _persist_terminal_audit_snapshot(pid, failure_snapshot)
                    with _ocr_jobs_lock:
                        current = _ocr_jobs.get(jid)
                        if current is not None:
                            # Keep the failed project reachable for audit, but do
                            # not mark this OCR revision as successfully imported.
                            # A second click must create and start a fresh child
                            # run instead of reusing the launch failure.
                            failed_projects = list(
                                current.get("failed_import_project_ids") or []
                            )
                            if pid not in failed_projects:
                                failed_projects.append(pid)
                            current["failed_import_project_ids"] = failed_projects
                            current["import_error"] = _safe_task_error(exc)
                else:
                    get_store().delete(pid)
            raise
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

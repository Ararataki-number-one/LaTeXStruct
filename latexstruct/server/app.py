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
from pathlib import Path
from typing import Dict, Optional
from weakref import WeakValueDictionary

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import AppConfig, load_config, save_config
from ..core.audit_schema import (
    ArtifactRole,
    AuditDepth,
    AuditSubmissionRequest,
    AuditWorkflow,
    RunSnapshot,
    TerminalStatus,
)
from ..core.audit_submission import make_audit_artifact
from ..core.invariants import IMG_RE
from ..core.ocr_quality import (
    OCR_QUALITY_PUBLICATION,
    assess_ocr_quality,
    normalize_ocr_quality_profile,
)
from ..core.parser import parse_latex
from ..core.pipeline import run_pipeline
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
            and callable(job.get("_transcribe_one"))
            and callable(job.get("_render_one"))
        )
        pages_summary = {
            str(n): {
                "status": page.get("status", "pending"),
                "low_conf": bool(page.get("low_conf")),
                "needs_review": page.get("needs_review", False),
                "error": str(page.get("error") or "")[:120],
                "attempts": page.get("attempts", 0),
                "task_index": page.get("task_index", 0),
                "retrying": page.get("retrying", False),
                "can_retry": retry_available and not page.get("retrying", False),
                "preview_ready": os.path.isfile(str(page.get("png") or "")),
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
                "raw_tex", "pages", "client", "dir", "target", "suffix",
                "pause_requested",
                "_transcribe_one", "_refresh_raw_preview", "_merge_job", "_render_one",
                "_mark_page_error",
                "_source_sha256",
            )
        }
        public["raw_revision"] = int(job.get("raw_revision") or 0)
        public["raw_chars"] = int(job.get("raw_chars") or len(job.get("raw_tex") or ""))
        public["state_revision"] = int(job.get("state_revision") or 0)
        # 旧任务没有该字段时明确标为 unknown；绝不能拿当前设置替它猜测，
        # 否则切换后端后历史任务会显示错误的计费来源。
        public["backend"] = str(job.get("backend") or "unknown")
        public["can_pause"] = job.get("status") == "running"
        public["can_resume"] = job.get("status") in {"pausing", "paused"}
        public["can_cancel"] = False
        public["pages"] = pages_summary
        public["quality_report"] = assess_ocr_quality(job)
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
OCR_PAGE_BREAK_RE = re.compile(r"(?m)^\s*%===\s*PAGE BREAK\s*===.*$")
OCR_PAGE_MARKER_RE = re.compile(r"(?m)^\s*%\s*Page\s+(?P<page>\d+)\s*$", re.I)


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
    page_path = Path(str(page.get("png") or ""))
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
    target = Path(str(job.get("target") or ""))
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
    elif target.is_file() and job.get("source_type") == "pdf":
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
        manifest = {
            "format": "latexstruct-ocr-bundle-v1",
            "source_type": str(verified_job.get("source_type") or ""),
            "source_sha256": source_sha256,
            "status": str(verified_job.get("status") or ""),
            "selected_start": int(verified_job.get("selected_start") or 1),
            "selected_end": int(
                verified_job.get("selected_end") or verified_job.get("selected_start") or 1
            ),
            "raw_revision": int(verified_job.get("raw_revision") or 0),
            "usage_revision": int(verified_job.get("usage_revision") or 0),
            "page_revision": int(verified_job.get("page_revision") or 0),
            "pages": _ocr_manifest_page_records(verified_job),
            "resources": resources,
            "evidence_errors": list(verified_job.get("evidence_errors") or []),
            "processing": {
                "profile": str(verified_job.get("quality_profile") or "standard"),
                "transcription_source": "full_page_visual_plus_bounded_pdf_evidence",
                "backend": str(verified_job.get("backend") or "unknown"),
                "model": str(verified_job.get("model") or ""),
                "reasoning_effort": str(verified_job.get("reasoning_effort") or ""),
                "dpi": int(verified_job.get("dpi") or 0),
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
        })
    return records


def _snapshot_ocr_bundle_job(job: dict) -> dict:
    """Copy only immutable/bundle-relevant OCR fields while holding the job lock."""
    return {
        "source_type": str(job.get("source_type") or ""),
        "source_outline": deepcopy(job.get("source_outline") or []),
        "_source_sha256": str(job.get("_source_sha256") or ""),
        "target": str(job.get("target") or ""),
        "status": str(job.get("status") or ""),
        "quality_profile": str(job.get("quality_profile") or "standard"),
        "backend": str(job.get("backend") or "unknown"),
        "model": str(job.get("model") or ""),
        "reasoning_effort": str(job.get("reasoning_effort") or ""),
        "producer_identity": deepcopy(
            job.get("producer_identity")
            if isinstance(job.get("producer_identity"), dict)
            else _unknown_producer_identity()
        ),
        "dpi": int(job.get("dpi") or 0),
        "output_template": str(job.get("output_template") or "faithfulbook"),
        "selected_start": int(job.get("selected_start") or 1),
        "selected_end": int(job.get("selected_end") or job.get("selected_start") or 1),
        "selected_pages": [int(page) for page in (job.get("selected_pages") or [])],
        "raw_revision": int(job.get("raw_revision") or 0),
        "usage_revision": int(job.get("usage_revision") or 0),
        "page_revision": int(job.get("page_revision") or 0),
        "pages": {
            page_no: {
                "png": str(page.get("png") or ""),
                "figures": deepcopy(page.get("figures") or []),
                "image_size_pixels": list(page.get("image_size_pixels") or []),
                "visual_input_sha256": str(page.get("visual_input_sha256") or ""),
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
            evidence_errors.append(f"第 {page_no} 页视觉输入已丢失或被改变")
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
    if source_type == "pdf":
        if not data.startswith(b"%PDF-"):
            raise RuntimeError("原始 OCR PDF 内容已损坏")
        extension = ".pdf"
    elif source_type == "image":
        extension = _raster_extension(data)
    else:
        raise RuntimeError("原始 OCR 文件类型未知")
    destination = (project_dir / f"ocr-source{extension}").resolve()
    destination.relative_to(project_dir.resolve())
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
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
        committed = True
    finally:
        if temporary.exists():
            temporary.unlink()
        if not committed and destination.exists():
            destination.unlink()
    return {
        "available": True,
        "path": destination.name,
        "bytes": len(data),
        "sha256": actual_hash,
        "source_type": source_type,
        "source_pages": int(job.get("source_total") or 1),
        "selected_start": int(job.get("selected_start") or 1),
        "selected_end": int(job.get("selected_end") or job.get("selected_start") or 1),
        "immutable_evidence": has_frozen_hash,
        "reason": "" if has_frozen_hash else "legacy_job_without_frozen_hash",
    }


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
    if expected_size is None or int(expected_size) != len(data):
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
            "selected_start",
            "selected_end",
            "immutable_evidence",
            "reason",
        )
        if key in source_info
    }
    public_record["path"] = rel
    return rel, data, public_record


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
        """Persist only a PDF already validated by the compile-artifact layer."""
        from ..core.preview import (
            COMPILED,
            PARTIAL_COMPILED,
            preview_artifact_path,
            preview_descriptor,
            preview_storage_filename,
        )

        payload = getattr(result, "compiled_pdf", b"")
        display_name = str(getattr(result, "compiled_pdf_name", "") or "")
        if not isinstance(payload, (bytes, bytearray, memoryview)) or not payload:
            return
        allowed = {
            preview_descriptor(COMPILED).filename,
            preview_descriptor(PARTIAL_COMPILED).filename,
        }
        if display_name not in allowed or not bytes(payload).startswith(b"%PDF-"):
            raise ValueError("编译预览工件格式无效，已阻止保存")
        evidence = (getattr(result, "verification", {}) or {}).get(
            "preview_artifact"
        )
        digest = sha256_bytes(bytes(payload))
        status = str(evidence.get("status") or "") if isinstance(evidence, dict) else ""
        if (
            not isinstance(evidence, dict)
            or evidence.get("sha256") != digest
            or evidence.get("display_filename") != display_name
            or evidence.get("filename") != preview_artifact_path(status, digest)
        ):
            raise ValueError("编译预览工件与验证记录不一致，已阻止保存")
        compiled_tex = str(getattr(result, "compiled_tex", "") or "")
        if evidence.get("tex_sha256") != sha256_bytes(compiled_tex.encode("utf-8")):
            raise ValueError("编译预览工件与候选 TEX 不一致，已阻止保存")
        from ..core.compilecheck import build_compile_input_manifest

        compile_inputs = build_compile_input_manifest(
            compiled_tex,
            dict(getattr(result, "compiled_extra_files", {}) or {}),
        )
        if evidence.get("compile_inputs") != compile_inputs:
            raise ValueError("编译预览工件与完整编译输入集不一致，已阻止保存")
        storage_name = preview_storage_filename(status, digest)
        get_store()._atomic_write_bytes(
            get_store()._dir(pid), storage_name, bytes(payload)
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
                source_is_pdf = source_record.get("source_type") == "pdf"
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
            add_artifact(
                ArtifactRole.RAW_OCR_PREVIEW,
                source_bytes,
                parents=(raw_artifact,),
                path="previews/raw-ocr-source-preview.txt",
                media_type="text/plain; charset=utf-8",
                preview_status="SOURCE_PREVIEW",
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
        reviewed_artifact = None
        if reviewed_text:
            reviewed_artifact = add_artifact(
                ArtifactRole.AI_REVIEWED_TEX,
                reviewed_text,
                parents=(analyzed_artifact or raw_artifact,),
                media_type="application/x-tex; charset=utf-8",
            )

        if pipeline_result is not None:
            if terminal_status is TerminalStatus.SUCCESS:
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

        preview_status = str(
            verification.get("preview_state")
            or capture.get("preview_state")
            or "SOURCE_PREVIEW"
        ).upper()
        if preview_status not in {"COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"}:
            preview_status = "SOURCE_PREVIEW"
        compiled_pdf = bytes(
            getattr(pipeline_result, "compiled_pdf", b"")
            or capture.get("compiled_pdf")
            or b""
        )
        if (
            preview_status in {"COMPILED", "PARTIAL_COMPILED"}
            and compiled_pdf.startswith(b"%PDF-")
        ):
            add_artifact(
                ArtifactRole.CURRENT_PREVIEW,
                compiled_pdf,
                parents=(current_artifact,),
                media_type="application/pdf",
                preview_status=preview_status,
            )
        else:
            preview_status = "SOURCE_PREVIEW"
            verification["preview_state"] = preview_status
            add_artifact(
                ArtifactRole.CURRENT_PREVIEW,
                current_text,
                parents=(current_artifact,),
                path="previews/current-source-preview.txt",
                media_type="text/plain; charset=utf-8",
                preview_status=preview_status,
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
            outline = meta.get("ocr_outline")
            if not isinstance(outline, list):
                outline = []
            add_artifact(
                ArtifactRole.OUTLINE,
                _audit_json_bytes({"outline": outline}),
                parents=(source_artifact,),
                media_type="application/json",
            )
            resource_info = meta.get("ocr_resources") or {}
            try:
                verified_resources = _verified_ocr_resource_bytes(
                    directory,
                    resource_info,
                    include_source_pages=True,
                    include_formula_crops=True,
                )
            except ValueError:
                verified_resources = {}
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

        safe_error = str(error or capture.get("error") or "").strip()
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

        blockers = []
        for item in verification.get("failures") or []:
            if isinstance(item, dict):
                message = str(item.get("summary") or item.get("label") or "").strip()
                if message:
                    blockers.append(message)
        if safe_error:
            blockers.append(safe_error)
        from .. import __version__

        cfg = capture.get("config_snapshot")
        if meta.get("kind") == "ocr":
            model = str((meta.get("ocr_processing") or {}).get("model") or "unknown")
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
        source_info = meta.get("ocr_source") or {}
        selected_start = int(source_info.get("selected_start") or 1)
        selected_end = int(source_info.get("selected_end") or selected_start)
        page_range = (
            f"{selected_start}-{selected_end}" if meta.get("kind") == "ocr" else "all"
        )
        return RunSnapshot(
            project_id=pid,
            run_id=str(run_id),
            workflow=workflow,
            terminal_status=terminal_status,
            captured_at=_audit_iso_timestamp(capture.get("finished") or time.time()),
            artifacts=tuple(artifacts),
            machine_verification=verification,
            blockers=tuple(blockers),
            model=model,
            app_version=__version__,
            template=str(meta.get("template") or "none"),
            page_range=page_range,
            metadata={
                "project_kind": str(meta.get("kind") or "tex"),
                "mode": str(meta.get("mode") or ""),
                "review_revision": _review_state_payload(meta)["revision"],
                "preview_status": preview_status,
                "host_state_fingerprint": _audit_host_state_fingerprint(pid),
            },
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
        return {
            "info": info,
            "verification": deepcopy(verification),
            "report_md": bytes(record.get("report") or b"").decode(
                "utf-8", errors="replace"
            ),
            "compiled_pdf": compiled_pdf,
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
            "filename": zip_filename,
            "folder": "下载/LaTeXStruct" if zip_filename else None,
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
        filename = f"{project.get('name') or pid}-AI-audit.zip"
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
        p = get_store().get(pid)
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
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        0.99,
                        "正在冻结终态并生成 AI 审计轻量材料",
                        {},
                    )
                _persist_terminal_audit_snapshot(pid, snapshot)
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
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        0.99,
                        "正在保存取消前已有阶段和错误记录",
                        {},
                    )
                _persist_terminal_audit_snapshot(pid, snapshot)
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
                if progress_callback:
                    progress_callback(
                        "audit_submission",
                        0.99,
                        "正在保存失败前已有阶段和错误记录",
                        {},
                    )
                _persist_terminal_audit_snapshot(pid, snapshot)
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
            "_source_sha256": hashlib.sha256(upload).hexdigest(),
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
            "output_template": "faithfulbook",
            "reasoning_effort": "",
            "created": time.time(),
            "updated": time.time(),
            "state_revision": 1,
            "pause_requested": False,
            "retrying_failed": False,
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
                "needs_review": False,
                "attempts": 0,
                "task_index": index,
                "retrying": False,
                "figures": [],
                "image_size_pixels": [],
                "visual_input_sha256": "",
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
            if job["source_type"] == "pdf":
                rendered = iter(iter_pdf_pages(
                    job["target"], [page_no], int(job.get("dpi") or dpi),
                ))
                try:
                    rendered_page, image_bytes = next(rendered)
                except StopIteration:
                    raise RuntimeError(f"原 PDF 第 {page_no} 页未生成图像") from None
                if int(rendered_page) != page_no:
                    raise RuntimeError(f"原 PDF 第 {page_no} 页渲染结果页码不一致")
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
                    relation_regions = pdf_page_relation_regions(
                        job["target"], page_no,
                    )
                except Exception:  # noqa: BLE001
                    relation_regions = []
                try:
                    divider_regions = pdf_page_divider_regions(
                        job["target"], page_no,
                    )
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
                    framed_inset_regions = pdf_page_framed_insets(
                        job["target"], page_no,
                    )
                except Exception:  # noqa: BLE001
                    framed_inset_regions = []
                try:
                    footnote_regions = pdf_page_footnote_regions(
                        job["target"], page_no,
                    )
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
                chunks = [page["tex"] for _page_no, page in completed]
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
                job["raw_tex"] = merged
                job["raw_ready"] = bool(chunks)
                job["raw_chars"] = len(merged)
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
                job["status"] = "done" if not errors else "partial"
                job["phase"] = "原始 OCR 已就绪" if not errors else "部分页面失败，等待重试"
                job["error"] = "" if not errors else str(errors[0]["reason"])
                job["pause_requested"] = False
                if complete_progress:
                    job["progress"] = 1.0
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

        def worker():
            try:
                client, selected_model, backend = _build_ocr_client(
                    launch_cfg, base_url, model, api_key,
                )
                with _ocr_jobs_lock:
                    job["client"] = client
                    job["model"] = selected_model
                    job["backend"] = backend
                    job["phase"] = (
                        "出版审校：逐页视觉转写与证据核验"
                        if quality_profile == OCR_QUALITY_PUBLICATION
                        else "逐页渲染与忠实转写"
                    )
                    _bump_ocr_state(job)
                for index, page_no in enumerate(page_nos, start=1):
                    _ocr_control(job)
                    page = job["pages"][page_no]
                    with _ocr_jobs_lock:
                        job["page"] = page_no
                        job["current_index"] = index
                        job["phase"] = (
                            f"正在转写原 PDF 第 {page_no} 页"
                            if job["source_type"] == "pdf" else "正在转写图片"
                        )
                        job["progress"] = round((index - 1) / max(1, len(page_nos)), 3)
                        _bump_ocr_state(job)
                    try:
                        _render_one(job, page_no)
                    except Exception as exc:  # noqa: BLE001
                        _mark_page_error(job, page_no, exc)
                        with _ocr_jobs_lock:
                            job["done"] = index
                            job["progress"] = round(index / max(1, len(page_nos)), 3)
                            _bump_ocr_state(job)
                        if index < len(page_nos):
                            _ocr_control(job)
                        continue
                    # 渲染也可能较慢；在真正发起付费视觉请求前再设一个安全点。
                    _ocr_control(job)
                    page_ok = _transcribe_one(job, client, page_no, page["png"])
                    if page_ok:
                        _refresh_raw_preview(job)
                    with _ocr_jobs_lock:
                        job["done"] = index
                        job["progress"] = round(index / max(1, len(page_nos)), 3)
                        _bump_ocr_state(job)
                    if index < len(page_nos):
                        _ocr_control(job)
                _merge_job(job)
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
                        if has_done else "准备或渲染失败"
                    )
                    job["error"] = message
                    _bump_ocr_state(job)

        threading.Thread(
            target=worker, daemon=True, name=f"latexstruct-ocr-{job['id'][:12]}",
        ).start()

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
        quality_profile: str = Form("standard"),
        output_template: str = Form("faithfulbook"),
    ):
        _cleanup_ocr_jobs()
        if not 72 <= dpi <= 300:
            raise HTTPException(400, "DPI 必须在 72-300 之间")
        if len(model) > 160 or len(base_url) > 500:
            raise HTTPException(400, "模型或 Base URL 输入过长")
        try:
            quality_profile = normalize_ocr_quality_profile(quality_profile)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if quality_profile == OCR_QUALITY_PUBLICATION and dpi < 200:
            raise HTTPException(400, "出版审校工作流要求至少 200 DPI")
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
                raise HTTPException(404, "任务不存在")
            return _public_ocr_job(job)

    @app.get("/api/ocr/jobs/{jid}/quality")
    def ocr_quality(jid: str):
        """Return the live evidence gate without claiming measured accuracy."""
        with _ocr_jobs_lock:
            job = _ocr_jobs.get(jid)
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
        with _update_state_lock:
            _raise_if_update_preparing()
            with _ocr_jobs_changed:
                job = _ocr_jobs.get(jid)
                if job is None:
                    raise HTTPException(404, "任务不存在")
                status = str(job.get("status") or "")
                if status in {"pausing", "paused"}:
                    job["pause_requested"] = False
                    job["status"] = "running"
                    job["phase"] = "已继续 OCR"
                    _bump_ocr_state(job)
                    _ocr_jobs_changed.notify_all()
                elif status != "running":
                    raise HTTPException(409, "当前 OCR 任务没有暂停")
                return _public_ocr_job(job)

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
                required = (
                    "_transcribe_one", "_refresh_raw_preview", "_merge_job",
                    "_render_one", "_mark_page_error",
                )
                if not all(callable(job.get(name)) for name in required):
                    raise HTTPException(409, "OCR 任务版本过旧，请重新上传后再试")
                page["retrying"] = True
                job["status"] = "running"
                job["pause_requested"] = False
                job["page"] = n
                job["current_index"] = page.get("task_index", 0)
                job["phase"] = (
                    f"重试原 PDF 第 {n} 页"
                    if job.get("source_type") == "pdf" else "重试图片"
                )
                _bump_ocr_state(job)
        ok = False
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

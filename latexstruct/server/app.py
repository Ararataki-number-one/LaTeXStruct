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
from weakref import WeakValueDictionary

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import AppConfig, load_config, save_config
from ..core.invariants import IMG_RE
from ..core.parser import parse_latex
from ..core.pipeline import run_pipeline
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
            )
        }
        public["raw_revision"] = int(job.get("raw_revision") or 0)
        public["raw_chars"] = int(job.get("raw_chars") or len(job.get("raw_tex") or ""))
        public["state_revision"] = int(job.get("state_revision") or 0)
        public["can_pause"] = job.get("status") == "running"
        public["can_resume"] = job.get("status") in {"pausing", "paused"}
        public["can_cancel"] = False
        public["pages"] = pages_summary
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


def _preserve_ocr_resources(job: dict, raw_tex: str, project_dir: Path) -> dict:
    """把 OCR ``includegraphics`` 占位绑定到原上传中的真实图片。

    优先提取真实图块。提取数量不足时，使用 OCR 实际看过的源页栅格作为
    明确标注的 ``page_fallback``，从而不会把悬空图片路径带入分析/审阅。
    """
    references, unsupported = _ocr_image_references(raw_tex)
    result = {
        "assets": [],
        "source_pages": [],
        "unresolved": list(unsupported),
        "errors": [],
    }
    project_dir = project_dir.resolve()
    if not references:
        preview_pages = job.get("selected_pages") or sorted((job.get("pages") or {}).keys())
        previews, _used = _preserve_source_page_previews(
            job, project_dir, preview_pages, MAX_PRESERVED_OCR_ASSET_BYTES
        )
        result["source_pages"] = previews
        return result
    target = Path(str(job.get("target") or ""))
    if not target.is_file():
        result["errors"].append("原始上传文件已不可用，改用已保存的 OCR 源页预览")

    extracted: dict[str, tuple[bytes, str, int]] = {}
    if target.is_file() and job.get("source_type") == "image":
        # 单张图片只有在正文只有一个图引用时才存在一一对应关系。
        if len(references) == 1 and references[0]["source_page"] == 1:
            data = target.read_bytes()
            suffix = target.suffix.lower()
            if suffix in {".png", ".jpg", ".jpeg"}:
                extracted[references[0]["path"]] = (data, suffix, 1)
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
                # 优先按页面版面提取真实图块。这样既保留嵌入位图，也能把 PDF 中
                # 由矢量线条组成、没有独立 xref 的数学插图裁成 PNG。
                clipped = []
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
                        if reference_offset >= len(page_references):
                            break
                        group.sort(key=lambda box: box.x0)
                        small_refs = 0
                        for reference in page_references[reference_offset:]:
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
                        # 矢量图的文字标签通常是独立文本对象，不在 drawing bbox 内。
                        # 留足约 24pt 边距，避免 x/y/L、节点编号和图下注释被裁断。
                        padding = 24
                        box = fitz.Rect(
                            max(page_rect.x0, box.x0 - padding),
                            max(page_rect.y0, box.y0 - padding),
                            min(page_rect.x1, box.x1 + padding),
                            min(page_rect.y1, box.y1 + padding),
                        )
                        pixmap = page.get_pixmap(clip=box, dpi=200, alpha=False)
                        data = pixmap.tobytes("png")
                        if data:
                            clipped.append(data)
                except Exception:  # noqa: BLE001 - 老版 PyMuPDF 回退到 xref 提取
                    clipped = []
                if len(clipped) >= len(page_references):
                    for reference, data in zip(page_references, clipped):
                        if not reference["ext"] or reference["ext"] == ".png":
                            extracted[reference["path"]] = (data, ".png", reference["index"])
                    continue
                xrefs = []
                for image in page.get_images(full=True):
                    try:
                        xref = int(image[0])
                    except (IndexError, TypeError, ValueError):
                        continue
                    if xref > 0 and xref not in xrefs:
                        xrefs.append(xref)
                # 引用按正文出现顺序、嵌入图按 PDF 页面顺序一一绑定；不信任模型
                # 偶尔生成的 0/1 基序号，也不在图片数不足时复用或伪造图片。
                for reference, xref in zip(page_references, xrefs):
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
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(
                "无法从原 PDF 提取插图：" + type(exc).__name__
            )
        finally:
            if document is not None:
                document.close()

    total = 0
    for reference in references:
        hit = extracted.get(reference["path"])
        asset_kind = "extracted"
        if hit is None:
            raster = _job_page_raster(job, reference["source_page"])
            if raster is not None:
                data, extension = raster
                hit = (data, extension, reference["index"])
                asset_kind = "page_fallback"
            else:
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
        result["assets"].append({
            "path": relative.replace("\\", "/"),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_page": reference["source_page"],
            "printed_page": reference["page"],
            "source_index": source_index,
            "kind": asset_kind,
            "format_matches_extension": format_matches,
        })
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
    fallback_count = sum(item.get("kind") == "page_fallback" for item in result["assets"])
    if fallback_count:
        result["errors"].append(
            f"{fallback_count} 个插图未能可靠裁切，已绑定对应 OCR 源页预览并在清单中标注"
        )
    return result


def _ocr_bundle_bytes(job: dict, raw_tex: str) -> tuple[bytes, dict]:
    """Build a self-contained raw OCR snapshot without mutating project state."""
    with tempfile.TemporaryDirectory(prefix="ls-ocr-bundle-") as tmp:
        bundle_root = Path(tmp).resolve()
        resources = _preserve_ocr_resources(job, raw_tex, bundle_root)
        manifest = {
            "format": "latexstruct-ocr-bundle-v1",
            "source_type": str(job.get("source_type") or ""),
            "status": str(job.get("status") or ""),
            "selected_start": int(job.get("selected_start") or 1),
            "selected_end": int(job.get("selected_end") or job.get("selected_start") or 1),
            "raw_revision": int(job.get("raw_revision") or 0),
            "usage_revision": int(job.get("usage_revision") or 0),
            "page_revision": int(job.get("page_revision") or 0),
            "resources": resources,
        }
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ocr.tex", raw_tex.encode("utf-8"))
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
        return output.getvalue(), manifest


def _snapshot_ocr_bundle_job(job: dict) -> dict:
    """Copy only immutable/bundle-relevant OCR fields while holding the job lock."""
    return {
        "source_type": str(job.get("source_type") or ""),
        "target": str(job.get("target") or ""),
        "status": str(job.get("status") or ""),
        "selected_start": int(job.get("selected_start") or 1),
        "selected_end": int(job.get("selected_end") or job.get("selected_start") or 1),
        "selected_pages": [int(page) for page in (job.get("selected_pages") or [])],
        "raw_revision": int(job.get("raw_revision") or 0),
        "usage_revision": int(job.get("usage_revision") or 0),
        "page_revision": int(job.get("page_revision") or 0),
        "pages": {
            page_no: {"png": str(page.get("png") or "")}
            for page_no, page in (job.get("pages") or {}).items()
        },
    }


def _verified_ocr_resource_bytes(
    project_dir: Path,
    resource_info: dict,
    *,
    include_source_pages: bool = False,
) -> dict[str, bytes]:
    """Read only manifest-listed, in-project OCR resources with matching hashes."""
    from ..core.project import safe_project_relpath

    project_dir = project_dir.resolve()
    groups = [resource_info.get("assets") or []]
    if include_source_pages:
        groups.append(resource_info.get("source_pages") or [])
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
        from ..core.template import ELEGANTBOOK, PRESERVE_SOURCE, list_template_presets

        return {
            "templates": list_template_presets(),
            "default": PRESERVE_SOURCE,
            "ocr_default": ELEGANTBOOK,
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
            process_project,
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
                    compile_check=True,
                    compile_files=files,
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
            meta["text_formats"] = {
                rel: decode_tex_bytes(files[rel]).metadata()
                for rel in {graph_obj.main_rel, *graph_obj.files}
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
                        "review": _persisted_review_summary(pr.review),
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

    def _write_ocr_package_resources(zf, pid: str, meta: dict, reserved: dict) -> None:
        resource_info = meta.get("ocr_resources") or {}
        project_dir = Path(get_store()._dir(pid)).resolve()
        try:
            resource_files = _verified_ocr_resource_bytes(
                project_dir,
                resource_info,
                include_source_pages=True,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        for rel, data in resource_files.items():
            if rel in reserved or rel == "main.tex":
                raise HTTPException(409, f"OCR 图片路径与工程文件冲突：{rel}")
            zf.writestr(rel, data)
        zf.writestr(
            "OCR-RESOURCES.json",
            json.dumps(resource_info, ensure_ascii=False, indent=2).encode("utf-8"),
        )

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
        reserved = {
            **template_assets,
            "LATEXSTRUCT-REPORT.md": current["report"],
            "LATEXSTRUCT-UNVERIFIED.txt": warning,
        }
        info = current.get("info") or {}
        per_file = info.get("per_file") if isinstance(info, dict) else None
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            written = set()
            if meta.get("kind") == "folder" and not (
                isinstance(per_file, dict) and per_file
            ):
                original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
                if not original_zip.is_file():
                    raise HTTPException(409, "原始文件夹工程快照缺失，已阻止保真导出")
                with zipfile.ZipFile(original_zip, "r") as source_zip:
                    for member in source_zip.infolist():
                        if member.is_dir():
                            continue
                        rel = safe_project_relpath(member.filename)
                        if rel in reserved:
                            raise HTTPException(
                                409, f"原项目中的 {rel} 与导出说明文件冲突"
                            )
                        zf.writestr(rel, source_zip.read(member))
                        written.add(rel)
            elif meta.get("kind") == "folder":
                from ..core.project import encode_project_files

                graph = meta.get("graph") or {}
                main_rel = safe_project_relpath(str(graph.get("main_rel") or "main.tex"))
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
                zf.writestr(main_rel, encoded_files[main_rel])
                written.add(main_rel)
                for rel, _content in per_file.items():
                    if not rel:
                        continue
                    safe_rel = safe_project_relpath(rel)
                    zf.writestr(safe_rel, encoded_files[safe_rel])
                    written.add(safe_rel)
            else:
                zf.writestr("main.tex", current["result"])
                written.add("main.tex")

            original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
            if original_zip.exists():
                with zipfile.ZipFile(original_zip, "r") as source_zip:
                    for member in source_zip.infolist():
                        rel = safe_project_relpath(member.filename)
                        if member.is_dir() or rel in written or rel in reserved:
                            continue
                        zf.writestr(rel, source_zip.read(member))
                        written.add(rel)
            if meta.get("kind") == "ocr":
                _write_ocr_package_resources(zf, pid, meta, reserved)
            existing = set(zf.namelist())
            for rel, data in reserved.items():
                if rel not in existing:
                    zf.writestr(rel, data)
        return output.getvalue(), False

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
        reserved = {**assets, "LATEXSTRUCT-REPORT.md": report_bytes}
        meta = json.loads(
            (Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8")
        )
        per_file = info.get("per_file") if isinstance(info, dict) else None
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            if per_file:
                from ..core.project import encode_project_files

                graph = meta.get("graph") or {}
                main_rel = safe_project_relpath(graph.get("main_rel", ""))
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
                                if data != reserved[rel]:
                                    raise HTTPException(
                                        409,
                                        f"原项目中的 {rel} 与固定工程资源冲突，已阻止打包",
                                    )
                            else:
                                zf.writestr(rel, data)
                            written.add(rel)
                zf.writestr(main_rel, encoded_files[main_rel])
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
                zf.writestr("main.tex", result_bytes)
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
        _info, result_bytes = _committed_export(pid)
        return Response(
            content=result_bytes,
            media_type="application/x-tex",
            headers={"Content-Disposition": f'attachment; filename="{pid}-structured.tex"'},
        )

    @app.get("/api/projects/{pid}/export-current")
    def export_current(pid: str):
        current = _current_record(pid)
        verified = bool(current["verified"])
        suffix = "" if verified else "-UNVERIFIED"
        return Response(
            content=current["result"],
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
            _info, data = _committed_export(pid)
            return data, f"{project_name}-structured.tex", True
        if artifact == "report":
            return _committed_report(pid), f"{project_name}-report.md", True
        if artifact in {"package", "folder"}:
            return _export_package_bytes(pid), f"{project_name}-structured-project.zip", True
        if artifact == "current":
            current = _current_record(pid)
            verified = bool(current["verified"])
            marker = "" if verified else "-UNVERIFIED"
            return current["result"], f"{project_name}-current{marker}.tex", verified
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
                          progress_callback=None, control_callback=None, commit_callback=None):
        p = get_store().get(pid)
        text = get_store().read_source(pid)
        cfg = get_config()
        mode = p["mode"]
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
            if phase == "draft" and isinstance((data or {}).get("preview"), str):
                latest_draft["text"] = data["preview"]
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
        res.verification["failures"] = failures
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
            failed_draft = latest_draft["text"] or res.result or text
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
        # Includes the final store commit. RLock is required because review
        # routes hold this transaction while updating meta.json before rerunning.
        with _project_lock(pid):
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
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
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
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
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
        with _project_lock(pid):
            if _process_jobs.active(pid):
                raise HTTPException(409, "请等待处理完成或先取消任务，再修改审阅结论")
            meta = json.loads(
                Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8")
            )
            meta["excludes"] = []
            Path(get_store()._dir(pid), "meta.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8"
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
            """转写单页；非空结果始终保留，仅明确暂时性失败自动重试。"""
            from ..ocr import ocr_page_needs_retry, ocr_page_needs_review, transcribe_page

            page = job["pages"][page_no]
            with _ocr_jobs_lock:
                page["status"] = "running"
                page["error"] = ""
                page["needs_review"] = False
                _bump_ocr_state(job)
            with open(png_path, "rb") as image_file:
                png = image_file.read()
            for attempt in range(1, max_attempts + 1):
                if attempt > 1:
                    # 上一次模型调用期间收到暂停请求时，不继续消耗下一次调用。
                    _ocr_control(job)
                with _ocr_jobs_lock:
                    page["attempts"] = page.get("attempts", 0) + 1
                    _bump_ocr_state(job)
                client.last_usage = {}
                try:
                    tex = transcribe_page(client, png, page_no)
                    needs_review = ocr_page_needs_review(tex)
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
                        job["page_revision"] = int(job.get("page_revision") or 0) + 1
                        _bump_ocr_state(job)
                    return True
                except Exception as exc:  # noqa: BLE001
                    message = _safe_task_error(exc)
                    with _ocr_jobs_lock:
                        page["error"] = message
                        _bump_ocr_state(job)
                    if attempt >= max_attempts or not _ocr_error_is_retryable(message):
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
            from ..ocr import iter_pdf_pages

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
            else:
                if page_no != 1:
                    raise RuntimeError("单张图片任务仅有第 1 页")
                with open(job["target"], "rb") as image_file:
                    image_bytes = image_file.read()
            if not image_bytes:
                raise RuntimeError(f"第 {page_no} 页渲染结果为空")
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
            from ..core.ai import LLMClient, RoleConfig

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
                with _ocr_jobs_lock:
                    job["client"] = client
                    job["model"] = selected_model
                    job["phase"] = "逐页渲染与忠实转写"
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
                _bump_ocr_state(job)
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
            headers={"X-LaTeXStruct-OCR-Complete": "true" if status == "done" else "false"},
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
            project_dir = Path(get_store()._dir(pid))
            resource_result = _preserve_ocr_resources(job, raw_tex, project_dir)
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
            meta["ocr_resources"] = resource_result
            get_store()._write_json(str(project_dir), "meta.json", meta)
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

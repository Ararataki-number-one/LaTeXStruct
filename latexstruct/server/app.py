# -*- coding: utf-8 -*-
"""FastAPI 本地服务（127.0.0.1）。"""

from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import io
import inspect
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
from dataclasses import fields, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
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
from ..core.ocr_artifacts import (
    available_ocr_artifacts,
    load_verified_ocr_baseline_bundle,
    resolve_ocr_artifact,
)
from ..core.ocr_runtime import (
    AdaptivePageConcurrency,
    BoundedOcrExecutor,
    OcrErrorCategory,
    OcrPageRecord,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunPaused,
    OcrRunStore,
    OcrStoreError,
    OcrValidationIssue,
    OCR_TRANSCRIPTION_SYSTEM_PROMPT,
    make_page_id,
    make_run_snapshot,
    normalize_quality_tier,
    ocr_batch_output_schema,
    ocr_batch_request_payload,
    progress_metrics as ocr_progress_metrics,
    public_page_state,
    quality_tier_policy,
    inspect_latex_fragment,
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
_ocr_adaptive_limiters: Dict[str, AdaptivePageConcurrency] = {}
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
        "暂时性", "临时", "网络错误", "连接失败", "超时", "timed out", "timeout",
        "connection", "temporarily", "temporary", "try again", "rate limit",
        "too many requests", "overloaded", "限流",
        "http 408", "http 409", "http 425", "http 429", "http 500", "http 502",
        "http 503", "http 504", "max_tokens", "被截断", "转写为空",
    ))


def _ocr_retry_wait(attempt: int) -> None:
    """页面层短指数退避；独立函数便于测试替换。"""
    time.sleep(min(4.0, 0.5 * (2 ** max(0, attempt - 1))))


def _ocr_v2_has_host_retry_evidence(execution) -> bool:
    """Whether a page-less result carries a host-issued repair instruction."""
    retry_state = thaw_json(getattr(execution, "retry_state", {}) or {})
    validation_code = (
        str(retry_state.get("validation_code") or "").strip()
        if isinstance(retry_state, dict)
        else ""
    )
    return bool(
        str(getattr(execution, "retry_instruction", "") or "").strip()
        or validation_code
    )


def _ocr_v2_attempt_outcome(execution, *, conflict: bool = False):
    """Classify one persisted recovery attempt from host facts only."""
    from ..core.ocr_recovery import AttemptOutcome

    validated = getattr(execution, "page", None)
    if conflict:
        return AttemptOutcome.CONFLICT
    if validated is not None and validated.needs_retry:
        return AttemptOutcome.RETRYABLE_FAILURE
    if validated is not None and validated.needs_review:
        return AttemptOutcome.NEEDS_REVIEW
    if validated is not None:
        return AttemptOutcome.PASSED
    if (
        getattr(execution, "error_category", None)
        in {
            OcrErrorCategory.TRANSIENT,
            OcrErrorCategory.RATE_LIMIT,
            OcrErrorCategory.BATCH_INCOMPATIBLE,
            OcrErrorCategory.TRUNCATED,
        }
        or _ocr_v2_has_host_retry_evidence(execution)
    ):
        return AttemptOutcome.RETRYABLE_FAILURE
    return AttemptOutcome.FAILED


def _ocr_v2_tex_sha256(execution) -> str:
    page = getattr(execution, "page", None)
    if page is None:
        return ""
    return hashlib.sha256(page.latex.encode("utf-8")).hexdigest()


def _ocr_v2_mark_review(execution, *, code: str, message: str):
    """Return an immutable execution whose candidate is explicitly review-only."""
    page = getattr(execution, "page", None)
    if page is None:
        return execution
    issue = OcrValidationIssue(
        code=code,
        severity="warning",
        message=message,
        retryable=False,
    )
    issues = tuple(page.issues)
    if not any(item.code == code for item in issues):
        issues += (issue,)
    return replace(
        execution,
        page=replace(
            page,
            issues=issues,
            needs_retry=False,
            needs_review=True,
        ),
    )


def _ocr_v2_prepare_independent_result(comparison_execution, independent_execution):
    """Journal read B but keep candidate A when the two reads disagree."""
    comparison_hash = _ocr_v2_tex_sha256(comparison_execution)
    independent_hash = _ocr_v2_tex_sha256(independent_execution)
    if not independent_hash:
        selected = comparison_execution or independent_execution
        if comparison_hash:
            reviewed = _ocr_v2_mark_review(
                comparison_execution,
                code="INDEPENDENT_READ_FAILED",
                message="独立第二次识别未形成可比较的 TeX；保留此前候选并要求人工确认",
            )
            selected = replace(independent_execution, page=reviewed.page)
        return independent_execution, selected, comparison_hash, False
    if not comparison_hash:
        review_only = _ocr_v2_mark_review(
            independent_execution,
            code="INDEPENDENT_READ_NO_COMPARISON",
            message="独立识别形成了首个有效 TeX，但没有此前候选可供一致性比较",
        )
        return review_only, review_only, "", False
    conflict = not hmac.compare_digest(comparison_hash, independent_hash)
    if conflict:
        reviewed = _ocr_v2_mark_review(
            comparison_execution,
            code="INDEPENDENT_READ_CONFLICT",
            message="独立第二次识别与此前候选不一致；宿主已保留此前候选并阻止自动通过",
        )
        selected = replace(independent_execution, page=reviewed.page)
        return independent_execution, selected, comparison_hash, True
    return independent_execution, independent_execution, comparison_hash, False


def _ocr_adaptive_observe(job: dict, limiter: AdaptivePageConcurrency, execution) -> int:
    """Update one job's next transport budget from a completed page result."""
    rate_limited = (
        getattr(execution, "error_category", None) is OcrErrorCategory.RATE_LIMIT
    )
    if rate_limited:
        current = limiter.on_rate_limit()
    elif getattr(execution, "page", None) is not None:
        current = limiter.on_success()
    else:
        current = limiter.current
    with _ocr_jobs_lock:
        if rate_limited:
            job["rate_limit_events"] = int(job.get("rate_limit_events") or 0) + 1
        job["current_concurrency_limit"] = current
        job["rate_limited"] = bool(rate_limited or current < limiter.maximum)
        _bump_ocr_state(job)
    return current


def _ocr_adaptive_budgets(
    limiter: AdaptivePageConcurrency,
    *,
    configured_batch_size: int,
    configured_concurrency_limit: int,
) -> tuple[int, int]:
    """Freeze the next group's batch and worker budgets from the limiter."""
    current = max(1, int(limiter.current))
    return (
        max(1, min(int(configured_batch_size), current)),
        max(1, min(int(configured_concurrency_limit), current)),
    )


def _ocr_effective_compile_status(job: dict) -> str | None:
    """A compiled preview counts only after merge and immutable raw freeze."""
    if not job.get("raw_ready") or not job.get("raw_frozen"):
        return None
    return str(job.get("compile_status") or "") or None


def _ocr_record_batch_attempt(job: dict, store, snapshot, attempt) -> dict:
    """Persist one sanitized shared batch failure and alias every child page."""
    public = dict(attempt.to_dict())
    payload = {
        "schema": "latexstruct-ocr-batch-attempt-v1",
        **public,
        "shared_call": True,
        "usage_accounting": "GLOBAL_ONCE",
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    record_sha256 = hashlib.sha256(canonical).hexdigest()
    stored = json.dumps(
        {**payload, "record_sha256": record_sha256},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    relative_path = (
        Path("recovery-evidence")
        / snapshot.run_id
        / "batch-attempts"
        / f"{attempt.batch_id}.json"
    )
    path = store.run_dir(snapshot.run_id) / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not hmac.compare_digest(path.read_bytes(), stored):
            raise OcrStoreError("共享 OCR 批次证据已存在但内容不一致")
    else:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_bytes(stored)
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    file_sha256 = hashlib.sha256(stored).hexdigest()
    summary = {
        "batch_id": attempt.batch_id,
        "page_ids": list(attempt.page_ids),
        "classification": attempt.classification,
        "fallback_to_single": bool(attempt.fallback_to_single),
        "shared_call": True,
        "usage_accounting": "GLOBAL_ONCE",
        "evidence_path": relative_path.as_posix(),
        "evidence_sha256": file_sha256,
        "record_sha256": record_sha256,
    }
    with _ocr_jobs_lock:
        index = job.setdefault("_v2_batch_attempt_index", {})
        prior = index.get(attempt.batch_id)
        if prior is not None and prior != summary:
            raise OcrStoreError("共享 OCR 批次索引发生不可变冲突")
        is_new_attempt = prior is None
        index[attempt.batch_id] = deepcopy(summary)
        rows = job.setdefault("batch_attempts", [])
        if not any(row.get("batch_id") == attempt.batch_id for row in rows):
            rows.append(deepcopy(summary))
        page_ids = set(attempt.page_ids)
        for page in job.get("pages", {}).values():
            task_index = int(page.get("task_index") or 0)
            if task_index < 1:
                continue
            page_id = make_page_id(task_index)
            if page_id not in page_ids:
                continue
            aliases = page.setdefault("batch_attempt_aliases", [])
            if not any(row.get("batch_id") == attempt.batch_id for row in aliases):
                aliases.append(deepcopy(summary))
        limiter = _ocr_adaptive_limiters.get(str(job.get("id") or ""))
        if (
            is_new_attempt
            and
            isinstance(limiter, AdaptivePageConcurrency)
            and attempt.classification == "PROVIDER:RATE_LIMIT"
        ):
            current = limiter.on_rate_limit()
            job["rate_limit_events"] = int(job.get("rate_limit_events") or 0) + 1
            job["current_concurrency_limit"] = current
            job["rate_limited"] = True
        _bump_ocr_state(job)
    return summary


def _ocr_attach_batch_attempt_alias(job: dict, execution):
    """Bind a single-page fallback result to its persisted shared parent."""
    if not execution.fell_back_to_single or not execution.batch_id:
        return execution
    with _ocr_jobs_lock:
        parent = deepcopy(
            (job.get("_v2_batch_attempt_index") or {}).get(execution.batch_id)
        )
    if not isinstance(parent, dict):
        raise OcrStoreError("批次 fallback 页缺少宿主共享证据")
    page = execution.page
    retry_state = thaw_json(execution.retry_state)
    if not isinstance(retry_state, dict):
        retry_state = {}
    retry_state["batch_parent"] = parent
    if page is None:
        return replace(execution, retry_state=retry_state)
    issue = OcrValidationIssue(
        code="BATCH_FALLBACK_PARENT",
        severity="info",
        message=f"单页 fallback 引用共享批次 {execution.batch_id}",
        retryable=False,
    )
    issues = tuple(page.issues)
    if not any(item.code == issue.code for item in issues):
        issues += (issue,)
    return replace(
        execution,
        page=replace(page, issues=issues),
        retry_state=retry_state,
    )


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


def _restore_ocr_recovery_telemetry(
    job: dict,
    store: OcrRunStore,
    snapshot,
    records: list[OcrPageRecord],
) -> None:
    """Recover usage and hash-chain summaries without replaying model calls.

    Page records are the authority for OCR text/status, while the append-only
    recovery journals are the authority for calls, usage and recovery history.
    Rebuilding this disposable in-memory view keeps a restarted job honest and
    avoids charging a resumed run as though its earlier calls never happened.
    """
    from ..core.ocr_recovery import (
        OcrRecoveryEvidenceStore,
        RecoveryEvidenceError,
    )
    from ..pricing import add_usage, summarize_ai_usage

    page_usage: dict[str, list[dict]] = {}
    for record in records:
        usage = thaw_json(record.usage)
        attempts = usage.get("attempts") if isinstance(usage, dict) else None
        page_usage[record.page_id] = [
            deepcopy(row) for row in (attempts or []) if isinstance(row, dict)
        ]
    job["_v2_page_usage"] = page_usage

    root = store.run_dir(snapshot.run_id) / "recovery-evidence"
    if not root.is_dir():
        return
    recovery = OcrRecoveryEvidenceStore(root)
    job["_v2_recovery_store"] = recovery
    records_by_id = {record.page_id: record for record in records}
    latest_by_page: dict[str, tuple[str, object, str]] = {}
    usage_events: dict[tuple[str, ...], tuple[dict, str]] = {}
    journal_page_usage: dict[str, list[dict]] = {
        record.page_id: [] for record in records
    }
    chain_rows: dict[str, list[dict]] = {record.page_id: [] for record in records}
    try:
        run_dirs = sorted(
            path for path in root.iterdir()
            if path.is_dir() and re.fullmatch(r"[0-9a-f]{16,64}", path.name)
        )
        for run_dir in run_dirs:
            for page_id, state in recovery.recover_run(run_dir.name).items():
                if page_id not in records_by_id:
                    continue
                attempts, verified_state = recovery.recover_page(
                    run_dir.name, page_id, repair=False,
                )
                ended_at = str(attempts[-1].ended_at or "") if attempts else ""
                chain_rows[page_id].append({
                    "run_id": run_dir.name,
                    "status": verified_state.status.value,
                    "stage": (
                        verified_state.current_stage.value
                        if verified_state.current_stage is not None else ""
                    ),
                    "attempt_count": verified_state.attempt_count,
                    "evidence_chain_sha256": verified_state.evidence_chain_sha256,
                    "ended_at": ended_at,
                })
                prior = latest_by_page.get(page_id)
                if prior is None or (ended_at, run_dir.name) > (prior[2], prior[0]):
                    latest_by_page[page_id] = (run_dir.name, verified_state, ended_at)
                for attempt in attempts:
                    usage = thaw_json(attempt.usage)
                    if not isinstance(usage, dict) or not usage:
                        continue
                    journal_page_usage[page_id].append({
                        "event_id": f"{run_dir.name}:{attempt.attempt_id}",
                        "call_index": int(attempt.sequence),
                        "batch_shared": bool(attempt.is_batched),
                        "batch_page_count": int(attempt.batch_size),
                        "started_at": str(attempt.started_at or ""),
                        "usage": deepcopy(usage),
                    })
                    event_key = (
                        ("batch", run_dir.name, str(attempt.batch_id))
                        if attempt.is_batched and attempt.batch_id
                        else (
                            "single", run_dir.name, page_id,
                            str(attempt.attempt_id),
                        )
                    )
                    usage_events.setdefault(event_key, (usage, str(attempt.model or "")))
    except (OSError, ValueError, RecoveryEvidenceError) as exc:
        # Text/page records remain usable, but corrupted optional telemetry must
        # never be promoted as verified usage or a valid evidence chain.
        job["recovery_restore_error"] = _safe_task_error(exc)
        return

    for page_id, (run_id, state, _ended_at) in latest_by_page.items():
        record = records_by_id[page_id]
        page = job["pages"].get(record.source_page)
        if page is None:
            continue
        page["recovery_run_id"] = run_id
        page["recovery_stage"] = (
            state.current_stage.value if state.current_stage is not None else ""
        )
        page["recovery_status"] = state.status.value
        page["recovery_attempt_count"] = state.attempt_count
        page["recovery_evidence_chain_sha256"] = state.evidence_chain_sha256
        page["recovery_chains"] = sorted(
            chain_rows.get(page_id) or [],
            key=lambda row: (str(row.get("ended_at") or ""), str(row.get("run_id") or "")),
        )

    # Journals are append-only and hash chained, so they supersede the mutable
    # page-record cache whenever at least one recorded attempt exists.  This
    # closes the crash window between journal persistence and final page commit.
    for page_id, rows in journal_page_usage.items():
        if rows:
            page_usage[page_id] = sorted(
                rows,
                key=lambda row: (
                    str(row.get("started_at") or ""),
                    int(row.get("call_index") or 0),
                    str(row.get("event_id") or ""),
                ),
            )
    job["_v2_page_usage"] = page_usage

    restored_usage: dict = {}
    for usage, model in usage_events.values():
        add_usage(restored_usage, usage, model or snapshot.ocr_model)
    if restored_usage:
        job["usage"] = restored_usage
        job["usage_revision"] = len(usage_events)
        job["cost"] = summarize_ai_usage({"ocr": restored_usage})


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
                "can_retry": (
                    retry_available
                    and not bool(job.get("raw_frozen"))
                    and not page.get("retrying", False)
                    and (
                        not str(page.get("page_id") or "")
                        or page.get("status") != "done"
                        or page.get("needs_review") is True
                        or page.get("low_conf") is True
                    )
                ),
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
                "recovery_stage": str(page.get("recovery_stage") or ""),
                "recovery_status": str(page.get("recovery_status") or ""),
                "recovery_attempt_count": int(
                    page.get("recovery_attempt_count") or 0
                ),
                "prompt_version": str(page.get("prompt_version") or "")[:120],
                "batch_attempt_aliases": deepcopy(
                    page.get("batch_attempt_aliases") or []
                )[:8],
                "page_strategy": str(page.get("page_strategy") or ""),
                "candidate_strategy": str(page.get("candidate_strategy") or ""),
                "visual_mode": str(page.get("visual_mode") or ""),
                "coverage_complete": bool(page.get("coverage_complete")),
                "coverage_checks": deepcopy(page.get("coverage_checks") or {}),
            }
            for n, page in job.get("pages", {}).items()
        }
        public = {
            key: deepcopy(value)
            for key, value in job.items()
            if not key.startswith("_") and key not in (
                "raw_tex", "pages", "client", "dir", "target", "visual_target", "suffix",
                "pause_requested",
                "_transcribe_one", "_refresh_raw_preview", "_merge_job", "_render_one",
                "_mark_page_error",
                "_source_sha256", "_visual_source_sha256", "_v2_store", "_v2_snapshot",
                "_v2_retry_page", "_v2_recovery_store", "_compatibility_single",
                "_v2_batch_attempt_index",
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
                    # ``raw_ready`` means a partial preview is downloadable;
                    # only the immutable freeze proves a complete ordered merge.
                    merge_complete=bool(job.get("raw_frozen")),
                    raw_frozen=bool(job.get("raw_frozen")),
                    compile_status=_ocr_effective_compile_status(job),
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
                    "ocr_baseline_manifest": "ocr-baseline-manifest",
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
        collector = job.get("_v2_metrics_collector")
        if collector is not None:
            try:
                public["performance_metrics"] = collector.performance_metrics(
                    now_seconds=time.time()
                )
                public["cost_report"] = collector.cost_report()
            except (TypeError, ValueError) as exc:
                public["metrics_error"] = _safe_task_error(exc)
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
    r"(?:"
    r"images/page_(?P<legacy_page>\d+)_(?P<legacy_index>\d+)"
    r"(?P<legacy_ext>\.(?:png|jpe?g))?"
    r"|"
    r"figures/page_(?P<v2_page>\d{4})_figure_(?P<v2_index>\d{2})"
    r"(?P<v2_ext>\.png)"
    r")",
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


def _call_ocr_visual_json(method, *args, operation: str = "OCR"):
    """Label real OCR calls without breaking older visual-client adapters."""
    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        parameters = {}
    supports_operation = "operation" in parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )
    if supports_operation:
        return method(*args, operation=operation)
    return method(*args)


OCR_VISUAL_REQUEST_PAGE_LIMIT = 4
OCR_VISUAL_NORMAL_CONCURRENCY = 4
OCR_VISUAL_MAX_CONCURRENCY = 6
OCR_VISUAL_PROMOTION_MIN_REQUESTS = 4
OCR_VISUAL_PROMOTION_LATENCY_MS = 15_000.0
OCR_RENDER_PREPARE_MIN_WORKERS = 2
OCR_RENDER_PREPARE_DEFAULT_WORKERS = 3
OCR_RENDER_PREPARE_MAX_WORKERS = 4
OCR_RENDER_PREPARE_OUTSTANDING_FACTOR = 2


def _visual_latency_p95(values) -> float | None:
    """Return the conservative nearest-rank p95 for measured verifier calls."""
    samples = sorted(float(value) for value in values if float(value) >= 0.0)
    if not samples:
        return None
    rank = max(1, math.ceil(len(samples) * 0.95))
    return samples[rank - 1]


def _run_bounded_visual_pool(
    groups,
    *,
    prepare_group,
    verify_group,
    commit_group,
    control,
    normal_workers: int = OCR_VISUAL_NORMAL_CONCURRENCY,
    max_workers: int = OCR_VISUAL_MAX_CONCURRENCY,
    promotion_min_requests: int = OCR_VISUAL_PROMOTION_MIN_REQUESTS,
    promotion_latency_ms: float = OCR_VISUAL_PROMOTION_LATENCY_MS,
    on_limit_change=None,
) -> dict:
    """Run bounded verifier batches concurrently and commit them in input order.

    Preparation and model submission may overlap, but ``commit_group`` is
    invoked strictly in the frozen group order.  The sum of in-flight batches
    and out-of-order completed results never exceeds the current worker limit,
    which also bounds retained page rasters.  Promotion from four to six
    requests requires measured, error-free low latency; missing telemetry is
    deliberately not treated as healthy evidence.
    """
    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

    batches = tuple(tuple(group) for group in groups)
    if any(
        not group or len(group) > OCR_VISUAL_REQUEST_PAGE_LIMIT
        for group in batches
    ):
        raise ValueError("visual verifier groups must contain 1..4 pages")
    normal_workers = int(normal_workers)
    max_workers = int(max_workers)
    promotion_min_requests = int(promotion_min_requests)
    promotion_latency_ms = float(promotion_latency_ms)
    if (
        normal_workers < 1
        or max_workers < normal_workers
        or max_workers > OCR_VISUAL_MAX_CONCURRENCY
        or promotion_min_requests < 1
        or not math.isfinite(promotion_latency_ms)
        or promotion_latency_ms <= 0.0
    ):
        raise ValueError("invalid visual verifier pool limits")
    if not batches:
        return {
            "normal_workers": normal_workers,
            "max_workers": max_workers,
            "final_workers": normal_workers,
            "promoted": False,
            "promotion_blocked": False,
            "successful_requests": 0,
            "latency_p95_ms": None,
            "max_in_flight_batches": 0,
            "max_in_flight_pages": 0,
            "max_outstanding_batches": 0,
        }

    current_limit = min(normal_workers, len(batches))
    promotion_blocked = False
    promoted = False
    successful_requests = 0
    request_latencies: list[float] = []
    next_submit = 0
    next_commit = 0
    in_flight = {}
    completed = {}
    max_in_flight_batches = 0
    max_in_flight_pages = 0
    max_outstanding_batches = 0

    def publish_limit() -> None:
        if callable(on_limit_change):
            on_limit_change(current_limit)

    publish_limit()
    with ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="ocr-visual-verifier",
    ) as pool:
        while next_commit < len(batches):
            control()
            while (
                next_submit < len(batches)
                and len(in_flight) + len(completed) < current_limit
            ):
                group_index = next_submit
                group = batches[group_index]
                try:
                    prepared = prepare_group(group_index, group)
                except Exception as exc:  # noqa: BLE001 - committed fail-closed
                    completed[group_index] = (group, None, exc)
                else:
                    future = pool.submit(
                        verify_group,
                        group_index,
                        group,
                        prepared,
                    )
                    in_flight[future] = (group_index, group)
                    max_in_flight_batches = max(
                        max_in_flight_batches, len(in_flight)
                    )
                    max_in_flight_pages = max(
                        max_in_flight_pages,
                        sum(len(item[1]) for item in in_flight.values()),
                    )
                next_submit += 1
                max_outstanding_batches = max(
                    max_outstanding_batches,
                    len(in_flight) + len(completed),
                )

            while next_commit in completed:
                group, result, pool_error = completed.pop(next_commit)
                signals = commit_group(
                    next_commit,
                    group,
                    result,
                    pool_error,
                ) or {}
                if bool(signals.get("had_error")) or pool_error is not None:
                    promotion_blocked = True
                successful = signals.get("successful_requests", 0)
                if isinstance(successful, int) and not isinstance(successful, bool):
                    successful_requests += max(0, successful)
                raw_latencies = signals.get("latency_ms") or ()
                for raw_latency in raw_latencies:
                    try:
                        latency = float(raw_latency)
                    except (TypeError, ValueError):
                        continue
                    if math.isfinite(latency) and latency >= 0.0:
                        request_latencies.append(latency)
                latency_p95 = _visual_latency_p95(request_latencies)
                previous_limit = current_limit
                if (
                    not promotion_blocked
                    and successful_requests >= promotion_min_requests
                    and len(request_latencies) >= promotion_min_requests
                    and latency_p95 is not None
                    and latency_p95 <= promotion_latency_ms
                ):
                    current_limit = min(max_workers, len(batches))
                    promoted = current_limit > normal_workers
                elif current_limit > normal_workers and (
                    promotion_blocked
                    or latency_p95 is None
                    or latency_p95 > promotion_latency_ms
                ):
                    current_limit = min(normal_workers, len(batches))
                if current_limit != previous_limit:
                    publish_limit()
                next_commit += 1

            if next_commit >= len(batches):
                break
            if not in_flight:
                if next_submit < len(batches):
                    continue
                # This can only happen if a coordinator callback violated its
                # contract and failed to publish the next ordered result.
                raise RuntimeError("visual verifier pool made no forward progress")
            done, _pending = wait(tuple(in_flight), return_when=FIRST_COMPLETED)
            for future in done:
                group_index, group = in_flight.pop(future)
                try:
                    result = future.result()
                    pool_error = None
                except Exception as exc:  # noqa: BLE001 - corresponding group only
                    result = None
                    pool_error = exc
                completed[group_index] = (group, result, pool_error)
            max_outstanding_batches = max(
                max_outstanding_batches,
                len(in_flight) + len(completed),
            )

    return {
        "normal_workers": normal_workers,
        "max_workers": max_workers,
        "final_workers": current_limit,
        "promoted": promoted,
        "promotion_blocked": promotion_blocked,
        "successful_requests": successful_requests,
        "latency_p95_ms": _visual_latency_p95(request_latencies),
        "max_in_flight_batches": max_in_flight_batches,
        "max_in_flight_pages": max_in_flight_pages,
        "max_outstanding_batches": max_outstanding_batches,
    }


class _OcrPrepareControlStop(RuntimeError):
    """Carry a coordinator stop without misclassifying it as a page failure."""

    def __init__(self, cause: Exception):
        super().__init__(str(cause))
        self.cause = cause


def _run_bounded_page_prepare_pool(
    pages,
    *,
    selected_index,
    page_id,
    prepare_page,
    consume_batch,
    batch_limit,
    control,
    resolve_page=None,
    on_prepare_error=None,
    workers: int = OCR_RENDER_PREPARE_DEFAULT_WORKERS,
) -> dict:
    """Overlap per-page rendering/request preparation under strict back-pressure.

    Pages are submitted and consumed in their frozen ``selected_index`` order.
    At most ``2 * workers`` tasks/results are outstanding, so prepared rasters
    cannot grow with book length.  ``control`` runs both before submission and
    inside each worker immediately before resolution/rendering; a paused or
    cancelled coordinator therefore cannot let already-queued work start a new
    render.  One preparation exception is reported only for its own page.
    """
    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

    workers = int(workers)
    if not OCR_RENDER_PREPARE_MIN_WORKERS <= workers <= OCR_RENDER_PREPARE_MAX_WORKERS:
        raise ValueError("render preparation workers must remain within 2..4")
    ordered = []
    for original_position, page in enumerate(tuple(pages)):
        frozen_index = selected_index(page)
        frozen_page_id = str(page_id(page) or "")
        if (
            not isinstance(frozen_index, int)
            or isinstance(frozen_index, bool)
            or frozen_index < 1
            or not frozen_page_id
        ):
            raise ValueError("render preparation pages require frozen identity")
        ordered.append((frozen_index, original_position, frozen_page_id, page))
    ordered.sort(key=lambda item: (item[0], item[1]))
    frozen_indexes = [item[0] for item in ordered]
    frozen_page_ids = [item[2] for item in ordered]
    if len(frozen_indexes) != len(set(frozen_indexes)):
        raise ValueError("render preparation contains duplicate selected_index")
    if len(frozen_page_ids) != len(set(frozen_page_ids)):
        raise ValueError("render preparation contains duplicate page_id")

    outstanding_limit = workers * OCR_RENDER_PREPARE_OUTSTANDING_FACTOR
    stats = {
        "workers": workers,
        "outstanding_limit": outstanding_limit,
        "submitted_pages": 0,
        "prepared_pages": 0,
        "failed_pages": 0,
        "skipped_pages": 0,
        "consumed_pages": 0,
        "consumed_batches": 0,
        "max_in_flight": 0,
        "max_outstanding": 0,
    }
    if not ordered:
        return stats

    skipped = object()
    next_submit = 0
    next_commit = 0
    in_flight = {}
    completed = {}
    ready_batch = []
    target_batch_size = None

    def update_maxima() -> None:
        stats["max_in_flight"] = max(stats["max_in_flight"], len(in_flight))
        stats["max_outstanding"] = max(
            stats["max_outstanding"],
            len(in_flight) + len(completed) + len(ready_batch),
        )
        if stats["max_outstanding"] > outstanding_limit:
            raise RuntimeError("render preparation pool exceeded its outstanding bound")

    def guarded_prepare(page):
        try:
            control()
        except Exception as exc:  # noqa: BLE001 - preserve coordinator authority
            raise _OcrPrepareControlStop(exc) from exc
        resolved = resolve_page(page) if callable(resolve_page) else page
        if resolved is None:
            return skipped, None
        return resolved, prepare_page(resolved)

    def current_batch_limit() -> int:
        value = batch_limit() if callable(batch_limit) else batch_limit
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("render preparation batch limit must be a positive integer")
        return value

    def flush_ready() -> None:
        nonlocal ready_batch, target_batch_size
        if not ready_batch:
            return
        consume_batch(tuple(ready_batch))
        stats["consumed_batches"] += 1
        stats["consumed_pages"] += len(ready_batch)
        ready_batch = []
        target_batch_size = None

    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="ocr-render-prepare",
    ) as pool:
        while next_commit < len(ordered):
            control()
            while (
                next_submit < len(ordered)
                and len(in_flight) + len(completed) + len(ready_batch)
                < outstanding_limit
            ):
                _index, _position, _page_id, page = ordered[next_submit]
                control()
                future = pool.submit(guarded_prepare, page)
                in_flight[future] = next_submit
                next_submit += 1
                stats["submitted_pages"] += 1
                update_maxima()

            made_progress = False
            while next_commit in completed:
                page, result, error = completed.pop(next_commit)
                next_commit += 1
                made_progress = True
                if isinstance(error, _OcrPrepareControlStop):
                    raise error.cause
                if error is not None:
                    stats["failed_pages"] += 1
                    if callable(on_prepare_error):
                        on_prepare_error(page, error)
                    continue
                resolved, prepared = result
                if resolved is skipped:
                    stats["skipped_pages"] += 1
                    continue
                stats["prepared_pages"] += 1
                if target_batch_size is None:
                    target_batch_size = current_batch_limit()
                ready_batch.append((resolved, prepared))
                update_maxima()
                if len(ready_batch) >= target_batch_size:
                    flush_ready()
                    break

            if next_commit >= len(ordered):
                flush_ready()
                break
            if made_progress:
                continue
            if not in_flight:
                raise RuntimeError("render preparation pool made no forward progress")
            done, _pending = wait(tuple(in_flight), return_when=FIRST_COMPLETED)
            for future in done:
                ordered_position = in_flight.pop(future)
                page = ordered[ordered_position][3]
                try:
                    result = future.result()
                    error = None
                except Exception as exc:  # noqa: BLE001 - corresponding page only
                    result = None
                    error = exc
                completed[ordered_position] = (page, result, error)
            update_maxima()

    return stats


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
    # ``transcribe_page`` prepends the physical PDF page to every legacy OCR
    # chunk.  The visual model may then copy the printed page number from the
    # footer and may also use that printed number in its legacy filename.
    # Therefore only the first Page marker in each PAGE BREAK chunk is
    # authoritative for ``images/page_*``.  By contrast, the v2 runtime rejects
    # a figure unless its host-owned path embeds the exact source page, so the
    # ``figures/page_NNNN_*`` path itself is authoritative even though the v2
    # merger deliberately omits legacy PAGE BREAK comments.
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
            printed_page = int(
                canonical.group("legacy_page") or canonical.group("v2_page")
            )
            figure_index = int(
                canonical.group("legacy_index") or canonical.group("v2_index")
            )
            extension = canonical.group("legacy_ext") or canonical.group("v2_ext") or ""
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
                    int(canonical.group("v2_page"))
                    if canonical.group("v2_page")
                    else int(page_marker.group("page"))
                    if page_marker
                    else printed_page
                ),
                "index": figure_index,
                "ext": extension.lower(),
                "width_hint": float(width_match.group("width")) if width_match else None,
            })
    return references, unsupported


_ACTIVE_OCR_GRAPHICS_PATH_RE = re.compile(
    r"\\includegraphics\s*(?:\[[^\]\r\n]*\]\s*)?"
    r"\{\s*(?P<path>[^{}\r\n]*?\S)\s*\}",
    re.I,
)


def _bind_v2_ocr_figure_paths(
    latex: str,
    figures: list[dict],
    source_page: int,
) -> tuple[str, list[dict]]:
    """Replace only active, parser-visible figure path spans with host paths."""
    document = parse_latex(latex)
    matches = list(_ACTIVE_OCR_GRAPHICS_PATH_RE.finditer(document.masked))
    if len(matches) != len(figures):
        raise OcrStoreError("宿主插图路径绑定数量与已校验 figures 不一致")
    edits: list[tuple[int, int, str]] = []
    host_figures: list[dict] = []
    for position, (match, raw_figure) in enumerate(zip(matches, figures), start=1):
        figure = deepcopy(raw_figure)
        legacy_path = str(figure.get("path") or "").replace("\\", "/").strip()
        active_path = match.group("path").replace("\\", "/").strip()
        if not legacy_path or active_path != legacy_path:
            raise OcrStoreError("宿主插图路径绑定与活动 LaTeX 顺序不一致")
        host_path = (
            f"figures/page_{int(source_page):04d}_figure_{position:02d}.png"
        )
        edits.append((match.start("path"), match.end("path"), host_path))
        figure["path"] = host_path
        figure["index"] = position
        host_figures.append(figure)
    for start, end, host_path in reversed(edits):
        latex = latex[:start] + host_path + latex[end:]
    rebound = [
        match.group("path").replace("\\", "/").strip()
        for match in _ACTIVE_OCR_GRAPHICS_PATH_RE.finditer(parse_latex(latex).masked)
    ]
    if rebound != [item[2] for item in edits]:
        raise OcrStoreError("宿主插图路径绑定后复核失败")
    return latex, host_figures


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


def _verified_ocr_recovery_json_files(
    root_text: str,
) -> list[tuple[tuple[str, ...], bytes, dict]]:
    """Load only bounded, in-root recovery journals and derived summaries."""
    if not str(root_text or "").strip():
        return []
    root = Path(root_text).resolve()
    if not root.is_dir() or root.is_symlink():
        return []
    output = []
    for source in sorted(root.rglob("*.json")):
        try:
            resolved = source.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_symlink() or not resolved.is_file():
            continue
        parts = relative.parts
        is_page_evidence = bool(
            len(parts) >= 4
            and parts[1] == "pages"
            and (
                parts[-2] == "attempts"
                or parts[-1] in {"state.json", "terminal-summary.json"}
            )
        )
        is_batch_evidence = bool(
            len(parts) == 3
            and parts[1] == "batch-attempts"
            and re.fullmatch(r"ocr-batch-[0-9a-f]{12}\.json", parts[-1])
        )
        if not is_page_evidence and not is_batch_evidence:
            continue
        data = resolved.read_bytes()
        if len(data) > 2 * 1024 * 1024:
            continue
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(parsed, dict):
            continue
        if is_batch_evidence:
            if parsed.get("schema") != "latexstruct-ocr-batch-attempt-v1":
                continue
            claimed = str(parsed.get("record_sha256") or "")
            canonical = json.dumps(
                {
                    key: value
                    for key, value in parsed.items()
                    if key != "record_sha256"
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if not hmac.compare_digest(
                claimed,
                hashlib.sha256(canonical).hexdigest(),
            ):
                continue
        output.append((parts, data, {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "kind": (
                "batch_attempt"
                if is_batch_evidence
                else
                "attempt"
                if parts[-2] == "attempts"
                else "terminal_summary"
                if parts[-1] == "terminal-summary.json"
                else "derived_state"
            ),
        }))
    return output


def _preserve_ocr_recovery_evidence(job: dict, project_dir: Path) -> list[dict]:
    """Copy verified JSON evidence into the project without local path leakage."""
    rows = []
    root_text = str(job.get("_recovery_evidence_root") or "")
    for parts, data, metadata in _verified_ocr_recovery_json_files(root_text):
        relative = (
            PurePosixPath("evidence", "ocr-recovery")
            / PurePosixPath(*parts)
        ).as_posix()
        target = (project_dir.resolve() / Path(relative)).resolve()
        try:
            target.relative_to(project_dir.resolve())
        except ValueError:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rows.append({"path": relative, **metadata})
    return rows


def _preserve_ocr_baseline_package(job: dict, project_dir: Path) -> list[dict]:
    """Copy an already-verified OCR-only package without regenerating evidence."""
    runtime_store = job.get("_v2_store")
    runtime_snapshot = job.get("_v2_snapshot")
    if not isinstance(runtime_store, OcrRunStore) or runtime_snapshot is None:
        return []
    if not _recomputable_ocr_contract(runtime_snapshot):
        return []
    if not _exact_ocr_manifest_required(runtime_snapshot):
        raise OcrStoreError(
            "non-exact OCR builds cannot publish a baseline evidence package"
        )
    from ..core.ocr_manifest import DEFAULT_MANIFEST_PATH

    bundle = load_verified_ocr_baseline_bundle(
        runtime_store, str(runtime_snapshot.run_id)
    )
    files = {
        DEFAULT_MANIFEST_PATH: bundle.manifest.canonical_bytes,
        **dict(bundle.artifact_bytes()),
    }
    root = project_dir.resolve()
    rows = []
    for logical_path, data in sorted(files.items()):
        relative = (
            PurePosixPath("evidence", "ocr-baseline") / logical_path
        ).as_posix()
        target = (root / Path(relative)).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise OcrStoreError("OCR baseline project path escaped its root") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != data:
            raise OcrStoreError("OCR baseline project evidence already differs")
        if not target.exists():
            tmp_path = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
            try:
                with tmp_path.open("wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp_path, target)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()
        rows.append({
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return rows


def _ocr_bundle_bytes(job: dict, raw_tex: str) -> tuple[bytes, dict]:
    """Build a self-contained raw OCR snapshot without mutating project state."""
    baseline_package_files: dict[str, bytes] = {}
    baseline_package_summary: dict[str, object] | None = None
    runtime_store = job.get("_v2_store")
    runtime_snapshot = job.get("_v2_snapshot")
    if not isinstance(runtime_store, OcrRunStore) or runtime_snapshot is None:
        candidate_run_id = str(job.get("id") or "")
        if re.fullmatch(r"[0-9a-f]{32}", candidate_run_id):
            candidate_store = OcrRunStore(Path(get_store().root).parent / "ocr-runs")
            try:
                candidate_snapshot = candidate_store.load_snapshot(candidate_run_id)
            except (OcrStoreError, OSError, ValueError):
                pass
            else:
                runtime_store = candidate_store
                runtime_snapshot = candidate_snapshot
    if (
        isinstance(runtime_store, OcrRunStore)
        and runtime_snapshot is not None
        and _recomputable_ocr_contract(runtime_snapshot)
        and _exact_ocr_manifest_required(runtime_snapshot)
    ):
        from ..core.ocr_manifest import DEFAULT_MANIFEST_PATH

        verified_baseline = load_verified_ocr_baseline_bundle(
            runtime_store, str(runtime_snapshot.run_id)
        )
        baseline_package_files = {
            DEFAULT_MANIFEST_PATH: verified_baseline.manifest.canonical_bytes,
            **dict(verified_baseline.artifact_bytes()),
        }
        baseline_package_summary = {
            "schema": "latexstruct-ocr-baseline-package-export-v1",
            "manifest_sha256": verified_baseline.manifest.sha256,
            "files": [
                {
                    "path": path,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for path, data in sorted(baseline_package_files.items())
            ],
        }
    verified_job = _verified_ocr_bundle_snapshot(job)
    with tempfile.TemporaryDirectory(prefix="ls-ocr-bundle-") as tmp:
        bundle_root = Path(tmp).resolve()
        resources = _preserve_ocr_resources(verified_job, raw_tex, bundle_root)
        recovery_files: list[tuple[str, bytes, dict]] = []
        for parts, data, metadata in _verified_ocr_recovery_json_files(str(
            verified_job.get("_recovery_evidence_root") or ""
        )):
            archive_path = (
                PurePosixPath("evidence", "ocr-recovery")
                / PurePosixPath(*parts)
            ).as_posix()
            recovery_files.append((
                archive_path,
                data,
                {"path": archive_path, **metadata},
            ))
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
            "recovery_evidence": [
                metadata for _path, _data, metadata in recovery_files
            ],
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
            "ocr_baseline_package": baseline_package_summary,
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
            for archive_path, data, _metadata in recovery_files:
                archive.writestr(archive_path, data)
            for logical_path, data in sorted(baseline_package_files.items()):
                archive.writestr(
                    (PurePosixPath("evidence", "ocr-baseline") / logical_path).as_posix(),
                    data,
                )
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
    """Detect/render retry-only PDF formula crops; failures intentionally propagate."""
    policy = quality_tier_policy(
        job.get("quality_tier") or job.get("quality_profile") or "recommended"
    )
    client = job.get("client")
    if (
        not policy.use_formula_crops
        or not bool((job.get("pages") or {}).get(page_no, {}).get("retrying"))
        or str(job.get("source_type") or "") != "pdf"
        or not any(callable(getattr(client, name, None)) for name in (
            "chat_vision_json_images_bytes", "chat_vision_structured_images_bytes",
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
        safe_usage = _safe_ocr_evidence_value(deepcopy(page.get("usage_v2") or {}))
        if not isinstance(safe_usage, dict):
            safe_usage = {}
        safe_quality_issues = _safe_ocr_evidence_value(
            deepcopy(page.get("quality_issues_v2") or [])
        )
        if not isinstance(safe_quality_issues, list):
            safe_quality_issues = []
        safe_unresolved_regions = _safe_ocr_evidence_value(
            deepcopy(page.get("unresolved_regions_v2") or [])
        )
        if not isinstance(safe_unresolved_regions, list):
            safe_unresolved_regions = []
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
            "usage": safe_usage,
            "quality_issues": safe_quality_issues[:32],
            "unresolved_regions": safe_unresolved_regions[:32],
            "terminal_error": _safe_task_error(
                page.get("terminal_error") or ""
            ),
            "recovery": {
                "run_id": str(page.get("recovery_run_id") or "")[:64],
                "stage": str(page.get("recovery_stage") or "")[:40],
                "status": str(page.get("recovery_status") or "")[:40],
                "attempt_count": max(
                    0, int(page.get("recovery_attempt_count") or 0)
                ),
                "evidence_chain_sha256": str(
                    page.get("recovery_evidence_chain_sha256") or ""
                )[:64],
            },
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
        "id": str(job.get("id") or ""),
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
        "batch_attempts": _safe_ocr_evidence_value(
            deepcopy(job.get("batch_attempts") or [])
        ),
        "recovery_restore_error": _safe_task_error(
            job.get("recovery_restore_error") or ""
        ),
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
                "quality_flags": _safe_ocr_evidence_value(
                    deepcopy(page.get("quality_flags") or [])
                ),
                "needs_review": bool(page.get("needs_review")),
                "status": str(page.get("status") or "pending"),
                "low_conf": bool(page.get("low_conf")),
                "error": _safe_task_error(page.get("error") or ""),
                "attempts": int(page.get("attempts") or 0),
                "recovery_run_id": str(page.get("recovery_run_id") or ""),
                "recovery_stage": str(page.get("recovery_stage") or ""),
                "recovery_status": str(page.get("recovery_status") or ""),
                "recovery_attempt_count": int(
                    page.get("recovery_attempt_count") or 0
                ),
                "recovery_evidence_chain_sha256": str(
                    page.get("recovery_evidence_chain_sha256") or ""
                ),
                "recovery_parent_run_id": str(
                    page.get("recovery_parent_run_id") or ""
                ),
                "recovery_chains": _safe_ocr_evidence_value(
                    deepcopy(page.get("recovery_chains") or [])
                )[:16],
                "prompt_version": str(page.get("prompt_version") or "")[:120],
                "batch_attempt_aliases": deepcopy(
                    page.get("batch_attempt_aliases") or []
                ),
            }
            for page_no, page in (job.get("pages") or {}).items()
        },
    }
    runtime_snapshot = job.get("_v2_snapshot")
    recovery_store = job.get("_v2_recovery_store")
    recovery_root = getattr(recovery_store, "root", None)
    if recovery_root is not None:
        snapshot["_recovery_evidence_root"] = str(recovery_root)
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
            "quality_issues_v2": _safe_ocr_evidence_value(
                thaw_json(record.quality_issues)
            ),
            "unresolved_regions_v2": _safe_ocr_evidence_value(
                thaw_json(record.unresolved_regions)
            ),
            "usage_v2": _safe_ocr_evidence_value(thaw_json(record.usage)),
            "terminal_error": _safe_task_error(record.error_reason),
        })
    if runtime_snapshot is not None:
        snapshot["ocr_run_snapshot"] = _safe_ocr_evidence_value(
            runtime_snapshot.to_dict()
        )
        if v2_records is not None:
            snapshot["performance_metrics"] = ocr_progress_metrics(
                runtime_snapshot,
                v2_records,
                terminal_epoch=job.get("terminal_epoch"),
                # A partial raw preview must not become an audit milestone.
                merge_complete=bool(job.get("raw_frozen")),
                raw_frozen=bool(job.get("raw_frozen")),
                compile_status=_ocr_effective_compile_status(job),
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


def _recomputable_ocr_contract(snapshot: object) -> dict:
    """Return the frozen high-speed OCR contract, or an empty legacy marker."""
    try:
        contract = thaw_json(getattr(snapshot, "pipeline_contract", {}) or {})
    except (TypeError, ValueError):
        return {}
    if not isinstance(contract, dict):
        return {}
    page_strategies = contract.get("page_strategies")
    if not isinstance(page_strategies, list) or not page_strategies:
        return {}
    return contract


def _exact_ocr_manifest_required(snapshot: object) -> bool:
    """Require the new manifest only for a clean, identity-bound v2 producer.

    Local source checkouts deliberately embed ``unknown`` build identity.  They
    may exercise OCR and its tests, but cannot create release evidence or unlock
    the strict optional-analysis entry.  A packaged candidate with a frozen
    commit/build ID must fail closed if its recomputable package is unavailable.
    """
    contract = _recomputable_ocr_contract(snapshot)
    if not contract:
        return False
    commit = str(contract.get("git_commit") or "").strip().lower()
    build_id = str(contract.get("build_id") or "").strip()
    return bool(
        re.fullmatch(r"[0-9a-f]{40}", commit)
        and build_id
        and build_id.lower() != "unknown"
        and contract.get("dirty") is False
    )


def _pdf_page_count_from_bytes(data: bytes) -> int:
    """Read the actual captured PDF page count; never trust a compiler claim."""
    if not bytes(data).startswith(b"%PDF-"):
        raise OcrStoreError("OCR baseline PDF is missing or corrupt")
    try:
        import pymupdf
    except ImportError:  # pragma: no cover - declared runtime dependency
        import fitz as pymupdf  # type: ignore
    try:
        document = pymupdf.open(stream=bytes(data), filetype="pdf")
    except Exception as exc:  # noqa: BLE001 - normalized into an evidence error
        raise OcrStoreError("OCR baseline PDF cannot be parsed") from exc
    try:
        page_count = int(document.page_count)
    finally:
        document.close()
    if page_count < 1:
        raise OcrStoreError("OCR baseline PDF has no pages")
    return page_count


def _persist_recomputable_ocr_baseline(
    store: OcrRunStore,
    snapshot: object,
    coverage_bundle: object,
    baseline: object,
    collector: object,
    *,
    created_at: str,
):
    """Build, atomically persist, reload, and recompute the OCR-only package."""
    from ..core.ocr_manifest import (
        OCR_PRODUCER_SCHEMA,
        OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
        ROLE_BASELINE_PDF,
        ROLE_BASELINE_TEX,
        ROLE_COST,
        ROLE_PAGE_MAP,
        ROLE_PAGE_RECORDS,
        ROLE_PERFORMANCE,
        ROLE_RAW_OCR_FREEZE,
        ROLE_RAW_OCR_TEX,
        ROLE_RUN_SNAPSHOT,
        ROLE_RUNTIME_PAGE_RECORDS,
        ROLE_SOURCE,
        ROLE_SYNTAX_BASELINE_TEX,
        ArtifactInput,
        CompilePassInput,
        build_ocr_baseline_manifest,
        canonical_json_bytes,
    )

    contract = _recomputable_ocr_contract(snapshot)
    if not contract or not _exact_ocr_manifest_required(snapshot):
        raise OcrStoreError("OCR baseline package requires an exact clean build identity")
    if collector is None or not callable(getattr(collector, "canonical_reports", None)):
        raise OcrStoreError("OCR baseline package is missing measured performance reports")
    run_id = str(getattr(snapshot, "run_id", "") or "")
    run_dir = store.run_dir(run_id)
    artifact_dir = run_dir / "artifacts"
    snapshot_bytes = (run_dir / "run-snapshot.json").read_bytes()
    source_bytes = store.verify_source(run_id).read_bytes()
    raw_ocr_bytes = (artifact_dir / "raw-ocr.tex").read_bytes()
    raw_freeze_bytes = (artifact_dir / "raw-ocr-freeze.json").read_bytes()
    page_records_bytes = bytes(getattr(coverage_bundle, "page_records_bytes", b""))
    if not page_records_bytes:
        raise OcrStoreError("OCR baseline package is missing canonical page coverage")
    runtime_page_records = canonical_json_bytes({
        "schema_version": OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
        "run_id": run_id,
        "pages": [record.to_dict() for record in store.list_records(run_id)],
    })
    try:
        report_now = datetime.fromisoformat(
            str(created_at).replace("Z", "+00:00")
        ).timestamp()
    except (TypeError, ValueError) as exc:
        raise OcrStoreError("OCR baseline package has an invalid terminal time") from exc
    reports = collector.canonical_reports(now_seconds=report_now)
    performance_bytes = bytes(reports["performance_metrics"])
    cost_bytes = bytes(reports["cost_report"])
    performance = json.loads(performance_bytes.decode("utf-8"))
    distribution = performance.get("strategy_distribution") or {}
    strategies = {
        "born_digital_verified": int(distribution.get("object_layer_verified") or 0),
        "full_visual_ocr": int(distribution.get("full_visual_ocr") or 0),
        "high_resolution_retry": int(
            distribution.get("high_resolution_retry") or 0
        ),
        "crop_review": int(distribution.get("crop_review") or 0),
    }

    compile_invocations = tuple(getattr(baseline, "compile_invocations", ()) or ())
    compile_passes = []
    for invocation in compile_invocations:
        if invocation.exit_code is None:
            raise OcrStoreError("OCR compile invocation has no measured exit code")
        if not (
            invocation.command
            and invocation.command_history
            and invocation.compile_workdir
            and invocation.input_inventory
            and invocation.compile_input_sha256
            and invocation.input_artifacts
        ):
            raise OcrStoreError(
                "OCR compile invocation is missing command/workdir/input evidence"
            )
        compile_passes.append(CompilePassInput(
            log_path=f"compile/pass-{int(invocation.sequence):02d}.log",
            log_bytes=str(invocation.log or "").encode("utf-8"),
            exit_code=int(invocation.exit_code),
            input_tex_sha256=str(invocation.input_tex_sha256 or "") or None,
            output_pdf_sha256=str(invocation.output_pdf_sha256 or "") or None,
            command=tuple(invocation.command),
            command_history=tuple(
                tuple(command) for command in invocation.command_history
            ),
            compile_workdir=str(invocation.compile_workdir),
            input_inventory=tuple(
                item.to_dict() for item in invocation.input_inventory
            ),
            compile_input_sha256=str(invocation.compile_input_sha256),
            input_files=tuple(
                (path, bytes(data))
                for path, data in invocation.input_artifacts
            ),
        ))
    if not compile_passes:
        raise OcrStoreError("OCR baseline package has no real compile invocation evidence")

    preview_status = getattr(baseline, "preview_status", None)
    compile_status = (
        preview_status.value if isinstance(preview_status, OcrPreviewStatus)
        else str(preview_status or "")
    )
    baseline_tex_bytes = str(getattr(baseline, "tex", "") or "").encode("utf-8")
    baseline_pdf_bytes = bytes(getattr(baseline, "pdf_bytes", b"") or b"")
    page_map_bytes = bytes(getattr(baseline, "page_map_json", b"") or b"")
    pdf_page_count = (
        0 if compile_status == OcrPreviewStatus.SOURCE_PREVIEW.value
        else _pdf_page_count_from_bytes(baseline_pdf_bytes)
    )
    error_lines = tuple(getattr(baseline, "error_lines", ()) or ())
    fatal_error = ""
    if compile_status != OcrPreviewStatus.COMPILED.value:
        first_error = error_lines[0] if error_lines else {}
        fatal_error_value = (
            first_error.get("message")
            if isinstance(first_error, dict)
            else first_error
        )
        fatal_error = str(
            fatal_error_value
            or "LaTeX compilation did not produce a complete baseline"
        )[:500]

    source_path = (
        "inputs/source.pdf"
        if getattr(snapshot, "source_type", "") == "pdf"
        else "inputs/source-images.zip"
        if getattr(snapshot, "source_type", "") == "images"
        else "inputs/source-image.bin"
    )
    baseline_pdf = (
        None
        if compile_status == OcrPreviewStatus.SOURCE_PREVIEW.value
        else ArtifactInput(ROLE_BASELINE_PDF, "baseline/baseline.pdf", baseline_pdf_bytes)
    )
    page_map = (
        ArtifactInput(ROLE_PAGE_MAP, "baseline/page-map.json", page_map_bytes)
        if compile_status == OcrPreviewStatus.COMPILED.value
        else None
    )
    producer = {
        "schema_version": OCR_PRODUCER_SCHEMA,
        "app_version": str(getattr(snapshot, "app_version", "") or ""),
        "git_commit": str(contract.get("git_commit") or "").lower(),
        "build_id": str(contract.get("build_id") or ""),
        "ocr_model": str(getattr(snapshot, "ocr_model", "") or ""),
        "verification_model": str(contract.get("verification_model") or ""),
        "prompt_version": str(contract.get("prompt_version") or ""),
        "api_backend": str(getattr(snapshot, "api_backend", "") or ""),
    }
    bundle = build_ocr_baseline_manifest(
        snapshot=ArtifactInput(
            ROLE_RUN_SNAPSHOT, "inputs/run-snapshot.json", snapshot_bytes
        ),
        source=ArtifactInput(ROLE_SOURCE, source_path, source_bytes),
        raw_ocr=ArtifactInput(
            ROLE_RAW_OCR_TEX, "baseline/raw-ocr.tex", raw_ocr_bytes
        ),
        raw_freeze=ArtifactInput(
            ROLE_RAW_OCR_FREEZE,
            "baseline/raw-ocr-freeze.json",
            raw_freeze_bytes,
        ),
        syntax_baseline=ArtifactInput(
            ROLE_SYNTAX_BASELINE_TEX,
            "baseline/syntax-baseline.tex",
            baseline_tex_bytes,
        ),
        baseline_tex=ArtifactInput(
            ROLE_BASELINE_TEX, "baseline/baseline.tex", baseline_tex_bytes
        ),
        baseline_pdf=baseline_pdf,
        page_map=page_map,
        page_records=ArtifactInput(
            ROLE_PAGE_RECORDS, "evidence/page-records.json", page_records_bytes
        ),
        runtime_page_records=ArtifactInput(
            ROLE_RUNTIME_PAGE_RECORDS,
            "evidence/runtime-page-records.json",
            runtime_page_records,
        ),
        performance_metrics=ArtifactInput(
            ROLE_PERFORMANCE,
            "metrics/performance-metrics.json",
            performance_bytes,
        ),
        cost_metrics=ArtifactInput(
            ROLE_COST, "metrics/cost-report.json", cost_bytes
        ),
        compile_passes=tuple(compile_passes),
        compile_status=compile_status,
        compile_engine=str(getattr(baseline, "engine", "xelatex") or "xelatex"),
        pdf_page_count=pdf_page_count,
        producer=producer,
        created_at=created_at,
        strategies=strategies,
        fatal_error=fatal_error,
        error_lines=error_lines,
    )
    manifest_path = store.save_ocr_baseline_bundle(run_id, bundle)
    verified = load_verified_ocr_baseline_bundle(store, run_id)
    if verified.manifest_path != manifest_path:
        raise OcrStoreError("OCR baseline manifest path changed after commit")
    payload = verified.manifest.to_dict()
    if payload.get("status", {}).get("compile_status") != compile_status:
        raise OcrStoreError("OCR baseline manifest terminal status mismatch")
    return verified


def _verified_v2_baseline_for_analysis(job: dict) -> tuple[str, dict]:
    """Return the exact twice-compiled OCR baseline and hash-only lineage."""
    runtime_store = job.get("_v2_store")
    runtime_snapshot = job.get("_v2_snapshot")
    if not isinstance(runtime_store, OcrRunStore) or runtime_snapshot is None:
        return str(job.get("raw_tex") or ""), {
            "schema": "latexstruct-ocr-baseline-lineage-v1",
            "source": "legacy_raw_ocr",
            "verified": False,
        }
    run_id = str(runtime_snapshot.run_id)
    if _recomputable_ocr_contract(runtime_snapshot):
        if not _exact_ocr_manifest_required(runtime_snapshot):
            raise OcrStoreError(
                "新版 OCR 基线来自非精确本地构建，不能打开或进入 AI 分析"
            )
        bundle = load_verified_ocr_baseline_bundle(runtime_store, run_id)
        payload = bundle.manifest.to_dict()
        status = payload.get("status") or {}
        compile_evidence = payload.get("compile") or {}
        if status != {
            "run_status": "SUCCESS",
            "ocr_status": "COMPLETED",
            "compile_status": OcrPreviewStatus.COMPILED.value,
        } or int(compile_evidence.get("successful_passes") or 0) < 2:
            raise OcrStoreError(
                "AI analysis requires a successful recomputable OCR-only baseline"
            )
        baseline_pdf_artifact = bundle.baseline_pdf
        if baseline_pdf_artifact is None or not baseline_pdf_artifact.data.startswith(
            b"%PDF-"
        ):
            raise OcrStoreError("OCR baseline package has no verified compiled PDF")
        try:
            baseline_tex = bundle.baseline_tex.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OcrStoreError("OCR baseline TEX is not valid UTF-8") from exc
        if not baseline_tex.strip():
            raise OcrStoreError("OCR baseline TEX is empty")
        raw_artifact = bundle.require_role("RAW_OCR_TEX")
        compile_log_hashes = [
            bundle.require_role(role).sha256
            for role in (payload.get("bindings") or {}).get("compile_logs") or []
        ]
        lineage = {
            "schema": "latexstruct-ocr-baseline-lineage-v2",
            "run_id": run_id,
            "source": "recomputable_ocr_only_baseline",
            "verified": True,
            "successful_passes": int(compile_evidence["successful_passes"]),
            "raw_ocr_sha256": raw_artifact.sha256,
            "baseline_tex_sha256": bundle.baseline_tex.sha256,
            "baseline_pdf_sha256": baseline_pdf_artifact.sha256,
            "compile_log_sha256s": compile_log_hashes,
            "baseline_manifest_sha256": bundle.manifest.sha256,
            "figure_assets": [],
        }
        return baseline_tex, lineage
    baseline_manifest_artifact = resolve_ocr_artifact(
        runtime_store, run_id, "baseline-manifest"
    )
    try:
        manifest = json.loads(
            baseline_manifest_artifact.path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise OcrStoreError("OCR baseline manifest cannot be read") from exc
    if not isinstance(manifest, dict) or str(manifest.get("run_id") or "") != run_id:
        raise OcrStoreError("OCR baseline manifest run identity mismatch")
    if (
        str(manifest.get("preview_status") or "") != OcrPreviewStatus.COMPILED.value
        or manifest.get("exit_code") != 0
        or int(manifest.get("successful_passes") or 0) < 2
    ):
        raise OcrStoreError(
            "AI analysis requires an OCR baseline with two successful real compile passes"
        )
    baseline_tex_artifact = resolve_ocr_artifact(runtime_store, run_id, "baseline-tex")
    baseline_pdf_artifact = resolve_ocr_artifact(runtime_store, run_id, "baseline-pdf")
    compile_log_artifact = resolve_ocr_artifact(runtime_store, run_id, "compile-log")
    raw_artifact = resolve_ocr_artifact(runtime_store, run_id, "raw-ocr")
    baseline_tex = baseline_tex_artifact.path.read_text(encoding="utf-8")
    if not baseline_tex.strip() or not baseline_pdf_artifact.path.read_bytes().startswith(b"%PDF-"):
        raise OcrStoreError("OCR baseline artifacts are empty or corrupt")
    lineage = {
        "schema": "latexstruct-ocr-baseline-lineage-v1",
        "run_id": run_id,
        "source": "twice_compiled_syntax_baseline",
        "verified": True,
        "successful_passes": int(manifest["successful_passes"]),
        "raw_ocr_sha256": raw_artifact.sha256,
        "baseline_tex_sha256": baseline_tex_artifact.sha256,
        "baseline_pdf_sha256": baseline_pdf_artifact.sha256,
        "compile_log_sha256": compile_log_artifact.sha256,
        "baseline_manifest_sha256": baseline_manifest_artifact.sha256,
        "figure_assets": deepcopy(manifest.get("extra_files") or []),
    }
    return baseline_tex, lineage


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


def _verified_ocr_recovery_resource_bytes(
    project_dir: Path,
    resource_info: dict,
) -> dict[str, bytes]:
    """Verify preserved append-only OCR recovery JSON for audit packaging."""
    from ..core.project import safe_project_relpath

    root = project_dir.resolve()
    files: dict[str, bytes] = {}
    for item in resource_info.get("recovery_evidence") or []:
        if not isinstance(item, dict):
            raise ValueError("OCR 恢复证据清单包含无效记录")
        rel = safe_project_relpath(str(item.get("path") or ""))
        if not rel.lower().endswith(".json"):
            raise ValueError(f"OCR 恢复证据不是 JSON：{rel}")
        path = (root / Path(rel)).resolve()
        try:
            path.relative_to(root)
            data = path.read_bytes()
        except (OSError, ValueError):
            raise ValueError(f"OCR 恢复证据丢失：{rel}") from None
        if path.is_symlink() or len(data) != int(item.get("bytes") or -1):
            raise ValueError(f"OCR 恢复证据大小校验失败：{rel}")
        digest = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(str(item.get("sha256") or ""), digest):
            raise ValueError(f"OCR 恢复证据哈希校验失败：{rel}")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError(f"OCR 恢复证据 JSON 损坏：{rel}") from None
        if not isinstance(payload, dict):
            raise ValueError(f"OCR 恢复证据 JSON 顶层无效：{rel}")
        files[rel] = data
    return files


def _analysis_v2_jsonable(value: object) -> object:
    """Convert v2 evidence to portable JSON without embedding binary material."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _analysis_v2_jsonable(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        return {
            str(key): _analysis_v2_jsonable(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_analysis_v2_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    public = getattr(value, "to_dict", None)
    if callable(public):
        return _analysis_v2_jsonable(public())
    if hasattr(value, "__dict__"):
        return _analysis_v2_jsonable(vars(value))
    return str(value)


def _analysis_v2_pdf_page_count(payload: bytes, label: str) -> int:
    try:
        import pymupdf

        with pymupdf.open(stream=bytes(payload), filetype="pdf") as document:
            count = int(document.page_count)
    except Exception:
        raise ValueError(f"{label}不是可读取的 PDF，已阻止 v2 分析") from None
    if count < 1:
        raise ValueError(f"{label}没有页面，已阻止 v2 分析")
    return count


def _analysis_v2_page_numbers(page_range: object) -> tuple[int, ...]:
    if (
        not isinstance(page_range, tuple)
        or len(page_range) != 2
        or any(type(item) is not int for item in page_range)
    ):
        raise ValueError("OCR v2 分析缺少宿主冻结的连续页范围")
    start, end = page_range
    if start < 1 or end < start:
        raise ValueError("OCR v2 分析页范围无效")
    return tuple(range(start, end + 1))


def _analysis_v2_candidate_page_map(
    verification: dict,
    *,
    source_pdf_bytes: bytes,
    candidate_pdf_bytes: bytes,
    page_range: object,
) -> tuple[dict[int, tuple[int, ...]], dict[str, object]]:
    """Load, hash-check and aggregate the current host-frozen reflow mapping.

    A generated contents page remains candidate-only. Repeated source entries
    are deliberately retained, so one source page may be reviewed against two
    or more compiled pages after template reflow.
    """
    from ..core.visual_quality import (
        CANDIDATE_SCOPE_REFLOW,
        frozen_page_alignment_from_report,
    )

    selected = _analysis_v2_page_numbers(page_range)
    source_count = _analysis_v2_pdf_page_count(source_pdf_bytes, "OCR 源 PDF")
    candidate_count = _analysis_v2_pdf_page_count(
        candidate_pdf_bytes, "旧流水线当前编译 PDF"
    )
    visual = verification.get("visual_quality_loop")
    if not isinstance(visual, dict):
        raise ValueError("当前候选没有 visual_quality 宿主证据")
    rounds = visual.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        raise ValueError("当前候选没有冻结的逐页视觉轮次")
    candidate_digest = hashlib.sha256(candidate_pdf_bytes).hexdigest()
    current = None
    for round_record in reversed(rounds):
        if not isinstance(round_record, dict):
            continue
        deterministic = round_record.get("deterministic")
        compile_record = round_record.get("compile")
        if not isinstance(deterministic, dict) or not isinstance(compile_record, dict):
            continue
        if (
            deterministic.get("candidate_pdf_sha256") == candidate_digest
            and compile_record.get("ok") is True
            and compile_record.get("preview_status") == "COMPILED"
        ):
            current = deterministic
            break
    if current is None:
        raise ValueError("当前 COMPILED PDF 与冻结 visual_quality 轮次不一致")
    raw_alignment = current.get("page_alignment")
    if (
        not isinstance(raw_alignment, dict)
        or raw_alignment.get("candidate_scope") != CANDIDATE_SCOPE_REFLOW
    ):
        raise ValueError("当前候选缺少宿主冻结的 reflow alignment")
    alignment = frozen_page_alignment_from_report(
        current,
        source_page_count=source_count,
        candidate_page_count=candidate_count,
        page_range=selected,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_pdf_sha256=hashlib.sha256(source_pdf_bytes).hexdigest(),
        candidate_pdf_sha256=candidate_digest,
    )
    if (
        not alignment.mapping_reliable
        or alignment.requires_model_review
        or alignment.missing_source_pages
        or alignment.ambiguous_candidate_pages
    ):
        raise ValueError("宿主冻结的 reflow alignment 不可靠或仍有缺页/歧义")
    grouped: dict[int, list[int]] = {page: [] for page in selected}
    candidate_only = set(alignment.candidate_only_pages)
    for mapping in alignment.mappings:
        candidate_page = mapping.candidate_page
        if candidate_page is None:
            raise ValueError(f"源第 {mapping.source_page} 页没有候选页映射")
        if candidate_page in candidate_only:
            raise ValueError("candidate-only 页面错误进入了源页映射")
        pages = grouped.get(mapping.source_page)
        if pages is None:
            raise ValueError("冻结页映射包含范围外源页")
        if candidate_page not in pages:
            pages.append(candidate_page)
    if any(not grouped[page] for page in selected):
        raise ValueError("冻结页映射没有覆盖全部源页")
    candidate_map = {
        page: tuple(grouped[page])
        for page in selected
    }
    return candidate_map, {
        "mapping_sha256": alignment.mapping_sha256,
        "strategy": alignment.strategy,
        "candidate_scope": alignment.candidate_scope,
        "candidate_only_pages": list(alignment.candidate_only_pages),
        "source_page_count": source_count,
        "candidate_page_count": candidate_count,
        "map": {str(page): list(pages) for page, pages in candidate_map.items()},
    }


def _analysis_v2_pdf_alignment_texts(
    payload: bytes,
    pages: tuple[int, ...] | None,
    label: str,
) -> tuple[int, dict[int, str]]:
    """Extract bounded PDF text for page alignment without pixel rendering."""

    try:
        import pymupdf

        with pymupdf.open(stream=bytes(payload), filetype="pdf") as document:
            count = int(document.page_count)
            targets = pages or tuple(range(1, count + 1))
            if count < 1 or any(page < 1 or page > count for page in targets):
                raise ValueError
            texts = {}
            for page in targets:
                loaded = document.load_page(page - 1)
                try:
                    text = loaded.get_text("text", sort=True)
                except TypeError:  # pragma: no cover - old PyMuPDF
                    text = loaded.get_text("text")
                texts[page] = re.sub(r"\s+", " ", str(text or "")).strip()[:20000]
            return count, texts
    except Exception:
        raise ValueError(f"{label}无法提取宿主页映射文本") from None


def _analysis_v2_live_candidate_page_map(
    *,
    source_pdf_bytes: bytes,
    candidate_pdf_bytes: bytes,
    page_range: object,
    source_page_texts: dict[int, str] | None = None,
    source_page_count: int | None = None,
) -> tuple[dict[int, tuple[int, ...]], dict[str, object]]:
    """Derive a fail-closed text-only map from the current candidate PDF."""

    from ..core.visual_quality import (
        CANDIDATE_SCOPE_REFLOW,
        build_page_alignment,
    )

    selected = _analysis_v2_page_numbers(page_range)

    if source_page_texts is None or source_page_count is None:
        source_count, source_texts = _analysis_v2_pdf_alignment_texts(
            source_pdf_bytes, selected, "OCR 源 PDF"
        )
    else:
        source_count = int(source_page_count)
        source_texts = {int(page): str(text) for page, text in source_page_texts.items()}
        if set(source_texts) != set(selected) or selected[-1] > source_count:
            raise ValueError("缓存的源页映射文本与冻结页范围不一致")
    candidate_count, candidate_texts = _analysis_v2_pdf_alignment_texts(
        candidate_pdf_bytes, None, "当前候选 PDF"
    )
    alignment = build_page_alignment(
        source_count,
        candidate_count,
        selected,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        source_page_texts=source_texts,
        candidate_page_texts=candidate_texts,
    )
    if (
        not alignment.mapping_reliable
        or alignment.requires_model_review
        or alignment.missing_source_pages
        or alignment.ambiguous_candidate_pages
    ):
        raise ValueError("当前候选 reflow alignment 不可靠或仍有缺页/歧义")
    grouped: dict[int, list[int]] = {page: [] for page in selected}
    candidate_only = set(alignment.candidate_only_pages)
    for item in alignment.mappings:
        candidate_page = item.candidate_page
        if candidate_page is None:
            raise ValueError("当前候选页映射存在缺失页")
        if candidate_page in candidate_only:
            raise ValueError("candidate-only 页面错误进入了当前候选源页映射")
        pages = grouped.get(item.source_page)
        if pages is None:
            raise ValueError("当前候选页映射包含范围外源页")
        if candidate_page not in pages:
            pages.append(candidate_page)
    if any(not grouped[page] for page in selected):
        raise ValueError("当前候选页映射没有覆盖全部冻结源页")
    mapping = {page: tuple(grouped[page]) for page in selected}
    return mapping, {
        "mapping_sha256": alignment.mapping_sha256,
        "strategy": alignment.strategy,
        "candidate_scope": alignment.candidate_scope,
        "candidate_only_pages": list(alignment.candidate_only_pages),
        "source_page_count": source_count,
        "candidate_page_count": candidate_count,
        "map": {str(page): list(pages) for page, pages in mapping.items()},
    }


def _analysis_v2_client_bindings(cfg: AppConfig) -> tuple[dict, dict, dict[str, str]]:
    """Bind each v2 role to the explicitly selected backend, with no fallback."""
    from ..core.ai import LLMClient

    backend = str(cfg.analysis_backend or "").strip().lower()
    if cfg.review_enabled is not True:
        raise ValueError("v2 分析需要显式启用独立 AI 复查")
    if backend == "codex_cli":
        from ..core.codex_cli import CodexCLIClient

        def codex_client():
            return CodexCLIClient(
                model=cfg.codex_model,
                reasoning_effort=cfg.codex_reasoning_effort,
            )

        decide_client = codex_client()
        review_client = codex_client()
        vision_client = codex_client()
        model = str(decide_client.cfg.model or "configured-codex")
        model_ids = {role: model for role in (
            "AI-1", "AI-2", "AI-3", "AI-4", "AI-5", "AI-6"
        )}
    elif backend == "api":
        ai_cfg = cfg.to_ai_config()
        decide_client = LLMClient(ai_cfg.decide)
        review_client = LLMClient(ai_cfg.review)
        vision_client, vision_model, vision_backend = _build_ocr_client(cfg)
        if vision_backend != "api":
            raise ValueError("API 模式的 OCR 视觉角色未绑定到显式 API 配置")
        model_ids = {
            "AI-1": str(ai_cfg.decide.model),
            "AI-2": str(ai_cfg.review.model),
            "AI-3": str(vision_model),
            "AI-4": str(ai_cfg.review.model),
            "AI-5": str(vision_model),
            "AI-6": str(ai_cfg.review.model),
        }
    else:
        raise ValueError("v2 分析后端只能是 api 或 codex_cli")
    text_clients = {
        "AI-1": decide_client,
        "AI-2": review_client,
        "AI-4": review_client,
        "AI-6": review_client,
    }
    vision_clients = {"AI-3": vision_client, "AI-5": vision_client}
    return text_clients, vision_clients, model_ids


def _analysis_v2_compiler():
    """Return the real include-PDF compiler callback used twice by the bridge."""
    def compiler(tex: str, *, extra_files: dict[str, bytes]):
        from ..core.compilecheck import compile_latex

        raw = dict(compile_latex(
            tex,
            extra_files=dict(extra_files),
            include_pdf=True,
        ))
        pdf_bytes = raw.get("pdf_bytes")
        complete = bool(
            raw.get("available") is True
            and raw.get("ok") is True
            and raw.get("preview_status") == "COMPILED"
            and isinstance(pdf_bytes, (bytes, bytearray, memoryview))
            and bytes(pdf_bytes).startswith(b"%PDF-")
            and int(raw.get("passes_completed") or 0) >= 1
        )
        if not complete:
            raw["ok"] = False
            errors = list(raw.get("errors") or [])
            errors.append("v2 要求真实、完整且可读取的 COMPILED PDF")
            raw["errors"] = errors
        return raw

    return compiler


def _analysis_v2_command_count(text: str, command: str) -> int:
    from ..core.verify import _masked

    return len(re.findall(rf"\\{re.escape(command)}(?![A-Za-z@])", _masked(text)))


def _analysis_v2_machine_verifier(
    *,
    raw_ocr_tex: str,
    source_pdf_bytes: bytes,
    page_range: tuple[int, ...],
    candidate_page_map: dict[int, tuple[int, ...]] | None = None,
    candidate_page_maps: dict[str, dict[str, object]] | None = None,
    pack: str | None,
    capture: dict,
):
    """Create the fact-only machine verifier; it has no status authority."""
    from ..core.formal_inventory import inventory_document
    from ..core.invariants import check_invariants
    from ..core.ocrstruct import check_ocr_structure
    from ..core.verify import check_braces, check_display_tag_safety, check_env_balance
    from ..core.visual_quality import (
        CANDIDATE_SCOPE_REFLOW,
        GEOMETRY_POLICY_TEMPLATE_REFLOW,
        VisualQualityStatus,
        evaluate_visual_quality,
    )

    def verify(request):
        from ..core.analysis_orchestrator import MachineVerificationFacts
        from ..core.analysis_adapter import stable_source_page_id

        invariants = check_invariants(
            raw_ocr_tex,
            request.tex,
            check_body_text=True,
            pack=pack,
        )
        env = check_env_balance(request.tex)
        braces = check_braces(request.tex)
        display = check_display_tag_safety(request.tex)
        inventory = inventory_document(parse_latex(request.tex)).as_dict()
        ocr_structure = check_ocr_structure(request.tex)
        final_visual = evaluate_visual_quality(
            source_pdf_bytes,
            request.pdf,
            page_range,
            preview_status="COMPILED",
            source_geometry_authoritative=False,
            geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
            candidate_scope=CANDIDATE_SCOPE_REFLOW,
        ).to_dict()
        mapping_ok = False
        final_map: dict[int, tuple[int, ...]] = {}
        try:
            final_map, _mapping_evidence = _analysis_v2_candidate_page_map(
                {"visual_quality_loop": {"rounds": [{
                    "compile": {"ok": True, "preview_status": "COMPILED"},
                    "deterministic": final_visual,
                }]}},
                source_pdf_bytes=source_pdf_bytes,
                candidate_pdf_bytes=request.pdf,
                page_range=(page_range[0], page_range[-1]),
            )
            registered = (candidate_page_maps or {}).get(request.candidate_hash)
            registered_map = (
                registered.get("map") if isinstance(registered, dict) else None
            )
            expected_map = registered_map or candidate_page_map
            mapping_ok = final_map == expected_map
        except ValueError:
            mapping_ok = False
        compiled_page_ids = tuple(
            page_id for page_id, _payload in request.compile_result.page_pdf_bytes
        )
        expected_page_ids = tuple(
            stable_source_page_id(
                hashlib.sha256(source_pdf_bytes).hexdigest(),
                source_page,
            )
            for source_page in page_range
        )
        payload_mapping_ok = compiled_page_ids == expected_page_ids
        mapping_ok = bool(mapping_ok and payload_mapping_ok)
        # The orchestrator accepts only these host-produced facts and derives
        # VERIFIED itself. A failed fact can never be promoted here.
        body = invariants.get("body_text") or {}
        math = invariants.get("math") or {}
        formal_findings = [
            item for item in inventory.get("findings") or []
            if item.get("kind") in {"missing", "wrong-env", "overwide", "duplicate"}
        ]
        visual_status = str(final_visual.get("status") or "")
        visual_hard_failure = visual_status in {
            VisualQualityStatus.FAIL.value,
            VisualQualityStatus.UNAVAILABLE.value,
        }
        footnote_loss = max(
            0,
            _analysis_v2_command_count(raw_ocr_tex, "footnote")
            - _analysis_v2_command_count(request.tex, "footnote"),
        )
        caption_loss = max(
            0,
            _analysis_v2_command_count(raw_ocr_tex, "caption")
            - _analysis_v2_command_count(request.tex, "caption"),
        )
        bibliography_loss = max(
            0,
            _analysis_v2_command_count(raw_ocr_tex, "bibitem")
            - _analysis_v2_command_count(request.tex, "bibitem"),
        )
        formal_errors = (
            len(formal_findings)
            + (0 if env.get("ok") else 1)
            + (0 if braces.get("ok") else 1)
            + (0 if display.get("ok") else int(display.get("count") or 1))
            + (0 if ocr_structure.get("checked") and ocr_structure.get("ok") else 1)
            + (1 if visual_hard_failure or not mapping_ok else 0)
        )
        capture.clear()
        capture.update({
            "invariants": invariants,
            "env_balance": env,
            "braces": braces,
            "display_tags": display,
            "formal_inventory": inventory,
            "ocr_structure": ocr_structure,
            "visual_quality": final_visual,
            "candidate_page_map": {
                str(page): list(pages) for page, pages in final_map.items()
            },
            "mapping_matches_current_candidate": mapping_ok,
        })
        return MachineVerificationFacts(
            candidate_hash=request.candidate_hash,
            checked_page_ids=(compiled_page_ids if mapping_ok else ()),
            silent_page_omissions=(
                0
                if mapping_ok
                else max(1, len(set(expected_page_ids) - set(compiled_page_ids)))
            ),
            silent_text_losses=(0 if body.get("checked") and body.get("equal") else 1),
            unauthorized_math_changes=(0 if math.get("equal") else 1),
            formal_errors=formal_errors,
            toc_complete_and_ordered=bool(
                ocr_structure.get("checked") and ocr_structure.get("ok")
            ),
            severe_equation_number_errors=(
                (0 if math.get("equal") else 1) + int(display.get("count") or 0)
            ),
            silent_footnote_losses=footnote_loss,
            silent_figure_caption_losses=caption_loss,
            silent_bibliography_losses=bibliography_loss,
        )

    return verify


def _analysis_v2_set_check(
    verification: dict,
    check_id: str,
    *,
    ok: bool,
    skipped: bool = False,
    **extra,
) -> None:
    checks = verification.setdefault("checks", [])
    for item in checks:
        if isinstance(item, dict) and item.get("id") == check_id:
            item.update({"ok": ok, "skipped": skipped, **extra})
            return
    checks.append({
        "id": check_id,
        "label": "v2 六阶段生产分析、双遍实编译与独立复核",
        "ok": ok,
        "skipped": skipped,
        **extra,
    })


def _analysis_v2_fail(
    result,
    *,
    status: str,
    reason: str,
    evidence: dict | None = None,
) -> None:
    verification = deepcopy(result.verification)
    record = dict(evidence or {})
    record.update({
        "schema": "latexstruct-production-analysis-v2",
        "required": True,
        "executed": status != "SKIPPED",
        "ok": False,
        "verified": False,
        "status": status,
        "reason": sanitize_plain_text(str(reason))[:1200],
    })
    verification["analysis_v2"] = record
    for check_id in (
        "analysis-v2-production",
        "structure-decisions",
        "final-formal-inventory",
        "compile-render-visual-repair",
    ):
        _analysis_v2_set_check(verification, check_id, ok=False, skipped=False)
    verification["safe_to_export"] = False
    verification["export_blocked"] = True
    verification["rolled_back"] = True
    result.verification = verification
    result.ok = False


def _run_analysis_v2_production_stage(
    result,
    *,
    pid: str,
    project: dict,
    project_dir: Path,
    cfg: AppConfig,
    raw_ocr_tex: str,
    source_pdf_bytes: bytes,
    source_pdf_page_range: object,
    compile_extra_files: dict[str, bytes] | None,
    pack: str | None,
    run_id: str,
    progress_callback=None,
    analysis_runner=None,
):
    """Execute and atomically publish v2 analysis, or retain the legacy candidate."""
    if project.get("kind") != "ocr" or project.get("mode") != "ai":
        verification = deepcopy(result.verification)
        verification["analysis_v2"] = {
            "schema": "latexstruct-production-analysis-v2",
            "required": False,
            "executed": False,
            "ok": None,
            "verified": False,
            "status": "SKIPPED",
            "reason": "仅 OCR + AI 工作流执行 v2 六阶段生产分析",
        }
        result.verification = verification
        return result

    legacy_tex = str(
        getattr(result, "compiled_snapshot", "")
        or getattr(result, "compiled_tex", "")
        or ""
    )
    legacy_pdf = bytes(getattr(result, "compiled_pdf", b"") or b"")
    legacy_verification = result.verification
    preview = legacy_verification.get("preview_artifact")
    compile_after = legacy_verification.get("compile_after")
    try:
        if not raw_ocr_tex or not source_pdf_bytes:
            raise ValueError("不可变 raw OCR TEX 或源 PDF 缺失")
        if not legacy_tex or not legacy_pdf:
            raise ValueError("旧流水线没有留下可供 v2 接管的 COMPILED 候选")
        legacy_pdf_hash = hashlib.sha256(legacy_pdf).hexdigest()
        legacy_tex_hash = hashlib.sha256(legacy_tex.encode("utf-8")).hexdigest()
        if (
            not isinstance(preview, dict)
            or preview.get("status") != "COMPILED"
            or preview.get("sha256") != legacy_pdf_hash
            or preview.get("pdf_sha256") != legacy_pdf_hash
            or preview.get("tex_sha256") != legacy_tex_hash
            or not isinstance(compile_after, dict)
            or compile_after.get("available") is not True
            or compile_after.get("ok") is not True
            or compile_after.get("preview_status") != "COMPILED"
        ):
            raise ValueError("旧流水线当前候选没有通过真实 COMPILED 工件绑定")
        page_numbers = _analysis_v2_page_numbers(source_pdf_page_range)
        candidate_page_map, mapping_evidence = _analysis_v2_candidate_page_map(
            legacy_verification,
            source_pdf_bytes=source_pdf_bytes,
            candidate_pdf_bytes=legacy_pdf,
            page_range=source_pdf_page_range,
        )
        text_clients, vision_clients, model_ids = _analysis_v2_client_bindings(cfg)
        compiler = _analysis_v2_compiler()
        source_alignment_count, source_alignment_texts = (
            _analysis_v2_pdf_alignment_texts(
                source_pdf_bytes,
                page_numbers,
                "OCR 源 PDF",
            )
        )
        candidate_page_maps: dict[str, dict[str, object]] = {}
        candidate_page_maps_lock = threading.Lock()

        def candidate_page_mapper(
            candidate_hash: str,
            candidate_pdf: bytes,
        ) -> dict[int, tuple[int, ...]]:
            current_map, current_evidence = _analysis_v2_live_candidate_page_map(
                source_pdf_bytes=source_pdf_bytes,
                candidate_pdf_bytes=candidate_pdf,
                page_range=source_pdf_page_range,
                source_page_texts=source_alignment_texts,
                source_page_count=source_alignment_count,
            )
            entry = {
                "candidate_hash": candidate_hash,
                "pdf_sha256": hashlib.sha256(candidate_pdf).hexdigest(),
                "map": dict(current_map),
                "mapping_sha256": current_evidence.get("mapping_sha256"),
                "candidate_only_pages": list(
                    current_evidence.get("candidate_only_pages") or []
                ),
            }
            with candidate_page_maps_lock:
                prior = candidate_page_maps.get(candidate_hash)
                if prior is not None and prior.get("map") != entry["map"]:
                    raise ValueError(
                        "同一候选 hash 的宿主页映射发生变化，已阻止继续审阅"
                    )
                candidate_page_maps[candidate_hash] = entry
            return current_map

        machine_capture: dict = {}
        machine_verifier = _analysis_v2_machine_verifier(
            raw_ocr_tex=raw_ocr_tex,
            source_pdf_bytes=source_pdf_bytes,
            page_range=page_numbers,
            candidate_page_map=candidate_page_map,
            candidate_page_maps=candidate_page_maps,
            pack=pack,
            capture=machine_capture,
        )
        if progress_callback:
            progress_callback(
                "analysis-v2",
                0.895,
                "正在执行 v2 六阶段逐页分析与双重独立复核",
                {},
            )
        if analysis_runner is None:
            from ..core.analysis_production import run_production_analysis

            analysis_runner = run_production_analysis
        from .. import __version__

        production = analysis_runner(
            run_id=run_id,
            project_id=pid,
            source_pdf=source_pdf_bytes,
            raw_ocr_tex=raw_ocr_tex,
            baseline_tex=legacy_tex,
            baseline_pdf=legacy_pdf,
            page_range=page_numbers,
            candidate_page_map=candidate_page_map,
            candidate_page_mapper=candidate_page_mapper,
            text_clients=text_clients,
            vision_clients=vision_clients,
            compiler=compiler,
            machine_verifier=machine_verifier,
            candidate_root=project_dir / "analysis-v2" / run_id / "candidates",
            compile_extra_files=dict(compile_extra_files or {}),
            raw_ocr_frozen=True,
            application_version=__version__,
            model_ids=model_ids,
        )
        orchestration = production.orchestration
        evidence = {
            "mapping": mapping_evidence,
            "candidate_mappings": {
                candidate_hash: {
                    **entry,
                    "map": {
                        str(page): list(pages)
                        for page, pages in dict(entry.get("map") or {}).items()
                    },
                }
                for candidate_hash, entry in sorted(candidate_page_maps.items())
            },
            "snapshot": _analysis_v2_jsonable(production.snapshot),
            "decision": _analysis_v2_jsonable(orchestration.decision),
            "verification_evidence": _analysis_v2_jsonable(orchestration.evidence),
            "best_candidate": _analysis_v2_jsonable(orchestration.best_candidate),
            "ledger": _analysis_v2_jsonable(orchestration.ledger),
            "invocations": _analysis_v2_jsonable(orchestration.invocations),
            "compile_invocations": _analysis_v2_jsonable(
                production.compile_invocations
            ),
            "transport_invocations": _analysis_v2_jsonable(
                production.transport_invocations
            ),
            "final_reviews": _analysis_v2_jsonable(orchestration.final_reviews),
            "performance": _analysis_v2_jsonable(orchestration.performance),
            "rollback_candidate_ids": list(orchestration.rollback_candidate_ids),
            "machine_verification": _analysis_v2_jsonable(machine_capture),
        }
        if orchestration.decision.verified is not True:
            _analysis_v2_fail(
                result,
                status=str(orchestration.decision.status.value),
                reason="；".join(orchestration.decision.failures) or "v2 机器门禁未通过",
                evidence=evidence,
            )
            result.report_md += (
                "\n\n## v2 核心分析\n\n"
                "- ❌ 六阶段分析已执行，但机器门禁或双重复核未全部通过；"
                "旧候选与历史安全结果均未覆盖。\n"
            )
            return result

        final_tex = str(orchestration.current_tex)
        final_pdf = bytes(orchestration.current_pdf)
        if not final_tex or not final_pdf.startswith(b"%PDF-"):
            raise ValueError("v2 VERIFIED 结果缺少最终 TEX 或真实 PDF")
        final_page_count = _analysis_v2_pdf_page_count(final_pdf, "v2 最终 PDF")
        final_pdf_hash = hashlib.sha256(final_pdf).hexdigest()
        final_tex_hash = hashlib.sha256(final_tex.encode("utf-8")).hexdigest()
        from ..core.compilecheck import build_compile_input_manifest
        from ..core.preview import (
            COMPILED,
            preview_artifact_path,
            preview_descriptor,
        )

        compile_inputs = build_compile_input_manifest(
            final_tex, dict(compile_extra_files or {})
        )
        engine = str(
            production.compile_invocations[-1].engine
            if production.compile_invocations else "xelatex"
        )
        current_compile_log = str(
            getattr(production, "current_compile_log", "") or ""
        )
        if not current_compile_log.strip():
            raise ValueError("v2 VERIFIED 结果缺少最终双遍编译日志")
        compile_record = {
            "engine": engine,
            "available": True,
            "ok": True,
            "pages": final_page_count,
            "page_count": final_page_count,
            "errors": [],
            "fatal_error": "",
            "fatal_line": None,
            "log": current_compile_log,
            "log_path": "audit/compile_current.log",
            "preview_status": COMPILED,
            "process_status": "success",
            "pdf_sha256": final_pdf_hash,
            "return_code": 0,
            "exit_code": 0,
            "timed_out": False,
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "input_manifest": compile_inputs,
            "compile_input_sha256": compile_inputs["manifest_sha256"],
        }
        descriptor = preview_descriptor(COMPILED)
        preview_record = {
            **descriptor.as_dict(),
            "display_filename": descriptor.filename,
            "filename": preview_artifact_path(COMPILED, final_pdf_hash),
            "sha256": final_pdf_hash,
            "bytes": len(final_pdf),
            "engine": engine,
            "passes_attempted": 2,
            "exit_code": 0,
            "page_count": final_page_count,
            "pdf_sha256": final_pdf_hash,
            "compile_input_sha256": compile_inputs["manifest_sha256"],
            "fatal_line": None,
            "fatal_error": "",
            "log_path": "audit/compile_current.log",
            "tex_sha256": final_tex_hash,
            "tex_lf_normalized_sha256": hashlib.sha256(
                final_tex.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
            ).hexdigest(),
            "compile_inputs": compile_inputs,
        }
        verification = deepcopy(result.verification)
        machine = machine_capture
        verification.update({
            "analysis_v2": {
                **evidence,
                "schema": "latexstruct-production-analysis-v2",
                "required": True,
                "executed": True,
                "ok": True,
                "verified": True,
                "status": "VERIFIED",
                "result_tex_sha256": final_tex_hash,
                "result_pdf_sha256": final_pdf_hash,
            },
            "content_invariant": bool(
                (machine.get("invariants") or {}).get("body_text", {}).get("equal")
                and (machine.get("invariants") or {}).get("math", {}).get("equal")
            ),
            "env_balance": machine.get("env_balance") or {},
            "braces": machine.get("braces") or {},
            "invariants": machine.get("invariants") or {},
            "display_tags": machine.get("display_tags") or {},
            "ocr_structure": machine.get("ocr_structure") or {},
            "final_formal_inventory": machine.get("formal_inventory") or {},
            "compile_after": compile_record,
            "preview_artifact": preview_record,
            "preview_state": COMPILED,
            "compile": {"ok": True, "checked": True, "unverified": False},
            "structure_decisions": {
                "ok": True,
                "source": "analysis-v2-ledger",
                "candidate_total": len(orchestration.ledger),
                "answered": len(orchestration.ledger),
                "coverage": 1.0,
                "missing_ids": [],
                "manual_required": 0,
                "manual_candidate_ids": [],
                "formal_residual_ids": [],
            },
            "full_document_review": {
                "checked": True,
                "ok": True,
                "source": "analysis-v2-independent-final-reviews",
                "passes": 2,
                "page_count": len(page_numbers),
                "invalid": [],
                "escalations": [],
            },
            "ai_review": {
                "ok": True,
                "checked": True,
                "invalid": 0,
                "escalations": 0,
                "source": "analysis-v2",
            },
        })
        visual_loop = deepcopy(verification.get("visual_quality_loop") or {})
        visual_loop.update({
            "checked": True,
            "ok": True,
            "invalid": [],
            "unresolved": [],
            "v2_final": machine.get("visual_quality") or {},
        })
        verification["visual_quality_loop"] = visual_loop
        for check_id in (
            "analysis-v2-production",
            "structure-decisions",
            "full-document-review",
            "final-formal-inventory",
            "ai-review",
            "compile-render-visual-repair",
            "compile",
        ):
            _analysis_v2_set_check(verification, check_id, ok=True, skipped=False)
        verification["safe_to_export"] = True
        verification["export_blocked"] = False
        verification["rolled_back"] = False

        # All derived records are complete before this in-memory publication.
        # A pre-publication exception therefore leaves the legacy candidate
        # untouched; subsequent host gates may still downgrade this result.
        result.result = final_tex
        result.export_text = final_tex.replace("\n", result.newline)
        result.compiled_tex = final_tex
        result.compiled_snapshot = final_tex
        result.compiled_pdf = final_pdf
        result.compiled_pdf_name = descriptor.filename
        result.compiled_extra_files = dict(compile_extra_files or {})
        result.reviewed_tex = final_tex
        result.verification = verification
        result.ok = True
        result.report_md += (
            "\n\n## v2 核心分析\n\n"
            "- ✅ AI-1 至 AI-6、两次真实编译、逐页视觉映射、"
            "两遍独立终审和机器事实门禁均已通过。\n"
        )
        if progress_callback:
            progress_callback(
                "analysis-v2",
                0.925,
                "v2 六阶段分析已通过，正在执行宿主最终门禁",
                {},
            )
        return result
    except Exception as exc:  # noqa: BLE001 - production boundary is fail-closed
        _analysis_v2_fail(
            result,
            status="FAILED",
            reason=str(exc) or exc.__class__.__name__,
        )
        result.report_md += (
            "\n\n## v2 核心分析\n\n"
            "- ❌ v2 生产分析未能形成完整可验证结果；"
            "旧候选与历史安全结果均未覆盖。\n"
        )
        return result


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


def _safe_task_error(exc: object) -> str:
    from ..core.audit_sanitize import sanitize_plain_text

    if exc is None:
        return ""
    text = str(exc)
    if not text:
        return "" if isinstance(exc, str) else exc.__class__.__name__
    if "not JSON serializable" in text:
        return (
            "审阅结果保存格式异常；本次结果未保存，原项目和上一份已验证结果保持不变。"
            "请更新到最新版本后重新分析"
        )
    return sanitize_plain_text(text)[:500]


def _safe_ocr_evidence_value(value: object) -> object:
    """Return JSON-compatible OCR evidence with credentials and host paths removed."""
    from ..core.audit_sanitize import sanitize_json_text

    try:
        encoded = json.dumps(
            thaw_json(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return json.loads(sanitize_json_text(encoded))
    except (TypeError, ValueError):
        # Evidence that cannot cross the JSON boundary is omitted fail closed;
        # exception details could themselves contain the value being protected.
        return {}


_OCR_SOURCE_EVIDENCE_LIMITS = {
    "italic_terms": 512,
    "relation_regions": 128,
    "divider_regions": 64,
    "framed_inset_regions": 64,
    "equation_tag_regions": 64,
    "footnote_regions": 32,
}


def _bounded_page_source_evidence_list(
    value: object,
    *,
    field_name: str,
    strings: bool = False,
) -> list:
    limit = _OCR_SOURCE_EVIDENCE_LIMITS[field_name]
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > limit:
        raise OcrStoreError(f"OCR page {field_name} evidence is invalid or exceeds its bound")
    safe = _safe_ocr_evidence_value(list(value))
    if not isinstance(safe, list) or len(safe) != len(value):
        raise OcrStoreError(f"OCR page {field_name} evidence cannot be serialized")
    if strings:
        if not all(isinstance(item, str) and len(item) <= 160 for item in safe):
            raise OcrStoreError(f"OCR page {field_name} contains an invalid term")
    elif not all(isinstance(item, dict) for item in safe):
        raise OcrStoreError(f"OCR page {field_name} contains a non-object region")
    return safe


def _build_page_source_evidence(page: dict) -> dict:
    """Build the bounded, local-only source inventory used by one model call."""
    text_hint = str(page.get("text_hint") or "")
    if len(text_hint) > 50_000:
        raise OcrStoreError("OCR page text hint exceeds the 50,000-character bound")
    text_sha = hashlib.sha256(text_hint.encode("utf-8")).hexdigest() if text_hint else ""
    if (
        int(page.get("text_hint_chars") or 0) != len(text_hint)
        or str(page.get("text_hint_sha256") or "") != text_sha
    ):
        raise OcrStoreError("OCR page text hint metadata mismatch")
    extraction_status = str(
        page.get("equation_tag_extraction_status") or "unknown"
    )
    if extraction_status not in {"ok", "error", "not_applicable", "pending", "unknown"}:
        raise OcrStoreError("OCR equation-tag extraction status is invalid")
    formula = _bounded_formula_evidence(page.get("formula_evidence") or [])
    return {
        "text_hint": text_hint,
        "text_hint_chars": len(text_hint),
        "text_hint_sha256": text_sha,
        "italic_terms": _bounded_page_source_evidence_list(
            page.get("italic_terms"), field_name="italic_terms", strings=True,
        ),
        "relation_regions": _bounded_page_source_evidence_list(
            page.get("relation_regions"), field_name="relation_regions",
        ),
        "divider_regions": _bounded_page_source_evidence_list(
            page.get("divider_regions"), field_name="divider_regions",
        ),
        "framed_inset_regions": _bounded_page_source_evidence_list(
            page.get("framed_inset_regions"), field_name="framed_inset_regions",
        ),
        "equation_tag_regions": _bounded_page_source_evidence_list(
            page.get("equation_tag_regions"), field_name="equation_tag_regions",
        ),
        "equation_tag_extraction_status": extraction_status,
        "footnote_regions": _bounded_page_source_evidence_list(
            page.get("footnote_regions"), field_name="footnote_regions",
        ),
        "formula_evidence": formula,
        "prompt_version": str(page.get("prompt_version") or "")[:120],
    }


def _restore_page_source_evidence(page: dict, evidence: object) -> None:
    """Restore only a hash-checked page-evidence sidecar into mutable job state."""
    if not isinstance(evidence, dict):
        raise OcrStoreError("OCR page source evidence is not an object")
    text_hint = evidence.get("text_hint")
    if not isinstance(text_hint, str) or len(text_hint) > 50_000:
        raise OcrStoreError("OCR page source evidence has an invalid text hint")
    text_sha = hashlib.sha256(text_hint.encode("utf-8")).hexdigest() if text_hint else ""
    if (
        evidence.get("text_hint_chars") != len(text_hint)
        or evidence.get("text_hint_sha256") != text_sha
    ):
        raise OcrStoreError("OCR page source evidence text hint hash mismatch")
    restored = {
        "text_hint": text_hint,
        "text_hint_chars": len(text_hint),
        "text_hint_sha256": text_sha,
    }
    for field_name in _OCR_SOURCE_EVIDENCE_LIMITS:
        restored[field_name] = _bounded_page_source_evidence_list(
            evidence.get(field_name),
            field_name=field_name,
            strings=field_name == "italic_terms",
        )
    extraction_status = str(evidence.get("equation_tag_extraction_status") or "")
    if extraction_status not in {"ok", "error", "not_applicable", "pending", "unknown"}:
        raise OcrStoreError("OCR page source evidence has an invalid equation status")
    restored["equation_tag_extraction_status"] = extraction_status
    formula = _bounded_formula_evidence(evidence.get("formula_evidence") or [])
    if len(formula) != len(evidence.get("formula_evidence") or []):
        raise OcrStoreError("OCR page formula evidence is invalid")
    restored["formula_evidence"] = formula
    restored["formula_evidence_inputs"] = []
    restored["prompt_version"] = str(evidence.get("prompt_version") or "")[:120]
    page.update(restored)


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
            _ocr_adaptive_limiters.pop(jid, None)
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
        verified_recovery_resources: dict[str, bytes] = {}
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
            try:
                verified_recovery_resources = _verified_ocr_recovery_resource_bytes(
                    directory,
                    resource_info,
                )
            except ValueError as exc:
                verification["ocr_recovery_evidence"] = {
                    "complete": False,
                    "error": str(exc),
                    "declared_files": len(
                        resource_info.get("recovery_evidence") or []
                    ),
                }
            else:
                verification["ocr_recovery_evidence"] = {
                    "complete": True,
                    "captured_files": len(verified_recovery_resources),
                    "pages": deepcopy(
                        (meta.get("ocr_recovery") or {}).get("pages") or []
                    ),
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
        recovery_capture = verification.get("ocr_recovery_evidence")
        if (
            isinstance(recovery_capture, dict)
            and recovery_capture.get("complete") is False
        ):
            blocker_rows.extend(structured_blockers([{
                "id": "ocr-recovery-evidence-capture",
                "severity": "P1",
                "module": "evidence",
                "summary": "OCR 重试/恢复证据未能按记录哈希完整冻结",
                "action": "恢复追加式恢复日志并重新生成终态快照",
                "acceptance": "ocr_recovery_evidence.complete == true",
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
            for index, item in enumerate(
                resource_info.get("recovery_evidence") or [], 1
            ):
                rel = str(item.get("path") or "")
                payload = verified_recovery_resources.get(rel)
                if payload:
                    add_artifact(
                        ArtifactRole.EVIDENCE,
                        payload,
                        parents=(raw_artifact,),
                        index=index,
                        filename=f"ocr-recovery/{index:05d}-{Path(rel).name}",
                        media_type="application/json",
                        metadata={
                            "evidence_kind": "ocr_recovery_journal",
                            "source_kind": item.get("kind"),
                            "source_sha256": item.get("sha256"),
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
        raw_ocr_tex = text
        if is_ocr_project:
            immutable_raw_path = project_dir / "original-source.tex"
            try:
                raw_ocr_tex = immutable_raw_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                raw_ocr_tex = ""
        res = _run_analysis_v2_production_stage(
            res,
            pid=pid,
            project=p,
            project_dir=project_dir,
            cfg=cfg,
            raw_ocr_tex=raw_ocr_tex,
            source_pdf_bytes=source_pdf_bytes,
            source_pdf_page_range=source_pdf_page_range,
            compile_extra_files=compile_extra_files,
            pack=pack,
            run_id=str(
                (audit_capture or {}).get("run_id")
                or f"analysis-v2-{uuid.uuid4().hex}"
            ),
            progress_callback=capture_progress,
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
        manifest_required = _exact_ocr_manifest_required(snapshot)
        restored_contract = _recomputable_ocr_contract(snapshot)
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
            "producer_identity": {
                "app_version": str(snapshot.app_version or "unknown"),
                "build_id": str(restored_contract.get("build_id") or "unknown"),
                "commit": str(restored_contract.get("git_commit") or "unknown"),
                "prompt_version": str(
                    restored_contract.get("prompt_version") or "unknown"
                ),
            },
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
            "ocr_baseline_manifest_required": manifest_required,
            "ocr_baseline_manifest_status": (
                "PENDING" if manifest_required else "UNAVAILABLE_NON_EXACT_BUILD"
            ),
        }
        for record in records:
            is_done = record.status in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW}
            is_error = record.status in {OcrPageStatus.FAILED, OcrPageStatus.CANCELLED}
            source_evidence = None
            source_evidence_error = ""
            if record.source_evidence_sha256:
                try:
                    source_evidence = store.load_page_source_evidence(
                        snapshot.run_id, record
                    )
                except (OcrStoreError, OSError, ValueError) as exc:
                    source_evidence_error = _safe_task_error(exc)
            elif (
                snapshot.quality_tier.value == "high"
                and (record.call_index > 0 or is_done)
            ):
                source_evidence_error = (
                    "出版级 OCR 页缺少调用前源证据绑定；该旧页不得升级为通过"
                )
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
                "error": _safe_task_error(record.error_reason),
                "png": os.path.join(tmpdir, f"page-{record.source_page}.img"),
                "persisted_visual_path": (
                    persisted_visual_path if persisted_visual else ""
                ),
                "low_conf": (
                    record.status == OcrPageStatus.NEEDS_REVIEW
                    or is_error
                    or bool(source_evidence_error)
                ),
                "needs_review": (
                    record.status == OcrPageStatus.NEEDS_REVIEW
                    or bool(source_evidence_error)
                ),
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
                "quality_flags": _safe_ocr_evidence_value(
                    list(thaw_json(record.host_quality_flags))
                ),
                "source_evidence_error": source_evidence_error,
            }
            if source_evidence is not None:
                try:
                    _restore_page_source_evidence(
                        job["pages"][record.source_page], source_evidence
                    )
                except (OcrStoreError, TypeError, ValueError) as exc:
                    source_evidence_error = _safe_task_error(exc)
                    page_state = job["pages"][record.source_page]
                    page_state["source_evidence_error"] = source_evidence_error
                    page_state["low_conf"] = True
                    page_state["needs_review"] = True
            if source_evidence_error:
                job["pages"][record.source_page]["quality_flags"].append({
                    "type": "source_evidence_integrity",
                    "status": "invalid",
                    "needs_review": True,
                })
            if is_error or not is_done:
                job["errors"].append({
                    "page": record.source_page,
                    "task_index": record.task_index,
                    "reason": _safe_task_error(
                        record.error_reason or record.status.value
                    ),
                })
        _restore_ocr_recovery_telemetry(job, store, snapshot, records)
        figure_manifest_path = store.run_dir(jid) / "artifacts" / "figures-manifest.json"
        try:
            recovered_figures: dict[int, list[dict]] = {}
            figure_manifest = json.loads(figure_manifest_path.read_text(encoding="utf-8"))
            figure_body = {
                key: figure_manifest.get(key)
                for key in ("schema_version", "run_id", "figures")
            }
            figure_body_sha = hashlib.sha256(json.dumps(
                figure_body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            if (
                figure_manifest.get("schema_version") != "latexstruct-ocr-figures-v1"
                or figure_manifest.get("run_id") != jid
                or not hmac.compare_digest(
                    str(figure_manifest.get("manifest_sha256") or ""),
                    figure_body_sha,
                )
            ):
                raise ValueError("figure manifest identity mismatch")
            for row in figure_manifest.get("figures") or []:
                if not isinstance(row, dict):
                    raise ValueError("figure manifest row must be an object")
                source_page = int(row.get("source_page") or 0)
                page = job["pages"].get(source_page)
                path = str(row.get("path") or "")
                canonical = OCR_CANONICAL_IMAGE_PATH_RE.fullmatch(path)
                if (
                    page is None
                    or canonical is None
                    or canonical.group("v2_page") is None
                    or int(canonical.group("v2_page")) != source_page
                    or row.get("source_image_sha256") != page.get("visual_input_sha256")
                ):
                    raise ValueError("figure manifest row is not bound to its page")
                recovered_figures.setdefault(source_page, []).append({
                    "path": path,
                    "index": int(canonical.group("v2_index")),
                    "bbox_normalized": list(row.get("bbox_normalized") or []),
                    "bbox_pixels": list(row.get("bbox_pixels") or []),
                    "image_size_pixels": list(page.get("image_size_pixels") or []),
                    "source": "host_materialized_crop",
                    "crop_sha256": str(row.get("sha256") or ""),
                })
            for source_page, figures in recovered_figures.items():
                job["pages"][source_page]["figures"] = figures
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            # Figure evidence is optional for text-only pages.  Any malformed
            # manifest remains absent rather than being promoted into job state.
            pass
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
        manifest_gate_passed = not manifest_required
        if manifest_required:
            try:
                verified_baseline = load_verified_ocr_baseline_bundle(store, jid)
                verified_payload = verified_baseline.manifest.to_dict()
                verified_status = verified_payload.get("status") or {}
                manifest_gate_passed = verified_status == {
                    "run_status": "SUCCESS",
                    "ocr_status": "COMPLETED",
                    "compile_status": OcrPreviewStatus.COMPILED.value,
                }
                job["ocr_baseline_manifest_status"] = "VERIFIED"
                job["ocr_baseline_manifest_sha256"] = (
                    verified_baseline.manifest.sha256
                )
                job["ocr_baseline_run_status"] = str(
                    verified_status.get("run_status") or ""
                )
                job["ocr_baseline_ocr_status"] = str(
                    verified_status.get("ocr_status") or ""
                )
                job["performance_metrics"] = json.loads(
                    verified_baseline.require_role("PERFORMANCE_METRICS").data
                )
                job["cost_report"] = json.loads(
                    verified_baseline.require_role("COST_METRICS").data
                )
            except (OcrStoreError, OSError, TypeError, ValueError) as exc:
                job["ocr_baseline_manifest_status"] = "FAILED"
                job["ocr_baseline_manifest_error"] = _safe_task_error(exc)
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
        all_success = bool(records) and all(
            record.status == OcrPageStatus.SUCCESS for record in records
        )
        baseline_compiled = (
            str(baseline_manifest.get("preview_status") or "")
            == OcrPreviewStatus.COMPILED.value
            and baseline_manifest.get("exit_code") == 0
            and int(baseline_manifest.get("successful_passes") or 0) >= 2
        )
        restored_gate_snapshot = _snapshot_ocr_bundle_job(
            job, v2_records=records
        )
        restored_gate_snapshot["status"] = "done"
        restored_quality = assess_ocr_quality(restored_gate_snapshot)
        page_gate_passed = restored_quality.get("page_gate_passed") is True
        if (
            all_success
            and job["raw_frozen"]
            and baseline_compiled
            and page_gate_passed
            and manifest_gate_passed
        ):
            job["status"] = "done"
            job["phase"] = "OCR 已从不可变快照完整恢复"
        elif all_success and job["raw_frozen"] and baseline_compiled:
            job["status"] = "partial"
            if not page_gate_passed:
                blocker = (restored_quality.get("blockers") or [{}])[0]
                job["phase"] = str(
                    blocker.get("message") or "OCR 已恢复，但页面质量门尚未通过"
                )[:240]
            else:
                job["phase"] = "OCR 已恢复，但可重算基线证据包未通过"
                job["error"] = str(
                    job.get("ocr_baseline_manifest_error")
                    or "OCR baseline package is not verified"
                )[:500]
        elif any(record.status == OcrPageStatus.NEEDS_REVIEW for record in records):
            job["status"] = "partial"
            job["phase"] = "OCR 已恢复；仍有页面需要确认或重试"
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
        resume_snapshot = job.get("_v2_snapshot")
        if resume_snapshot is not None:
            launch_cfg.analysis_backend = resume_snapshot.api_backend
            if resume_snapshot.api_backend == "codex_cli":
                launch_cfg.codex_model = resume_snapshot.ocr_model
        quality_tier = normalize_quality_tier(
            job.get("quality_tier") or quality_profile
        )
        tier_policy = quality_tier_policy(quality_tier)
        from ..core.ocr_recovery import RecoveryStage

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

        def _render_one(job, page_no: int, *, render_dpi: int) -> str:
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
                    visual_path, [page_no], int(render_dpi),
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

        def _refresh_raw_preview(job, changed_page: int | None = None, *, force=False):
            from ..ocr import merge_raw_ocr_book

            def page_chunk(page_no: int, page: dict) -> str:
                page_id = str(page.get("page_id") or "")
                marker = f"% Page {page_no}"
                if page_id:
                    marker += (
                        "\n% LaTeXStruct-Page: "
                        f"page_id={page_id} source_page={page_no}"
                    )
                return f"{marker}\n{page.get('tex') or ''}"

            with _ocr_jobs_lock:
                preview_chunks = job.get("_raw_preview_chunks")
                if not isinstance(preview_chunks, dict):
                    preview_chunks = {
                        int(page_no): page_chunk(int(page_no), page)
                        for page_no, page in (job.get("pages") or {}).items()
                        if page.get("status") == "done"
                    }
                    job["_raw_preview_chunks"] = preview_chunks
                if changed_page is not None:
                    changed = job["pages"].get(changed_page) or {}
                    if changed.get("status") == "done":
                        preview_chunks[int(changed_page)] = page_chunk(
                            int(changed_page), changed
                        )
                completed_count = len(preview_chunks)
                last_count = int(job.get("_raw_preview_materialized_count") or 0)
                selected_count = len(job.get("selected_pages") or [])
                replacing_materialized_page = bool(
                    changed_page is not None
                    and int(changed_page) in preview_chunks
                    and completed_count == last_count
                )
                should_materialize = bool(
                    force
                    or completed_count <= 3
                    or completed_count == selected_count
                    or completed_count - last_count >= 25
                    or replacing_materialized_page
                )
                job["raw_ready"] = completed_count > 0
                if not should_materialize:
                    _bump_ocr_state(job)
                    return
                completed = [
                    (page_no, job["pages"][page_no])
                    for page_no in job["selected_pages"]
                    if job["pages"][page_no]["status"] == "done"
                ]
                chunks = [
                    page_chunk(page_no, page)
                    for page_no, page in completed
                ]
                merged = merge_raw_ocr_book(chunks)
                previous = str(job.get("raw_tex") or "")
                job["raw_tex"] = merged
                job["raw_ready"] = bool(chunks)
                job["raw_chars"] = len(merged)
                job["_raw_preview_materialized_count"] = completed_count
                if merged != previous:
                    job["raw_revision"] = int(job.get("raw_revision") or 0) + 1
                _bump_ocr_state(job)

        def _merge_job(job, complete_progress: bool = True):
            with _ocr_jobs_lock:
                errors = []
                review_pages = []
                for page_no in job["selected_pages"]:
                    page = job["pages"][page_no]
                    if page["status"] != "done":
                        errors.append({
                            "page": page_no,
                            "task_index": page["task_index"],
                            "reason": page["error"] or page["status"],
                        })
                    elif page.get("needs_review") or page.get("low_conf"):
                        review_pages.append(page_no)
                job["errors"] = errors
                if job.get("pause_requested"):
                    job["status"] = "pausing"
                    job["phase"] = "正在完成当前步骤，随后安全暂停"
                else:
                    compile_status = str(job.get("compile_status") or "")
                    gate_snapshot = _snapshot_ocr_bundle_job(job)
                    gate_snapshot["status"] = "done"
                    quality_report = assess_ocr_quality(gate_snapshot)
                    page_gate_passed = (
                        quality_report.get("page_gate_passed") is True
                    )
                    manifest_gate_passed = bool(
                        not job.get("ocr_baseline_manifest_required")
                        or (
                            job.get("ocr_baseline_manifest_status") == "VERIFIED"
                            and job.get("ocr_baseline_run_status") == "SUCCESS"
                            and job.get("ocr_baseline_ocr_status") == "COMPLETED"
                        )
                    )
                    fully_ready = bool(
                        not errors
                        and not review_pages
                        and job.get("raw_frozen")
                        and compile_status == OcrPreviewStatus.COMPILED.value
                        and page_gate_passed
                        and manifest_gate_passed
                    )
                    job["status"] = "done" if fully_ready else "partial"
                    if errors:
                        job["phase"] = "部分页面失败，等待重试"
                    elif review_pages:
                        job["phase"] = "OCR 页面已处理；待确认页可单独重试"
                    elif compile_status and compile_status != OcrPreviewStatus.COMPILED.value:
                        job["phase"] = "OCR 原稿已冻结；基线编译需检查"
                    elif not page_gate_passed:
                        blocker = (quality_report.get("blockers") or [{}])[0]
                        job["phase"] = str(
                            blocker.get("message") or "OCR 页面质量门尚未通过"
                        )[:240]
                    elif not manifest_gate_passed:
                        job["phase"] = "OCR 基线证据包未通过可重算门禁"
                    elif fully_ready:
                        job["phase"] = "OCR 基线已真实编译"
                    else:
                        job["phase"] = "正在生成 OCR 基线产物"
                job["error"] = (
                    str(errors[0]["reason"])
                    if errors
                    else "仍有页面需要确认" if review_pages else ""
                )
                if (
                    not job.get("pause_requested")
                    and not errors
                    and not review_pages
                    and (not page_gate_passed or not manifest_gate_passed)
                ):
                    if not page_gate_passed:
                        blocker = (quality_report.get("blockers") or [{}])[0]
                        job["error"] = str(
                            blocker.get("message") or "OCR 页面质量门尚未通过"
                        )[:500]
                    else:
                        job["error"] = str(
                            job.get("ocr_baseline_manifest_error")
                            or "OCR 基线证据包未通过可重算门禁"
                        )[:500]
                if not job.get("pause_requested"):
                    job["pause_requested"] = False
                if complete_progress:
                    # A terminal attempt is not necessarily a completed OCR
                    # result.  Keep review/failure/source-preview runs below
                    # 100% so the public status cannot contradict the gate.
                    job["progress"] = (
                        1.0
                        if fully_ready
                        else min(float(job.get("progress") or 0.95), 0.99)
                    )
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

        # A provider attempt is different from entering a host wrapper: an
        # incompatible adapter may fail before any paid/model request exists.
        # Keep this marker thread-local because full OCR batches may run in
        # parallel and metrics must never invent a request from another worker.
        provider_call_state = threading.local()

        def _record_v2_stage(
            stage: str,
            *,
            duration_ms: float,
            items: int = 1,
            succeeded: bool = True,
        ) -> None:
            collector = job.get("_v2_metrics_collector")
            if collector is None:
                return
            try:
                collector.record_stage_execution(
                    stage,
                    duration_ms=duration_ms,
                    items=items,
                    succeeded=succeeded,
                )
            except (TypeError, ValueError) as exc:
                with _ocr_jobs_lock:
                    job["metrics_error"] = _safe_task_error(exc)
                    _bump_ocr_state(job)

        def _record_v2_final_page_metric(snapshot, record) -> None:
            """Bind one final successful page without guessing attempt data."""
            from ..core.ocr_metrics import (
                OcrStrategy,
                PageFinalStatus,
            )

            if record.status is not OcrPageStatus.SUCCESS:
                return
            collector = job.get("_v2_metrics_collector")
            if collector is None:
                return
            page_state = job["pages"].get(record.source_page) or {}
            candidate_strategy = str(page_state.get("candidate_strategy") or "")
            visual_mode = str(page_state.get("visual_mode") or "")
            dpi_history = tuple(
                int(value)
                for value in page_state.get("dpi_history") or ()
                if isinstance(value, int) and not isinstance(value, bool) and value > 0
            )
            if visual_mode == "VERIFIER" or candidate_strategy.startswith("OBJECT_LAYER"):
                strategy = OcrStrategy.OBJECT_LAYER_VERIFIED
            elif visual_mode == "FULL_OCR_WITH_CROPS":
                strategy = OcrStrategy.CROP_REVIEW
            elif record.retry_count > 0 or record.dpi > snapshot.initial_dpi:
                strategy = OcrStrategy.HIGH_RESOLUTION_RETRY
            else:
                strategy = OcrStrategy.FULL_VISUAL_OCR
            completed_at = time.time()
            try:
                completed_at = datetime.fromisoformat(
                    str(record.ended_at).replace("Z", "+00:00")
                ).timestamp()
            except (TypeError, ValueError):
                pass
            try:
                collector.record_page_result(
                    record.page_id,
                    status=PageFinalStatus.SUCCESS,
                    strategy=strategy,
                    completed_at_seconds=completed_at,
                    dpi_history=dpi_history or ((record.dpi,) if record.dpi else ()),
                )
            except ValueError as exc:
                # Finalization is deliberately idempotent.  A page already
                # present in this append-only collector is the same immutable
                # page result; every other metrics error remains visible.
                if "already exists" not in str(exc):
                    with _ocr_jobs_lock:
                        job["metrics_error"] = _safe_task_error(exc)
                        _bump_ocr_state(job)

        def _record_v2_usage(
            client,
            usage: dict,
            *,
            allow_client_fallback: bool = True,
        ) -> None:
            if not isinstance(usage, dict) or not usage:
                usage = (
                    client.last_usage
                    if allow_client_fallback
                    and isinstance(getattr(client, "last_usage", None), dict)
                    else {}
                )
            if not usage:
                return
            from ..pricing import add_usage, summarize_ai_usage

            with _ocr_jobs_lock:
                add_usage(job["usage"], usage, getattr(client.cfg, "model", ""))
                job["cost"] = summarize_ai_usage({"ocr": job["usage"]})
                job["usage_revision"] = int(job.get("usage_revision") or 0) + 1
                _bump_ocr_state(job)

        def _record_v2_page_usage(requests, usage: dict) -> None:
            """Persist bounded per-page usage for both success and gate retry."""
            if not isinstance(usage, dict) or not usage:
                return
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

        def _v2_model_call_impl(client, requests):
            expected = [request.page_id for request in requests]
            prompt = ocr_batch_request_payload(requests)
            schema = ocr_batch_output_schema(expected)
            _ocr_control(job)
            client.last_usage = {}
            active_backend = str(job.get("backend") or "api")
            publication_grade = bool(
                str(job.get("quality_profile") or "") == OCR_QUALITY_PUBLICATION
                or str(job.get("quality_tier") or "") == "high"
            )
            host_validated_single = getattr(
                client, "chat_vision_structured_bytes", None
            )
            use_host_validated_codex = bool(
                len(requests) == 1
                and active_backend == "codex_cli"
                and callable(host_validated_single)
            )
            if active_backend == "codex_cli" and not use_host_validated_codex:
                raise RuntimeError(
                    "结构化输出协议不兼容：Codex OCR 缺少宿主逐页验证适配器"
                )
            if publication_grade and not use_host_validated_codex:
                raise RuntimeError(
                    "结构化输出协议不兼容：出版级 OCR 当前只允许经过宿主逐页门禁的 Codex 路径"
                )
            if len(requests) == 1:
                generic_single = getattr(client, "chat_vision_json_bytes", None)
                generic_multi = getattr(client, "chat_vision_json_images_bytes", None)
                configured_key = str(getattr(getattr(client, "cfg", None), "api_key", "") or "")
                # Codex CLI OCR is intentionally single-page in the v2
                # executor.  Its established structured adapter is also the
                # path that performs every host-owned publisher gate (relation
                # glyphs, dividers, equation tags, footnotes, framed insets and
                # italic prose) before a page can become SUCCESS.  Prefer it
                # over the generic JSON transport; the outer v2 wrapper still
                # owns page_id, immutable persistence and the recovery ladder.
                if (
                    not use_host_validated_codex
                    and requests[0].crops
                    and callable(generic_multi)
                    and (
                        active_backend == "codex_cli" or configured_key
                    )
                ):
                    provider_call_state.called = True
                    response, usage = _call_ocr_visual_json(
                        generic_multi,
                        OCR_TRANSCRIPTION_SYSTEM_PROMPT,
                        prompt,
                        [requests[0].image_bytes, *requests[0].crops],
                        schema,
                    )
                elif not use_host_validated_codex and callable(generic_single) and (
                    active_backend == "codex_cli" or configured_key
                ):
                    provider_call_state.called = True
                    response, usage = _call_ocr_visual_json(
                        generic_single,
                        OCR_TRANSCRIPTION_SYSTEM_PROMPT,
                        prompt,
                        requests[0].image_bytes,
                        schema,
                    )
                else:
                    # Host-validated Codex path, plus standard-profile
                    # compatibility for old provider adapters. Publication has
                    # already failed closed above unless this is validated Codex.
                    from ..ocr import transcribe_page_result

                    legacy_page = job["pages"][requests[0].source_page]
                    try:
                        provider_call_state.called = True
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
                    except Exception as exc:
                        # A deterministic host gate may reject a paid response
                        # and schedule a targeted retry.  Preserve the primary
                        # call plus any local verifier usage before re-raising;
                        # otherwise failed attempts disappear from cost/audit
                        # telemetry even though their recovery evidence remains.
                        failed_usage = (
                            client.last_usage
                            if isinstance(client.last_usage, dict)
                            else {}
                        )
                        provider_call_state.usage = deepcopy(failed_usage)
                        _record_v2_usage(client, failed_usage)
                        _record_v2_page_usage(requests, failed_usage)
                        if use_host_validated_codex and (
                            getattr(exc, "model_raw_response", None) is not None
                            or getattr(exc, "model_raw_latex", "")
                        ):
                            trusted = {
                                "schema_version": "latexstruct-ocr-host-result-v1",
                                "page_id": requests[0].page_id,
                                "source_page": requests[0].source_page,
                                "call_index": int(legacy_page.get("attempts") or 0),
                                "gate_applied": True,
                                "model_raw_latex": str(
                                    getattr(exc, "model_raw_latex", "") or ""
                                ),
                                "model_raw_response": deepcopy(
                                    getattr(exc, "model_raw_response", None)
                                ),
                                "host_quality_flags": [],
                                "formula_evidence": [],
                            }
                            trusted_key = (
                                f"{requests[0].page_id}:{trusted['call_index']}"
                            )
                            with _ocr_jobs_lock:
                                job.setdefault(
                                    "_v2_trusted_host_results", {}
                                )[trusted_key] = trusted
                                _bump_ocr_state(job)
                        raise
                    legacy_tex = re.sub(
                        r"(?mi)^\s*%\s*Page\s+\d+\s*$",
                        "",
                        transcription.tex,
                    ).strip()
                    # The visual adapter validates its historical
                    # ``images/page_N_I`` namespace before returning.  The v2
                    # runtime deliberately accepts only host-owned figure paths.
                    # Translate that already-validated metadata at this narrow
                    # boundary; the model never chooses the persisted path.
                    legacy_tex, host_figures = _bind_v2_ocr_figure_paths(
                        legacy_tex,
                        list(transcription.figures or []),
                        requests[0].source_page,
                    )
                    unresolved = [
                        {"type": "legacy_quality_flag", **deepcopy(flag)}
                        for flag in (transcription.quality_flags or [])
                        if isinstance(flag, dict) and flag.get("needs_review")
                    ]
                    response = {"pages": [{
                        "page_id": requests[0].page_id,
                        "latex": legacy_tex,
                        "figures": host_figures,
                        "unresolved_regions": unresolved,
                    }]}
                    trusted = {
                        "schema_version": "latexstruct-ocr-host-result-v1",
                        "page_id": requests[0].page_id,
                        "source_page": requests[0].source_page,
                        "call_index": int(legacy_page.get("attempts") or 0),
                        "gate_applied": bool(use_host_validated_codex),
                        "model_raw_latex": transcription.model_raw_latex,
                        "model_raw_response": deepcopy(
                            transcription.model_raw_response
                        ),
                        "host_quality_flags": deepcopy(
                            transcription.quality_flags or []
                        ),
                        "formula_evidence": deepcopy(
                            transcription.formula_evidence or []
                        ),
                    }
                    trusted_key = (
                        f"{requests[0].page_id}:{trusted['call_index']}"
                    )
                    with _ocr_jobs_lock:
                        results = job.setdefault("_v2_trusted_host_results", {})
                        prior = results.get(trusted_key)
                        if prior is not None and prior != trusted:
                            raise OcrStoreError("宿主 OCR 结果 side-channel 发生冲突")
                        results[trusted_key] = trusted
                        _bump_ocr_state(job)
                    usage = client.last_usage if isinstance(client.last_usage, dict) else {}
            else:
                generic_batch = getattr(client, "chat_vision_json_images_bytes", None)
                configured_key = str(getattr(getattr(client, "cfg", None), "api_key", "") or "")
                if not callable(generic_batch) or (
                    active_backend == "api" and not configured_key
                ):
                    raise RuntimeError("batch unsupported by this provider adapter")
                provider_call_state.called = True
                response, usage = _call_ocr_visual_json(
                    generic_batch,
                    OCR_TRANSCRIPTION_SYSTEM_PROMPT,
                    prompt,
                    [request.image_bytes for request in requests],
                    schema,
                )
            provider_call_state.usage = deepcopy(
                usage if isinstance(usage, dict) else {}
            )
            _record_v2_usage(client, usage)
            # Keep bounded, per-page telemetry next to the immutable page
            # record.  A multi-image provider reports one shared usage object;
            # record that relationship instead of dividing tokens by guesswork.
            _record_v2_page_usage(requests, usage)
            return response

        def _v2_model_call(client, requests):
            """Measure exactly one full-OCR provider invocation."""
            from ..core.ocr_metrics import RequestKind

            started = time.perf_counter()
            error = None
            provider_call_state.called = False
            provider_call_state.usage = {}
            try:
                return _v2_model_call_impl(client, requests)
            except Exception as exc:  # noqa: BLE001 - measurement then preserve failure
                error = exc
                raise
            finally:
                collector = job.get("_v2_metrics_collector")
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                if collector is not None and bool(
                    getattr(provider_call_state, "called", False)
                ):
                    usage = deepcopy(
                        getattr(provider_call_state, "usage", {}) or {}
                    )
                    input_tokens = usage.get("input_tokens")
                    if not isinstance(input_tokens, int):
                        input_tokens = usage.get("prompt_tokens")
                    output_tokens = usage.get("output_tokens")
                    if not isinstance(output_tokens, int):
                        output_tokens = usage.get("completion_tokens")
                    retry = any(
                        bool(request.correction_instruction)
                        or request.dpi > int(job.get("full_ocr_dpi") or request.dpi)
                        for request in requests
                    )
                    kind = (
                        RequestKind.CROP_RECOGNITION
                        if any(request.crops for request in requests)
                        else RequestKind.HIGH_RESOLUTION_RETRY
                        if retry
                        else RequestKind.FULL_OCR
                    )
                    try:
                        collector.record_request(
                            f"full-ocr-{uuid.uuid4().hex}",
                            kind=kind,
                            latency_ms=elapsed_ms,
                            page_count=len(requests),
                            input_tokens=(
                                input_tokens if isinstance(input_tokens, int) else None
                            ),
                            output_tokens=(
                                output_tokens if isinstance(output_tokens, int) else None
                            ),
                            dpi=max(request.dpi for request in requests),
                            retry=retry,
                            truncated=(
                                False if error is None else
                                True if "truncat" in str(error).casefold() else None
                            ),
                            strong_model=True,
                        )
                    except (TypeError, ValueError) as exc:
                        with _ocr_jobs_lock:
                            job["metrics_error"] = _safe_task_error(exc)
                            _bump_ocr_state(job)
                    _record_v2_stage(
                        "full_ocr",
                        duration_ms=elapsed_ms,
                        items=len(requests),
                        succeeded=error is None,
                    )

        def _record_v2_verifier_usage(classifications, usage: dict) -> None:
            """Bind shared verifier usage without inventing per-page token splits."""
            if not isinstance(usage, dict) or not usage:
                return
            with _ocr_jobs_lock:
                telemetry = job.setdefault("_v2_page_usage", {})
                for classification in classifications:
                    telemetry.setdefault(classification.page_id, []).append({
                        "call_index": int(
                            job["pages"][classification.source_page_number].get(
                                "attempts"
                            ) or 0
                        ),
                        "request_kind": "visual_verification",
                        "batch_shared": len(classifications) > 1,
                        "batch_page_count": len(classifications),
                        "usage": deepcopy(usage),
                    })
                _bump_ocr_state(job)

        def _v2_visual_verify_call_impl(
            client, snapshot, classifications, image_bytes_list
        ):
            """Perform one bounded, strict page-candidate verification batch."""
            from ..core.ocr_visual import (
                VISUAL_VERIFIER_SYSTEM_PROMPT,
                validate_visual_verification_response,
                visual_verification_output_schema,
                visual_verification_request_payload,
            )

            if not 1 <= len(classifications) <= 4:
                raise ValueError("OCR visual verification batch must contain 1..4 pages")
            if len(classifications) != len(image_bytes_list):
                raise ValueError("OCR visual verification image/page count mismatch")
            batch_seed = ":".join(
                [snapshot.run_id, *(item.page_id for item in classifications)]
            )
            batch_id = "ocr-verify-batch-" + hashlib.sha256(
                batch_seed.encode("utf-8")
            ).hexdigest()[:24]
            request_payload = visual_verification_request_payload(
                batch_id,
                tuple(item.candidate for item in classifications),
                required_checks_by_page_id={
                    item.page_id: (
                        "reading_order",
                        "full_text_coverage",
                        "mathematics_and_equation_numbers",
                        "footnotes_captions_tables_figures_references",
                    )
                    for item in classifications
                },
            )
            prompt = json.dumps(
                request_payload,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            schema = visual_verification_output_schema()
            _ocr_control(job)
            configured_key = str(
                getattr(getattr(client, "cfg", None), "api_key", "") or ""
            )
            if len(classifications) == 1:
                method = getattr(client, "chat_vision_json_bytes", None)
                call_args = (
                    VISUAL_VERIFIER_SYSTEM_PROMPT,
                    prompt,
                    image_bytes_list[0],
                    schema,
                )
            else:
                method = getattr(client, "chat_vision_json_images_bytes", None)
                call_args = (
                    VISUAL_VERIFIER_SYSTEM_PROMPT,
                    prompt,
                    list(image_bytes_list),
                    schema,
                )
            if not callable(method) or (
                str(job.get("backend") or "api") == "api" and not configured_key
            ):
                raise RuntimeError(
                    "当前 OCR 后端不支持严格的对象层视觉验证协议"
                )
            provider_call_state.called = True
            response, usage = _call_ocr_visual_json(
                method,
                *call_args,
                operation="OCR visual verification",
            )
            provider_call_state.usage = deepcopy(
                usage if isinstance(usage, dict) else {}
            )
            # The adapter returns usage together with this exact response.  A
            # shared ``client.last_usage`` field is not an authority here:
            # concurrent verifier calls could otherwise steal one another's
            # telemetry and silently double-count a request.
            _record_v2_usage(client, usage, allow_client_fallback=False)
            _record_v2_verifier_usage(classifications, usage)
            batch = validate_visual_verification_response(
                response,
                batch_id=batch_id,
                candidates=tuple(item.candidate for item in classifications),
            )
            return batch, response

        def _v2_visual_verify_call(
            client, snapshot, classifications, image_bytes_list
        ):
            """Measure exactly one verifier request, including failed validation."""
            from ..core.ocr_metrics import RequestKind

            started = time.perf_counter()
            error = None
            provider_call_state.called = False
            provider_call_state.usage = {}
            try:
                return _v2_visual_verify_call_impl(
                    client, snapshot, classifications, image_bytes_list
                )
            except Exception as exc:  # noqa: BLE001 - measurement then preserve failure
                error = exc
                raise
            finally:
                collector = job.get("_v2_metrics_collector")
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                if collector is not None and bool(
                    getattr(provider_call_state, "called", False)
                ):
                    usage = deepcopy(
                        getattr(provider_call_state, "usage", {}) or {}
                    )
                    input_tokens = usage.get("input_tokens")
                    if not isinstance(input_tokens, int):
                        input_tokens = usage.get("prompt_tokens")
                    output_tokens = usage.get("output_tokens")
                    if not isinstance(output_tokens, int):
                        output_tokens = usage.get("completion_tokens")
                    try:
                        collector.record_request(
                            f"visual-verifier-{uuid.uuid4().hex}",
                            kind=RequestKind.VISUAL_VERIFICATION,
                            latency_ms=elapsed_ms,
                            page_count=len(classifications),
                            input_tokens=(
                                input_tokens if isinstance(input_tokens, int) else None
                            ),
                            output_tokens=(
                                output_tokens if isinstance(output_tokens, int) else None
                            ),
                            dpi=int(job.get("verification_dpi") or 160),
                            retry=False,
                            truncated=(
                                False if error is None else
                                True if "truncat" in str(error).casefold() else None
                            ),
                            strong_model=False,
                        )
                    except (TypeError, ValueError) as exc:
                        with _ocr_jobs_lock:
                            job["metrics_error"] = _safe_task_error(exc)
                            _bump_ocr_state(job)
                    _record_v2_stage(
                        "visual_verification",
                        duration_ms=elapsed_ms,
                        items=len(classifications),
                        succeeded=error is None,
                    )

        def _prepare_v2_verification_image(store, snapshot, record, classification):
            """Render and persist the exact 160-DPI verifier authority image."""
            verification_dpi = int(
                (thaw_json(snapshot.pipeline_contract) or {}).get(
                    "verification_dpi", 160
                )
            )
            page_no = record.source_page
            page = job["pages"][page_no]
            with _ocr_jobs_lock:
                job["dpi"] = verification_dpi
                job["page"] = page_no
                job["current_index"] = record.task_index
                job["current_strategy"] = "对象层验证"
                job["phase"] = f"正在验证第 {page_no} 页对象层候选"
                page["prompt_version"] = _ocr_prompt_version()
                _bump_ocr_state(job)
            if record.status in {OcrPageStatus.FAILED, OcrPageStatus.NEEDS_REVIEW}:
                record = record.transition(
                    OcrPageStatus.RETRYING,
                    retry_count=record.retry_count + 1,
                    error_reason="重新执行对象层视觉验证",
                )
            record = record.transition(OcrPageStatus.RENDERING, dpi=verification_dpi)
            store.persist_record(snapshot.run_id, record)
            render_started = time.perf_counter()
            try:
                _render_one(job, page_no, render_dpi=verification_dpi)
            except Exception:
                _record_v2_stage(
                    "rendering",
                    duration_ms=(time.perf_counter() - render_started) * 1000.0,
                    succeeded=False,
                )
                raise
            _record_v2_stage(
                "rendering",
                duration_ms=(time.perf_counter() - render_started) * 1000.0,
            )
            image_bytes = Path(page["png"]).read_bytes()
            image_sha256 = hashlib.sha256(image_bytes).hexdigest()
            source_evidence = _build_page_source_evidence(page)
            source_evidence["candidate"] = classification.candidate.to_dict()
            record = record.transition(
                OcrPageStatus.VERIFYING,
                image_sha256=image_sha256,
                image_size_pixels=tuple(page.get("image_size_pixels") or ()),
                source_evidence_sha256=store.persist_page_source_evidence(
                    snapshot.run_id,
                    record,
                    source_evidence,
                ),
                dpi=verification_dpi,
                model=str(
                    (thaw_json(snapshot.pipeline_contract) or {}).get(
                        "verification_model"
                    ) or snapshot.ocr_model
                ),
                call_index=record.call_index + 1,
                started_at=record.started_at or _iso_now(),
                error_reason="",
            )
            store.persist_record(snapshot.run_id, record)
            persisted_path = store.persist_page_image(
                snapshot.run_id, record, image_bytes
            )
            with _ocr_jobs_lock:
                page["verification_image_sha256"] = image_sha256
                page["verification_dpi"] = verification_dpi
                page["persisted_visual_path"] = str(persisted_path)
                page["visual_input_sha256"] = image_sha256
                page["visual_input_persisted"] = True
                page["dpi_history"] = list(dict.fromkeys([
                    *(page.get("dpi_history") or []),
                    verification_dpi,
                ]))
                page["attempts"] = max(
                    int(page.get("attempts") or 0), int(record.call_index)
                )
                _bump_ocr_state(job)
            return image_bytes

        def _v2_page_evidence_store(store, snapshot):
            """Return the page-evidence store bound to this immutable run/source."""
            from ..core.ocr_page_evidence import PageEvidenceStore

            existing = job.get("_v2_page_evidence_store")
            if isinstance(existing, PageEvidenceStore):
                if (
                    existing.run_id != snapshot.run_id
                    or existing.source_sha256 != snapshot.source_sha256
                ):
                    raise OcrStoreError("页面证据存储与不可变 OCR 任务不一致")
                return existing
            evidence_store = PageEvidenceStore(
                store.root,
                snapshot.run_id,
                snapshot.source_sha256,
            )
            with _ocr_jobs_lock:
                job["_v2_page_evidence_store"] = evidence_store
                _bump_ocr_state(job)
            return evidence_store

        def _persist_v2_terminal_page_evidence(
            store,
            snapshot,
            classification,
            *,
            verification_evidence,
            raw_response,
            page_tex: str,
            final_status: str,
            visual_verification=None,
            full_ocr_performed: bool = False,
            full_ocr_with_crops: bool = False,
            reading_order_checked: bool = False,
            text_coverage_checked: bool = False,
            math_region_coverage_checked: bool = False,
            syntax_checked: bool = False,
            unresolved_regions=(),
        ):
            """Commit the five fixed page artifacts, then derive eight checks."""
            from ..core.ocr_page_evidence import (
                FinalPageStatus,
                PageCoverageFacts,
            )

            evidence_store = _v2_page_evidence_store(store, snapshot)
            evidence_store.persist_page_bundle(
                classification,
                verification=verification_evidence,
                raw_response=raw_response,
                page_tex=page_tex,
            )
            coverage_record = evidence_store.build_coverage_record(
                classification,
                PageCoverageFacts(
                    source_sha256=snapshot.source_sha256,
                    source_page_object_hash=(
                        classification.source_page_object_hash
                    ),
                    final_page_tex=page_tex,
                    final_status=FinalPageStatus(final_status),
                    verification=visual_verification,
                    full_ocr_performed=bool(full_ocr_performed),
                    full_ocr_with_crops=bool(full_ocr_with_crops),
                    full_ocr_reading_order_checked=bool(reading_order_checked),
                    full_ocr_text_coverage_checked=bool(text_coverage_checked),
                    full_ocr_math_region_coverage_checked=bool(
                        math_region_coverage_checked
                    ),
                    syntax_checked=bool(syntax_checked),
                    unresolved_regions=tuple(unresolved_regions or ()),
                ),
            )
            with _ocr_jobs_lock:
                page_state = job["pages"][classification.source_page_number]
                page_state["coverage_record"] = coverage_record.to_dict()
                page_state["coverage_complete"] = coverage_record.evidence_complete
                page_state["coverage_checks"] = coverage_record.checks.to_dict()
                job.setdefault("_v2_page_coverage_records", {})[
                    classification.page_id
                ] = coverage_record
                _bump_ocr_state(job)
            return coverage_record

        def _commit_v2_visual_result(
            store,
            snapshot,
            classification,
            verification,
            batch,
            raw_response,
        ) -> bool:
            """Commit a PASS/PATCH candidate; escalation stays eligible for full OCR."""
            from ..core.ocr_visual import resolve_visual_candidate

            resolution = resolve_visual_candidate(
                classification.candidate, verification
            )
            page_no = classification.source_page_number
            page = job["pages"][page_no]
            with _ocr_jobs_lock:
                page["verification"] = verification.to_dict()
                page["verification_sha256"] = resolution.verification_sha256
                page["visual_verdict"] = verification.verdict.value
                page["patched_block_ids"] = list(resolution.patched_block_ids)
                _bump_ocr_state(job)
            if resolution.requires_full_ocr:
                with _ocr_jobs_lock:
                    page["candidate_strategy"] = "FULL_OCR_REQUIRED"
                    page["current_strategy"] = "完整视觉 OCR"
                    _bump_ocr_state(job)
                return False
            issues = inspect_latex_fragment(
                resolution.candidate_tex,
                reference_text=classification.candidate_tex,
            )
            if any(issue.retryable or issue.severity == "error" for issue in issues):
                with _ocr_jobs_lock:
                    page["candidate_strategy"] = "FULL_OCR_REQUIRED"
                    page["quality_flags"] = [
                        {
                            "type": "object_candidate_validation",
                            **issue.to_dict(),
                            "needs_review": True,
                        }
                        for issue in issues
                    ]
                    _bump_ocr_state(job)
                return False
            record = store.load_record(snapshot.run_id, classification.page_id)
            transport = {
                "page_id": classification.page_id,
                "latex": resolution.candidate_tex,
                "figures": [],
                "unresolved_regions": [],
            }
            flags = [{
                "type": "visual_verifier",
                "verdict": verification.verdict.value,
                "patched_block_ids": list(resolution.patched_block_ids),
                "reading_order_ok": verification.reading_order_ok,
                "coverage_ok": verification.coverage_ok,
                "needs_review": False,
            }]
            envelope = {
                "schema_version": "latexstruct-ocr-visual-response-v1",
                "page_id": record.page_id,
                "source_page": record.source_page,
                "task_index": record.task_index,
                "call_index": record.call_index,
                "gate_applied": True,
                "source_evidence_sha256": record.source_evidence_sha256,
                "candidate_tex": classification.candidate_tex,
                "candidate_tex_sha256": hashlib.sha256(
                    classification.candidate_tex.encode("utf-8")
                ).hexdigest(),
                "verification_batch_id": batch.batch_id,
                "verification_response_sha256": batch.response_sha256,
                "model_raw_response": deepcopy(raw_response),
                "verification_page": verification.to_dict(),
                "visual_mode": "VERIFIER",
                "patched_block_ids": list(resolution.patched_block_ids),
                "transport_response": transport,
                "host_quality_flags": flags,
            }
            raw_bytes = json.dumps(
                envelope,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            elapsed = None
            try:
                started = datetime.fromisoformat(
                    record.started_at.replace("Z", "+00:00")
                )
                elapsed = max(
                    0.0,
                    (datetime.now(timezone.utc) - started).total_seconds(),
                )
            except (TypeError, ValueError):
                pass
            record = record.transition(OcrPageStatus.VALIDATING)
            record = record.transition(
                OcrPageStatus.SUCCESS,
                raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                raw_tex=classification.candidate_tex,
                cleaned_tex=resolution.candidate_tex,
                ended_at=_iso_now(),
                elapsed_seconds=elapsed,
                quality_issues=(
                    tuple(record.quality_issues)
                    + tuple(issue.to_dict() for issue in issues)
                ),
                host_quality_flags=tuple(flags),
                unresolved_regions=(),
                usage={
                    "attempts": deepcopy(
                        (job.get("_v2_page_usage") or {}).get(record.page_id) or []
                    )
                },
                error_reason="",
            )
            store.persist_record(snapshot.run_id, record, raw_response=envelope)
            _persist_v2_terminal_page_evidence(
                store,
                snapshot,
                classification,
                verification_evidence={
                    "page_id": classification.page_id,
                    "visual_mode": "VERIFIER",
                    "visual_verification": verification.to_dict(),
                    "syntax_checked": True,
                },
                raw_response=envelope,
                page_tex=resolution.candidate_tex,
                final_status="SUCCESS",
                visual_verification=verification,
                syntax_checked=True,
            )
            with _ocr_jobs_lock:
                page["tex"] = resolution.candidate_tex
                page["status"] = "done"
                page["error"] = ""
                page["low_conf"] = False
                page["needs_review"] = False
                page["retrying"] = False
                page["figures"] = []
                page["quality_flags"] = flags
                page["candidate_strategy"] = (
                    "OBJECT_LAYER_PATCHED"
                    if resolution.patched_block_ids
                    else "OBJECT_LAYER_VERIFIED"
                )
                page["visual_mode"] = "VERIFIER"
                job["page_revision"] = int(job.get("page_revision") or 0) + 1
                _bump_ocr_state(job)
            _refresh_raw_preview(job, page_no)
            return True

        def _run_v2_visual_fast_path(
            store,
            snapshot,
            client,
            source_classification,
        ) -> None:
            """Verify digital candidates concurrently; commit pages deterministically."""
            from ..core.ocr_schema import PageStrategy

            eligible_strategies = {
                PageStrategy.BORN_DIGITAL_CLEAN,
                PageStrategy.BORN_DIGITAL_RISKY,
                PageStrategy.HYBRID,
            }
            eligible = []
            for classification in source_classification.pages:
                if classification.strategy not in eligible_strategies:
                    continue
                record = store.load_record(snapshot.run_id, classification.page_id)
                if record.status is OcrPageStatus.SUCCESS:
                    continue
                if record.status not in {
                    OcrPageStatus.PENDING,
                    OcrPageStatus.FAILED,
                    OcrPageStatus.NEEDS_REVIEW,
                }:
                    continue
                eligible.append(classification)
            eligible.sort(key=lambda item: item.selected_index)
            if len({item.selected_index for item in eligible}) != len(eligible):
                raise OcrStoreError("对象层视觉验证出现重复 selected_index")
            groups = tuple(
                tuple(eligible[start:start + OCR_VISUAL_REQUEST_PAGE_LIMIT])
                for start in range(0, len(eligible), OCR_VISUAL_REQUEST_PAGE_LIMIT)
            )
            if not groups:
                return

            frozen_contract = thaw_json(snapshot.pipeline_contract)
            scheduler_contract = (
                frozen_contract.get("scheduler_profile")
                if isinstance(frozen_contract, dict)
                else {}
            )
            verifier_pool = (
                (scheduler_contract.get("pools") or {}).get(
                    "visual_verification"
                )
                if isinstance(scheduler_contract, dict)
                else {}
            ) or {}
            try:
                configured_initial = int(
                    verifier_pool.get("initial_workers")
                    or OCR_VISUAL_NORMAL_CONCURRENCY
                )
                configured_max = int(
                    verifier_pool.get("max_workers")
                    or OCR_VISUAL_MAX_CONCURRENCY
                )
            except (TypeError, ValueError):
                configured_initial = OCR_VISUAL_NORMAL_CONCURRENCY
                configured_max = OCR_VISUAL_MAX_CONCURRENCY
            normal_workers = min(
                OCR_VISUAL_NORMAL_CONCURRENCY,
                max(1, configured_initial),
            )
            max_workers = min(
                OCR_VISUAL_MAX_CONCURRENCY,
                max(normal_workers, configured_max),
            )
            try:
                scheduler_latency_limit = float(
                    scheduler_contract.get("p95_latency_soft_limit_ms")
                )
            except (AttributeError, TypeError, ValueError):
                scheduler_latency_limit = OCR_VISUAL_PROMOTION_LATENCY_MS
            if (
                not math.isfinite(scheduler_latency_limit)
                or scheduler_latency_limit <= 0.0
            ):
                scheduler_latency_limit = OCR_VISUAL_PROMOTION_LATENCY_MS
            promotion_latency_ms = min(
                OCR_VISUAL_PROMOTION_LATENCY_MS,
                scheduler_latency_limit,
            )

            def mark_full_ocr(classification, message: str, flag_type: str) -> None:
                """Fail only this page closed and keep it eligible for full OCR."""
                safe_message = str(message or "视觉验证未完成")[:500]
                current = store.load_record(
                    snapshot.run_id, classification.page_id
                )
                if current.status in {
                    OcrPageStatus.CLASSIFYING,
                    OcrPageStatus.EXTRACTING,
                    OcrPageStatus.RENDERING,
                    OcrPageStatus.QUEUED,
                    OcrPageStatus.VERIFYING,
                    OcrPageStatus.OCR_RUNNING,
                    OcrPageStatus.VALIDATING,
                    OcrPageStatus.RETRYING,
                }:
                    current = current.transition(
                        OcrPageStatus.FAILED,
                        error_reason=safe_message,
                        ended_at=_iso_now(),
                    )
                    store.persist_record(snapshot.run_id, current)
                with _ocr_jobs_lock:
                    page = job["pages"][classification.source_page_number]
                    page["candidate_strategy"] = "FULL_OCR_REQUIRED"
                    page["current_strategy"] = "完整视觉 OCR"
                    page["visual_verdict"] = "UNRESOLVED"
                    page.setdefault("quality_flags", []).append({
                        "type": flag_type,
                        "message": safe_message,
                        "needs_review": True,
                    })
                    _bump_ocr_state(job)

            def prepare_group(_group_index, group):
                prepared = []
                page_errors = {}
                for classification in group:
                    _ocr_control(job)
                    try:
                        record = store.load_record(
                            snapshot.run_id, classification.page_id
                        )
                        image_bytes = _prepare_v2_verification_image(
                            store, snapshot, record, classification
                        )
                    except Exception as exc:  # noqa: BLE001 - page-local escalation
                        page_errors[classification.page_id] = {
                            "type": "visual_verification_render_failure",
                            "message": _safe_task_error(exc),
                        }
                    else:
                        prepared.append((classification, image_bytes))
                return {"prepared": prepared, "page_errors": page_errors}

            def verify_group(group_index, _group, payload):
                result = {
                    "group_index": group_index,
                    "attempts": [],
                    "outcomes": {},
                    "page_errors": dict(payload.get("page_errors") or {}),
                }

                def verify_prepared(items) -> None:
                    if not items:
                        return
                    classifications = [item[0] for item in items]
                    images = [item[1] for item in items]
                    started = time.perf_counter()
                    try:
                        batch, raw_response = _v2_visual_verify_call(
                            client, snapshot, classifications, images
                        )
                    except Exception as exc:  # noqa: BLE001 - split, then page-local
                        latency_ms = (time.perf_counter() - started) * 1000.0
                        result["attempts"].append({
                            "page_ids": [
                                item.page_id for item in classifications
                            ],
                            "status": "FAILED_TO_VALIDATE",
                            "error": _safe_task_error(exc),
                            "response_sha256": "",
                            "latency_ms": round(latency_ms, 3),
                        })
                        if len(items) > 1:
                            middle = len(items) // 2
                            verify_prepared(items[:middle])
                            verify_prepared(items[middle:])
                        else:
                            classification = classifications[0]
                            result["page_errors"][classification.page_id] = {
                                "type": "visual_verifier_failure",
                                "message": _safe_task_error(exc),
                            }
                        return
                    latency_ms = (time.perf_counter() - started) * 1000.0
                    result["attempts"].append({
                        "batch_id": batch.batch_id,
                        "page_ids": [item.page_id for item in classifications],
                        "status": "VALIDATED",
                        "response_sha256": batch.response_sha256,
                        "latency_ms": round(latency_ms, 3),
                    })
                    for classification, verification in zip(
                        classifications, batch.pages
                    ):
                        result["outcomes"][classification.page_id] = (
                            verification,
                            batch,
                            raw_response,
                        )

                verify_prepared(list(payload.get("prepared") or ()))
                return result

            def commit_group(group_index, group, result, pool_error):
                if result is None:
                    message = _safe_task_error(
                        pool_error or RuntimeError("视觉验证工作线程未返回结果")
                    )
                    result = {
                        "attempts": [{
                            "page_ids": [item.page_id for item in group],
                            "status": "FAILED_TO_VALIDATE",
                            "error": message,
                            "response_sha256": "",
                            "latency_ms": None,
                        }],
                        "outcomes": {},
                        "page_errors": {
                            item.page_id: {
                                "type": "visual_verifier_failure",
                                "message": message,
                            }
                            for item in group
                        },
                    }
                attempts = [
                    {"group_index": group_index, **dict(attempt)}
                    for attempt in (result.get("attempts") or [])
                ]
                with _ocr_jobs_lock:
                    job.setdefault("visual_verification_attempts", []).extend(
                        attempts
                    )
                    _bump_ocr_state(job)

                page_errors = dict(result.get("page_errors") or {})
                outcomes = dict(result.get("outcomes") or {})
                had_error = bool(page_errors) or any(
                    attempt.get("status") != "VALIDATED"
                    for attempt in attempts
                )
                for classification in sorted(
                    group, key=lambda item: item.selected_index
                ):
                    outcome = outcomes.get(classification.page_id)
                    if outcome is None:
                        error = page_errors.get(classification.page_id) or {}
                        mark_full_ocr(
                            classification,
                            str(error.get("message") or "视觉验证未返回该页"),
                            str(error.get("type") or "visual_verifier_failure"),
                        )
                        had_error = True
                        continue
                    verification, batch, raw_response = outcome
                    _commit_v2_visual_result(
                        store,
                        snapshot,
                        classification,
                        verification,
                        batch,
                        raw_response,
                    )
                validated_attempts = [
                    attempt
                    for attempt in attempts
                    if attempt.get("status") == "VALIDATED"
                ]
                return {
                    "had_error": had_error,
                    "successful_requests": len(validated_attempts),
                    "latency_ms": [
                        attempt.get("latency_ms")
                        for attempt in validated_attempts
                        if attempt.get("latency_ms") is not None
                    ],
                }

            def publish_limit(limit: int) -> None:
                with _ocr_jobs_lock:
                    job["visual_verifier_concurrency"] = int(limit)
                    _bump_ocr_state(job)

            stats = _run_bounded_visual_pool(
                groups,
                prepare_group=prepare_group,
                verify_group=verify_group,
                commit_group=commit_group,
                control=lambda: _ocr_control(job),
                normal_workers=normal_workers,
                max_workers=max_workers,
                promotion_latency_ms=promotion_latency_ms,
                on_limit_change=publish_limit,
            )
            with _ocr_jobs_lock:
                job["visual_verifier_pool"] = stats
                job["visual_verifier_max_observed_concurrency"] = stats[
                    "max_in_flight_batches"
                ]
                job["visual_verifier_max_in_flight_pages"] = stats[
                    "max_in_flight_pages"
                ]
                _bump_ocr_state(job)

        def _prepare_v2_render(
            store,
            snapshot,
            record,
            *,
            retry: bool = False,
            correction_instruction: str = "",
            retry_state: dict | None = None,
            recovery_stage: RecoveryStage | None = None,
        ) -> dict:
            page_no = record.source_page
            page = job["pages"][page_no]
            # A user-triggered resume/retry starts a fresh append-only recovery
            # chain when this page has already made a provider call.  Reusing an
            # exhausted chain would make its next legal stage ``none`` and the
            # first repaired request would be rejected before reaching the
            # model.  The older chain remains on disk and is exported alongside
            # the new one; successful page records are never routed here.
            if (
                recovery_stage is None
                and (record.call_index > 0 or record.retry_count > 0)
            ):
                with _ocr_jobs_lock:
                    parent_run_id = str(
                        page.get("recovery_run_id") or snapshot.run_id
                    )
                    recovery_run_id = hashlib.sha256(
                        (
                            f"{snapshot.run_id}:{record.page_id}:resume:"
                            f"{uuid.uuid4().hex}"
                        ).encode("utf-8")
                    ).hexdigest()
                    page["recovery_parent_run_id"] = parent_run_id
                    page["recovery_run_id"] = recovery_run_id
                    page["prompt_version"] = _ocr_prompt_version()
                    _bump_ocr_state(job)
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
            same_dpi_stages = {
                RecoveryStage.SAME_DPI_RETRY,
                RecoveryStage.BATCH_TO_SINGLE,
            }
            render_dpi = (
                snapshot.initial_dpi
                if not retry or recovery_stage in same_dpi_stages
                else tier_policy.retry_dpi
            )
            context_id = f"ocr-context-{uuid.uuid4().hex}"
            if recovery_stage is RecoveryStage.INDEPENDENT_SECOND_READ:
                correction_instruction = (
                    "独立重新识别整页：不得参考、复述或修补上一轮答案；"
                    "只依据本次提供的页面像素完整转写。"
                )
                retry_state = {
                    "recovery_stage": recovery_stage.value,
                    "independent_context": True,
                }
            with _ocr_jobs_lock:
                job["dpi"] = render_dpi
                job["page"] = page_no
                job["current_index"] = record.task_index
                job["phase"] = (
                    f"正在以 {render_dpi} DPI 重试第 {page_no} 页"
                    if retry else f"正在渲染并识别第 {page_no} 页"
                )
                page["retrying"] = retry
                page["recovery_stage"] = (
                    recovery_stage.value
                    if recovery_stage is not None
                    else RecoveryStage.INITIAL_READ.value
                )
                page["model_context_id"] = context_id
                page["prompt_version"] = _ocr_prompt_version()
                _bump_ocr_state(job)
            record = record.transition(OcrPageStatus.RENDERING, dpi=render_dpi)
            store.persist_record(snapshot.run_id, record)
            if (
                job.get("recovered_after_restart")
                and snapshot.quality_tier.value == "high"
                and (record.call_index > 0 or record.retry_count > 0)
                and not record.source_evidence_sha256
            ):
                raise OcrStoreError(
                    "旧出版级 OCR 页缺少调用前源证据绑定；不得以新代码静默升级或重试"
                )
            render_started = time.perf_counter()
            try:
                _render_one(job, page_no, render_dpi=render_dpi)
            except Exception:
                _record_v2_stage(
                    "rendering",
                    duration_ms=(time.perf_counter() - render_started) * 1000.0,
                    succeeded=False,
                )
                raise
            _record_v2_stage(
                "rendering",
                duration_ms=(time.perf_counter() - render_started) * 1000.0,
            )
            return {
                "page_id": record.page_id,
                "source_page": page_no,
                "task_index": record.task_index,
                "render_dpi": render_dpi,
                "retry": bool(retry),
                "correction_instruction": str(correction_instruction or ""),
                "retry_state": deepcopy(retry_state),
                "recovery_stage": (
                    recovery_stage.value if recovery_stage is not None else None
                ),
                "model_context_id": context_id,
            }

        def _dispatch_v2_render(store, snapshot, prepared: dict):
            from ..ocr import make_host_ocr_page_request

            expected_keys = {
                "page_id",
                "source_page",
                "task_index",
                "render_dpi",
                "retry",
                "correction_instruction",
                "retry_state",
                "recovery_stage",
                "model_context_id",
            }
            if not isinstance(prepared, dict) or set(prepared) != expected_keys:
                raise OcrStoreError("OCR rendered-page dispatch metadata is invalid")
            page_id = str(prepared["page_id"] or "")
            page_no = int(prepared["source_page"])
            task_index = int(prepared["task_index"])
            render_dpi = int(prepared["render_dpi"])
            retry = prepared["retry"] is True
            correction_instruction = str(
                prepared["correction_instruction"] or ""
            )
            retry_state = deepcopy(prepared["retry_state"])
            recovery_stage_value = prepared["recovery_stage"]
            recovery_stage = (
                RecoveryStage(str(recovery_stage_value))
                if recovery_stage_value is not None
                else None
            )
            record = store.load_record(snapshot.run_id, page_id)
            if (
                record.status is not OcrPageStatus.RENDERING
                or record.source_page != page_no
                or record.task_index != task_index
                or record.dpi != render_dpi
            ):
                raise OcrStoreError(
                    "OCR rendered page changed before model dispatch"
                )
            page = job["pages"][page_no]
            image_bytes = Path(page["png"]).read_bytes()
            if not image_bytes:
                raise OcrStoreError(f"第 {page_no} 页渲染图像在模型提交前为空")
            with _ocr_jobs_lock:
                page["status"] = "running"
                page["dpi_history"] = list(dict.fromkeys([
                    *(page.get("dpi_history") or []),
                    render_dpi,
                ]))
                _bump_ocr_state(job)
            record = record.transition(
                OcrPageStatus.OCR_RUNNING,
                image_sha256=hashlib.sha256(image_bytes).hexdigest(),
                image_size_pixels=tuple(page.get("image_size_pixels") or ()),
                source_evidence_sha256=store.persist_page_source_evidence(
                    snapshot.run_id,
                    record,
                    _build_page_source_evidence(page),
                ),
                dpi=render_dpi,
                model=snapshot.ocr_model,
                call_index=record.call_index + 1,
                started_at=_iso_now(),
                error_reason="",
            )
            store.persist_record(snapshot.run_id, record)
            crop_bytes: list[bytes] = []
            if (
                retry
                and tier_policy.use_formula_crops
                and recovery_stage is RecoveryStage.PAGE_WITH_CROPS
            ):
                evidence_root = (Path(job["dir"]) / "formula-evidence").resolve()
                for evidence in (page.get("formula_evidence_inputs") or [])[:4]:
                    if not isinstance(evidence, dict):
                        continue
                    crop_path = Path(str(evidence.get("crop_path") or ""))
                    expected_sha = str(evidence.get("crop_sha256") or "").lower()
                    try:
                        resolved = crop_path.resolve(strict=True)
                        resolved.relative_to(evidence_root)
                        data = resolved.read_bytes()
                    except (OSError, ValueError):
                        raise OcrStoreError(
                            f"第 {page_no} 页公式裁片证据缺失或路径无效"
                        ) from None
                    if (
                        resolved.is_symlink()
                        or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None
                        or not hmac.compare_digest(
                            hashlib.sha256(data).hexdigest(), expected_sha
                        )
                        or not (
                            data.startswith(b"\x89PNG\r\n\x1a\n")
                            or data.startswith(b"\xff\xd8\xff")
                        )
                    ):
                        raise OcrStoreError(
                            f"第 {page_no} 页公式裁片证据哈希或格式无效"
                        )
                    crop_bytes.append(data)
            with _ocr_jobs_lock:
                page["attempts"] = max(
                    int(page.get("attempts") or 0),
                    int(record.call_index or 0),
                )
                _bump_ocr_state(job)
            return make_host_ocr_page_request(
                image_bytes,
                page_no,
                task_index,
                dpi=render_dpi,
                text_layer_hint=str(page.get("text_hint") or ""),
                crops=tuple(crop_bytes),
                correction_instruction=correction_instruction,
                retry_state=retry_state,
                image_size_pixels=tuple(record.image_size_pixels),
            )

        def _prepare_v2_request(
            store,
            snapshot,
            record,
            *,
            retry: bool = False,
            correction_instruction: str = "",
            retry_state: dict | None = None,
            recovery_stage: RecoveryStage | None = None,
        ):
            prepared = _prepare_v2_render(
                store,
                snapshot,
                record,
                retry=retry,
                correction_instruction=correction_instruction,
                retry_state=retry_state,
                recovery_stage=recovery_stage,
            )
            return _dispatch_v2_render(store, snapshot, prepared)

        def _v2_host_response_envelope(execution, *, consume: bool = False) -> dict:
            """Combine provider bytes and trusted host metadata without mixing provenance."""
            request = execution.request
            record = job["_v2_store"].load_record(
                job["_v2_snapshot"].run_id, request.page_id
            )
            key = f"{request.page_id}:{record.call_index}"
            with _ocr_jobs_lock:
                trusted_results = job.get("_v2_trusted_host_results") or {}
                trusted = deepcopy(trusted_results.get(key))
                if consume and trusted is not None:
                    trusted_results.pop(key, None)
            # ``model_raw_response`` below preserves the exact provider object.
            # Keep ``transport_response`` as the separately named, host-cleaned
            # four-field page contract that was actually committed.  This makes
            # raw-vs-cleaned provenance explicit and lets restart verification
            # bind the sidecar back to ``record.cleaned_tex`` byte-for-byte.
            transport = None
            if execution.page is not None:
                transport = {
                    "page_id": execution.page.page_id,
                    "latex": execution.page.latex,
                    "figures": thaw_json(execution.page.figures),
                    "unresolved_regions": thaw_json(
                        execution.page.unresolved_regions
                    ),
                }
            if trusted is not None:
                if (
                    trusted.get("schema_version") != "latexstruct-ocr-host-result-v1"
                    or trusted.get("page_id") != request.page_id
                    or trusted.get("source_page") != request.source_page
                    or trusted.get("call_index") != record.call_index
                ):
                    raise OcrStoreError("OCR trusted host result identity mismatch")
            publication_grade = job["_v2_snapshot"].quality_tier.value == "high"
            if publication_grade and execution.page is not None and (
                trusted is None or trusted.get("gate_applied") is not True
            ):
                raise OcrStoreError("出版级 OCR 缺少可信宿主逐页门禁结果")
            model_raw_response = (
                deepcopy(trusted.get("model_raw_response"))
                if trusted is not None
                else deepcopy(execution.raw_response)
            )
            if trusted is not None:
                model_raw_latex = str(trusted.get("model_raw_latex") or "")
            else:
                raw_payload = execution.raw_response
                raw_page = raw_payload if isinstance(raw_payload, dict) else {}
                if isinstance(raw_page.get("pages"), list):
                    raw_page = next(
                        (
                            item for item in raw_page["pages"]
                            if isinstance(item, dict)
                            and item.get("page_id") == request.page_id
                        ),
                        {},
                    )
                model_raw_latex = str(
                    raw_page.get("latex")
                    if isinstance(raw_page, dict)
                    else ""
                ) or str((transport or {}).get("latex") or "")
            retry_state = thaw_json(execution.retry_state)
            batch_parent = (
                deepcopy(retry_state.get("batch_parent"))
                if isinstance(retry_state, dict)
                and isinstance(retry_state.get("batch_parent"), dict)
                else None
            )
            return {
                "schema_version": "latexstruct-ocr-host-response-v1",
                "page_id": request.page_id,
                "source_page": request.source_page,
                "task_index": request.task_index,
                "call_index": record.call_index,
                "gate_applied": bool(
                    trusted is not None and trusted.get("gate_applied") is True
                ),
                "source_evidence_sha256": record.source_evidence_sha256,
                "model_raw_latex": model_raw_latex,
                "model_raw_response": model_raw_response,
                "transport_response": transport,
                "host_quality_flags": (
                    deepcopy(trusted.get("host_quality_flags") or [])
                    if trusted is not None else []
                ),
                "formula_evidence": (
                    deepcopy(trusted.get("formula_evidence") or [])
                    if trusted is not None else []
                ),
                "batch_parent": batch_parent,
            }

        def _record_v2_recovery_attempt(
            store,
            snapshot,
            execution,
            *,
            stage: RecoveryStage,
            comparison_tex_sha256: str = "",
        ):
            """Durably append one real model attempt and expose its next stage."""
            from ..core.ocr_recovery import (
                AttemptOutcome,
                OcrRecoveryEvidenceStore,
                RecoveryImageInput,
                RecoveryImageRole,
            )

            request = execution.request
            page_state = job["pages"][request.source_page]
            recovery_run_id = str(
                page_state.get("recovery_run_id") or snapshot.run_id
            )
            page_state["recovery_run_id"] = recovery_run_id
            recovery = OcrRecoveryEvidenceStore(
                store.run_dir(snapshot.run_id) / "recovery-evidence"
            )
            width, height = tuple(request.image_size_pixels or (1, 1))
            full_hash = hashlib.sha256(request.image_bytes).hexdigest()
            images = [RecoveryImageInput(
                role=RecoveryImageRole.FULL_PAGE,
                content=request.image_bytes,
                dpi=request.dpi,
                width_pixels=max(1, int(width)),
                height_pixels=max(1, int(height)),
            )]
            evidence_rows = [
                item for item in (page_state.get("formula_evidence_inputs") or [])
                if isinstance(item, dict)
            ]
            for index, crop in enumerate(request.crops):
                evidence = evidence_rows[index] if index < len(evidence_rows) else {}
                bbox_points = evidence.get("source_bbox_points") or ()
                try:
                    bbox = tuple(
                        max(0, int(round(float(value) * request.dpi / 72.0)))
                        for value in bbox_points
                    )
                except (TypeError, ValueError):
                    bbox = ()
                if len(bbox) != 4 or bbox[2] <= bbox[0] or bbox[3] <= bbox[1]:
                    bbox = (0, 0, max(1, int(width) - 1), max(1, int(height) - 1))
                crop_size = evidence.get("image_size_pixels") or (1, 1)
                images.append(RecoveryImageInput(
                    role=RecoveryImageRole.CROP,
                    content=crop,
                    dpi=request.dpi,
                    width_pixels=max(1, int(crop_size[0])),
                    height_pixels=max(1, int(crop_size[1])),
                    crop_id=str(evidence.get("id") or f"formula-{index + 1:02d}"),
                    bbox_pixels=bbox,
                    source_image_sha256=full_hash,
                    region_type="formula",
                ))
            validated = execution.page
            tex_hash = (
                hashlib.sha256(validated.latex.encode("utf-8")).hexdigest()
                if validated is not None
                else ""
            )
            conflict = bool(
                stage is RecoveryStage.INDEPENDENT_SECOND_READ
                and comparison_tex_sha256
                and tex_hash
                and not hmac.compare_digest(tex_hash, comparison_tex_sha256)
            )
            outcome = _ocr_v2_attempt_outcome(execution, conflict=conflict)
            response_envelope = _v2_host_response_envelope(execution)
            response_envelope["host_error"] = (
                {
                    "message": _safe_task_error(
                        execution.error or "OCR call failed"
                    ),
                    "category": (
                        execution.error_category.value
                        if execution.error_category is not None
                        else OcrErrorCategory.UNKNOWN.value
                    ),
                    "retry_state": thaw_json(execution.retry_state),
                }
                if validated is None else None
            )
            raw_response = json.dumps(
                response_envelope,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            usage_rows = (
                (job.get("_v2_page_usage") or {}).get(request.page_id) or []
            )
            usage = {}
            if usage_rows and isinstance(usage_rows[-1], dict):
                candidate_usage = usage_rows[-1].get("usage")
                if isinstance(candidate_usage, dict):
                    usage = deepcopy(candidate_usage)
            ended_at = _iso_now()
            record = store.load_record(snapshot.run_id, request.page_id)
            started_at = str(record.started_at or ended_at)
            duration_ms = 0
            try:
                started_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                ended_dt = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
                duration_ms = max(0, int((ended_dt - started_dt).total_seconds() * 1000))
            except ValueError:
                pass
            unresolved_hashes = tuple(
                hashlib.sha256(json.dumps(
                    thaw_json(region),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")).hexdigest()
                for region in (
                    validated.unresolved_regions if validated is not None else ()
                )
            )
            persisted_attempt = recovery.record_attempt(
                run_id=recovery_run_id,
                page_id=request.page_id,
                source_page=request.source_page,
                task_index=request.task_index,
                stage=stage,
                outcome=outcome,
                base_dpi=snapshot.initial_dpi,
                dpi=request.dpi,
                model=snapshot.ocr_model,
                backend=snapshot.api_backend,
                model_context_id=str(
                    page_state.get("model_context_id")
                    or f"ocr-context-{uuid.uuid4().hex}"
                ),
                images=images,
                raw_response=raw_response,
                duration_ms=duration_ms,
                usage=usage,
                error=(
                    {
                        "message": _safe_task_error(execution.error or ""),
                        "category": (
                            execution.error_category.value
                            if execution.error_category is not None
                            else OcrErrorCategory.UNKNOWN.value
                        ),
                    }
                    if outcome not in {
                        AttemptOutcome.PASSED,
                        AttemptOutcome.NEEDS_REVIEW,
                        AttemptOutcome.CONFLICT,
                    }
                    else None
                ),
                tex_sha256=tex_hash,
                comparison_tex_sha256=comparison_tex_sha256,
                is_batched=bool(execution.used_batch),
                batch_id=execution.batch_id if execution.used_batch else "",
                batch_size=(execution.batch_size if execution.used_batch else 1),
                quality_issue_codes=tuple(
                    issue.code for issue in (validated.issues if validated is not None else ())
                ),
                unresolved_region_hashes=unresolved_hashes,
                started_at=started_at,
                ended_at=ended_at,
                crops_available=bool(
                    tier_policy.use_formula_crops
                    and page_state.get("formula_evidence_inputs")
                ),
                independent_second_read=tier_policy.independent_second_read,
            )
            with _ocr_jobs_lock:
                usage_rows = (
                    (job.get("_v2_page_usage") or {}).get(request.page_id) or []
                )
                if usage_rows and isinstance(usage_rows[-1], dict):
                    usage_rows[-1].setdefault(
                        "event_id",
                        f"{recovery_run_id}:{persisted_attempt.attempt_id}",
                    )
                    usage_rows[-1].setdefault(
                        "started_at", str(persisted_attempt.started_at or "")
                    )
            _attempts, state = recovery.recover_page(
                recovery_run_id,
                request.page_id,
                crops_available=bool(
                    tier_policy.use_formula_crops
                    and page_state.get("formula_evidence_inputs")
                ),
                independent_second_read=tier_policy.independent_second_read,
            )
            with _ocr_jobs_lock:
                page_state["recovery_stage"] = (
                    state.current_stage.value if state.current_stage else ""
                )
                page_state["recovery_status"] = state.status.value
                page_state["recovery_attempt_count"] = state.attempt_count
                page_state["recovery_evidence_chain_sha256"] = (
                    state.evidence_chain_sha256
                )
                job["_v2_recovery_store"] = recovery
                _bump_ocr_state(job)
            return state, conflict

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
                safe_execution_error = _safe_task_error(
                    execution.error or "OCR 未返回可验证页面结果"
                )
                failure_issue = {
                    "code": "OCR_CALL_FAILED",
                    "severity": "error",
                    "category": (
                        execution.error_category.value
                        if execution.error_category is not None
                        else OcrErrorCategory.UNKNOWN.value
                    ),
                    "message": safe_execution_error,
                }
                record = record.transition(
                    OcrPageStatus.FAILED,
                    ended_at=_iso_now(),
                    error_reason=safe_execution_error,
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
            raw_object = _v2_host_response_envelope(execution, consume=True)
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
                raw_tex=str(raw_object.get("model_raw_latex") or ""),
                cleaned_tex=validated.latex,
                ended_at=_iso_now(),
                elapsed_seconds=elapsed,
                quality_issues=(
                    tuple(record.quality_issues)
                    + tuple(issue.to_dict() for issue in validated.issues)
                ),
                host_quality_flags=tuple(
                    deepcopy(flag)
                    for flag in (raw_object.get("host_quality_flags") or [])
                    if isinstance(flag, dict)
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
            source_classification = job.get("_v2_source_classification")
            classification = next(
                (
                    item for item in getattr(source_classification, "pages", ())
                    if item.page_id == request.page_id
                ),
                None,
            )
            if classification is None:
                raise OcrStoreError("完整 OCR 结果缺少冻结的页面分类证据")
            full_page_checks_passed = not validated.needs_retry
            syntax_checked = not any(
                issue.retryable or issue.severity == "error"
                for issue in validated.issues
            )
            visual_mode = (
                "FULL_OCR_WITH_CROPS" if request.crops else "FULL_OCR"
            )
            _persist_v2_terminal_page_evidence(
                store,
                snapshot,
                classification,
                verification_evidence={
                    "page_id": request.page_id,
                    "visual_mode": visual_mode,
                    "full_ocr_performed": True,
                    "full_ocr_with_crops": bool(request.crops),
                    "reading_order_checked": full_page_checks_passed,
                    "text_coverage_checked": full_page_checks_passed,
                    "math_region_coverage_checked": full_page_checks_passed,
                    "syntax_checked": syntax_checked,
                    "unresolved_regions": thaw_json(validated.unresolved_regions),
                },
                raw_response=raw_object,
                page_tex=validated.latex,
                final_status=final_status.value,
                full_ocr_performed=True,
                full_ocr_with_crops=bool(request.crops),
                reading_order_checked=full_page_checks_passed,
                text_coverage_checked=full_page_checks_passed,
                math_region_coverage_checked=full_page_checks_passed,
                syntax_checked=syntax_checked,
                unresolved_regions=thaw_json(validated.unresolved_regions),
            )
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
                    for flag in thaw_json(record.host_quality_flags)
                ]
                page["quality_flags"] = legacy_flags or runtime_flags
                page["formula_evidence"] = _bounded_formula_evidence(
                    raw_object.get("formula_evidence") or []
                )
                job["page_revision"] = int(job.get("page_revision") or 0) + 1
                _bump_ocr_state(job)
            _refresh_raw_preview(job, request.source_page)
            return True

        def _begin_v2_recovery(store, snapshot, execution):
            """Persist one initial read without entering its retry ladder."""
            limiter = _ocr_adaptive_limiters.get(str(job.get("id") or ""))
            if isinstance(limiter, AdaptivePageConcurrency):
                _ocr_adaptive_observe(job, limiter, execution)
            recovery_state, _conflict = _record_v2_recovery_attempt(
                store,
                snapshot,
                execution,
                stage=RecoveryStage.INITIAL_READ,
            )
            return {
                "current": execution,
                "state": recovery_state,
                "attempts": 0,
                "comparison": execution if execution.page is not None else None,
            }

        def _v2_context_should_retry(snapshot, context) -> bool:
            current = context["current"]
            if current.page is not None and not current.page.needs_retry:
                return False
            if (
                context["attempts"] >= snapshot.max_retries
                or context["state"].next_stage is None
            ):
                return False
            return bool(
                current.page is not None
                or _ocr_v2_has_host_retry_evidence(current)
                or current.error_category in {
                    OcrErrorCategory.TRANSIENT,
                    OcrErrorCategory.RATE_LIMIT,
                    OcrErrorCategory.BATCH_INCOMPATIBLE,
                    OcrErrorCategory.TRUNCATED,
                }
            )

        def _prepare_v2_recovery_request(store, snapshot, context):
            current = context["current"]
            recovery_stage = context["state"].next_stage
            record = store.load_record(snapshot.run_id, current.request.page_id)
            if record.status == OcrPageStatus.OCR_RUNNING:
                safe_retry_error = _safe_task_error(
                    current.error
                    or current.retry_instruction
                    or "页面质量门要求重新识别"
                )
                retry_issue = {
                    "code": "OCR_RETRY_SCHEDULED",
                    "severity": "warning",
                    "category": (
                        current.error_category.value
                        if current.error_category is not None
                        else OcrErrorCategory.UNKNOWN.value
                    ),
                    "message": safe_retry_error,
                }
                record = record.transition(
                    OcrPageStatus.RETRYING,
                    retry_count=record.retry_count + 1,
                    error_reason=safe_retry_error,
                    quality_issues=tuple(record.quality_issues) + (retry_issue,),
                )
                store.persist_record(snapshot.run_id, record)
            request = _prepare_v2_request(
                store,
                snapshot,
                record,
                retry=True,
                correction_instruction=current.retry_instruction,
                retry_state=thaw_json(current.retry_state),
                recovery_stage=recovery_stage,
            )
            return request, recovery_stage

        def _advance_v2_recovery(store, snapshot, context, execution, recovery_stage):
            limiter = _ocr_adaptive_limiters.get(str(job.get("id") or ""))
            if isinstance(limiter, AdaptivePageConcurrency):
                _ocr_adaptive_observe(job, limiter, execution)
            evidence_execution = execution
            selected_execution = execution
            comparison_tex_sha256 = ""
            expected_conflict = False
            if recovery_stage is RecoveryStage.INDEPENDENT_SECOND_READ:
                (
                    evidence_execution,
                    selected_execution,
                    comparison_tex_sha256,
                    expected_conflict,
                ) = _ocr_v2_prepare_independent_result(
                    context["comparison"],
                    execution,
                )
            recovery_state, conflict = _record_v2_recovery_attempt(
                store,
                snapshot,
                evidence_execution,
                stage=recovery_stage,
                comparison_tex_sha256=comparison_tex_sha256,
            )
            if conflict != expected_conflict:
                raise OcrStoreError(
                    "独立第二次识别的宿主冲突判定与证据账本不一致"
                )
            comparison = context["comparison"]
            if (
                recovery_stage is not RecoveryStage.INDEPENDENT_SECOND_READ
                and selected_execution.page is not None
            ):
                comparison = selected_execution
            return {
                "current": selected_execution,
                "state": recovery_state,
                "attempts": context["attempts"] + 1,
                "comparison": comparison,
            }

        def _drain_v2_recovery_waves(
            store,
            snapshot,
            client,
            contexts,
            *,
            on_terminal,
        ):
            """Advance equal recovery stages together; never recurse per page."""
            pending = list(contexts)
            while pending:
                terminal = [
                    context for context in pending
                    if not _v2_context_should_retry(snapshot, context)
                ]
                pending = [
                    context for context in pending
                    if _v2_context_should_retry(snapshot, context)
                ]
                for context in terminal:
                    current = context["current"]
                    on_terminal(
                        current,
                        bool(current.page is not None and current.page.needs_retry),
                    )
                if not pending:
                    break
                recovery_stage = pending[0]["state"].next_stage
                same_stage = sorted([
                    context for context in pending
                    if context["state"].next_stage is recovery_stage
                ], key=lambda item: item["current"].request.task_index)
                pending = [
                    context for context in pending
                    if context["state"].next_stage is not recovery_stage
                ]
                progressed = []
                progressed_lock = threading.Lock()
                offset = 0
                while offset < len(same_stage):
                    limiter = _ocr_adaptive_limiters.get(str(job.get("id") or ""))
                    effective_concurrency = snapshot.concurrency_limit
                    if isinstance(limiter, AdaptivePageConcurrency):
                        _batch_budget, effective_concurrency = _ocr_adaptive_budgets(
                            limiter,
                            configured_batch_size=1,
                            configured_concurrency_limit=snapshot.concurrency_limit,
                        )
                    wave = same_stage[offset:offset + effective_concurrency]
                    offset += len(wave)
                    if any(
                        context["current"].error_category
                        in {OcrErrorCategory.TRANSIENT, OcrErrorCategory.RATE_LIMIT}
                        for context in wave
                    ):
                        _ocr_retry_wait(max(context["attempts"] for context in wave) + 1)
                    request_contexts = {}
                    requests = []
                    for context in wave:
                        try:
                            request, stage = _prepare_v2_recovery_request(
                                store, snapshot, context
                            )
                        except Exception as exc:  # noqa: BLE001
                            failed = store.load_record(
                                snapshot.run_id,
                                context["current"].request.page_id,
                            )
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
                            _mark_page_error(job, failed.source_page, exc)
                            continue
                        requests.append(request)
                        request_contexts[request.page_id] = (context, stage)
                    if not requests:
                        continue

                    def _persist_recovery_result(result):
                        context, stage = request_contexts[result.request.page_id]
                        advanced = _advance_v2_recovery(
                            store,
                            snapshot,
                            context,
                            result,
                            stage,
                        )
                        with progressed_lock:
                            progressed.append(advanced)

                    BoundedOcrExecutor(
                        batch_size=1,
                        concurrency_limit=effective_concurrency,
                    ).run(
                        requests,
                        single_call=lambda item: _v2_model_call(client, [item]),
                        batch_call=None,
                        on_result=_persist_recovery_result,
                    )
                pending.extend(sorted(
                    progressed,
                    key=lambda item: item["current"].request.task_index,
                ))

        def _retry_v2_execution(store, snapshot, client, execution):
            terminal = []
            context = _begin_v2_recovery(store, snapshot, execution)
            _drain_v2_recovery_waves(
                store,
                snapshot,
                client,
                [context],
                on_terminal=lambda current, exhausted: terminal.append(
                    (current, exhausted)
                ),
            )
            if not terminal:
                raise OcrStoreError("OCR 恢复波次未形成终态结果")
            return terminal[-1]

        def _ensure_v2_page_coverage(store, snapshot):
            """Rebuild and freeze strict page summaries from immutable artifacts."""
            from ..core.ocr_page_evidence import (
                FinalPageStatus,
                PageCoverageFacts,
                PageCoverageRecord,
                PageEvidenceIntegrityError,
            )
            from ..core.ocr_visual import validate_visual_verification_response

            source_classification = job.get("_v2_source_classification")
            classifications = {
                item.page_id: item
                for item in getattr(source_classification, "pages", ())
            }
            runtime_records = store.list_records(snapshot.run_id)
            if set(classifications) != {record.page_id for record in runtime_records}:
                raise OcrStoreError("页面覆盖分类与不可变页范围不一致")
            evidence_store = _v2_page_evidence_store(store, snapshot)
            cached_records = job.get("_v2_page_coverage_records") or {}
            coverage_records = []
            for runtime_record in runtime_records:
                if runtime_record.status not in {
                    OcrPageStatus.SUCCESS,
                    OcrPageStatus.NEEDS_REVIEW,
                }:
                    raise OcrStoreError("页面覆盖尚未形成可冻结终态")
                classification = classifications[runtime_record.page_id]
                cached = cached_records.get(runtime_record.page_id)
                if isinstance(cached, PageCoverageRecord):
                    actual_hashes = evidence_store.verify_page_artifacts(
                        runtime_record.page_id
                    )
                    if dict(actual_hashes) != dict(cached.artifact_hashes):
                        raise OcrStoreError("页面覆盖缓存与持久化工件哈希不一致")
                    coverage_record = cached
                    if (
                        not coverage_record.evidence_complete
                        or coverage_record.final_status is not FinalPageStatus.SUCCESS
                    ):
                        raise OcrStoreError(
                            f"页面八项覆盖门禁未完全通过：{runtime_record.page_id}"
                        )
                    coverage_records.append(coverage_record)
                    continue
                transport = store.verify_saved_response(
                    snapshot.run_id, runtime_record
                )
                envelope = store.load_raw_response(
                    snapshot.run_id, runtime_record
                )
                syntax_issues = inspect_latex_fragment(
                    runtime_record.cleaned_tex,
                    reference_text=classification.candidate_tex,
                )
                syntax_checked = not any(
                    issue.retryable or issue.severity == "error"
                    for issue in syntax_issues
                )
                persisted_verification = None
                try:
                    evidence_store.verify_page_artifacts(runtime_record.page_id)
                    wrapper = json.loads(
                        (
                            evidence_store.page_dir(runtime_record.page_id)
                            / "verification.json"
                        ).read_text(encoding="utf-8")
                    )
                    persisted_verification = wrapper.get("verification")
                except (OSError, ValueError, PageEvidenceIntegrityError):
                    persisted_verification = None
                visual_mode = (
                    str(persisted_verification.get("visual_mode") or "")
                    if isinstance(persisted_verification, dict)
                    else ""
                )
                if visual_mode == "VERIFIER":
                    verification_page = persisted_verification.get(
                        "visual_verification"
                    )
                    batch_id = "ocr-coverage-persisted-" + runtime_record.page_id
                    batch = validate_visual_verification_response(
                        {"batch_id": batch_id, "pages": [verification_page]},
                        batch_id=batch_id,
                        candidates=(classification.candidate,),
                    )
                    verification = batch.pages[0]
                    coverage_record = evidence_store.build_coverage_record(
                        classification,
                        PageCoverageFacts(
                            source_sha256=snapshot.source_sha256,
                            source_page_object_hash=(
                                classification.source_page_object_hash
                            ),
                            final_page_tex=runtime_record.cleaned_tex,
                            final_status=FinalPageStatus(runtime_record.status.value),
                            verification=verification,
                            syntax_checked=bool(
                                persisted_verification.get("syntax_checked")
                            ),
                            unresolved_regions=tuple(
                                thaw_json(runtime_record.unresolved_regions)
                            ),
                        ),
                    )
                elif visual_mode in {"FULL_OCR", "FULL_OCR_WITH_CROPS"}:
                    coverage_record = evidence_store.build_coverage_record(
                        classification,
                        PageCoverageFacts(
                            source_sha256=snapshot.source_sha256,
                            source_page_object_hash=(
                                classification.source_page_object_hash
                            ),
                            final_page_tex=runtime_record.cleaned_tex,
                            final_status=FinalPageStatus(runtime_record.status.value),
                            full_ocr_performed=True,
                            full_ocr_with_crops=(
                                visual_mode == "FULL_OCR_WITH_CROPS"
                            ),
                            full_ocr_reading_order_checked=bool(
                                persisted_verification.get(
                                    "reading_order_checked"
                                )
                            ),
                            full_ocr_text_coverage_checked=bool(
                                persisted_verification.get(
                                    "text_coverage_checked"
                                )
                            ),
                            full_ocr_math_region_coverage_checked=bool(
                                persisted_verification.get(
                                    "math_region_coverage_checked"
                                )
                            ),
                            syntax_checked=bool(
                                persisted_verification.get("syntax_checked")
                            ),
                            unresolved_regions=tuple(
                                persisted_verification.get("unresolved_regions")
                                or ()
                            ),
                        ),
                    )
                elif envelope.get("schema_version") == "latexstruct-ocr-visual-response-v1":
                    verification_page = envelope.get("verification_page")
                    batch_id = "ocr-coverage-rebuild-" + runtime_record.page_id
                    batch = validate_visual_verification_response(
                        {
                            "batch_id": batch_id,
                            "pages": [verification_page],
                        },
                        batch_id=batch_id,
                        candidates=(classification.candidate,),
                    )
                    verification = batch.pages[0]
                    coverage_record = _persist_v2_terminal_page_evidence(
                        store,
                        snapshot,
                        classification,
                        verification_evidence={
                            "page_id": runtime_record.page_id,
                            "visual_mode": "VERIFIER",
                            "visual_verification": verification.to_dict(),
                            "syntax_checked": syntax_checked,
                        },
                        raw_response=envelope,
                        page_tex=runtime_record.cleaned_tex,
                        final_status=runtime_record.status.value,
                        visual_verification=verification,
                        syntax_checked=syntax_checked,
                        unresolved_regions=thaw_json(
                            runtime_record.unresolved_regions
                        ),
                    )
                else:
                    full_page_checks_passed = not any(
                        bool(issue.get("retryable"))
                        for issue in thaw_json(runtime_record.quality_issues)
                        if isinstance(issue, dict)
                    )
                    has_crops = bool(
                        job["pages"][runtime_record.source_page].get(
                            "formula_evidence_inputs"
                        )
                    ) and runtime_record.dpi >= snapshot.retry_dpi
                    visual_mode = (
                        "FULL_OCR_WITH_CROPS" if has_crops else "FULL_OCR"
                    )
                    unresolved = thaw_json(runtime_record.unresolved_regions)
                    verification_evidence = {
                        "page_id": runtime_record.page_id,
                        "visual_mode": visual_mode,
                        "full_ocr_performed": True,
                        "full_ocr_with_crops": has_crops,
                        "reading_order_checked": full_page_checks_passed,
                        "text_coverage_checked": full_page_checks_passed,
                        "math_region_coverage_checked": full_page_checks_passed,
                        "syntax_checked": syntax_checked,
                        "unresolved_regions": unresolved,
                    }
                    if not isinstance(transport, dict):
                        raise OcrStoreError("完整 OCR 页面缺少严格传输结果")
                    coverage_record = _persist_v2_terminal_page_evidence(
                        store,
                        snapshot,
                        classification,
                        verification_evidence=verification_evidence,
                        raw_response=envelope,
                        page_tex=runtime_record.cleaned_tex,
                        final_status=runtime_record.status.value,
                        full_ocr_performed=True,
                        full_ocr_with_crops=has_crops,
                        reading_order_checked=full_page_checks_passed,
                        text_coverage_checked=full_page_checks_passed,
                        math_region_coverage_checked=full_page_checks_passed,
                        syntax_checked=syntax_checked,
                        unresolved_regions=unresolved,
                    )
                if (
                    not coverage_record.evidence_complete
                    or coverage_record.final_status is not FinalPageStatus.SUCCESS
                ):
                    raise OcrStoreError(
                        f"页面八项覆盖门禁未完全通过：{runtime_record.page_id}"
                    )
                coverage_records.append(coverage_record)
            bundle = evidence_store.persist_summaries(
                coverage_records,
                expected_source_pages=snapshot.selected_pages,
            )
            with _ocr_jobs_lock:
                job["coverage_summary"] = dict(bundle.coverage)
                job["coverage_sha256"] = bundle.coverage_sha256
                job["page_records_sha256"] = bundle.page_records_sha256
                _bump_ocr_state(job)
            return bundle

        def _finalize_v2_ocr(store, snapshot):
            from ..core.ocr_baseline import compile_ocr_baseline
            from ..ocr import merge_raw_ocr_book

            with _ocr_jobs_lock:
                job["phase"] = "正在核验逐页八项覆盖并冻结 OCR 原稿"
                _bump_ocr_state(job)
            coverage_bundle = _ensure_v2_page_coverage(store, snapshot)
            for final_record in store.list_records(snapshot.run_id):
                _record_v2_final_page_metric(snapshot, final_record)
            figure_assets, figure_manifest = store.materialize_figure_assets(
                snapshot.run_id
            )
            raw_manifest = store.freeze_raw_ocr(
                snapshot.run_id,
                document_builder=merge_raw_ocr_book,
                model_usage=job.get("usage") or {},
                merge_version="2.0.0",
                figure_manifest=figure_manifest,
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
                from ..core.ocr_baseline import build_source_preview_pdf

                manifest = store.save_compile_baseline(
                    snapshot.run_id,
                    baseline_tex=raw_tex,
                    compile_log=(
                        "SOURCE_PREVIEW：这不是 LaTeX 编译结果；旧兼容适配器未执行基线编译。"
                    ),
                    preview_status=OcrPreviewStatus.SOURCE_PREVIEW,
                    exit_code=1,
                    successful_passes=0,
                    pdf_bytes=build_source_preview_pdf(raw_tex),
                    preview_filename="source-preview.pdf",
                )
                with _ocr_jobs_lock:
                    job["compile_status"] = OcrPreviewStatus.SOURCE_PREVIEW.value
                    job["baseline_compile"] = manifest
                    job["baseline_tex_sha256"] = manifest.get("baseline_tex_sha256")
                    job["raw_ocr_sha256"] = raw_manifest.get("raw_ocr_sha256")
                    job["ocr_baseline_manifest_required"] = (
                        _exact_ocr_manifest_required(snapshot)
                    )
                    job["ocr_baseline_manifest_status"] = (
                        "BLOCKED_NO_REAL_COMPILE"
                        if job["ocr_baseline_manifest_required"]
                        else "UNAVAILABLE_NON_EXACT_BUILD"
                    )
                    _bump_ocr_state(job)
                return
            compile_started = time.perf_counter()
            try:
                baseline = compile_ocr_baseline(
                    raw_tex,
                    extra_files=figure_assets,
                    selected_pages=snapshot.selected_pages,
                )
            except Exception:
                _record_v2_stage(
                    "compilation",
                    duration_ms=(time.perf_counter() - compile_started) * 1000.0,
                    succeeded=False,
                )
                raise
            _record_v2_stage(
                "compilation",
                duration_ms=(time.perf_counter() - compile_started) * 1000.0,
                succeeded=(baseline.preview_status == OcrPreviewStatus.COMPILED),
            )
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
                extra_files=figure_assets,
            )
            manifest_required = _exact_ocr_manifest_required(snapshot)
            verified_baseline = None
            if manifest_required:
                try:
                    verified_baseline = _persist_recomputable_ocr_baseline(
                        store,
                        snapshot,
                        coverage_bundle,
                        baseline,
                        job.get("_v2_metrics_collector"),
                        created_at=str(manifest.get("created_at") or ""),
                    )
                except Exception as exc:  # noqa: BLE001 - exact builds fail closed
                    with _ocr_jobs_lock:
                        job["ocr_baseline_manifest_required"] = True
                        job["ocr_baseline_manifest_status"] = "FAILED"
                        job["ocr_baseline_manifest_error"] = _safe_task_error(exc)
                        _bump_ocr_state(job)
                    raise
            with _ocr_jobs_lock:
                job["compile_status"] = baseline.preview_status.value
                job["baseline_compile"] = manifest
                job["baseline_tex_sha256"] = manifest.get("baseline_tex_sha256")
                job["raw_ocr_sha256"] = raw_manifest.get("raw_ocr_sha256")
                job["ocr_baseline_manifest_required"] = manifest_required
                if verified_baseline is not None:
                    verified_payload = verified_baseline.manifest.to_dict()
                    job["ocr_baseline_manifest_status"] = "VERIFIED"
                    job["ocr_baseline_manifest_sha256"] = (
                        verified_baseline.manifest.sha256
                    )
                    job["ocr_baseline_run_status"] = str(
                        (verified_payload.get("status") or {}).get("run_status") or ""
                    )
                    job["ocr_baseline_ocr_status"] = str(
                        (verified_payload.get("status") or {}).get("ocr_status") or ""
                    )
                else:
                    job["ocr_baseline_manifest_status"] = (
                        "UNAVAILABLE_NON_EXACT_BUILD"
                    )
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
            with _ocr_jobs_lock:
                job["pages"][page_no]["recovery_run_id"] = hashlib.sha256(
                    (
                        f"{snapshot.run_id}:{record.page_id}:manual:"
                        f"{uuid.uuid4().hex}"
                    ).encode("utf-8")
                ).hexdigest()
                _bump_ocr_state(job)
            request = _prepare_v2_request(
                store,
                snapshot,
                record,
                retry=True,
                recovery_stage=RecoveryStage.INITIAL_READ,
            )
            execution = BoundedOcrExecutor(batch_size=1, concurrency_limit=1).run(
                [request],
                single_call=lambda item: _v2_model_call(client, [item]),
            )[0]
            final, exhausted = _retry_v2_execution(store, snapshot, client, execution)
            ok = _commit_v2_result(store, snapshot, final, exhausted=exhausted)
            remaining = store.list_records(snapshot.run_id)
            if all(item.status == OcrPageStatus.SUCCESS for item in remaining):
                _finalize_v2_ocr(store, snapshot)
            _merge_job(job)
            return ok

        def worker():
            try:
                client, selected_model, backend = _build_ocr_client(
                    launch_cfg, base_url, model, api_key,
                )
                from .. import __version__
                from ..core.ocr_pipeline import (
                    classify_source_pages,
                    estimate_ocr_requests,
                    visual_strict_fallback_classification,
                )
                from ..core.ocr_scheduler import scheduler_profile

                source_bytes = Path(job["target"]).read_bytes()
                visual_source_bytes = (
                    Path(job["visual_target"]).read_bytes()
                    if job.get("source_type") == "images" and job.get("visual_target")
                    else b""
                )
                classification_error = ""
                classification_started = time.perf_counter()
                try:
                    source_classification = classify_source_pages(
                        source_type=str(job.get("source_type") or ""),
                        source_bytes=source_bytes,
                        selected_pages=tuple(page_nos),
                        visual_source_bytes=visual_source_bytes,
                    )
                except Exception as exc:  # noqa: BLE001 - extraction failure forces visual OCR
                    classification_error = _safe_task_error(exc)
                    source_classification = visual_strict_fallback_classification(
                        source_type=str(job.get("source_type") or ""),
                        source_bytes=source_bytes,
                        selected_pages=tuple(page_nos),
                    )
                classification_elapsed_ms = (
                    time.perf_counter() - classification_started
                ) * 1000.0
                classification_pages = source_classification.snapshot_contract_pages()
                scheduler_contract = scheduler_profile(quality_tier.value)
                producer_identity = dict(job.get("producer_identity") or {})
                producer_commit = str(producer_identity.get("commit") or "unknown")
                producer_build_id = str(producer_identity.get("build_id") or "unknown")
                pipeline_contract = {
                    "project_id": "",
                    "document_strategy": source_classification.document_strategy.value,
                    "page_strategies": classification_pages,
                    "verification_model": selected_model,
                    "strong_model": selected_model,
                    "prompt_version": _ocr_prompt_version(),
                    "response_schema_version": "latexstruct-ocr-page-response-v2",
                    "git_commit": producer_commit,
                    "build_id": producer_build_id,
                    "dirty": bool(
                        producer_commit == "unknown" or producer_build_id == "unknown"
                    ),
                    "latex_engine": "xelatex",
                    "verification_dpi": 160,
                    "full_ocr_dpi": tier_policy.initial_dpi,
                    "retry_dpi": tier_policy.retry_dpi,
                    "verification_batch_size": 4,
                    "ocr_batch_size": tier_policy.batch_size,
                    "concurrency_limit": tier_policy.concurrency_limit,
                    "target_30_min_applicable": bool(
                        quality_tier.value == "recommended"
                        and len(page_nos) == 600
                    ),
                    "target_30_min_not_applicable_reason": (
                        "" if quality_tier.value == "recommended" and len(page_nos) == 600
                        else "requires an authorized real 600-page recommended-tier run"
                    ),
                    "scheduler_profile": scheduler_contract.to_dict(),
                }
                request_estimate = estimate_ocr_requests(
                    source_classification,
                    verifier_batch_size=4,
                    full_ocr_batch_size=tier_policy.batch_size,
                )
                with _ocr_jobs_lock:
                    job["document_strategy"] = (
                        source_classification.document_strategy.value
                    )
                    job["page_strategy_counts"] = (
                        source_classification.strategy_counts
                    )
                    job["request_estimate"] = request_estimate
                    job["scheduler_profile"] = scheduler_contract.to_dict()
                    job["classification_error"] = classification_error
                    job["current_strategy"] = "对象层分类与候选生成"
                    job["verification_dpi"] = 160
                    job["full_ocr_dpi"] = tier_policy.initial_dpi
                    job["retry_dpi"] = tier_policy.retry_dpi
                    for classification in source_classification.pages:
                        page_state = job["pages"][classification.source_page_number]
                        page_state.update({
                            "page_strategy": classification.strategy.value,
                            "source_page_object_hash": (
                                classification.source_page_object_hash
                            ),
                            "source_text_layer_sha256": (
                                classification.source_text_layer_sha256
                            ),
                            "candidate_tex": classification.candidate_tex,
                            "candidate_tex_sha256": hashlib.sha256(
                                classification.candidate_tex.encode("utf-8")
                            ).hexdigest(),
                            "candidate_blocks": [
                                block.to_dict() for block in classification.blocks
                            ],
                            "page_features": classification.features.to_dict(),
                            "candidate_strategy": "OBJECT_LAYER",
                        })
                    _bump_ocr_state(job)
                store = OcrRunStore(Path(get_store().root).parent / "ocr-runs")
                snapshot_path = store.run_dir(job["id"]) / "run-snapshot.json"
                if snapshot_path.is_file():
                    snapshot = store.load_snapshot(job["id"])
                    stored_contract = thaw_json(snapshot.pipeline_contract)
                    stored_page_strategies = (
                        stored_contract.get("page_strategies")
                        if isinstance(stored_contract, dict)
                        else None
                    )
                    if (
                        snapshot.source_sha256 != hashlib.sha256(source_bytes).hexdigest()
                        or snapshot.selected_pages != tuple(page_nos)
                        or snapshot.ocr_model != selected_model
                        or snapshot.api_backend != backend
                        or (
                            stored_page_strategies
                            and stored_page_strategies != classification_pages
                        )
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
                        page_sizes=source_classification.snapshot_page_sizes(),
                        text_layer_status=source_classification.text_layer_status,
                        source_images=tuple(job.get("source_images") or ()),
                        visual_source_bytes=visual_source_bytes,
                        runtime_options={
                            "initial_dpi": tier_policy.initial_dpi,
                            "max_retries": tier_policy.max_retries,
                            "batch_size": tier_policy.batch_size,
                            "concurrency_limit": tier_policy.concurrency_limit,
                            "retry_dpi": tier_policy.retry_dpi,
                            "verification_dpi": 160,
                            "verification_batch_size": 4,
                        },
                        pipeline_contract=pipeline_contract,
                        run_id=job["id"],
                    )
                    store.initialize(
                        snapshot,
                        source_bytes,
                        visual_source_bytes=visual_source_bytes,
                    )
                records = store.recover(snapshot.run_id)
                from ..core.ocr_metrics import OcrMetricsCollector

                collector = job.get("_v2_metrics_collector")
                if not isinstance(collector, OcrMetricsCollector):
                    try:
                        metrics_started_at = datetime.fromisoformat(
                            snapshot.started_at.replace("Z", "+00:00")
                        ).timestamp()
                    except (AttributeError, TypeError, ValueError):
                        metrics_started_at = time.time()
                    collector = OcrMetricsCollector(
                        snapshot.run_id,
                        selected_pages=len(snapshot.selected_pages),
                        started_at_seconds=metrics_started_at,
                        clock=time.time,
                    )
                    collector.record_stage_execution(
                        "object_extraction",
                        duration_ms=classification_elapsed_ms,
                        items=len(snapshot.selected_pages),
                        succeeded=True,
                    )
                with _ocr_jobs_lock:
                    job["client"] = client
                    job["model"] = selected_model
                    job["backend"] = backend
                    job["_v2_store"] = store
                    job["_v2_snapshot"] = snapshot
                    job["_v2_source_classification"] = source_classification
                    job["_v2_metrics_collector"] = collector
                    job["_v2_retry_page"] = _retry_v2_page
                    job["started_at"] = snapshot.started_at
                    job["phase"] = "三页批处理 OCR；失败页自动提高清晰度重试"
                    _bump_ocr_state(job)
                configured_key = str(
                    getattr(getattr(client, "cfg", None), "api_key", "") or ""
                )
                compatibility_single = backend == "api" and not configured_key
                configured_batch_size = (
                    1 if compatibility_single else snapshot.batch_size
                )
                configured_concurrency_limit = (
                    1 if compatibility_single else snapshot.concurrency_limit
                )
                limiter = AdaptivePageConcurrency(
                    maximum=configured_concurrency_limit,
                )
                with _ocr_jobs_lock:
                    job["_compatibility_single"] = compatibility_single
                    _ocr_adaptive_limiters[job["id"]] = limiter
                    job["current_concurrency_limit"] = limiter.current
                    job["current_batch_size"] = configured_batch_size
                    _bump_ocr_state(job)
                frozen_pipeline_contract = thaw_json(snapshot.pipeline_contract)
                if (
                    isinstance(frozen_pipeline_contract, dict)
                    and frozen_pipeline_contract.get("page_strategies")
                ):
                    _run_v2_visual_fast_path(
                        store,
                        snapshot,
                        client,
                        source_classification,
                    )
                records = store.list_records(snapshot.run_id)
                pending = [
                    record for record in records
                    if record.status in {
                        OcrPageStatus.PENDING,
                        OcrPageStatus.RETRYING,
                        OcrPageStatus.FAILED,
                        OcrPageStatus.VERIFYING,
                    }
                ]
                frozen_contract = thaw_json(snapshot.pipeline_contract)
                render_pool_contract = (
                    ((frozen_contract.get("scheduler_profile") or {}).get("pools") or {}).get(
                        "rendering"
                    )
                    if isinstance(frozen_contract, dict)
                    else None
                )
                try:
                    render_workers = int(
                        (render_pool_contract or {}).get("initial_workers")
                        or OCR_RENDER_PREPARE_DEFAULT_WORKERS
                    )
                except (AttributeError, TypeError, ValueError):
                    render_workers = OCR_RENDER_PREPARE_DEFAULT_WORKERS
                render_workers = max(
                    OCR_RENDER_PREPARE_MIN_WORKERS,
                    min(OCR_RENDER_PREPARE_MAX_WORKERS, render_workers),
                )
                next_execution_budget = {
                    "batch_size": configured_batch_size,
                    "concurrency": configured_concurrency_limit,
                }

                def _next_prepare_batch_limit() -> int:
                    effective_batch_size, effective_concurrency = (
                        _ocr_adaptive_budgets(
                            limiter,
                            configured_batch_size=configured_batch_size,
                            configured_concurrency_limit=configured_concurrency_limit,
                        )
                    )
                    next_execution_budget["batch_size"] = effective_batch_size
                    next_execution_budget["concurrency"] = effective_concurrency
                    with _ocr_jobs_lock:
                        job["current_batch_size"] = effective_batch_size
                        job["current_concurrency_limit"] = effective_concurrency
                        _bump_ocr_state(job)
                    return effective_batch_size

                def _resolve_pending_record(record):
                    current = store.load_record(snapshot.run_id, record.page_id)
                    if current.status is OcrPageStatus.SUCCESS:
                        return None
                    if current.status not in {
                        OcrPageStatus.PENDING,
                        OcrPageStatus.RETRYING,
                        OcrPageStatus.FAILED,
                        OcrPageStatus.VERIFYING,
                    }:
                        raise OcrStoreError(
                            f"页面 {current.page_id} 在渲染前进入非法状态 "
                            f"{current.status.value}"
                        )
                    return current

                def _prepare_pending_record(record):
                    return _prepare_v2_render(
                        store,
                        snapshot,
                        record,
                        retry=record.status in {
                            OcrPageStatus.RETRYING,
                            OcrPageStatus.FAILED,
                        },
                    )

                def _record_prepare_failure(record, exc):
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

                def _consume_prepared_batch(prepared_batch):
                    _ocr_control(job)
                    requests = []
                    for record, prepared in prepared_batch:
                        try:
                            requests.append(
                                _dispatch_v2_render(store, snapshot, prepared)
                            )
                        except Exception as exc:  # noqa: BLE001 - page-local dispatch
                            _record_prepare_failure(record, exc)
                    if not requests:
                        return
                    effective_batch_size = max(
                        1,
                        min(int(next_execution_budget["batch_size"]), len(requests)),
                    )
                    effective_concurrency = max(
                        1,
                        min(
                            int(next_execution_budget["concurrency"]),
                            configured_concurrency_limit,
                        ),
                    )
                    executor = BoundedOcrExecutor(
                        batch_size=effective_batch_size,
                        concurrency_limit=effective_concurrency,
                    )
                    recovery_contexts = []
                    recovery_contexts_lock = threading.Lock()

                    def _publish_terminal_execution(final, exhausted):
                        _commit_v2_result(
                            store, snapshot, final, exhausted=exhausted
                        )
                        with _ocr_jobs_lock:
                            job["done"] = sum(
                                page.get("status") in {"done", "error"}
                                for page in job["pages"].values()
                            )
                            _bump_ocr_state(job)

                    def _persist_completed_execution(execution):
                        execution = _ocr_attach_batch_attempt_alias(job, execution)
                        context = _begin_v2_recovery(
                            store, snapshot, execution
                        )
                        if _v2_context_should_retry(snapshot, context):
                            with recovery_contexts_lock:
                                recovery_contexts.append(context)
                        else:
                            current = context["current"]
                            _publish_terminal_execution(
                                current,
                                bool(
                                    current.page is not None
                                    and current.page.needs_retry
                                ),
                            )

                    executor.run(
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
                        on_result=_persist_completed_execution,
                        on_batch_attempt=lambda attempt: _ocr_record_batch_attempt(
                            job, store, snapshot, attempt
                        ),
                    )
                    # No recovery call starts until every result in the current
                    # initial wave has reached its append-only journal or final
                    # page record. Subsequent levels remain wave-synchronous.
                    _drain_v2_recovery_waves(
                        store,
                        snapshot,
                        client,
                        recovery_contexts,
                        on_terminal=_publish_terminal_execution,
                    )

                render_stats = _run_bounded_page_prepare_pool(
                    pending,
                    selected_index=lambda record: record.task_index,
                    page_id=lambda record: record.page_id,
                    resolve_page=_resolve_pending_record,
                    prepare_page=_prepare_pending_record,
                    consume_batch=_consume_prepared_batch,
                    batch_limit=_next_prepare_batch_limit,
                    control=lambda: _ocr_control(job),
                    on_prepare_error=_record_prepare_failure,
                    workers=render_workers,
                )
                with _ocr_jobs_lock:
                    job["render_prepare_pool"] = dict(render_stats)
                    _bump_ocr_state(job)
                final_records = store.list_records(snapshot.run_id)
                errors = [
                    record for record in final_records
                    if record.status in {OcrPageStatus.FAILED, OcrPageStatus.CANCELLED}
                ]
                if not errors and all(
                    record.status == OcrPageStatus.SUCCESS for record in final_records
                ):
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
                _ocr_adaptive_limiters.pop(jid, None)
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
        prior_terminal_status = "partial"
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
                # The immutable raw artifact is the terminal OCR authority.  A
                # recovered job intentionally has no live provider client, but
                # that must not turn an immutable-page rejection into the less
                # precise "not initialized" error or leave room for a later
                # client bootstrap to mutate the frozen run.
                if job.get("raw_frozen"):
                    raise HTTPException(
                        409,
                        "OCR 原稿已经冻结；如需重做请创建新的 OCR 任务",
                    )
                prior_terminal_status = str(job.get("status") or "partial")
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
                    # An immutable-page rejection performs no OCR, compile, or
                    # freeze transition.  Restore the exact pre-retry terminal
                    # state; raw_frozen alone must never promote SOURCE_PREVIEW
                    # to a completed/compiled job.
                    job["status"] = (
                        prior_terminal_status
                        if prior_terminal_status not in OCR_ACTIVE_STATUSES
                        else "partial"
                    )
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
                if job.get("raw_frozen"):
                    raise HTTPException(
                        409,
                        "OCR 原稿已经冻结；如需重做请创建新的 OCR 任务",
                    )
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
                    if (
                        job["pages"][page_no].get("status") != "done"
                        or job["pages"][page_no].get("needs_review") is True
                        or job["pages"][page_no].get("low_conf") is True
                    )
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
        start_analysis: bool = True,
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
                    "start_analysis": bool(start_analysis),
                }
                import_snapshot = _snapshot_ocr_bundle_job(job)
                baseline_runtime = {
                    "_v2_store": job.get("_v2_store"),
                    "_v2_snapshot": job.get("_v2_snapshot"),
                    "raw_tex": job.get("raw_tex"),
                }
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
        # v2 分析从已经两遍实编译的纯语法 baseline 开始；不可变 raw OCR
        # 另存为 original-source.tex 并保留独立 lineage，二者绝不混写。
        pid = ""
        process_started = False
        try:
            # Hashing hundreds of rendered pages can take noticeable time.  It
            # must happen after the immutable snapshot/importing flag is frozen,
            # but outside the global OCR lock so other jobs can still poll,
            # pause, and finish their current page.
            verified_snapshot = _verified_ocr_bundle_snapshot(import_snapshot)
            try:
                analysis_source_tex, baseline_lineage = _verified_v2_baseline_for_analysis(
                    baseline_runtime
                )
            except (OcrStoreError, OSError, ValueError) as exc:
                raise HTTPException(
                    409,
                    "OCR 双遍编译基线缺失或校验失败；请重新完成 OCR 基线编译后再分析",
                ) from exc
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
                analysis_source_tex,
                name,
                mode,
                template,
                kind="ocr",
                template_title=title or name,
                original_source=raw_tex.encode("utf-8"),
                source_format={
                    "encoding": "utf-8",
                    "newline": "lf",
                    "role": "immutable_raw_ocr",
                },
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
            resource_result["recovery_evidence"] = (
                _preserve_ocr_recovery_evidence(import_snapshot, project_dir)
            )
            resource_result["baseline_evidence"] = (
                _preserve_ocr_baseline_package(baseline_runtime, project_dir)
            )
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
            meta["ocr_recovery"] = {
                "pages": [
                    {
                        "source_page": row.get("source_page"),
                        "recovery": deepcopy(
                            (row.get("telemetry") or {}).get("recovery") or {}
                        ),
                    }
                    for row in _ocr_manifest_page_records(import_snapshot)
                ],
                "evidence_files": len(
                    resource_result.get("recovery_evidence") or []
                ),
            }
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
            meta["ocr_baseline_lineage"] = baseline_lineage
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
                        "ocr_recovery": deepcopy(meta.get("ocr_recovery") or {}),
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
            if not start_analysis:
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
                        current["baseline_project_id"] = pid
                        current["imported_options"] = import_options
                        current["imported_processed"] = False
                        _bump_ocr_state(current)
                return {
                    "id": pid,
                    "processed": False,
                    "process": None,
                    "analysis_started": False,
                    "ocr_snapshot_id": ocr_submission.snapshot_id,
                }
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

    @app.post("/api/ocr/jobs/{jid}/open")
    def ocr_open_without_analysis(
        jid: str,
        name: str = "OCR 基线项目",
    ):
        """Create/open the verified OCR baseline without starting analysis."""
        return ocr_import(
            jid=jid,
            name=name,
            mode="rule",
            template="faithfulbook",
            title="",
            start_analysis=False,
        )

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

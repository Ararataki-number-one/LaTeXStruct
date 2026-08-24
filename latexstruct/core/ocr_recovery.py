# -*- coding: utf-8 -*-
"""Append-only evidence and deterministic recovery stages for OCR v2.

The OCR runtime owns model calls.  This module owns the durable evidence for
those calls: every page image, crop and raw response is content-addressed;
every error, usage object and duration is hashed; and attempt records form an
append-only hash chain.  Mutable ``state.json`` files are only caches.  They
can always be rebuilt from the attempt journal after an interrupted write.

No model can promote a page to success here.  In particular, an independent
second read whose TeX hash differs from its host-selected comparison target is
always summarized as ``NEEDS_REVIEW``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping, Sequence


OCR_RECOVERY_ATTEMPT_SCHEMA = "latexstruct-ocr-recovery-attempt-v2"
OCR_RECOVERY_STATE_SCHEMA = "latexstruct-ocr-recovery-state-v2"
OCR_RECOVERY_SUMMARY_SCHEMA = "latexstruct-ocr-recovery-summary-v2"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
_PAGE_ID_RE = re.compile(r"^ocr-page-[0-9]{6}$")
_ATTEMPT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{7,63}$")


class RecoveryEvidenceError(ValueError):
    """Raised when an append-only recovery journal fails integrity checks."""


class RecoveryStage(str, Enum):
    """Initial read plus the five host-authoritative recovery levels."""

    INITIAL_READ = "INITIAL_READ"
    SAME_DPI_RETRY = "SAME_DPI_RETRY"
    BATCH_TO_SINGLE = "BATCH_TO_SINGLE"
    DPI_300_RETRY = "DPI_300_RETRY"
    PAGE_WITH_CROPS = "PAGE_WITH_CROPS"
    INDEPENDENT_SECOND_READ = "INDEPENDENT_SECOND_READ"


RECOVERY_LEVELS = (
    RecoveryStage.SAME_DPI_RETRY,
    RecoveryStage.BATCH_TO_SINGLE,
    RecoveryStage.DPI_300_RETRY,
    RecoveryStage.PAGE_WITH_CROPS,
    RecoveryStage.INDEPENDENT_SECOND_READ,
)


class AttemptOutcome(str, Enum):
    PASSED = "PASSED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    PAUSED = "PAUSED"
    FAILED = "FAILED"
    CONFLICT = "CONFLICT"
    CANCELLED = "CANCELLED"


class RecoveryPageStatus(str, Enum):
    PENDING = "PENDING"
    RETRYING = "RETRYING"
    SUCCESS = "SUCCESS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    PAUSED = "PAUSED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RecoveryImageRole(str, Enum):
    FULL_PAGE = "FULL_PAGE"
    CROP = "CROP"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("recovery evidence must be finite JSON data") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_sha256(value: object, label: str, *, allow_empty: bool = False) -> str:
    digest = str(value or "").strip().lower()
    if allow_empty and not digest:
        return ""
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _freeze_json(value: object) -> object:
    # Canonical serialization is also the validation boundary.  Round-tripping
    # prevents callers from retaining mutable aliases inside durable records.
    result = json.loads(_canonical_json(value))
    return _freeze_loaded(result)


def _freeze_loaded(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({str(key): _freeze_loaded(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_loaded(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def _safe_storage_key(value: object) -> str:
    key = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(key)
    if not key or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError("evidence storage_key must be a safe relative path")
    return path.as_posix()


def _as_stage(value: object) -> RecoveryStage:
    if isinstance(value, RecoveryStage):
        return value
    try:
        return RecoveryStage(str(value))
    except ValueError as exc:
        raise ValueError(f"unknown OCR recovery stage: {value!r}") from exc


def next_stage(
    current: RecoveryStage | str | None,
    *,
    source_was_batched: bool = True,
    crops_available: bool = True,
    independent_second_read: bool = True,
) -> RecoveryStage | None:
    """Return the next legal host recovery stage without mutating any state.

    ``None`` means that the initial visual read has not run yet.  The second
    recovery level is skipped for a source call that was already single-page;
    crop and independent-read levels may likewise be disabled by host policy.
    """

    if current is None:
        return RecoveryStage.INITIAL_READ
    stage = _as_stage(current)
    if stage is RecoveryStage.INITIAL_READ:
        return RecoveryStage.SAME_DPI_RETRY
    if stage is RecoveryStage.SAME_DPI_RETRY:
        if source_was_batched:
            return RecoveryStage.BATCH_TO_SINGLE
        return RecoveryStage.DPI_300_RETRY
    if stage is RecoveryStage.BATCH_TO_SINGLE:
        return RecoveryStage.DPI_300_RETRY
    if stage is RecoveryStage.DPI_300_RETRY:
        if crops_available:
            return RecoveryStage.PAGE_WITH_CROPS
        if independent_second_read:
            return RecoveryStage.INDEPENDENT_SECOND_READ
        return None
    if stage is RecoveryStage.PAGE_WITH_CROPS:
        if independent_second_read:
            return RecoveryStage.INDEPENDENT_SECOND_READ
        return None
    return None


@dataclass(frozen=True, slots=True)
class EvidenceBlob:
    sha256: str
    size_bytes: int
    media_type: str
    storage_key: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "sha256", _validate_sha256(self.sha256, "blob sha256"))
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
            raise ValueError("blob size_bytes must be an integer")
        if self.size_bytes < 0:
            raise ValueError("blob size_bytes cannot be negative")
        media_type = str(self.media_type or "application/octet-stream").strip().lower()
        if "/" not in media_type:
            raise ValueError("blob media_type is invalid")
        object.__setattr__(self, "media_type", media_type)
        object.__setattr__(self, "storage_key", _safe_storage_key(self.storage_key))

    def to_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "storage_key": self.storage_key,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EvidenceBlob":
        return cls(
            sha256=value.get("sha256", ""),
            size_bytes=value.get("size_bytes", -1),
            media_type=value.get("media_type", "application/octet-stream"),
            storage_key=value.get("storage_key", ""),
        )


@dataclass(frozen=True, slots=True)
class RecoveryImageInput:
    role: RecoveryImageRole
    content: bytes = field(repr=False)
    dpi: int = 200
    width_pixels: int = 1
    height_pixels: int = 1
    crop_id: str = ""
    bbox_pixels: tuple[int, int, int, int] | None = None
    source_image_sha256: str = ""
    region_type: str = ""
    media_type: str = "image/png"

    def __post_init__(self) -> None:
        role = (
            self.role
            if isinstance(self.role, RecoveryImageRole)
            else RecoveryImageRole(str(self.role))
        )
        content = bytes(self.content)
        if not content:
            raise ValueError("recovery image content cannot be empty")
        if not 72 <= int(self.dpi) <= 600:
            raise ValueError("recovery image DPI must be in 72..600")
        if int(self.width_pixels) < 1 or int(self.height_pixels) < 1:
            raise ValueError("recovery image dimensions must be positive")
        bbox = tuple(self.bbox_pixels) if self.bbox_pixels is not None else None
        source_hash = _validate_sha256(
            self.source_image_sha256, "crop source image sha256", allow_empty=True
        )
        crop_id = str(self.crop_id or "").strip()
        region_type = str(self.region_type or "").strip()
        if role is RecoveryImageRole.FULL_PAGE:
            if bbox is not None or crop_id or source_hash or region_type:
                raise ValueError("full-page evidence cannot carry crop metadata")
        else:
            if not crop_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", crop_id):
                raise ValueError("crop evidence requires a stable crop_id")
            if (
                bbox is None
                or len(bbox) != 4
                or any(not isinstance(item, int) or isinstance(item, bool) for item in bbox)
            ):
                raise ValueError("crop evidence requires a four-integer bbox")
            x0, y0, x1, y1 = bbox
            if min(x0, y0) < 0 or x1 <= x0 or y1 <= y0:
                raise ValueError("crop bbox is invalid")
            if not source_hash or not region_type:
                raise ValueError("crop evidence requires source hash and region_type")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "content", content)
        object.__setattr__(self, "dpi", int(self.dpi))
        object.__setattr__(self, "width_pixels", int(self.width_pixels))
        object.__setattr__(self, "height_pixels", int(self.height_pixels))
        object.__setattr__(self, "crop_id", crop_id)
        object.__setattr__(self, "bbox_pixels", bbox)
        object.__setattr__(self, "source_image_sha256", source_hash)
        object.__setattr__(self, "region_type", region_type)


@dataclass(frozen=True, slots=True)
class RecoveryImageEvidence:
    role: RecoveryImageRole
    blob: EvidenceBlob
    dpi: int
    width_pixels: int
    height_pixels: int
    crop_id: str = ""
    bbox_pixels: tuple[int, int, int, int] | None = None
    source_image_sha256: str = ""
    region_type: str = ""

    def __post_init__(self) -> None:
        role = (
            self.role
            if isinstance(self.role, RecoveryImageRole)
            else RecoveryImageRole(str(self.role))
        )
        if not 72 <= int(self.dpi) <= 600:
            raise ValueError("recovery image DPI must be in 72..600")
        if int(self.width_pixels) < 1 or int(self.height_pixels) < 1:
            raise ValueError("recovery image dimensions must be positive")
        bbox = tuple(self.bbox_pixels) if self.bbox_pixels is not None else None
        source_hash = _validate_sha256(
            self.source_image_sha256, "crop source image sha256", allow_empty=True
        )
        if role is RecoveryImageRole.FULL_PAGE:
            if bbox is not None or self.crop_id or source_hash or self.region_type:
                raise ValueError("full-page evidence cannot carry crop metadata")
        else:
            if not self.crop_id or bbox is None or len(bbox) != 4:
                raise ValueError("crop evidence is incomplete")
            x0, y0, x1, y1 = bbox
            if min(x0, y0) < 0 or x1 <= x0 or y1 <= y0:
                raise ValueError("crop bbox is invalid")
            if not source_hash or not self.region_type:
                raise ValueError("crop evidence requires source hash and region type")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "dpi", int(self.dpi))
        object.__setattr__(self, "width_pixels", int(self.width_pixels))
        object.__setattr__(self, "height_pixels", int(self.height_pixels))
        object.__setattr__(self, "bbox_pixels", bbox)
        object.__setattr__(self, "source_image_sha256", source_hash)

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "blob": self.blob.to_dict(),
            "dpi": self.dpi,
            "width_pixels": self.width_pixels,
            "height_pixels": self.height_pixels,
            "crop_id": self.crop_id,
            "bbox_pixels": list(self.bbox_pixels) if self.bbox_pixels is not None else None,
            "source_image_sha256": self.source_image_sha256,
            "region_type": self.region_type,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RecoveryImageEvidence":
        blob = value.get("blob")
        if not isinstance(blob, Mapping):
            raise ValueError("recovery image blob is missing")
        bbox = value.get("bbox_pixels")
        return cls(
            role=value.get("role", ""),
            blob=EvidenceBlob.from_dict(blob),
            dpi=value.get("dpi", 0),
            width_pixels=value.get("width_pixels", 0),
            height_pixels=value.get("height_pixels", 0),
            crop_id=str(value.get("crop_id") or ""),
            bbox_pixels=tuple(bbox) if bbox is not None else None,
            source_image_sha256=str(value.get("source_image_sha256") or ""),
            region_type=str(value.get("region_type") or ""),
        )


@dataclass(frozen=True, slots=True)
class RecoveryAttempt:
    run_id: str
    page_id: str
    source_page: int
    task_index: int
    attempt_id: str
    sequence: int
    stage: RecoveryStage
    outcome: AttemptOutcome
    base_dpi: int
    dpi: int
    model: str
    backend: str
    model_context_id: str
    images: tuple[RecoveryImageEvidence, ...]
    response: EvidenceBlob | None
    started_at: str
    ended_at: str
    duration_ms: int
    duration_sha256: str
    usage: Mapping[str, object] = field(default_factory=dict, repr=False)
    usage_sha256: str = ""
    error: Mapping[str, object] = field(default_factory=dict, repr=False)
    error_sha256: str = ""
    tex_sha256: str = ""
    comparison_tex_sha256: str = ""
    is_batched: bool = False
    batch_id: str = ""
    batch_size: int = 1
    quality_issue_codes: tuple[str, ...] = ()
    unresolved_region_hashes: tuple[str, ...] = ()
    previous_attempt_sha256: str = ""
    record_sha256: str = ""
    schema_version: str = OCR_RECOVERY_ATTEMPT_SCHEMA

    def __post_init__(self) -> None:
        run_id = str(self.run_id or "").strip().lower()
        page_id = str(self.page_id or "").strip()
        attempt_id = str(self.attempt_id or "").strip().lower()
        if not _RUN_ID_RE.fullmatch(run_id):
            raise ValueError("recovery run_id must be 16-64 lowercase hex characters")
        if not _PAGE_ID_RE.fullmatch(page_id):
            raise ValueError("recovery page_id is invalid")
        if not _ATTEMPT_ID_RE.fullmatch(attempt_id):
            raise ValueError("recovery attempt_id is invalid")
        if (
            not isinstance(self.source_page, int)
            or isinstance(self.source_page, bool)
            or self.source_page < 1
        ):
            raise ValueError("source_page must be a positive integer")
        if (
            not isinstance(self.task_index, int)
            or isinstance(self.task_index, bool)
            or self.task_index < 1
        ):
            raise ValueError("task_index must be a positive integer")
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 1
        ):
            raise ValueError("attempt sequence must be a positive integer")
        stage = _as_stage(self.stage)
        outcome = (
            self.outcome
            if isinstance(self.outcome, AttemptOutcome)
            else AttemptOutcome(str(self.outcome))
        )
        base_dpi = int(self.base_dpi)
        dpi = int(self.dpi)
        if not 72 <= base_dpi <= 600 or not 72 <= dpi <= 600:
            raise ValueError("attempt DPI must be in 72..600")
        images = tuple(self.images)
        if not images or sum(item.role is RecoveryImageRole.FULL_PAGE for item in images) != 1:
            raise ValueError("each attempt requires exactly one full-page image")
        if any(item.dpi != dpi for item in images):
            raise ValueError("all attempt images must use the recorded attempt DPI")
        is_batched = bool(self.is_batched)
        batch_size = int(self.batch_size)
        batch_id = str(self.batch_id or "").strip()
        if is_batched:
            if batch_size < 2 or batch_size > 3 or not batch_id:
                raise ValueError("batched attempts require batch_id and batch_size in 2..3")
        elif batch_size != 1 or batch_id:
            raise ValueError("single-page attempts cannot carry batch metadata")
        if (
            stage in {RecoveryStage.SAME_DPI_RETRY, RecoveryStage.BATCH_TO_SINGLE}
            and dpi != base_dpi
        ):
            raise ValueError("same-DPI and batch-fallback attempts must keep the base DPI")
        if stage is RecoveryStage.BATCH_TO_SINGLE and is_batched:
            raise ValueError("batch fallback must be a single-page attempt")
        if (
            stage
            in {
                RecoveryStage.DPI_300_RETRY,
                RecoveryStage.PAGE_WITH_CROPS,
                RecoveryStage.INDEPENDENT_SECOND_READ,
            }
            and dpi < 300
        ):
            raise ValueError("high-resolution recovery stages require at least 300 DPI")
        crop_count = sum(item.role is RecoveryImageRole.CROP for item in images)
        if stage is RecoveryStage.PAGE_WITH_CROPS and crop_count < 1:
            raise ValueError("crop recovery requires at least one local crop")
        full_page_hash = next(
            item.blob.sha256 for item in images if item.role is RecoveryImageRole.FULL_PAGE
        )
        if any(
            item.role is RecoveryImageRole.CROP and item.source_image_sha256 != full_page_hash
            for item in images
        ):
            raise ValueError("every crop must be hash-bound to this attempt's full-page image")
        context_id = str(self.model_context_id or "").strip()
        if not context_id:
            raise ValueError("every OCR attempt requires a host-recorded model context id")
        tex_hash = _validate_sha256(self.tex_sha256, "attempt TeX sha256", allow_empty=True)
        comparison_hash = _validate_sha256(
            self.comparison_tex_sha256, "comparison TeX sha256", allow_empty=True
        )
        if stage is RecoveryStage.INDEPENDENT_SECOND_READ:
            if not context_id:
                raise ValueError("independent second read requires a context id")
        elif comparison_hash:
            raise ValueError("comparison hash belongs only to the fifth recovery level")
        if outcome in {
            AttemptOutcome.PASSED,
            AttemptOutcome.NEEDS_REVIEW,
            AttemptOutcome.CONFLICT,
        }:
            if self.response is None or not tex_hash:
                raise ValueError("successful/conflicting attempts require response and TeX hashes")
        error = _freeze_json(dict(self.error or {}))
        usage = _freeze_json(dict(self.usage or {}))
        error_hash = _sha256(_canonical_json(_thaw_json(error))) if error else ""
        usage_hash = _sha256(_canonical_json(_thaw_json(usage)))
        supplied_error_hash = _validate_sha256(
            self.error_sha256, "attempt error sha256", allow_empty=True
        )
        supplied_usage_hash = _validate_sha256(
            self.usage_sha256, "attempt usage sha256", allow_empty=True
        )
        if supplied_error_hash and supplied_error_hash != error_hash:
            raise ValueError("attempt error hash does not match error evidence")
        if supplied_usage_hash and supplied_usage_hash != usage_hash:
            raise ValueError("attempt usage hash does not match usage evidence")
        if (
            outcome
            in {
                AttemptOutcome.RETRYABLE_FAILURE,
                AttemptOutcome.PAUSED,
                AttemptOutcome.FAILED,
            }
            and not error
        ):
            raise ValueError("failed/paused attempts require structured error evidence")
        if int(self.duration_ms) < 0:
            raise ValueError("attempt duration cannot be negative")
        duration_payload = {
            "started_at": str(self.started_at or ""),
            "ended_at": str(self.ended_at or ""),
            "duration_ms": int(self.duration_ms),
        }
        if not duration_payload["started_at"] or not duration_payload["ended_at"]:
            raise ValueError("attempt start and end timestamps are required")
        duration_hash = _sha256(_canonical_json(duration_payload))
        supplied_duration_hash = _validate_sha256(
            self.duration_sha256, "attempt duration sha256", allow_empty=True
        )
        if supplied_duration_hash and supplied_duration_hash != duration_hash:
            raise ValueError("attempt duration hash does not match timing evidence")
        issues = tuple(
            sorted(set(str(item).strip() for item in self.quality_issue_codes if str(item).strip()))
        )
        unresolved = tuple(
            sorted(
                set(
                    _validate_sha256(item, "unresolved region sha256")
                    for item in self.unresolved_region_hashes
                )
            )
        )
        previous = _validate_sha256(
            self.previous_attempt_sha256, "previous attempt sha256", allow_empty=True
        )
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "page_id", page_id)
        object.__setattr__(self, "attempt_id", attempt_id)
        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "base_dpi", base_dpi)
        object.__setattr__(self, "dpi", dpi)
        object.__setattr__(self, "model", str(self.model or "").strip())
        object.__setattr__(self, "backend", str(self.backend or "").strip())
        object.__setattr__(self, "model_context_id", context_id)
        object.__setattr__(self, "images", images)
        object.__setattr__(self, "duration_ms", int(self.duration_ms))
        object.__setattr__(self, "duration_sha256", duration_hash)
        object.__setattr__(self, "usage", usage)
        object.__setattr__(self, "usage_sha256", usage_hash)
        object.__setattr__(self, "error", error)
        object.__setattr__(self, "error_sha256", error_hash)
        object.__setattr__(self, "tex_sha256", tex_hash)
        object.__setattr__(self, "comparison_tex_sha256", comparison_hash)
        object.__setattr__(self, "is_batched", is_batched)
        object.__setattr__(self, "batch_id", batch_id)
        object.__setattr__(self, "batch_size", batch_size)
        object.__setattr__(self, "quality_issue_codes", issues)
        object.__setattr__(self, "unresolved_region_hashes", unresolved)
        object.__setattr__(self, "previous_attempt_sha256", previous)
        object.__setattr__(self, "schema_version", OCR_RECOVERY_ATTEMPT_SCHEMA)
        calculated = _sha256(_canonical_json(self._payload()))
        supplied_record_hash = _validate_sha256(
            self.record_sha256, "attempt record sha256", allow_empty=True
        )
        if supplied_record_hash and supplied_record_hash != calculated:
            raise ValueError("attempt record hash does not match its evidence")
        object.__setattr__(self, "record_sha256", calculated)

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "page_id": self.page_id,
            "source_page": self.source_page,
            "task_index": self.task_index,
            "attempt_id": self.attempt_id,
            "sequence": self.sequence,
            "stage": self.stage.value,
            "outcome": self.outcome.value,
            "base_dpi": self.base_dpi,
            "dpi": self.dpi,
            "model": self.model,
            "backend": self.backend,
            "model_context_id": self.model_context_id,
            "images": [item.to_dict() for item in self.images],
            "response": self.response.to_dict() if self.response is not None else None,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "duration_sha256": self.duration_sha256,
            "usage": _thaw_json(self.usage),
            "usage_sha256": self.usage_sha256,
            "error": _thaw_json(self.error),
            "error_sha256": self.error_sha256,
            "tex_sha256": self.tex_sha256,
            "comparison_tex_sha256": self.comparison_tex_sha256,
            "is_batched": self.is_batched,
            "batch_id": self.batch_id,
            "batch_size": self.batch_size,
            "quality_issue_codes": list(self.quality_issue_codes),
            "unresolved_region_hashes": list(self.unresolved_region_hashes),
            "previous_attempt_sha256": self.previous_attempt_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._payload(), "record_sha256": self.record_sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RecoveryAttempt":
        if value.get("schema_version") != OCR_RECOVERY_ATTEMPT_SCHEMA:
            raise ValueError("unsupported OCR recovery attempt schema")
        images = value.get("images") or ()
        if not isinstance(images, Sequence) or isinstance(images, (str, bytes, bytearray)):
            raise ValueError("attempt images must be an array")
        response = value.get("response")
        if response is not None and not isinstance(response, Mapping):
            raise ValueError("attempt response evidence is invalid")
        return cls(
            run_id=value.get("run_id", ""),
            page_id=value.get("page_id", ""),
            source_page=value.get("source_page", 0),
            task_index=value.get("task_index", 0),
            attempt_id=value.get("attempt_id", ""),
            sequence=value.get("sequence", 0),
            stage=value.get("stage", ""),
            outcome=value.get("outcome", ""),
            base_dpi=value.get("base_dpi", 0),
            dpi=value.get("dpi", 0),
            model=value.get("model", ""),
            backend=value.get("backend", ""),
            model_context_id=value.get("model_context_id", ""),
            images=tuple(RecoveryImageEvidence.from_dict(item) for item in images),
            response=EvidenceBlob.from_dict(response) if response is not None else None,
            started_at=value.get("started_at", ""),
            ended_at=value.get("ended_at", ""),
            duration_ms=value.get("duration_ms", -1),
            duration_sha256=value.get("duration_sha256", ""),
            usage=value.get("usage") or {},
            usage_sha256=value.get("usage_sha256", ""),
            error=value.get("error") or {},
            error_sha256=value.get("error_sha256", ""),
            tex_sha256=value.get("tex_sha256", ""),
            comparison_tex_sha256=value.get("comparison_tex_sha256", ""),
            is_batched=bool(value.get("is_batched", False)),
            batch_id=value.get("batch_id", ""),
            batch_size=value.get("batch_size", 1),
            quality_issue_codes=tuple(value.get("quality_issue_codes") or ()),
            unresolved_region_hashes=tuple(value.get("unresolved_region_hashes") or ()),
            previous_attempt_sha256=value.get("previous_attempt_sha256", ""),
            record_sha256=value.get("record_sha256", ""),
        )


def second_read_status(
    comparison_tex_sha256: str,
    independent_tex_sha256: str,
    *,
    conflict_region_hashes: Sequence[str] = (),
) -> RecoveryPageStatus:
    """Fail closed: any fifth-level disagreement requires human review."""

    primary = _validate_sha256(comparison_tex_sha256, "comparison TeX sha256")
    independent = _validate_sha256(independent_tex_sha256, "independent TeX sha256")
    conflicts = tuple(
        _validate_sha256(item, "conflict region sha256") for item in conflict_region_hashes
    )
    if primary != independent or conflicts:
        return RecoveryPageStatus.NEEDS_REVIEW
    return RecoveryPageStatus.SUCCESS


@dataclass(frozen=True, slots=True)
class RecoveryPageState:
    run_id: str
    page_id: str
    status: RecoveryPageStatus
    current_stage: RecoveryStage | None
    next_stage: RecoveryStage | None
    attempt_count: int
    retry_count: int
    source_was_batched: bool
    conflict_detected: bool
    recoverable: bool
    last_attempt_sha256: str
    evidence_chain_sha256: str
    updated_at: str
    schema_version: str = OCR_RECOVERY_STATE_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "page_id": self.page_id,
            "status": self.status.value,
            "current_stage": self.current_stage.value if self.current_stage else None,
            "next_stage": self.next_stage.value if self.next_stage else None,
            "attempt_count": self.attempt_count,
            "retry_count": self.retry_count,
            "source_was_batched": self.source_was_batched,
            "conflict_detected": self.conflict_detected,
            "recoverable": self.recoverable,
            "last_attempt_sha256": self.last_attempt_sha256,
            "evidence_chain_sha256": self.evidence_chain_sha256,
            "updated_at": self.updated_at,
        }


def _sum_usage(attempts: Sequence[RecoveryAttempt]) -> dict[str, float | int]:
    totals: dict[str, float | int] = {}
    for attempt in attempts:
        for key, value in attempt.usage.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            totals[str(key)] = totals.get(str(key), 0) + value
    return totals


@dataclass(frozen=True, slots=True)
class RecoveryTerminalSummary:
    run_id: str
    page_id: str
    status: RecoveryPageStatus
    attempt_count: int
    retry_count: int
    total_duration_ms: int
    usage_totals: Mapping[str, float | int]
    stages_attempted: tuple[str, ...]
    stage_counts: Mapping[str, int]
    dpi_counts: Mapping[str, int]
    batch_call_count: int
    batch_to_single_count: int
    crop_call_count: int
    independent_read_count: int
    image_sha256s: tuple[str, ...]
    response_sha256s: tuple[str, ...]
    error_sha256s: tuple[str, ...]
    final_tex_sha256: str
    unresolved_region_hashes: tuple[str, ...]
    evidence_chain_sha256: str
    completed_at: str
    summary_sha256: str = ""
    schema_version: str = OCR_RECOVERY_SUMMARY_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in {
            RecoveryPageStatus.SUCCESS,
            RecoveryPageStatus.NEEDS_REVIEW,
            RecoveryPageStatus.PAUSED,
            RecoveryPageStatus.FAILED,
            RecoveryPageStatus.CANCELLED,
        }:
            raise ValueError("terminal summary requires a terminal or paused page status")
        usage = _freeze_json(dict(self.usage_totals))
        stage_counts = _freeze_json(dict(self.stage_counts))
        dpi_counts = _freeze_json(dict(self.dpi_counts))
        object.__setattr__(self, "usage_totals", usage)
        object.__setattr__(self, "stage_counts", stage_counts)
        object.__setattr__(self, "dpi_counts", dpi_counts)
        calculated = _sha256(_canonical_json(self._payload()))
        supplied = _validate_sha256(self.summary_sha256, "summary sha256", allow_empty=True)
        if supplied and supplied != calculated:
            raise ValueError("terminal summary hash does not match its evidence")
        object.__setattr__(self, "summary_sha256", calculated)

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "page_id": self.page_id,
            "status": self.status.value,
            "attempt_count": self.attempt_count,
            "retry_count": self.retry_count,
            "total_duration_ms": self.total_duration_ms,
            "usage_totals": _thaw_json(self.usage_totals),
            "stages_attempted": list(self.stages_attempted),
            "stage_counts": _thaw_json(self.stage_counts),
            "dpi_counts": _thaw_json(self.dpi_counts),
            "batch_call_count": self.batch_call_count,
            "batch_to_single_count": self.batch_to_single_count,
            "crop_call_count": self.crop_call_count,
            "independent_read_count": self.independent_read_count,
            "image_sha256s": list(self.image_sha256s),
            "response_sha256s": list(self.response_sha256s),
            "error_sha256s": list(self.error_sha256s),
            "final_tex_sha256": self.final_tex_sha256,
            "unresolved_region_hashes": list(self.unresolved_region_hashes),
            "evidence_chain_sha256": self.evidence_chain_sha256,
            "completed_at": self.completed_at,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._payload(), "summary_sha256": self.summary_sha256}


def derive_page_state(
    run_id: str,
    page_id: str,
    attempts: Sequence[RecoveryAttempt],
    *,
    crops_available: bool = True,
    independent_second_read: bool = True,
) -> RecoveryPageState:
    """Derive recoverable state only from the append-only attempt chain."""

    ordered = tuple(attempts)
    source_was_batched = any(item.is_batched for item in ordered)
    if not ordered:
        status = RecoveryPageStatus.PENDING
        current = None
        upcoming = next_stage(None)
        conflict = False
        recoverable = True
        last_hash = ""
        chain_hash = _sha256(b"")
        updated = _utc_now()
    else:
        last = ordered[-1]
        current = last.stage
        last_hash = last.record_sha256
        chain_hash = _sha256("".join(item.record_sha256 for item in ordered).encode("ascii"))
        updated = last.ended_at
        conflict = last.outcome is AttemptOutcome.CONFLICT
        if (
            last.stage is RecoveryStage.INDEPENDENT_SECOND_READ
            and last.tex_sha256
            and last.comparison_tex_sha256
        ):
            conflict = (
                conflict
                or second_read_status(
                    last.comparison_tex_sha256,
                    last.tex_sha256,
                    conflict_region_hashes=last.unresolved_region_hashes,
                )
                is RecoveryPageStatus.NEEDS_REVIEW
            )
        if conflict or last.outcome is AttemptOutcome.NEEDS_REVIEW:
            status = RecoveryPageStatus.NEEDS_REVIEW
            upcoming = None
            recoverable = False
        elif last.outcome is AttemptOutcome.PASSED:
            status = RecoveryPageStatus.SUCCESS
            upcoming = None
            recoverable = False
        elif last.outcome is AttemptOutcome.CANCELLED:
            status = RecoveryPageStatus.CANCELLED
            upcoming = None
            recoverable = False
        elif last.outcome is AttemptOutcome.PAUSED:
            status = RecoveryPageStatus.PAUSED
            upcoming = current
            recoverable = True
        elif last.outcome is AttemptOutcome.FAILED:
            status = RecoveryPageStatus.FAILED
            upcoming = current
            recoverable = True
        else:
            upcoming = next_stage(
                current,
                source_was_batched=source_was_batched,
                crops_available=crops_available,
                independent_second_read=independent_second_read,
            )
            if upcoming is None:
                status = RecoveryPageStatus.NEEDS_REVIEW
                recoverable = False
            else:
                status = RecoveryPageStatus.RETRYING
                recoverable = True
    return RecoveryPageState(
        run_id=run_id,
        page_id=page_id,
        status=status,
        current_stage=current,
        next_stage=upcoming,
        attempt_count=len(ordered),
        retry_count=max(0, len(ordered) - 1),
        source_was_batched=source_was_batched,
        conflict_detected=conflict,
        recoverable=recoverable,
        last_attempt_sha256=last_hash,
        evidence_chain_sha256=chain_hash,
        updated_at=updated,
    )


def build_terminal_summary(
    attempts: Sequence[RecoveryAttempt],
    state: RecoveryPageState,
) -> RecoveryTerminalSummary:
    ordered = tuple(attempts)
    if not ordered:
        raise ValueError("cannot summarize a page with no attempts")
    stage_counts = {stage.value: 0 for stage in RecoveryStage}
    dpi_counts: dict[str, int] = {}
    for item in ordered:
        stage_counts[item.stage.value] += 1
        dpi_counts[str(item.dpi)] = dpi_counts.get(str(item.dpi), 0) + 1
    return RecoveryTerminalSummary(
        run_id=state.run_id,
        page_id=state.page_id,
        status=state.status,
        attempt_count=len(ordered),
        retry_count=state.retry_count,
        total_duration_ms=sum(item.duration_ms for item in ordered),
        usage_totals=_sum_usage(ordered),
        stages_attempted=tuple(dict.fromkeys(item.stage.value for item in ordered)),
        stage_counts=stage_counts,
        dpi_counts=dpi_counts,
        batch_call_count=sum(item.is_batched for item in ordered),
        batch_to_single_count=sum(item.stage is RecoveryStage.BATCH_TO_SINGLE for item in ordered),
        crop_call_count=sum(item.stage is RecoveryStage.PAGE_WITH_CROPS for item in ordered),
        independent_read_count=sum(
            item.stage is RecoveryStage.INDEPENDENT_SECOND_READ for item in ordered
        ),
        image_sha256s=tuple(item.blob.sha256 for attempt in ordered for item in attempt.images),
        response_sha256s=tuple(
            item.response.sha256 for item in ordered if item.response is not None
        ),
        error_sha256s=tuple(item.error_sha256 for item in ordered if item.error_sha256),
        final_tex_sha256=ordered[-1].tex_sha256,
        unresolved_region_hashes=tuple(
            sorted(set(digest for item in ordered for digest in item.unresolved_region_hashes))
        ),
        evidence_chain_sha256=state.evidence_chain_sha256,
        completed_at=ordered[-1].ended_at,
    )


class OcrRecoveryEvidenceStore:
    """Content-addressed blob store plus one append-only journal per page."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @staticmethod
    def _validate_identity(run_id: object, page_id: object) -> tuple[str, str]:
        run = str(run_id or "").strip().lower()
        page = str(page_id or "").strip()
        if not _RUN_ID_RE.fullmatch(run) or not _PAGE_ID_RE.fullmatch(page):
            raise ValueError("invalid OCR recovery run/page identity")
        return run, page

    def _run_dir(self, run_id: str) -> Path:
        return self.root / run_id

    def _page_dir(self, run_id: str, page_id: str) -> Path:
        return self._run_dir(run_id) / "pages" / page_id

    def _blob_path(self, run_id: str, digest: str) -> Path:
        return self._run_dir(run_id) / "blobs" / digest[:2] / digest

    @staticmethod
    def _atomic_replace(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _atomic_create(path: Path, data: bytes) -> None:
        """Atomically create an immutable journal member without replacement."""

        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise RecoveryEvidenceError("attempt journal entry already exists") from exc
            except OSError:
                # Filesystems without hard-link support still get exclusive
                # creation.  A truncated fallback is detected on recovery and
                # can never be mistaken for a valid evidence event.
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                descriptor = os.open(path, flags, 0o600)
                try:
                    offset = 0
                    while offset < len(data):
                        offset += os.write(descriptor, data[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _persist_blob(self, run_id: str, content: bytes, media_type: str) -> EvidenceBlob:
        data = bytes(content)
        digest = _sha256(data)
        path = self._blob_path(run_id, digest)
        if path.exists():
            existing = path.read_bytes()
            if len(existing) != len(data) or _sha256(existing) != digest:
                raise RecoveryEvidenceError("content-addressed OCR evidence blob is corrupted")
        else:
            self._atomic_replace(path, data)
        relative = path.relative_to(self._run_dir(run_id)).as_posix()
        return EvidenceBlob(digest, len(data), media_type, relative)

    def record_attempt(
        self,
        *,
        run_id: str,
        page_id: str,
        source_page: int,
        task_index: int,
        stage: RecoveryStage | str,
        outcome: AttemptOutcome | str,
        base_dpi: int,
        dpi: int,
        model: str,
        backend: str,
        model_context_id: str,
        images: Sequence[RecoveryImageInput],
        raw_response: bytes | str | None,
        duration_ms: int,
        usage: Mapping[str, object] | None = None,
        error: Mapping[str, object] | str | None = None,
        tex_sha256: str = "",
        comparison_tex_sha256: str = "",
        is_batched: bool = False,
        batch_id: str = "",
        batch_size: int = 1,
        quality_issue_codes: Sequence[str] = (),
        unresolved_region_hashes: Sequence[str] = (),
        started_at: str | None = None,
        ended_at: str | None = None,
        attempt_id: str | None = None,
        crops_available: bool = True,
        independent_second_read: bool = True,
    ) -> RecoveryAttempt:
        """Hash, persist and append exactly one completed model attempt."""

        run, page = self._validate_identity(run_id, page_id)
        with self._lock:
            existing, prior_state = self.recover_page(
                run,
                page,
                repair=False,
                crops_available=crops_available,
                independent_second_read=independent_second_read,
            )
            requested_stage = _as_stage(stage)
            allowed_stage = prior_state.next_stage
            if prior_state.status in {RecoveryPageStatus.PAUSED, RecoveryPageStatus.FAILED}:
                allowed_stage = prior_state.current_stage
            if requested_stage is not allowed_stage:
                expected = allowed_stage.value if allowed_stage else "none"
                raise RecoveryEvidenceError(
                    f"illegal recovery stage append: got {requested_stage.value}, expected {expected}"
                )
            if requested_stage is RecoveryStage.INDEPENDENT_SECOND_READ and str(
                model_context_id or ""
            ).strip() in {item.model_context_id for item in existing}:
                raise RecoveryEvidenceError(
                    "independent second read reused a previous model context"
                )
            image_evidence: list[RecoveryImageEvidence] = []
            for image in images:
                if not isinstance(image, RecoveryImageInput):
                    raise TypeError("images must contain RecoveryImageInput values")
                blob = self._persist_blob(run, image.content, image.media_type)
                image_evidence.append(
                    RecoveryImageEvidence(
                        role=image.role,
                        blob=blob,
                        dpi=image.dpi,
                        width_pixels=image.width_pixels,
                        height_pixels=image.height_pixels,
                        crop_id=image.crop_id,
                        bbox_pixels=image.bbox_pixels,
                        source_image_sha256=image.source_image_sha256,
                        region_type=image.region_type,
                    )
                )
            if isinstance(raw_response, str):
                response_data = raw_response.encode("utf-8")
                response_type = "application/json; charset=utf-8"
            elif raw_response is None:
                response_data = None
                response_type = "application/octet-stream"
            else:
                response_data = bytes(raw_response)
                response_type = "application/octet-stream"
            response = (
                self._persist_blob(run, response_data, response_type)
                if response_data is not None
                else None
            )
            if isinstance(error, str):
                error_value: Mapping[str, object] = {"message": error}
            else:
                error_value = dict(error or {})
            started = str(started_at or _utc_now())
            ended = str(ended_at or _utc_now())
            duration_hash = _sha256(
                _canonical_json(
                    {"started_at": started, "ended_at": ended, "duration_ms": int(duration_ms)}
                )
            )
            attempt = RecoveryAttempt(
                run_id=run,
                page_id=page,
                source_page=source_page,
                task_index=task_index,
                attempt_id=str(attempt_id or uuid.uuid4().hex),
                sequence=len(existing) + 1,
                stage=requested_stage,
                outcome=outcome,
                base_dpi=base_dpi,
                dpi=dpi,
                model=model,
                backend=backend,
                model_context_id=model_context_id,
                images=tuple(image_evidence),
                response=response,
                started_at=started,
                ended_at=ended,
                duration_ms=duration_ms,
                duration_sha256=duration_hash,
                usage=dict(usage or {}),
                error=error_value,
                tex_sha256=tex_sha256,
                comparison_tex_sha256=comparison_tex_sha256,
                is_batched=is_batched,
                batch_id=batch_id,
                batch_size=batch_size,
                quality_issue_codes=tuple(quality_issue_codes),
                unresolved_region_hashes=tuple(unresolved_region_hashes),
                previous_attempt_sha256=(existing[-1].record_sha256 if existing else ""),
            )
            attempt_path = (
                self._page_dir(run, page)
                / "attempts"
                / f"{attempt.sequence:06d}-{attempt.attempt_id}.json"
            )
            self._atomic_create(attempt_path, _canonical_json(attempt.to_dict()))
            attempts = (*existing, attempt)
            state = derive_page_state(
                run,
                page,
                attempts,
                crops_available=crops_available,
                independent_second_read=independent_second_read,
            )
            self._write_derived_state(attempts, state)
            return attempt

    def _load_attempts(self, run_id: str, page_id: str) -> tuple[RecoveryAttempt, ...]:
        directory = self._page_dir(run_id, page_id) / "attempts"
        if not directory.is_dir():
            return ()
        attempts: list[RecoveryAttempt] = []
        for path in sorted(directory.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                attempt = RecoveryAttempt.from_dict(raw)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise RecoveryEvidenceError(
                    f"invalid recovery attempt journal: {path.name}"
                ) from exc
            expected_prefix = f"{attempt.sequence:06d}-{attempt.attempt_id}.json"
            if path.name != expected_prefix:
                raise RecoveryEvidenceError("attempt filename does not match signed identity")
            attempts.append(attempt)
        previous = ""
        seen_ids: set[str] = set()
        for expected_sequence, attempt in enumerate(attempts, 1):
            if attempt.run_id != run_id or attempt.page_id != page_id:
                raise RecoveryEvidenceError("attempt journal crosses run/page identity")
            if attempt.sequence != expected_sequence or attempt.attempt_id in seen_ids:
                raise RecoveryEvidenceError("attempt journal is not a unique contiguous sequence")
            if attempt.previous_attempt_sha256 != previous:
                raise RecoveryEvidenceError("attempt hash chain is broken")
            self._verify_attempt_blobs(run_id, attempt)
            previous = attempt.record_sha256
            seen_ids.add(attempt.attempt_id)
        return tuple(attempts)

    def _verify_attempt_blobs(self, run_id: str, attempt: RecoveryAttempt) -> None:
        references = [item.blob for item in attempt.images]
        if attempt.response is not None:
            references.append(attempt.response)
        for reference in references:
            expected = self._run_dir(run_id) / PurePosixPath(reference.storage_key)
            try:
                expected.resolve().relative_to(self._run_dir(run_id).resolve())
            except ValueError as exc:
                raise RecoveryEvidenceError("evidence blob escaped the run directory") from exc
            if not expected.is_file():
                raise RecoveryEvidenceError("referenced recovery evidence blob is missing")
            data = expected.read_bytes()
            if len(data) != reference.size_bytes or _sha256(data) != reference.sha256:
                raise RecoveryEvidenceError("referenced recovery evidence blob hash failed")

    def recover_page(
        self,
        run_id: str,
        page_id: str,
        *,
        repair: bool = True,
        crops_available: bool = True,
        independent_second_read: bool = True,
    ) -> tuple[tuple[RecoveryAttempt, ...], RecoveryPageState]:
        """Validate the journal and optionally rebuild disposable snapshots."""

        run, page = self._validate_identity(run_id, page_id)
        with self._lock:
            attempts = self._load_attempts(run, page)
            state = derive_page_state(
                run,
                page,
                attempts,
                crops_available=crops_available,
                independent_second_read=independent_second_read,
            )
            if repair and attempts:
                self._write_derived_state(attempts, state)
            return attempts, state

    def _write_derived_state(
        self,
        attempts: Sequence[RecoveryAttempt],
        state: RecoveryPageState,
    ) -> None:
        page_dir = self._page_dir(state.run_id, state.page_id)
        self._atomic_replace(page_dir / "state.json", _canonical_json(state.to_dict()))
        terminal = state.status in {
            RecoveryPageStatus.SUCCESS,
            RecoveryPageStatus.NEEDS_REVIEW,
            RecoveryPageStatus.PAUSED,
            RecoveryPageStatus.FAILED,
            RecoveryPageStatus.CANCELLED,
        }
        if terminal:
            summary = build_terminal_summary(attempts, state)
            self._atomic_replace(
                page_dir / "terminal-summary.json", _canonical_json(summary.to_dict())
            )

    def read_terminal_summary(
        self,
        run_id: str,
        page_id: str,
    ) -> RecoveryTerminalSummary:
        attempts, state = self.recover_page(run_id, page_id)
        return build_terminal_summary(attempts, state)

    def recover_run(
        self,
        run_id: str,
        *,
        crops_available: bool = True,
        independent_second_read: bool = True,
    ) -> dict[str, RecoveryPageState]:
        run = str(run_id or "").strip().lower()
        if not _RUN_ID_RE.fullmatch(run):
            raise ValueError("invalid OCR recovery run identity")
        pages_dir = self._run_dir(run) / "pages"
        if not pages_dir.is_dir():
            return {}
        output: dict[str, RecoveryPageState] = {}
        for path in sorted(item for item in pages_dir.iterdir() if item.is_dir()):
            if not _PAGE_ID_RE.fullmatch(path.name):
                continue
            _, state = self.recover_page(
                run,
                path.name,
                crops_available=crops_available,
                independent_second_read=independent_second_read,
            )
            output[path.name] = state
        return output


__all__ = [
    "AttemptOutcome",
    "EvidenceBlob",
    "OCR_RECOVERY_ATTEMPT_SCHEMA",
    "OCR_RECOVERY_STATE_SCHEMA",
    "OCR_RECOVERY_SUMMARY_SCHEMA",
    "OcrRecoveryEvidenceStore",
    "RECOVERY_LEVELS",
    "RecoveryAttempt",
    "RecoveryEvidenceError",
    "RecoveryImageEvidence",
    "RecoveryImageInput",
    "RecoveryImageRole",
    "RecoveryPageState",
    "RecoveryPageStatus",
    "RecoveryStage",
    "RecoveryTerminalSummary",
    "build_terminal_summary",
    "derive_page_state",
    "next_stage",
    "second_read_status",
]

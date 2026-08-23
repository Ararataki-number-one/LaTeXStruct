# -*- coding: utf-8 -*-
"""Host-authoritative runtime contract for resumable mathematical OCR.

This module intentionally contains no model-specific code.  The host freezes an
``OcrRunSnapshot`` before the first paid request, assigns every page identifier,
validates every model response against those identifiers, and atomically saves
each page.  A model may transcribe page pixels; it cannot decide which pages
exist, silently omit one, or promote a run to compiled/verified.

The legacy OCR endpoints can adopt this module incrementally: all public
helpers return ordinary JSON values and the on-disk store is independent of the
project export layout.  Existing TEX/project ZIP export behavior is therefore
unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence


OCR_RUNTIME_SCHEMA = "latexstruct-ocr-runtime-v1"
OCR_PAGE_RECORD_SCHEMA = "latexstruct-ocr-page-record-v1"
OCR_RAW_FREEZE_SCHEMA = "latexstruct-raw-ocr-freeze-v1"
OCR_BASELINE_SCHEMA = "latexstruct-ocr-baseline-v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
_PAGE_ID_RE = re.compile(r"^ocr-page-(?P<index>[0-9]{6})$")
_HOST_PAGE_MARKER_RE = re.compile(r"(?mi)^\s*%\s*Page\s+[0-9]+\s*$")
_FORBIDDEN_PREAMBLE_RE = re.compile(
    r"\\(?:documentclass|usepackage)\b|\\begin\s*\{\s*document\s*\}", re.I,
)
_FORBIDDEN_SEMANTIC_STRUCTURE_RE = re.compile(
    r"\\(?:part|chapter|section|subsection|subsubsection)\*?\s*\{"
    r"|\\begin\s*\{\s*(?:theorem|lemma|proposition|corollary|definition|"
    r"remark|example|exercise|proof)\*?\s*\}",
    re.I,
)
_DISPLAY_ENV_RE = re.compile(
    r"\\begin\s*\{(?P<name>equation\*?|align\*?|alignat\*?|flalign\*?|"
    r"gather\*?|multline\*?|displaymath)\}(?P<body>.*?)"
    r"\\end\s*\{(?P=name)\}",
    re.I | re.S,
)
_ENV_TOKEN_RE = re.compile(r"\\(?P<kind>begin|end)\s*\{\s*(?P<name>[^{}\s]+)\s*\}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    return value


def thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def _enum_value(enum_type: type[Enum], value: object, label: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except ValueError as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise ValueError(f"invalid {label}: {value!r}; expected one of {choices}") from exc


class OcrQualityTier(str, Enum):
    FAST = "fast"
    RECOMMENDED = "recommended"
    HIGH = "high"


def normalize_quality_tier(value: object) -> OcrQualityTier:
    """Normalize the v2 tier while accepting the two pre-v2 workflow names."""
    if isinstance(value, OcrQualityTier):
        return value
    raw = str(value or OcrQualityTier.RECOMMENDED.value).strip().lower().replace("-", "_")
    aliases = {
        "fast": OcrQualityTier.FAST,
        "quick": OcrQualityTier.FAST,
        "standard": OcrQualityTier.RECOMMENDED,
        "recommended": OcrQualityTier.RECOMMENDED,
        "recommend": OcrQualityTier.RECOMMENDED,
        "publication": OcrQualityTier.HIGH,
        "high": OcrQualityTier.HIGH,
        "high_quality": OcrQualityTier.HIGH,
    }
    if raw not in aliases:
        raise ValueError("OCR 识别质量只能是 fast、recommended 或 high")
    return aliases[raw]


@dataclass(frozen=True, slots=True)
class OcrTierPolicy:
    quality_tier: OcrQualityTier
    initial_dpi: int
    retry_dpi: int
    batch_size: int
    concurrency_limit: int
    max_retries: int
    use_text_layer_hint: bool
    detect_formula_regions: bool
    use_formula_crops: bool
    independent_second_read: bool


_TIER_POLICIES = {
    OcrQualityTier.FAST: OcrTierPolicy(
        OcrQualityTier.FAST, 200, 200, 3, 3, 1, False, True, False, False,
    ),
    OcrQualityTier.RECOMMENDED: OcrTierPolicy(
        OcrQualityTier.RECOMMENDED, 200, 300, 3, 3, 3, True, True, True, False,
    ),
    OcrQualityTier.HIGH: OcrTierPolicy(
        OcrQualityTier.HIGH, 200, 300, 3, 3, 4, True, True, True, True,
    ),
}


def quality_tier_policy(value: object) -> OcrTierPolicy:
    return _TIER_POLICIES[normalize_quality_tier(value)]


class OcrPageStatus(str, Enum):
    PENDING = "PENDING"
    RENDERING = "RENDERING"
    QUEUED = "QUEUED"
    OCR_RUNNING = "OCR_RUNNING"
    VALIDATING = "VALIDATING"
    RETRYING = "RETRYING"
    SUCCESS = "SUCCESS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


_TRANSIENT_PAGE_STATUSES = frozenset({
    OcrPageStatus.RENDERING,
    OcrPageStatus.QUEUED,
    OcrPageStatus.OCR_RUNNING,
    OcrPageStatus.VALIDATING,
})
_FINALIZED_PAGE_STATUSES = frozenset({
    OcrPageStatus.SUCCESS,
    OcrPageStatus.NEEDS_REVIEW,
    OcrPageStatus.FAILED,
    OcrPageStatus.CANCELLED,
})
_RESUMABLE_PAGE_STATUSES = frozenset({
    OcrPageStatus.PENDING,
    OcrPageStatus.RETRYING,
    OcrPageStatus.FAILED,
    OcrPageStatus.NEEDS_REVIEW,
})
_ALLOWED_PAGE_TRANSITIONS = {
    OcrPageStatus.PENDING: {
        OcrPageStatus.RENDERING, OcrPageStatus.QUEUED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.RENDERING: {
        OcrPageStatus.QUEUED, OcrPageStatus.OCR_RUNNING, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.QUEUED: {
        OcrPageStatus.OCR_RUNNING, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.OCR_RUNNING: {
        OcrPageStatus.VALIDATING, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.VALIDATING: {
        OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.RETRYING: {
        OcrPageStatus.RENDERING, OcrPageStatus.QUEUED, OcrPageStatus.OCR_RUNNING,
        OcrPageStatus.VALIDATING, OcrPageStatus.FAILED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.NEEDS_REVIEW: {OcrPageStatus.RETRYING, OcrPageStatus.CANCELLED},
    OcrPageStatus.FAILED: {OcrPageStatus.RETRYING, OcrPageStatus.CANCELLED},
    OcrPageStatus.SUCCESS: {OcrPageStatus.SUCCESS},
    OcrPageStatus.CANCELLED: {OcrPageStatus.CANCELLED},
}


class OcrPreviewStatus(str, Enum):
    COMPILED = "COMPILED"
    PARTIAL_COMPILED = "PARTIAL_COMPILED"
    SOURCE_PREVIEW = "SOURCE_PREVIEW"


class OcrTextLayerStatus(str, Enum):
    PRESENT = "PRESENT"
    PARTIAL = "PARTIAL"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


def make_page_id(task_index: int) -> str:
    if not isinstance(task_index, int) or isinstance(task_index, bool) or not 1 <= task_index <= 999999:
        raise ValueError("OCR task_index must be an integer in 1..999999")
    return f"ocr-page-{task_index:06d}"


def _validate_sha256(value: object, label: str, *, allow_empty: bool = False) -> str:
    digest = str(value or "").strip().lower()
    if not digest and allow_empty:
        return ""
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


@dataclass(frozen=True, slots=True)
class OcrRunSnapshot:
    """Immutable host-owned description of exactly one OCR run."""

    run_id: str
    source_type: str
    original_filename: str
    source_sha256: str
    source_total_pages: int
    selected_pages: tuple[int, ...]
    page_range: str
    ocr_model: str
    api_backend: str
    app_version: str
    quality_tier: OcrQualityTier = OcrQualityTier.RECOMMENDED
    initial_dpi: int = 200
    max_retries: int = 3
    batch_size: int = 3
    concurrency_limit: int = 3
    started_at: str = field(default_factory=_utc_now)
    text_layer_status: OcrTextLayerStatus = OcrTextLayerStatus.UNKNOWN
    bookmarks: tuple[Mapping[str, object], ...] = ()
    page_sizes: tuple[Mapping[str, object], ...] = ()
    source_images: tuple[Mapping[str, object], ...] = ()
    visual_source_sha256: str = ""
    config_sha256: str = ""
    schema_version: str = OCR_RUNTIME_SCHEMA

    def __post_init__(self) -> None:
        run_id = str(self.run_id or "").strip().lower()
        if not _RUN_ID_RE.fullmatch(run_id):
            raise ValueError("run_id must be 16-64 lowercase hexadecimal characters")
        source_type = str(self.source_type or "").strip().lower()
        if source_type not in {"pdf", "image", "images"}:
            raise ValueError("source_type must be pdf, image or images")
        filename = Path(str(self.original_filename or "")).name.strip()
        if not filename or filename in {".", ".."}:
            raise ValueError("original_filename cannot be empty")
        total = self.source_total_pages
        if not isinstance(total, int) or isinstance(total, bool) or total < 1:
            raise ValueError("source_total_pages must be a positive integer")
        pages = tuple(self.selected_pages or ())
        if not pages or any(
            not isinstance(page, int) or isinstance(page, bool) or not 1 <= page <= total
            for page in pages
        ):
            raise ValueError("selected_pages must contain valid source page numbers")
        if tuple(sorted(set(pages))) != pages:
            raise ValueError("selected_pages must be unique and strictly increasing")
        tier = normalize_quality_tier(self.quality_tier)
        text_layer = _enum_value(OcrTextLayerStatus, self.text_layer_status, "text layer status")
        if not 72 <= int(self.initial_dpi) <= 600:
            raise ValueError("initial_dpi must be in 72..600")
        if not 0 <= int(self.max_retries) <= 10:
            raise ValueError("max_retries must be in 0..10")
        if not 1 <= int(self.batch_size) <= 3:
            raise ValueError("batch_size must be in 1..3")
        if not 1 <= int(self.concurrency_limit) <= 3:
            raise ValueError("concurrency_limit must be in 1..3")
        config_sha256 = _validate_sha256(self.config_sha256, "config_sha256")
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "original_filename", filename)
        object.__setattr__(self, "source_sha256", _validate_sha256(self.source_sha256, "source_sha256"))
        object.__setattr__(self, "selected_pages", pages)
        object.__setattr__(self, "page_range", str(self.page_range or _page_range_label(pages)))
        object.__setattr__(self, "ocr_model", str(self.ocr_model or "").strip())
        object.__setattr__(self, "api_backend", str(self.api_backend or "").strip())
        object.__setattr__(self, "app_version", str(self.app_version or "unknown").strip())
        object.__setattr__(self, "quality_tier", tier)
        object.__setattr__(self, "initial_dpi", int(self.initial_dpi))
        object.__setattr__(self, "max_retries", int(self.max_retries))
        object.__setattr__(self, "batch_size", int(self.batch_size))
        object.__setattr__(self, "concurrency_limit", int(self.concurrency_limit))
        object.__setattr__(self, "started_at", str(self.started_at or _utc_now()))
        object.__setattr__(self, "text_layer_status", text_layer)
        object.__setattr__(self, "bookmarks", tuple(_freeze(item) for item in self.bookmarks))
        object.__setattr__(self, "page_sizes", tuple(_freeze(item) for item in self.page_sizes))
        source_images = tuple(_freeze(item) for item in self.source_images)
        visual_sha = _validate_sha256(
            self.visual_source_sha256, "visual_source_sha256", allow_empty=True,
        )
        if source_type == "images":
            if len(source_images) != total or total < 2:
                raise ValueError("images source must describe every original image")
            if any(not isinstance(item, Mapping) for item in source_images):
                raise ValueError("images source metadata must contain objects")
            orders = [item.get("order") for item in source_images]
            if orders != list(range(1, total + 1)) or not visual_sha:
                raise ValueError("images source order and derived visual hash are required")
            for item in source_images:
                if (
                    not str(item.get("original_filename") or "").strip()
                    or Path(str(item.get("original_filename") or "")).name
                    != str(item.get("original_filename") or "")
                    or not isinstance(item.get("bytes"), int)
                    or isinstance(item.get("bytes"), bool)
                    or int(item.get("bytes")) < 1
                ):
                    raise ValueError("images source metadata is invalid")
                _validate_sha256(item.get("sha256"), "source image sha256")
        elif source_images or visual_sha:
            raise ValueError("source image collection metadata requires source_type=images")
        object.__setattr__(self, "source_images", source_images)
        object.__setattr__(self, "visual_source_sha256", visual_sha)
        object.__setattr__(self, "config_sha256", config_sha256)
        object.__setattr__(self, "schema_version", OCR_RUNTIME_SCHEMA)

    def page_identity(self, task_index: int) -> tuple[str, int]:
        return make_page_id(task_index), self.selected_pages[task_index - 1]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "source_type": self.source_type,
            "original_filename": self.original_filename,
            "source_sha256": self.source_sha256,
            "source_total_pages": self.source_total_pages,
            "selected_pages": list(self.selected_pages),
            "page_range": self.page_range,
            "ocr_model": self.ocr_model,
            "api_backend": self.api_backend,
            "app_version": self.app_version,
            "quality_tier": self.quality_tier.value,
            "initial_dpi": self.initial_dpi,
            "max_retries": self.max_retries,
            "batch_size": self.batch_size,
            "concurrency_limit": self.concurrency_limit,
            "started_at": self.started_at,
            "text_layer_status": self.text_layer_status.value,
            "bookmarks": thaw_json(self.bookmarks),
            "page_sizes": thaw_json(self.page_sizes),
            "source_images": thaw_json(self.source_images),
            "visual_source_sha256": self.visual_source_sha256,
            "config_sha256": self.config_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "OcrRunSnapshot":
        if value.get("schema_version") != OCR_RUNTIME_SCHEMA:
            raise ValueError("unsupported OCR runtime snapshot schema")
        return cls(
            run_id=value.get("run_id", ""),
            source_type=value.get("source_type", ""),
            original_filename=value.get("original_filename", ""),
            source_sha256=value.get("source_sha256", ""),
            source_total_pages=value.get("source_total_pages", 0),
            selected_pages=tuple(value.get("selected_pages") or ()),
            page_range=value.get("page_range", ""),
            ocr_model=value.get("ocr_model", ""),
            api_backend=value.get("api_backend", ""),
            app_version=value.get("app_version", "unknown"),
            quality_tier=value.get("quality_tier", OcrQualityTier.RECOMMENDED.value),
            initial_dpi=value.get("initial_dpi", 200),
            max_retries=value.get("max_retries", 3),
            batch_size=value.get("batch_size", 3),
            concurrency_limit=value.get("concurrency_limit", 3),
            started_at=value.get("started_at", ""),
            text_layer_status=value.get("text_layer_status", OcrTextLayerStatus.UNKNOWN.value),
            bookmarks=tuple(value.get("bookmarks") or ()),
            page_sizes=tuple(value.get("page_sizes") or ()),
            source_images=tuple(value.get("source_images") or ()),
            visual_source_sha256=value.get("visual_source_sha256", ""),
            config_sha256=value.get("config_sha256", ""),
        )


def _page_range_label(pages: Sequence[int]) -> str:
    if not pages:
        return ""
    groups: list[str] = []
    start = previous = int(pages[0])
    for page in pages[1:]:
        page = int(page)
        if page == previous + 1:
            previous = page
            continue
        groups.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = page
    groups.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(groups)


def make_run_snapshot(
    *,
    source_bytes: bytes,
    source_type: str,
    original_filename: str,
    source_total_pages: int,
    selected_pages: Sequence[int],
    ocr_model: str,
    api_backend: str,
    app_version: str,
    quality_tier: object = OcrQualityTier.RECOMMENDED,
    text_layer_status: object = OcrTextLayerStatus.UNKNOWN,
    bookmarks: Sequence[Mapping[str, object]] = (),
    page_sizes: Sequence[Mapping[str, object]] = (),
    source_images: Sequence[Mapping[str, object]] = (),
    visual_source_bytes: bytes = b"",
    runtime_options: Mapping[str, object] | None = None,
    run_id: str = "",
    started_at: str = "",
) -> OcrRunSnapshot:
    """Create the immutable snapshot from bytes and allowlisted runtime options.

    API keys and absolute paths must never be passed in ``runtime_options``.  A
    defensive deny-list rejects the common secret/path spellings before the
    options are hashed.
    """
    if not isinstance(source_bytes, bytes | bytearray | memoryview) or not source_bytes:
        raise ValueError("source_bytes cannot be empty")
    tier = normalize_quality_tier(quality_tier)
    policy = quality_tier_policy(tier)
    options = dict(runtime_options or {})
    forbidden = [
        str(key) for key in options
        if any(token in str(key).lower() for token in ("api_key", "authorization", "password", "path"))
    ]
    if forbidden:
        raise ValueError(f"runtime_options contains sensitive/path fields: {forbidden[0]}")
    initial_dpi = int(options.get("initial_dpi", policy.initial_dpi))
    max_retries = int(options.get("max_retries", policy.max_retries))
    batch_size = int(options.get("batch_size", policy.batch_size))
    concurrency_limit = int(options.get("concurrency_limit", policy.concurrency_limit))
    frozen_config = {
        "api_backend": str(api_backend or ""),
        "ocr_model": str(ocr_model or ""),
        "quality_tier": tier.value,
        "initial_dpi": initial_dpi,
        "max_retries": max_retries,
        "batch_size": batch_size,
        "concurrency_limit": concurrency_limit,
        "runtime_options": options,
        "source_images": thaw_json(tuple(source_images)),
        "visual_source_sha256": (
            _sha256_bytes(bytes(visual_source_bytes)) if visual_source_bytes else ""
        ),
    }
    return OcrRunSnapshot(
        run_id=(run_id or uuid.uuid4().hex),
        source_type=source_type,
        original_filename=original_filename,
        source_sha256=_sha256_bytes(bytes(source_bytes)),
        source_total_pages=source_total_pages,
        selected_pages=tuple(selected_pages),
        page_range=_page_range_label(selected_pages),
        ocr_model=ocr_model,
        api_backend=api_backend,
        app_version=app_version,
        quality_tier=tier,
        initial_dpi=initial_dpi,
        max_retries=max_retries,
        batch_size=batch_size,
        concurrency_limit=concurrency_limit,
        started_at=started_at or _utc_now(),
        text_layer_status=text_layer_status,
        bookmarks=tuple(bookmarks),
        page_sizes=tuple(page_sizes),
        source_images=tuple(source_images),
        visual_source_sha256=(
            _sha256_bytes(bytes(visual_source_bytes)) if visual_source_bytes else ""
        ),
        config_sha256=_sha256_bytes(_canonical_json(frozen_config)),
    )


@dataclass(frozen=True, slots=True)
class OcrPageRecord:
    page_id: str
    source_page: int
    task_index: int
    status: OcrPageStatus = OcrPageStatus.PENDING
    image_sha256: str = ""
    image_size_pixels: tuple[int, int] = ()
    dpi: int = 0
    model: str = ""
    call_index: int = 0
    batch_call: bool = False
    batch_id: str = ""
    raw_response_sha256: str = ""
    raw_tex: str = ""
    cleaned_tex: str = ""
    tex_sha256: str = ""
    started_at: str = ""
    ended_at: str = ""
    elapsed_seconds: float | None = None
    retry_count: int = 0
    quality_issues: tuple[Mapping[str, object], ...] = ()
    unresolved_regions: tuple[Mapping[str, object], ...] = ()
    usage: Mapping[str, object] = field(default_factory=dict)
    error_reason: str = ""
    updated_at: str = field(default_factory=_utc_now)
    schema_version: str = OCR_PAGE_RECORD_SCHEMA

    def __post_init__(self) -> None:
        match = _PAGE_ID_RE.fullmatch(str(self.page_id or ""))
        if match is None:
            raise ValueError("invalid OCR page_id")
        if not isinstance(self.task_index, int) or isinstance(self.task_index, bool) or self.task_index < 1:
            raise ValueError("task_index must be a positive integer")
        if int(match.group("index")) != self.task_index:
            raise ValueError("page_id must encode task_index")
        if not isinstance(self.source_page, int) or isinstance(self.source_page, bool) or self.source_page < 1:
            raise ValueError("source_page must be a positive integer")
        status = _enum_value(OcrPageStatus, self.status, "OCR page status")
        image_sha = _validate_sha256(self.image_sha256, "image_sha256", allow_empty=True)
        response_sha = _validate_sha256(
            self.raw_response_sha256, "raw_response_sha256", allow_empty=True,
        )
        tex_sha = _validate_sha256(self.tex_sha256, "tex_sha256", allow_empty=True)
        size = tuple(self.image_size_pixels or ())
        if size and (
            len(size) != 2 or any(
                not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in size
            )
        ):
            raise ValueError("image_size_pixels must be two positive integers")
        if self.cleaned_tex:
            actual_tex_sha = _sha256_bytes(self.cleaned_tex.encode("utf-8"))
            if tex_sha and not hmac.compare_digest(actual_tex_sha, tex_sha):
                raise ValueError("tex_sha256 does not match cleaned_tex")
            tex_sha = actual_tex_sha
        elif tex_sha:
            raise ValueError("tex_sha256 requires cleaned_tex")
        if status == OcrPageStatus.SUCCESS and not self.cleaned_tex.strip():
            raise ValueError("SUCCESS page requires non-empty cleaned_tex")
        if status in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW} and not response_sha:
            raise ValueError(f"{status.value} page requires raw_response_sha256")
        if not 0 <= int(self.retry_count) <= 100:
            raise ValueError("retry_count is out of range")
        elapsed = self.elapsed_seconds
        if elapsed is not None and (not math.isfinite(float(elapsed)) or float(elapsed) < 0):
            raise ValueError("elapsed_seconds must be finite and non-negative")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "image_sha256", image_sha)
        object.__setattr__(self, "raw_response_sha256", response_sha)
        object.__setattr__(self, "tex_sha256", tex_sha)
        object.__setattr__(self, "image_size_pixels", size)
        object.__setattr__(self, "dpi", int(self.dpi or 0))
        object.__setattr__(self, "model", str(self.model or ""))
        object.__setattr__(self, "call_index", int(self.call_index or 0))
        object.__setattr__(self, "batch_call", bool(self.batch_call))
        object.__setattr__(self, "batch_id", str(self.batch_id or ""))
        object.__setattr__(self, "raw_tex", str(self.raw_tex or ""))
        object.__setattr__(self, "cleaned_tex", str(self.cleaned_tex or ""))
        object.__setattr__(self, "started_at", str(self.started_at or ""))
        object.__setattr__(self, "ended_at", str(self.ended_at or ""))
        object.__setattr__(self, "elapsed_seconds", None if elapsed is None else float(elapsed))
        object.__setattr__(self, "retry_count", int(self.retry_count))
        object.__setattr__(self, "quality_issues", tuple(_freeze(item) for item in self.quality_issues))
        object.__setattr__(self, "unresolved_regions", tuple(
            _freeze(item) for item in self.unresolved_regions
        ))
        object.__setattr__(self, "usage", _freeze(dict(self.usage or {})))
        object.__setattr__(self, "error_reason", str(self.error_reason or "")[:1000])
        object.__setattr__(self, "updated_at", str(self.updated_at or _utc_now()))
        object.__setattr__(self, "schema_version", OCR_PAGE_RECORD_SCHEMA)

    @classmethod
    def pending(cls, task_index: int, source_page: int) -> "OcrPageRecord":
        return cls(page_id=make_page_id(task_index), source_page=source_page, task_index=task_index)

    def transition(self, status: OcrPageStatus | str, **updates: object) -> "OcrPageRecord":
        target = _enum_value(OcrPageStatus, status, "OCR page status")
        if target not in _ALLOWED_PAGE_TRANSITIONS[self.status]:
            raise ValueError(f"illegal OCR page transition: {self.status.value} -> {target.value}")
        return replace(self, status=target, updated_at=_utc_now(), **updates)

    def recovered_after_interruption(self) -> "OcrPageRecord":
        if self.status not in _TRANSIENT_PAGE_STATUSES:
            return self
        issue = {
            "code": "INTERRUPTED_ATTEMPT_RECOVERED",
            "severity": "info",
            "message": f"recovered from transient state {self.status.value}",
        }
        # PENDING is host recovery state, not an ordinary runtime transition.
        return replace(
            self,
            status=OcrPageStatus.PENDING,
            error_reason="上次运行在页面完成前中断；将从该 page_id 继续",
            quality_issues=tuple(self.quality_issues) + (issue,),
            updated_at=_utc_now(),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "page_id": self.page_id,
            "source_page": self.source_page,
            "task_index": self.task_index,
            "status": self.status.value,
            "image_sha256": self.image_sha256,
            "image_size_pixels": list(self.image_size_pixels),
            "dpi": self.dpi,
            "model": self.model,
            "call_index": self.call_index,
            "batch_call": self.batch_call,
            "batch_id": self.batch_id,
            "raw_response_sha256": self.raw_response_sha256,
            "raw_tex": self.raw_tex,
            "cleaned_tex": self.cleaned_tex,
            "tex_sha256": self.tex_sha256,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_seconds": self.elapsed_seconds,
            "retry_count": self.retry_count,
            "quality_issues": thaw_json(self.quality_issues),
            "unresolved_regions": thaw_json(self.unresolved_regions),
            "usage": thaw_json(self.usage),
            "error_reason": self.error_reason,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "OcrPageRecord":
        if value.get("schema_version") != OCR_PAGE_RECORD_SCHEMA:
            raise ValueError("unsupported OCR page record schema")
        return cls(
            page_id=value.get("page_id", ""),
            source_page=value.get("source_page", 0),
            task_index=value.get("task_index", 0),
            status=value.get("status", OcrPageStatus.PENDING.value),
            image_sha256=value.get("image_sha256", ""),
            image_size_pixels=tuple(value.get("image_size_pixels") or ()),
            dpi=value.get("dpi", 0),
            model=value.get("model", ""),
            call_index=value.get("call_index", 0),
            batch_call=value.get("batch_call", False),
            batch_id=value.get("batch_id", ""),
            raw_response_sha256=value.get("raw_response_sha256", ""),
            raw_tex=value.get("raw_tex", ""),
            cleaned_tex=value.get("cleaned_tex", ""),
            tex_sha256=value.get("tex_sha256", ""),
            started_at=value.get("started_at", ""),
            ended_at=value.get("ended_at", ""),
            elapsed_seconds=value.get("elapsed_seconds"),
            retry_count=value.get("retry_count", 0),
            quality_issues=tuple(value.get("quality_issues") or ()),
            unresolved_regions=tuple(value.get("unresolved_regions") or ()),
            usage=value.get("usage") or {},
            error_reason=value.get("error_reason", ""),
            updated_at=value.get("updated_at", ""),
        )


def public_page_state(record: OcrPageRecord) -> dict[str, object]:
    """Bounded page state for polling; never exposes OCR text or raw responses."""
    return {
        "page_id": record.page_id,
        "source_page": record.source_page,
        "task_index": record.task_index,
        "status": record.status.value,
        "dpi": record.dpi or None,
        "retry_count": record.retry_count,
        "attempts": max(record.call_index, record.retry_count + (1 if record.call_index else 0)),
        "batch_call": record.batch_call,
        "batch_id": record.batch_id or None,
        "elapsed_seconds": record.elapsed_seconds,
        "quality_issue_count": len(record.quality_issues),
        "unresolved_region_count": len(record.unresolved_regions),
        "needs_review": record.status == OcrPageStatus.NEEDS_REVIEW,
        "error": record.error_reason[:240] or None,
        "updated_at": record.updated_at,
    }


class OcrStoreError(RuntimeError):
    pass


class OcrRunStore:
    """Crash-safe per-run storage with a write-once snapshot and raw OCR freeze."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def run_dir(self, run_id: str) -> Path:
        if not _RUN_ID_RE.fullmatch(str(run_id or "")):
            raise ValueError("invalid OCR run_id")
        return self.root / str(run_id)

    def initialize(
        self,
        snapshot: OcrRunSnapshot,
        source_bytes: bytes,
        *,
        visual_source_bytes: bytes = b"",
    ) -> Path:
        if _sha256_bytes(bytes(source_bytes)) != snapshot.source_sha256:
            raise OcrStoreError("source bytes do not match immutable OcrRunSnapshot")
        visual = bytes(visual_source_bytes)
        if snapshot.source_type == "images":
            if (
                not visual.startswith(b"%PDF-")
                or _sha256_bytes(visual) != snapshot.visual_source_sha256
            ):
                raise OcrStoreError(
                    "derived multi-image visual PDF does not match immutable snapshot"
                )
            try:
                from .ocr_sources import verify_multi_image_source

                verify_multi_image_source(
                    bytes(source_bytes),
                    expected_images=snapshot.source_images,
                    expected_visual_sha256=snapshot.visual_source_sha256,
                )
            except (OSError, ValueError) as exc:
                raise OcrStoreError(
                    "multi-image source bundle does not match immutable snapshot"
                ) from exc
        with self._lock:
            directory = self.run_dir(snapshot.run_id)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "pages").mkdir(exist_ok=True)
            (directory / "page-images").mkdir(exist_ok=True)
            (directory / "responses").mkdir(exist_ok=True)
            (directory / "artifacts").mkdir(exist_ok=True)
            snapshot_path = directory / "run-snapshot.json"
            snapshot_bytes = _canonical_json(snapshot.to_dict())
            if snapshot_path.exists():
                if snapshot_path.read_bytes() != snapshot_bytes:
                    raise OcrStoreError("immutable OcrRunSnapshot already exists with different bytes")
            else:
                self._atomic_write(snapshot_path, snapshot_bytes)
            suffix = Path(snapshot.original_filename).suffix.lower()
            if snapshot.source_type == "images":
                source_name = "source.zip"
            else:
                source_name = "source" + (
                    suffix if suffix in {".pdf", ".png", ".jpg", ".jpeg"} else ".bin"
                )
            source_path = directory / source_name
            if source_path.exists():
                if _sha256_bytes(source_path.read_bytes()) != snapshot.source_sha256:
                    raise OcrStoreError("frozen OCR input no longer matches source SHA-256")
            else:
                self._atomic_write(source_path, bytes(source_bytes))
            if snapshot.source_type == "images":
                visual_path = directory / "visual-source.pdf"
                if visual_path.exists():
                    if _sha256_bytes(visual_path.read_bytes()) != snapshot.visual_source_sha256:
                        raise OcrStoreError("immutable visual source already has different bytes")
                else:
                    self._atomic_write(visual_path, visual)
                manifest_path = directory / "source-images-manifest.json"
                manifest_bytes = _canonical_json({
                        "schema": "latexstruct-ocr-source-images-snapshot-v1",
                        "run_id": snapshot.run_id,
                        "source_sha256": snapshot.source_sha256,
                        "visual_source_sha256": snapshot.visual_source_sha256,
                        "images": thaw_json(snapshot.source_images),
                    })
                if manifest_path.exists():
                    if manifest_path.read_bytes() != manifest_bytes:
                        raise OcrStoreError("immutable source image manifest has different bytes")
                else:
                    self._atomic_write(manifest_path, manifest_bytes)
            for index, page_no in enumerate(snapshot.selected_pages, start=1):
                path = self._record_path(snapshot.run_id, make_page_id(index))
                if not path.exists():
                    record = OcrPageRecord.pending(index, page_no)
                    self._atomic_write(path, _canonical_json(record.to_dict()))
            return directory

    def load_snapshot(self, run_id: str) -> OcrRunSnapshot:
        path = self.run_dir(run_id) / "run-snapshot.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OcrStoreError("OCR run snapshot is missing or corrupt") from exc
        return OcrRunSnapshot.from_dict(value)

    def verify_source(self, run_id: str) -> Path:
        snapshot = self.load_snapshot(run_id)
        candidates = list(self.run_dir(run_id).glob("source.*"))
        if len(candidates) != 1:
            raise OcrStoreError("frozen OCR source SHA-256 verification failed")
        source_bytes = candidates[0].read_bytes()
        if _sha256_bytes(source_bytes) != snapshot.source_sha256:
            raise OcrStoreError("frozen OCR source SHA-256 verification failed")
        if snapshot.source_type == "images":
            try:
                from .ocr_sources import verify_multi_image_source

                verify_multi_image_source(
                    source_bytes,
                    expected_images=snapshot.source_images,
                    expected_visual_sha256=snapshot.visual_source_sha256,
                )
            except (OSError, ValueError) as exc:
                raise OcrStoreError(
                    "frozen multi-image source manifest verification failed"
                ) from exc
        return candidates[0]

    def verify_visual_source(self, run_id: str) -> Path:
        snapshot = self.load_snapshot(run_id)
        if snapshot.source_type != "images" or not snapshot.visual_source_sha256:
            raise OcrStoreError("OCR run has no derived multi-image visual source")
        path = self.run_dir(run_id) / "visual-source.pdf"
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise OcrStoreError("derived multi-image visual source is missing") from exc
        if (
            path.is_symlink()
            or not path.is_file()
            or not data.startswith(b"%PDF-")
            or _sha256_bytes(data) != snapshot.visual_source_sha256
        ):
            raise OcrStoreError("derived multi-image visual source SHA-256 verification failed")
        return path

    def _record_path(self, run_id: str, page_id: str) -> Path:
        if _PAGE_ID_RE.fullmatch(str(page_id or "")) is None:
            raise ValueError("invalid OCR page_id")
        return self.run_dir(run_id) / "pages" / f"{page_id}.json"

    def load_record(self, run_id: str, page_id: str) -> OcrPageRecord:
        try:
            value = json.loads(self._record_path(run_id, page_id).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OcrStoreError(f"OCR page record is missing or corrupt: {page_id}") from exc
        record = OcrPageRecord.from_dict(value)
        self._validate_record_identity(self.load_snapshot(run_id), record)
        return record

    def list_records(self, run_id: str) -> list[OcrPageRecord]:
        snapshot = self.load_snapshot(run_id)
        return [self.load_record(run_id, make_page_id(index)) for index in range(1, len(snapshot.selected_pages) + 1)]

    def _page_image_path(self, run_id: str, record: OcrPageRecord) -> Path:
        """Return the hash-addressed path for one exact model visual input."""
        self._validate_record_identity(self.load_snapshot(run_id), record)
        if not record.image_sha256:
            raise OcrStoreError("OCR page visual input is missing its SHA-256")
        return self.run_dir(run_id) / "page-images" / (
            f"{record.page_id}-{record.image_sha256}.img"
        )

    def persist_page_image(
        self,
        run_id: str,
        record: OcrPageRecord,
        image_bytes: bytes,
    ) -> Path:
        """Write the exact page pixels used by the model before finalizing it.

        The filename is bound to both the immutable page id and byte hash.  A
        retry may therefore use different pixels without overwriting an earlier
        attempt, while a same-name collision is rejected rather than replaced.
        """
        data = bytes(image_bytes)
        if not data or _sha256_bytes(data) != record.image_sha256:
            raise OcrStoreError("OCR page image bytes do not match the page record SHA-256")
        with self._lock:
            path = self._page_image_path(run_id, record)
            if path.exists():
                if path.is_symlink() or path.read_bytes() != data:
                    raise OcrStoreError("immutable OCR page image already exists with different bytes")
            else:
                self._atomic_write(path, data)
            return path

    def verify_page_image(self, run_id: str, record: OcrPageRecord) -> Path:
        """Resolve a persisted model input only after rechecking its byte hash."""
        with self._lock:
            path = self._page_image_path(run_id, record)
            try:
                if path.is_symlink() or not path.is_file():
                    raise OcrStoreError("persisted OCR page image is missing")
                data = path.read_bytes()
            except OSError as exc:
                raise OcrStoreError("persisted OCR page image cannot be read") from exc
            if not hmac.compare_digest(_sha256_bytes(data), record.image_sha256):
                raise OcrStoreError("persisted OCR page image SHA-256 verification failed")
            return path

    def persist_record(
        self,
        run_id: str,
        record: OcrPageRecord,
        *,
        raw_response: object | None = None,
    ) -> None:
        """Persist response first and the page record last as the commit marker."""
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            self._validate_record_identity(snapshot, record)
            path = self._record_path(run_id, record.page_id)
            previous = self.load_record(run_id, record.page_id) if path.exists() else None
            if previous is not None:
                self._validate_record_update(previous, record)
            if raw_response is not None:
                response_bytes = self._response_bytes(raw_response)
                digest = _sha256_bytes(response_bytes)
                if not record.raw_response_sha256 or not hmac.compare_digest(
                    digest, record.raw_response_sha256,
                ):
                    raise OcrStoreError("raw model response hash does not match OcrPageRecord")
                response_path = self.run_dir(run_id) / "responses" / f"{record.page_id}-{digest}.json"
                if response_path.exists() and response_path.read_bytes() != response_bytes:
                    raise OcrStoreError("raw response hash collision")
                if not response_path.exists():
                    self._atomic_write(response_path, response_bytes)
            elif record.status in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW}:
                response_path = self.run_dir(run_id) / "responses" / (
                    f"{record.page_id}-{record.raw_response_sha256}.json"
                )
                if not response_path.is_file():
                    raise OcrStoreError("successful page requires its saved raw model response")
            self._atomic_write(path, _canonical_json(record.to_dict()))

    def recover(self, run_id: str) -> list[OcrPageRecord]:
        """Verify frozen input/TEX hashes and reset interrupted pages to PENDING."""
        with self._lock:
            self.verify_source(run_id)
            snapshot = self.load_snapshot(run_id)
            recovered: list[OcrPageRecord] = []
            for record in self.list_records(run_id):
                self._validate_record_identity(snapshot, record)
                if record.status == OcrPageStatus.SUCCESS:
                    if not record.tex_sha256 or _sha256_bytes(
                        record.cleaned_tex.encode("utf-8")
                    ) != record.tex_sha256:
                        raise OcrStoreError(f"successful page TEX hash mismatch: {record.page_id}")
                updated = record.recovered_after_interruption()
                if updated is not record:
                    self.persist_record(run_id, updated)
                recovered.append(updated)
            return recovered

    def resumable_records(self, run_id: str) -> list[OcrPageRecord]:
        return [record for record in self.recover(run_id) if record.status in _RESUMABLE_PAGE_STATUSES]

    def freeze_raw_ocr(
        self,
        run_id: str,
        *,
        document_builder: Callable[[list[str]], str] | None = None,
        model_usage: Mapping[str, object] | None = None,
        merge_version: str = "1",
    ) -> dict[str, object]:
        """Merge every selected page in source order and freeze it write-once.

        FAILED/CANCELLED pages receive an explicit host comment so a partial raw
        file can never look complete through silent omission.
        """
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            records = self.list_records(run_id)
            seen: set[str] = set()
            fragments: list[str] = []
            for record in records:
                if record.page_id in seen:
                    raise OcrStoreError(f"duplicate page_id while merging: {record.page_id}")
                seen.add(record.page_id)
                if record.source_page != snapshot.selected_pages[record.task_index - 1]:
                    raise OcrStoreError(f"page order mismatch while merging: {record.page_id}")
                body = _strip_host_page_markers(record.cleaned_tex).strip()
                marker = f"% Page {record.source_page}"
                if body:
                    fragments.append(f"{marker}\n{body}")
                else:
                    fragments.append(
                        f"{marker}\n% OCR PAGE UNAVAILABLE: {record.page_id} status={record.status.value}"
                    )
            expected = {make_page_id(index) for index in range(1, len(snapshot.selected_pages) + 1)}
            if seen != expected:
                raise OcrStoreError("OCR merge page_id coverage mismatch")
            raw_tex = document_builder(fragments) if document_builder else "\n\n".join(fragments) + "\n"
            raw_bytes = raw_tex.encode("utf-8")
            raw_sha = _sha256_bytes(raw_bytes)
            manifest = {
                "schema_version": OCR_RAW_FREEZE_SCHEMA,
                "run_id": run_id,
                "created_at": _utc_now(),
                "raw_ocr_sha256": raw_sha,
                "selected_pages": list(snapshot.selected_pages),
                "page_records": [
                    {
                        "page_id": record.page_id,
                        "source_page": record.source_page,
                        "status": record.status.value,
                        "tex_sha256": record.tex_sha256 or None,
                        "raw_response_sha256": record.raw_response_sha256 or None,
                    }
                    for record in records
                ],
                "ocr_model": snapshot.ocr_model,
                "api_backend": snapshot.api_backend,
                "usage": thaw_json(model_usage or {}),
                "unresolved_regions": [
                    {"page_id": record.page_id, "regions": thaw_json(record.unresolved_regions)}
                    for record in records if record.unresolved_regions
                ],
                "error_pages": [
                    record.source_page for record in records
                    if record.status in {OcrPageStatus.FAILED, OcrPageStatus.CANCELLED}
                ],
                "merge_version": str(merge_version),
            }
            directory = self.run_dir(run_id) / "artifacts"
            raw_path = directory / "raw-ocr.tex"
            marker_path = directory / "raw-ocr-freeze.json"
            if marker_path.exists():
                existing = json.loads(marker_path.read_text(encoding="utf-8"))
                if existing.get("raw_ocr_sha256") != raw_sha or raw_path.read_bytes() != raw_bytes:
                    raise OcrStoreError("immutable raw OCR TEX is already frozen with different bytes")
                return existing
            if raw_path.exists() and raw_path.read_bytes() != raw_bytes:
                raise OcrStoreError("uncommitted raw OCR TEX conflicts with current merge")
            if not raw_path.exists():
                self._atomic_write(raw_path, raw_bytes)
            self._atomic_write(marker_path, _canonical_json(manifest))
            return manifest

    def save_compile_baseline(
        self,
        run_id: str,
        *,
        baseline_tex: str,
        compile_log: str,
        preview_status: OcrPreviewStatus | str,
        exit_code: int,
        successful_passes: int,
        pdf_bytes: bytes | None = None,
        syntax_repairs: Sequence[Mapping[str, object]] = (),
        error_lines: Sequence[Mapping[str, object]] = (),
        preview_filename: str = "",
    ) -> dict[str, object]:
        """Record real compile evidence without ever replacing raw-ocr.tex."""
        with self._lock:
            self.load_snapshot(run_id)
            raw_manifest_path = self.run_dir(run_id) / "artifacts" / "raw-ocr-freeze.json"
            if not raw_manifest_path.is_file():
                raise OcrStoreError("raw OCR must be frozen before baseline compilation")
            status = _enum_value(OcrPreviewStatus, preview_status, "OCR preview status")
            pdf = bytes(pdf_bytes or b"")
            if status == OcrPreviewStatus.COMPILED:
                if exit_code != 0 or successful_passes < 2 or not pdf.startswith(b"%PDF-"):
                    raise OcrStoreError("COMPILED requires two successful real LaTeX passes and a PDF")
            elif status == OcrPreviewStatus.PARTIAL_COMPILED:
                if exit_code == 0 or not pdf.startswith(b"%PDF-"):
                    raise OcrStoreError("PARTIAL_COMPILED requires failed compile evidence and a partial PDF")
            else:
                if pdf and not pdf.startswith(b"%PDF-"):
                    raise OcrStoreError("SOURCE_PREVIEW bytes must be a PDF")
                if "compiled" in str(preview_filename or "").lower():
                    raise OcrStoreError("SOURCE_PREVIEW filename must not contain compiled")
                if pdf and b"not a latex compile" not in pdf.lower() and "不是 LaTeX 编译结果" not in compile_log:
                    raise OcrStoreError("SOURCE_PREVIEW must explicitly declare it is not a LaTeX compile")
            directory = self.run_dir(run_id) / "artifacts"
            tex_bytes = baseline_tex.encode("utf-8")
            log_bytes = compile_log.encode("utf-8")
            manifest = {
                "schema_version": OCR_BASELINE_SCHEMA,
                "run_id": run_id,
                "created_at": _utc_now(),
                "preview_status": status.value,
                "baseline_tex_sha256": _sha256_bytes(tex_bytes),
                "compile_log_sha256": _sha256_bytes(log_bytes),
                "pdf_sha256": _sha256_bytes(pdf) if pdf else None,
                "exit_code": int(exit_code),
                "successful_passes": int(successful_passes),
                "syntax_repairs": thaw_json(tuple(syntax_repairs)),
                "error_lines": thaw_json(tuple(error_lines)),
            }
            marker_path = directory / "baseline-manifest.json"
            if marker_path.exists():
                existing = json.loads(marker_path.read_text(encoding="utf-8"))
                if _canonical_json(existing) != _canonical_json(manifest):
                    raise OcrStoreError("OCR baseline evidence is already frozen with different bytes")
                return existing
            self._atomic_write(directory / "baseline.tex", tex_bytes)
            self._atomic_write(directory / "compile-baseline.log", log_bytes)
            if pdf:
                name = (
                    "baseline.pdf" if status == OcrPreviewStatus.COMPILED
                    else "partial-baseline.pdf" if status == OcrPreviewStatus.PARTIAL_COMPILED
                    else (Path(preview_filename).name or "source-preview.pdf")
                )
                self._atomic_write(directory / name, pdf)
            self._atomic_write(marker_path, _canonical_json(manifest))
            return manifest

    @staticmethod
    def _response_bytes(response: object) -> bytes:
        if isinstance(response, bytes):
            return response
        if isinstance(response, str):
            return response.encode("utf-8")
        return _canonical_json(response)

    @staticmethod
    def _validate_record_identity(snapshot: OcrRunSnapshot, record: OcrPageRecord) -> None:
        if record.task_index > len(snapshot.selected_pages):
            raise OcrStoreError(f"page record outside immutable selection: {record.page_id}")
        expected_id, expected_page = snapshot.page_identity(record.task_index)
        if record.page_id != expected_id or record.source_page != expected_page:
            raise OcrStoreError(f"page record identity mismatch: {record.page_id}")
        if record.model and record.model != snapshot.ocr_model:
            raise OcrStoreError(f"page model differs from immutable snapshot: {record.page_id}")

    @staticmethod
    def _validate_record_update(previous: OcrPageRecord, current: OcrPageRecord) -> None:
        if (previous.page_id, previous.source_page, previous.task_index) != (
            current.page_id, current.source_page, current.task_index,
        ):
            raise OcrStoreError("OCR page identity is immutable")
        if previous.status == OcrPageStatus.SUCCESS and previous.to_dict() != current.to_dict():
            raise OcrStoreError("successful OCR page record is immutable")
        if current.call_index < previous.call_index or current.retry_count < previous.retry_count:
            raise OcrStoreError("OCR page call/retry counters cannot decrease")
        if current.status != previous.status and not _page_status_reachable(
            previous.status, current.status,
        ):
            # The only exception is the explicit crash recovery reset.
            if not (
                previous.status in _TRANSIENT_PAGE_STATUSES
                and current.status == OcrPageStatus.PENDING
            ):
                raise OcrStoreError(
                    f"illegal persisted OCR page transition: {previous.status.value} -> {current.status.value}"
                )

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _page_status_reachable(start: OcrPageStatus, target: OcrPageStatus) -> bool:
    """Allow one atomic record write to commit several in-memory transient steps."""
    pending = [start]
    seen = {start}
    while pending:
        current = pending.pop()
        for next_status in _ALLOWED_PAGE_TRANSITIONS[current]:
            if next_status == target:
                return True
            if next_status not in seen:
                seen.add(next_status)
                pending.append(next_status)
    return False


def _strip_host_page_markers(text: str) -> str:
    return _HOST_PAGE_MARKER_RE.sub("", str(text or "")).strip()


@dataclass(frozen=True, slots=True)
class OcrValidationIssue:
    code: str
    severity: str
    message: str
    retryable: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class ValidatedOcrPage:
    page_id: str
    latex: str
    figures: tuple[Mapping[str, object], ...]
    unresolved_regions: tuple[Mapping[str, object], ...]
    issues: tuple[OcrValidationIssue, ...]
    needs_retry: bool
    needs_review: bool
    raw_object: Mapping[str, object] = field(repr=False)


class OcrBatchValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _model_payload(response: object) -> object:
    if isinstance(response, bytes):
        try:
            response = response.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OcrBatchValidationError("NON_JSON", "OCR batch response is not UTF-8 JSON") from exc
    if isinstance(response, str):
        if "```" in response:
            raise OcrBatchValidationError("MARKDOWN_FENCE", "OCR batch response contains a Markdown fence")
        try:
            return json.loads(response)
        except json.JSONDecodeError as exc:
            raise OcrBatchValidationError("NON_JSON", "OCR batch response is not valid JSON") from exc
    return response


def validate_ocr_batch_response(
    response: object,
    expected_page_ids: Sequence[str],
    *,
    reference_text_by_page_id: Mapping[str, str] | None = None,
    minimum_nonspace_chars: int = 8,
) -> list[ValidatedOcrPage]:
    """Require exact page-id coverage and validate every page independently."""
    expected = tuple(str(item) for item in expected_page_ids)
    if not expected or len(expected) > 3 or len(set(expected)) != len(expected):
        raise ValueError("expected_page_ids must contain 1-3 unique IDs")
    if any(_PAGE_ID_RE.fullmatch(item) is None for item in expected):
        raise ValueError("expected_page_ids contains an invalid page_id")
    payload = _model_payload(response)
    if isinstance(payload, Mapping) and isinstance(payload.get("pages"), list):
        values = payload["pages"]
    elif isinstance(payload, list):
        values = payload
    elif len(expected) == 1 and isinstance(payload, Mapping):
        values = [payload]
    else:
        raise OcrBatchValidationError("TOP_LEVEL_SCHEMA", "OCR response must contain a pages array")
    if not all(isinstance(item, Mapping) for item in values):
        raise OcrBatchValidationError("TOP_LEVEL_SCHEMA", "every OCR page response must be an object")
    ids = [str(item.get("page_id") or "") for item in values]
    duplicates = sorted({item for item in ids if item and ids.count(item) > 1})
    if duplicates:
        raise OcrBatchValidationError("DUPLICATE_PAGE_ID", f"duplicate OCR page_id: {duplicates[0]}")
    unknown = sorted(set(ids) - set(expected))
    if unknown:
        raise OcrBatchValidationError("UNKNOWN_PAGE_ID", f"unknown OCR page_id: {unknown[0]}")
    missing = sorted(set(expected) - set(ids))
    if missing:
        raise OcrBatchValidationError("MISSING_PAGE_ID", f"missing OCR page_id: {missing[0]}")
    if len(values) != len(expected):
        raise OcrBatchValidationError("PAGE_ID_COVERAGE", "OCR response page count does not match request")
    by_id = {str(item["page_id"]): item for item in values}
    references = dict(reference_text_by_page_id or {})
    output: list[ValidatedOcrPage] = []
    for page_id in expected:
        item = by_id[page_id]
        latex = item.get("latex")
        figures = item.get("figures")
        unresolved = item.get("unresolved_regions")
        if not isinstance(latex, str):
            raise OcrBatchValidationError("INVALID_LATEX", f"{page_id} latex must be a string")
        if not isinstance(figures, list):
            raise OcrBatchValidationError("INVALID_FIGURES", f"{page_id} figures must be an array")
        if not isinstance(unresolved, list):
            raise OcrBatchValidationError(
                "INVALID_UNRESOLVED_REGIONS", f"{page_id} unresolved_regions must be an array",
            )
        if not all(isinstance(entry, Mapping) for entry in figures):
            raise OcrBatchValidationError("INVALID_FIGURES", f"{page_id} contains an invalid figure")
        if not all(isinstance(entry, Mapping) for entry in unresolved):
            raise OcrBatchValidationError(
                "INVALID_UNRESOLVED_REGIONS", f"{page_id} contains an invalid unresolved region",
            )
        issues = inspect_latex_fragment(
            latex,
            reference_text=references.get(page_id, ""),
            minimum_nonspace_chars=minimum_nonspace_chars,
        )
        if unresolved:
            issues.append(OcrValidationIssue(
                "UNRESOLVED_REGIONS", "warning",
                f"{len(unresolved)} region(s) require confirmation", False,
            ))
        needs_retry = any(issue.retryable for issue in issues)
        needs_review = bool(unresolved) or any(issue.severity == "warning" for issue in issues)
        output.append(ValidatedOcrPage(
            page_id=page_id,
            latex=_strip_host_page_markers(latex),
            figures=tuple(_freeze(entry) for entry in figures),
            unresolved_regions=tuple(_freeze(entry) for entry in unresolved),
            issues=tuple(issues),
            needs_retry=needs_retry,
            needs_review=needs_review,
            raw_object=_freeze(dict(item)),
        ))
    return output


def inspect_latex_fragment(
    text: str,
    *,
    reference_text: str = "",
    minimum_nonspace_chars: int = 8,
) -> list[OcrValidationIssue]:
    """Deterministic, lightweight syntax/coverage checks for one page fragment."""
    value = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    issues: list[OcrValidationIssue] = []
    visible = re.sub(r"\s+", "", value)
    if not visible:
        issues.append(OcrValidationIssue("EMPTY_LATEX", "error", "page LaTeX is empty", True))
        return issues
    if len(visible) < max(1, int(minimum_nonspace_chars)):
        issues.append(OcrValidationIssue("ABNORMALLY_SHORT", "error", "page LaTeX is abnormally short", True))
    if "```" in value:
        issues.append(OcrValidationIssue("MARKDOWN_FENCE", "error", "Markdown fences are forbidden", True))
    if _FORBIDDEN_PREAMBLE_RE.search(value):
        issues.append(OcrValidationIssue("DOCUMENT_PREAMBLE", "error", "page returned a document preamble", True))
    if _FORBIDDEN_SEMANTIC_STRUCTURE_RE.search(value):
        # Preserve the non-empty transcription but require review.  Stage A is
        # pixel transcription only; structure remains an independent action.
        issues.append(OcrValidationIssue(
            "FORBIDDEN_SEMANTIC_STRUCTURE",
            "warning",
            "OCR page added semantic structure that is not visible transcription",
            False,
        ))
    if _HOST_PAGE_MARKER_RE.search(value):
        issues.append(OcrValidationIssue("MODEL_PAGE_MARKER", "error", "% Page markers are host-owned", True))
    active = _mask_comments(value)
    if not _braces_balanced(active):
        issues.append(OcrValidationIssue("UNBALANCED_BRACES", "error", "LaTeX braces are unbalanced", True))
    if not _math_delimiters_balanced(active):
        issues.append(OcrValidationIssue(
            "UNBALANCED_MATH_DELIMITERS", "error", "math delimiters are unbalanced", True,
        ))
    if not _environments_balanced(active):
        issues.append(OcrValidationIssue("UNCLOSED_ENVIRONMENT", "error", "begin/end environments mismatch", True))
    if any(re.search(r"\n\s*\n", match.group("body")) for match in _DISPLAY_ENV_RE.finditer(active)):
        issues.append(OcrValidationIssue(
            "DISPLAY_MATH_BLANK_PARAGRAPH", "error",
            "display math contains a destructive blank paragraph", True,
        ))
    reference = _plain_reference_tokens(reference_text)
    if len(reference) >= 30:
        output = _plain_reference_tokens(value)
        overlap = len(reference.intersection(output)) / max(1, len(reference))
        if overlap < 0.18:
            issues.append(OcrValidationIssue(
                "SEVERE_TEXT_COVERAGE_GAP", "error",
                "visual OCR has severe disagreement with the auxiliary text layer", True,
            ))
    return issues


def _mask_comments(text: str) -> str:
    lines = []
    for line in text.splitlines(keepends=True):
        escaped = False
        cut = len(line)
        for index, char in enumerate(line):
            if char == "%" and not escaped:
                cut = index
                break
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
        lines.append(line[:cut] + (" " * (len(line) - cut)))
    return "".join(lines)


def _braces_balanced(text: str) -> bool:
    depth = 0
    escaped = False
    for char in text:
        if char == "\\" and not escaped:
            escaped = True
            continue
        if not escaped:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth < 0:
                    return False
        escaped = False
    return depth == 0


def _math_delimiters_balanced(text: str) -> bool:
    # Remove escaped dollars before checking odd single-dollar runs.
    clean = re.sub(r"\\\$", "", text)
    clean = re.sub(r"\$\$.*?\$\$", "", clean, flags=re.S)
    if len(re.findall(r"(?<!\\)\$", clean)) % 2:
        return False
    stack: list[str] = []
    for match in re.finditer(r"\\(?P<token>\[|\]|\(|\))", clean):
        token = match.group("token")
        if token in {"[", "("}:
            stack.append(token)
        elif not stack or (token == "]" and stack.pop() != "[") or (token == ")" and stack.pop() != "("):
            return False
    return not stack


def _environments_balanced(text: str) -> bool:
    stack: list[str] = []
    for match in _ENV_TOKEN_RE.finditer(text):
        name = match.group("name")
        if match.group("kind").lower() == "begin":
            stack.append(name)
        elif not stack or stack.pop() != name:
            return False
    return not stack


def _plain_reference_tokens(text: str) -> set[str]:
    plain = re.sub(r"\\[A-Za-z@]+\*?", " ", str(text or ""))
    return {token.casefold() for token in re.findall(r"[\w\u4e00-\u9fff]{2,}", plain)}


class OcrErrorCategory(str, Enum):
    TRANSIENT = "TRANSIENT"
    RATE_LIMIT = "RATE_LIMIT"
    BATCH_INCOMPATIBLE = "BATCH_INCOMPATIBLE"
    TRUNCATED = "TRUNCATED"
    AUTH = "AUTH"
    QUOTA = "QUOTA"
    CONFIG = "CONFIG"
    REFUSAL = "REFUSAL"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


def classify_ocr_error(error: object) -> OcrErrorCategory:
    text = str(error or "").casefold()
    if any(token in text for token in ("cancelled", "canceled", "用户取消", "已取消")):
        return OcrErrorCategory.CANCELLED
    if any(token in text for token in ("http 401", "http 403", "unauthorized", "api key", "登录失效")):
        return OcrErrorCategory.AUTH
    if any(token in text for token in ("quota", "额度耗尽", "insufficient balance", "余额不足")):
        return OcrErrorCategory.QUOTA
    if any(token in text for token in ("model not found", "unknown model", "base url", "模型不存在")):
        return OcrErrorCategory.CONFIG
    if any(token in text for token in ("content refusal", "refused", "内容拒绝", "safety refusal")):
        return OcrErrorCategory.REFUSAL
    if any(token in text for token in ("http 429", "rate limit", "too many requests", "限流")):
        return OcrErrorCategory.RATE_LIMIT
    if any(token in text for token in ("multiple image", "multi-image", "多图不", "batch unsupported")):
        return OcrErrorCategory.BATCH_INCOMPATIBLE
    if any(token in text for token in ("max_tokens", "truncated", "截断", "request too large")):
        return OcrErrorCategory.TRUNCATED
    if any(token in text for token in (
        "timeout", "timed out", "connection", "http 408", "http 500", "http 502",
        "http 503", "http 504", "temporary", "temporarily", "网络", "临时",
    )):
        return OcrErrorCategory.TRANSIENT
    if any(token in text for token in (
        "安全配置不兼容", "功能清单不兼容", "功能清单无法读取",
        "未返回可验证的功能清单", "结构化输出协议不兼容",
    )):
        return OcrErrorCategory.CONFIG
    return OcrErrorCategory.UNKNOWN


_BATCH_FALLBACK_CODES = frozenset({
    "NON_JSON", "TOP_LEVEL_SCHEMA", "MARKDOWN_FENCE", "MISSING_PAGE_ID",
    "DUPLICATE_PAGE_ID", "UNKNOWN_PAGE_ID", "PAGE_ID_COVERAGE", "INVALID_LATEX",
    "INVALID_FIGURES", "INVALID_UNRESOLVED_REGIONS",
})
_BATCH_FALLBACK_CATEGORIES = frozenset({
    OcrErrorCategory.TRANSIENT,
    OcrErrorCategory.RATE_LIMIT,
    OcrErrorCategory.BATCH_INCOMPATIBLE,
    OcrErrorCategory.TRUNCATED,
})


class OcrRunPaused(RuntimeError):
    """A non-retryable provider/configuration failure; saved pages remain valid."""

    def __init__(self, category: OcrErrorCategory, message: str):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, slots=True)
class OcrPageRequest:
    page_id: str
    source_page: int
    task_index: int
    image_bytes: bytes = field(repr=False)
    dpi: int = 200
    text_layer_hint: str = ""
    crops: tuple[bytes, ...] = field(default_factory=tuple, repr=False)
    correction_instruction: str = ""
    retry_state: Mapping[str, object] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.page_id != make_page_id(self.task_index):
            raise ValueError("OCR request page_id/task_index mismatch")
        if self.source_page < 1 or not self.image_bytes:
            raise ValueError("OCR request requires source page and image bytes")
        if not 72 <= int(self.dpi) <= 600:
            raise ValueError("OCR request DPI is outside 72..600")
        if len(self.crops) > 4 or any(not crop for crop in self.crops):
            raise ValueError("OCR request supports at most four non-empty crops")
        object.__setattr__(self, "correction_instruction", str(self.correction_instruction or "")[:1600])
        object.__setattr__(self, "retry_state", _freeze(dict(self.retry_state or {})))

    def public_payload(self) -> dict[str, object]:
        return {
            "page_id": self.page_id,
            "source_page": self.source_page,
            "task_index": self.task_index,
            "dpi": self.dpi,
            "image_sha256": _sha256_bytes(self.image_bytes),
            "crop_count": len(self.crops),
        }


@dataclass(frozen=True, slots=True)
class OcrExecutionResult:
    request: OcrPageRequest
    page: ValidatedOcrPage | None
    error: str = ""
    error_category: OcrErrorCategory | None = None
    retry_instruction: str = ""
    retry_state: Mapping[str, object] = field(default_factory=dict, repr=False)
    batch_id: str = ""
    used_batch: bool = False
    fell_back_to_single: bool = False


class AdaptivePageConcurrency:
    """Small deterministic limiter: reduce immediately on 429, recover slowly."""

    def __init__(self, maximum: int = 3, recovery_successes: int = 12):
        if not 1 <= int(maximum) <= 3:
            raise ValueError("maximum OCR concurrency must be in 1..3")
        self.maximum = int(maximum)
        self.current = self.maximum
        self.recovery_successes = max(1, int(recovery_successes))
        self._successes = 0
        self._lock = threading.Lock()

    def on_rate_limit(self) -> int:
        with self._lock:
            self.current = max(1, self.current - 1)
            self._successes = 0
            return self.current

    def on_success(self) -> int:
        with self._lock:
            self._successes += 1
            if self.current < self.maximum and self._successes >= self.recovery_successes:
                self.current += 1
                self._successes = 0
            return self.current


class BoundedOcrExecutor:
    """Run at most three page tasks at once with strict conservative fallback.

    A batch of three consumes the entire default page-concurrency budget, so
    batches are launched sequentially.  Non-batch/single fallback calls may use
    a thread pool whose worker count is still capped at three.
    """

    def __init__(self, *, batch_size: int = 3, concurrency_limit: int = 3):
        if not 1 <= int(batch_size) <= 3 or not 1 <= int(concurrency_limit) <= 3:
            raise ValueError("OCR batch size and concurrency must be in 1..3")
        self.batch_size = int(batch_size)
        self.concurrency_limit = int(concurrency_limit)

    def run(
        self,
        requests: Sequence[OcrPageRequest],
        *,
        single_call: Callable[[OcrPageRequest], object],
        batch_call: Callable[[Sequence[OcrPageRequest]], object] | None = None,
        on_result: Callable[[OcrExecutionResult], None] | None = None,
    ) -> list[OcrExecutionResult]:
        if len({request.page_id for request in requests}) != len(requests):
            raise ValueError("OCR request page_id values must be unique")
        # A one-page request must always use the single-page contract.  Apart
        # from avoiding pointless batch schema overhead, this ensures a generic
        # local-runtime failure becomes a page result which the host can retry
        # at 300 DPI instead of escaping from the batch exception path.
        if len(requests) <= 1 or batch_call is None or self.batch_size == 1:
            results = self._run_singles(requests, single_call, False, "")
            self._emit(results, on_result)
            return sorted(results, key=lambda item: item.request.task_index)
        results: list[OcrExecutionResult] = []
        for offset in range(0, len(requests), self.batch_size):
            batch = tuple(requests[offset:offset + self.batch_size])
            batch_id = f"ocr-batch-{uuid.uuid4().hex[:12]}"
            try:
                raw = batch_call(batch)
                pages = validate_ocr_batch_response(
                    raw,
                    [request.page_id for request in batch],
                    reference_text_by_page_id={
                        request.page_id: request.text_layer_hint for request in batch
                    },
                )
                by_id = {page.page_id: page for page in pages}
                current = [
                    OcrExecutionResult(
                        request=request,
                        page=by_id[request.page_id],
                        batch_id=batch_id,
                        used_batch=True,
                    )
                    for request in batch
                ]
            except OcrBatchValidationError as exc:
                if exc.code not in _BATCH_FALLBACK_CODES:
                    raise
                current = self._run_singles(batch, single_call, True, batch_id)
            except Exception as exc:  # provider categories are host policy, not model policy
                category = classify_ocr_error(exc)
                if category not in _BATCH_FALLBACK_CATEGORIES:
                    if category in {
                        OcrErrorCategory.AUTH, OcrErrorCategory.QUOTA, OcrErrorCategory.CONFIG,
                        OcrErrorCategory.REFUSAL, OcrErrorCategory.CANCELLED,
                    }:
                        raise OcrRunPaused(category, str(exc)) from exc
                    raise
                current = self._run_singles(batch, single_call, True, batch_id)
            results.extend(current)
            self._emit(current, on_result)
        return sorted(results, key=lambda item: item.request.task_index)

    def _run_singles(
        self,
        requests: Sequence[OcrPageRequest],
        single_call: Callable[[OcrPageRequest], object],
        fallback: bool,
        batch_id: str,
    ) -> list[OcrExecutionResult]:
        def invoke(request: OcrPageRequest) -> OcrExecutionResult:
            try:
                raw = single_call(request)
                page = validate_ocr_batch_response(
                    raw,
                    [request.page_id],
                    reference_text_by_page_id={request.page_id: request.text_layer_hint},
                )[0]
                return OcrExecutionResult(
                    request=request,
                    page=page,
                    batch_id=batch_id,
                    used_batch=False,
                    fell_back_to_single=fallback,
                )
            except Exception as exc:  # one page failure does not erase siblings
                category = classify_ocr_error(exc)
                if category in {
                    OcrErrorCategory.AUTH, OcrErrorCategory.QUOTA, OcrErrorCategory.CONFIG,
                    OcrErrorCategory.REFUSAL, OcrErrorCategory.CANCELLED,
                }:
                    raise OcrRunPaused(category, str(exc)) from exc
                return OcrExecutionResult(
                    request=request,
                    page=None,
                    error=str(exc)[:1000],
                    error_category=category,
                    retry_instruction=str(getattr(exc, "retry_instruction", "") or "")[:1600],
                    retry_state=_freeze(
                        getattr(exc, "retry_state", {})
                        if isinstance(getattr(exc, "retry_state", {}), Mapping)
                        else {}
                    ),
                    batch_id=batch_id,
                    used_batch=False,
                    fell_back_to_single=fallback,
                )

        if len(requests) <= 1:
            return [invoke(requests[0])] if requests else []
        output: list[OcrExecutionResult] = []
        with ThreadPoolExecutor(max_workers=min(self.concurrency_limit, len(requests))) as pool:
            futures: dict[Future[OcrExecutionResult], OcrPageRequest] = {
                pool.submit(invoke, request): request for request in requests
            }
            for future in as_completed(futures):
                output.append(future.result())
        return output

    @staticmethod
    def _emit(
        results: Sequence[OcrExecutionResult],
        callback: Callable[[OcrExecutionResult], None] | None,
    ) -> None:
        if callback is not None:
            for result in results:
                callback(result)


def progress_metrics(
    snapshot: OcrRunSnapshot,
    records: Sequence[OcrPageRecord],
    *,
    now_epoch: float | None = None,
    terminal_epoch: float | None = None,
    merge_complete: bool = False,
    raw_frozen: bool = False,
    compile_status: OcrPreviewStatus | str | None = None,
    rate_limited: bool = False,
    concurrency_limit: int | None = None,
) -> dict[str, object]:
    """Return truthful page counters, measured speed and compile milestones."""
    if len(records) != len(snapshot.selected_pages):
        raise ValueError("progress records must cover the immutable page selection")
    ordered = sorted(records, key=lambda item: item.task_index)
    for index, record in enumerate(ordered, start=1):
        if (record.page_id, record.source_page) != snapshot.page_identity(index):
            raise ValueError("progress record identity/order mismatch")
    counts = {status.value: 0 for status in OcrPageStatus}
    for record in ordered:
        counts[record.status.value] += 1
    total = len(ordered)
    finalized = sum(counts[status.value] for status in _FINALIZED_PAGE_STATUSES)
    active = [record for record in ordered if record.status in _TRANSIENT_PAGE_STATUSES]
    retry_pages = [record for record in ordered if record.retry_count > 0]
    now_value = time.time() if now_epoch is None else float(now_epoch)
    try:
        started_epoch = datetime.fromisoformat(snapshot.started_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        started_epoch = now_value
    # Page completion is not job completion: merge, immutable freeze, baseline
    # repair and two real compile passes all happen afterwards.  Only a terminal
    # boundary frozen by the host may stop the workflow clock.
    elapsed_frozen = False
    metric_now = now_value
    if terminal_epoch is not None:
        try:
            terminal_value = float(terminal_epoch)
        except (TypeError, ValueError):
            terminal_value = math.nan
        if math.isfinite(terminal_value) and terminal_value >= started_epoch:
            elapsed_frozen = True
            metric_now = terminal_value
    elapsed = max(0.0, metric_now - started_epoch)
    result_pages = counts[OcrPageStatus.SUCCESS.value] + counts[OcrPageStatus.NEEDS_REVIEW.value]
    average = (result_pages * 60.0 / elapsed) if elapsed > 0 else 0.0
    recent = 0
    for record in ordered:
        if record.status not in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW} or not record.ended_at:
            continue
        try:
            ended = datetime.fromisoformat(record.ended_at.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        if metric_now - 60.0 <= ended <= metric_now + 1.0:
            recent += 1
    recent_rate = float(recent)
    effective_rate = recent_rate or average
    unfinished = total - result_pages - counts[OcrPageStatus.CANCELLED.value]
    eta = (unfinished * 60.0 / effective_rate) if unfinished > 0 and effective_rate > 0 else None
    recognition_progress = finalized / total if total else 0.0
    # Explicit milestones keep log/snapshot writes from pretending the run is
    # 99% complete.  COMPILED is the only state that reaches 100%.
    overall = 0.02 + 0.88 * recognition_progress
    if merge_complete:
        overall = max(overall, 0.93)
    if raw_frozen:
        overall = max(overall, 0.95)
    normalized_compile = None
    if compile_status is not None:
        normalized_compile = _enum_value(OcrPreviewStatus, compile_status, "OCR preview status")
        if normalized_compile == OcrPreviewStatus.COMPILED:
            overall = 1.0
        elif normalized_compile == OcrPreviewStatus.PARTIAL_COMPILED:
            overall = max(overall, 0.97)
    current_limit = max(1, min(3, int(concurrency_limit or snapshot.concurrency_limit)))
    current_pages = [record.source_page for record in active]
    current_dpi = max((record.dpi for record in active), default=0) or snapshot.initial_dpi
    public_counts = {
        "total": total,
        "pending": counts[OcrPageStatus.PENDING.value],
        "processing": len(active),
        "success": counts[OcrPageStatus.SUCCESS.value],
        "retrying": counts[OcrPageStatus.RETRYING.value],
        "needs_review": counts[OcrPageStatus.NEEDS_REVIEW.value],
        "failed": counts[OcrPageStatus.FAILED.value],
        "cancelled": counts[OcrPageStatus.CANCELLED.value],
        "automatic_retry_pages": len(retry_pages),
    }
    return {
        "run_id": snapshot.run_id,
        "quality_tier": snapshot.quality_tier.value,
        "counts": public_counts,
        "status_counts": counts,
        "recognition_progress": round(recognition_progress, 6),
        "overall_progress": round(min(1.0, overall), 6),
        "elapsed_seconds": round(elapsed, 3),
        "elapsed_frozen": elapsed_frozen,
        "average_pages_per_minute": round(average, 3),
        "recent_pages_per_minute": round(recent_rate, 3),
        "eta_seconds": round(eta, 1) if eta is not None else None,
        "rate_limited": bool(rate_limited),
        "current_concurrency": len(active),
        "concurrency_limit": current_limit,
        "current_dpi": current_dpi,
        "current_pages": current_pages,
        "current_page": current_pages[0] if current_pages else None,
        "merge_complete": bool(merge_complete),
        "raw_frozen": bool(raw_frozen),
        "compile_status": normalized_compile.value if normalized_compile else None,
    }


OCR_TRANSCRIPTION_SYSTEM_PROMPT = r"""你是数学文档页面忠实转写器。
你的任务是把当前页面图像逐字转写为可编辑 LaTeX 正文片段。
不得总结、润色、解释、扩写、补写或根据数学常识纠正原文。
页面像素是内容权威；PDF 文本层只作为辅助提示。
必须保留正文顺序、公式、编号、脚注、图题、表题和参考文献。
不得自行添加 theorem、lemma、proof、chapter、section 等语义环境。
页面中可见的 Theorem、Proof 等标题只按普通可见文字忠实输出。
不输出 documentclass、usepackage、begin document 或 end document。
不输出 Markdown 代码围栏，不输出解释性文字。
若页面包含必须保留的非文字插图，在正文中使用
\includegraphics{figures/page_XXXX_figure_YY.png}，并在 figures 中按出现顺序给出
同一路径、从 1 开始的 index、完整页归一化坐标和像素坐标；不要把整页当作插图。
不确定的区域不得猜测，必须在 unresolved_regions 中给出 type、reason 和完整页
归一化坐标；没有插图或不确定区域时返回空数组。
每页必须准确回显宿主给出的 page_id。
严格返回符合宿主 schema 的 JSON。"""


_OCR_BBOX_NORMALIZED_SCHEMA = {
    "type": "array",
    "items": {"type": "number", "minimum": 0, "maximum": 1},
    "minItems": 4,
    "maxItems": 4,
}

_OCR_BBOX_PIXELS_SCHEMA = {
    "type": "array",
    "items": {"type": "integer", "minimum": 0},
    "minItems": 4,
    "maxItems": 4,
}

_OCR_FIGURE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "path": {"type": "string"},
        "index": {"type": "integer", "minimum": 1},
        "bbox_normalized": _OCR_BBOX_NORMALIZED_SCHEMA,
        "bbox_pixels": _OCR_BBOX_PIXELS_SCHEMA,
    },
    "required": ["path", "index", "bbox_normalized", "bbox_pixels"],
}

_OCR_UNRESOLVED_REGION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "type": {
            "type": "string",
            "enum": ["text", "formula", "figure", "table", "layout", "other"],
        },
        "reason": {"type": "string"},
        "bbox_normalized": _OCR_BBOX_NORMALIZED_SCHEMA,
    },
    "required": ["type", "reason", "bbox_normalized"],
}


def ocr_batch_output_schema(expected_page_ids: Sequence[str]) -> dict[str, object]:
    ids = [str(item) for item in expected_page_ids]
    if not 1 <= len(ids) <= 3 or len(set(ids)) != len(ids):
        raise ValueError("OCR schema requires 1-3 unique page IDs")
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "pages": {
                "type": "array",
                "minItems": len(ids),
                "maxItems": len(ids),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "page_id": {"type": "string", "enum": ids},
                        "latex": {"type": "string"},
                        "figures": {"type": "array", "items": _OCR_FIGURE_SCHEMA},
                        "unresolved_regions": {
                            "type": "array", "items": _OCR_UNRESOLVED_REGION_SCHEMA,
                        },
                    },
                    "required": ["page_id", "latex", "figures", "unresolved_regions"],
                },
            },
        },
        "required": ["pages"],
    }


def ocr_batch_request_payload(requests: Sequence[OcrPageRequest]) -> str:
    if not 1 <= len(requests) <= 3:
        raise ValueError("one OCR call must contain 1-3 independent pages")
    if len({request.page_id for request in requests}) != len(requests):
        raise ValueError("OCR request page IDs must be unique")
    pages = []
    for image_index, request in enumerate(requests, start=1):
        item: dict[str, object] = {
            "image_index": image_index,
            "page_id": request.page_id,
            "source_page": request.source_page,
            "dpi": request.dpi,
            "instruction": "只转写该 image_index 对应的独立页面，并回显 page_id",
        }
        if request.text_layer_hint:
            item["untrusted_pdf_text_reference"] = request.text_layer_hint[:12000]
            item["reference_policy"] = "仅辅助拼写与顺序；页面像素冲突时以像素为准"
        if request.correction_instruction:
            item["retry_correction"] = request.correction_instruction
            item["retry_policy"] = "只修复列出的可定位问题；仍须忠实转写当前页面像素"
        if request.retry_state:
            item["host_verified_retry_evidence"] = thaw_json(request.retry_state)
        pages.append(item)
    return json.dumps({"page_requests": pages}, ensure_ascii=False, separators=(",", ":"))

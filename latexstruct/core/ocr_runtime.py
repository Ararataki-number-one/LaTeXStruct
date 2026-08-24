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
import platform
import re
import stat
import sys
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence


OCR_RUNTIME_SCHEMA = "latexstruct-ocr-runtime-v1"
OCR_PAGE_RECORD_SCHEMA = "latexstruct-ocr-page-record-v1"
OCR_RAW_FREEZE_SCHEMA = "latexstruct-raw-ocr-freeze-v1"
OCR_BASELINE_SCHEMA = "latexstruct-ocr-baseline-v1"
OCR_PAGE_SOURCE_EVIDENCE_SCHEMA = "latexstruct-ocr-page-source-evidence-v1"

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
_OCR_INCLUDEGRAPHICS_RE = re.compile(
    r"\\includegraphics(?:\s*\[[^\]\r\n]*\])?\s*\{([^{}\r\n]+)\}",
    re.I,
)
_OCR_BOUNDARY_DECIMAL_RE = re.compile(r"^[0-9]{1,6}$")
_OCR_TARGET_TEXT_BLOCK_PAGE_RATIO = 125.0 / 155.0
_OCR_FIGURE_WIDTH_MIN = 0.25
_OCR_FIGURE_WIDTH_MAX = 1.0
_OCR_FIGURE_HEIGHT_MAX = 0.72
_OCR_BASELINE_PACKAGE_DIRECTORY = "ocr-baseline"


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


def _strict_ocr_bundle_relative_path(value: object, label: str) -> str:
    """Validate one portable package path before it reaches ``pathlib``.

    Manifest paths are POSIX paths even on Windows.  Rejecting normalization,
    alternate separators, drive syntax, and Windows filename aliases here keeps
    two logical artifact names from ever resolving to the same host file.
    """
    if not isinstance(value, str):
        raise OcrStoreError(f"{label} must be a relative POSIX path")
    path = value
    if (
        not path
        or "\\" in path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:", path)
        or path.startswith("//")
        or "://" in path
        or "\x00" in path
    ):
        raise OcrStoreError(f"{label} must be a relative POSIX path")
    pure = PurePosixPath(path)
    parts = pure.parts
    if (
        path != pure.as_posix()
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part or part.rstrip(" .") != part for part in parts)
    ):
        raise OcrStoreError(f"{label} must be a normalized relative POSIX path")
    return path


def _path_is_reparse_point(path: Path) -> bool:
    """Return whether a path can redirect package I/O outside its tree."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return path.is_symlink() or bool(reparse_flag and attributes & reparse_flag)


def _ocr_bundle_expected_directories(paths: set[str]) -> set[str]:
    expected: set[str] = set()
    for logical_path in paths:
        parent = PurePosixPath(logical_path).parent
        while parent.as_posix() != ".":
            expected.add(parent.as_posix())
            parent = parent.parent
    return expected


def _scan_ocr_bundle_tree(
    package_root: Path,
    *,
    expected_files: set[str],
) -> tuple[set[str], set[str]]:
    """Scan a package without following links and reject unexpected entries."""
    if not package_root.exists():
        return set(), set()
    if not package_root.is_dir() or _path_is_reparse_point(package_root):
        raise OcrStoreError("OCR baseline package root is not a plain directory")
    expected_directories = _ocr_bundle_expected_directories(expected_files)
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for entry in package_root.rglob("*"):
        relative = entry.relative_to(package_root).as_posix()
        if _path_is_reparse_point(entry):
            raise OcrStoreError(f"OCR baseline package contains a link: {relative}")
        if entry.is_dir():
            actual_directories.add(relative)
            if relative not in expected_directories:
                raise OcrStoreError(
                    f"OCR baseline package contains an extra directory: {relative}"
                )
        elif entry.is_file():
            actual_files.add(relative)
            if relative not in expected_files:
                raise OcrStoreError(
                    f"OCR baseline package contains an extra file: {relative}"
                )
        else:
            raise OcrStoreError(
                f"OCR baseline package contains an unsupported entry: {relative}"
            )
    if not actual_directories.issubset(expected_directories):
        raise OcrStoreError("OCR baseline package directory closure is invalid")
    return actual_files, actual_directories


def _crop_ocr_figure_png(
    image_bytes: bytes,
    bbox_pixels: tuple[int, int, int, int],
    image_size_pixels: tuple[int, int],
) -> tuple[bytes, tuple[int, int]]:
    """Crop one exact raster input without trusting model file bytes or paths."""
    try:
        import pymupdf

        width, height = image_size_pixels
        x0, y0, x1, y1 = bbox_pixels
        document = pymupdf.open(stream=bytes(image_bytes))
        try:
            if document.page_count != 1:
                raise ValueError("page visual must contain exactly one raster page")
            page = document[0]
            page_rect = page.rect
            if page_rect.width <= 0 or page_rect.height <= 0:
                raise ValueError("page visual has invalid geometry")
            clip = pymupdf.Rect(
                page_rect.x0 + (x0 / width) * page_rect.width,
                page_rect.y0 + (y0 / height) * page_rect.height,
                page_rect.x0 + (x1 / width) * page_rect.width,
                page_rect.y0 + (y1 / height) * page_rect.height,
            )
            matrix = pymupdf.Matrix(width / page_rect.width, height / page_rect.height)
            pixmap = page.get_pixmap(matrix=matrix, clip=clip, alpha=False)
            expected_width = x1 - x0
            expected_height = y1 - y0
            if (
                pixmap.width < 1
                or pixmap.height < 1
                or abs(pixmap.width - expected_width) > 2
                or abs(pixmap.height - expected_height) > 2
            ):
                raise ValueError("cropped figure dimensions do not match the validated bbox")
            result = pixmap.tobytes("png")
            if not result.startswith(b"\x89PNG\r\n\x1a\n"):
                raise ValueError("figure crop encoder did not return PNG")
            return result, (pixmap.width, pixmap.height)
        finally:
            document.close()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise OcrStoreError("failed to crop a host-validated OCR figure") from exc


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
        OcrQualityTier.RECOMMENDED, 200, 300, 3, 3, 5, True, True, True, True,
    ),
    OcrQualityTier.HIGH: OcrTierPolicy(
        OcrQualityTier.HIGH, 200, 300, 3, 3, 5, True, True, True, True,
    ),
}


def quality_tier_policy(value: object) -> OcrTierPolicy:
    return _TIER_POLICIES[normalize_quality_tier(value)]


class OcrPageStatus(str, Enum):
    PENDING = "PENDING"
    CLASSIFYING = "CLASSIFYING"
    EXTRACTING = "EXTRACTING"
    RENDERING = "RENDERING"
    QUEUED = "QUEUED"
    VERIFYING = "VERIFYING"
    OCR_RUNNING = "OCR_RUNNING"
    VALIDATING = "VALIDATING"
    RETRYING = "RETRYING"
    SUCCESS = "SUCCESS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"


_TRANSIENT_PAGE_STATUSES = frozenset({
    OcrPageStatus.CLASSIFYING,
    OcrPageStatus.EXTRACTING,
    OcrPageStatus.RENDERING,
    OcrPageStatus.QUEUED,
    OcrPageStatus.VERIFYING,
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
    OcrPageStatus.PAUSED,
})
_ALLOWED_PAGE_TRANSITIONS = {
    OcrPageStatus.PENDING: {
        OcrPageStatus.CLASSIFYING, OcrPageStatus.EXTRACTING,
        OcrPageStatus.RENDERING, OcrPageStatus.QUEUED,
        OcrPageStatus.PAUSED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.CLASSIFYING: {
        OcrPageStatus.EXTRACTING, OcrPageStatus.RENDERING,
        OcrPageStatus.QUEUED, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.PAUSED,
        OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.EXTRACTING: {
        OcrPageStatus.RENDERING, OcrPageStatus.QUEUED,
        OcrPageStatus.VERIFYING, OcrPageStatus.OCR_RUNNING,
        OcrPageStatus.VALIDATING, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.PAUSED,
        OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.RENDERING: {
        OcrPageStatus.QUEUED, OcrPageStatus.VERIFYING,
        OcrPageStatus.OCR_RUNNING, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.PAUSED,
        OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.QUEUED: {
        OcrPageStatus.VERIFYING, OcrPageStatus.OCR_RUNNING,
        OcrPageStatus.RETRYING, OcrPageStatus.FAILED,
        OcrPageStatus.PAUSED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.VERIFYING: {
        OcrPageStatus.RENDERING, OcrPageStatus.VALIDATING,
        OcrPageStatus.OCR_RUNNING,
        OcrPageStatus.RETRYING, OcrPageStatus.FAILED,
        OcrPageStatus.PAUSED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.OCR_RUNNING: {
        OcrPageStatus.VALIDATING, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.PAUSED,
        OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.VALIDATING: {
        OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW, OcrPageStatus.RETRYING,
        OcrPageStatus.FAILED, OcrPageStatus.PAUSED,
        OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.RETRYING: {
        OcrPageStatus.CLASSIFYING, OcrPageStatus.EXTRACTING,
        OcrPageStatus.RENDERING, OcrPageStatus.QUEUED,
        OcrPageStatus.VERIFYING, OcrPageStatus.OCR_RUNNING,
        OcrPageStatus.VALIDATING, OcrPageStatus.FAILED,
        OcrPageStatus.PAUSED, OcrPageStatus.CANCELLED,
    },
    OcrPageStatus.NEEDS_REVIEW: {OcrPageStatus.RETRYING, OcrPageStatus.CANCELLED},
    OcrPageStatus.FAILED: {OcrPageStatus.RETRYING, OcrPageStatus.CANCELLED},
    OcrPageStatus.PAUSED: {
        OcrPageStatus.PENDING, OcrPageStatus.RETRYING, OcrPageStatus.CANCELLED,
    },
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
    pipeline_contract: Mapping[str, object] = field(default_factory=dict)
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
        pipeline_contract = dict(self.pipeline_contract or {})
        forbidden_contract_keys = [
            str(key) for key in pipeline_contract
            if any(token in str(key).casefold() for token in (
                "api_key", "authorization", "password", "access_token",
                "refresh_token", "credential", "user_home", "temp_dir",
                "cache_dir", "project_root", "compile_workdir",
            ))
        ]
        if forbidden_contract_keys:
            raise ValueError(
                "pipeline_contract contains sensitive/path fields: "
                f"{forbidden_contract_keys[0]}"
            )
        try:
            contract_bytes = _canonical_json(pipeline_contract)
        except (TypeError, ValueError) as exc:
            raise ValueError("pipeline_contract must contain JSON values") from exc
        if len(contract_bytes) > 512_000:
            raise ValueError("pipeline_contract is too large")
        page_strategies = pipeline_contract.get("page_strategies") or []
        if page_strategies:
            if not isinstance(page_strategies, list) or len(page_strategies) != len(pages):
                raise ValueError(
                    "pipeline_contract page_strategies must describe every selected page"
                )
            expected_ids = [make_page_id(index) for index in range(1, len(pages) + 1)]
            actual_ids = [
                str(item.get("page_id") or "") if isinstance(item, Mapping) else ""
                for item in page_strategies
            ]
            if actual_ids != expected_ids:
                raise ValueError(
                    "pipeline_contract page_strategies are not in stable page_id order"
                )
        object.__setattr__(self, "pipeline_contract", _freeze(pipeline_contract))
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
            "pipeline_contract": thaw_json(self.pipeline_contract),
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
            pipeline_contract=value.get("pipeline_contract") or {},
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
    pipeline_contract: Mapping[str, object] | None = None,
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
    verification_dpi = int(options.get("verification_dpi", 160))
    retry_dpi = int(options.get("retry_dpi", policy.retry_dpi))
    verification_batch_size = int(options.get("verification_batch_size", 4))
    requested_contract = dict(pipeline_contract or {})
    contract = {
        "project_id": "",
        "document_strategy": "UNKNOWN",
        "page_strategies": [],
        "verification_model": str(ocr_model or ""),
        "strong_model": "",
        "prompt_version": "unknown",
        "response_schema_version": "latexstruct-ocr-page-response-v2",
        "git_commit": "unknown",
        "build_id": "unknown",
        # Unknown provenance is deliberately fail-closed: it may not be
        # represented as a clean release build.
        "dirty": True,
        "python_version": platform.python_version() or sys.version.split()[0],
        "operating_system": platform.platform(),
        "latex_engine": "unknown",
        "verification_dpi": verification_dpi,
        "full_ocr_dpi": initial_dpi,
        "retry_dpi": retry_dpi,
        "verification_batch_size": verification_batch_size,
        "ocr_batch_size": batch_size,
        "concurrency_limit": concurrency_limit,
        "max_input_tokens": int(options.get("max_input_tokens", 0)),
        "max_output_tokens": int(options.get("max_output_tokens", 0)),
        "max_requests": int(options.get("max_requests", 0)),
        "max_strong_model_calls": int(options.get("max_strong_model_calls", 0)),
        "max_cost": float(options.get("max_cost", 0.0)),
        "max_wall_time_minutes": float(options.get("max_wall_time_minutes", 0.0)),
        "target_30_min_applicable": bool(
            tier is OcrQualityTier.RECOMMENDED and int(source_total_pages) == 600
        ),
        "target_30_min_not_applicable_reason": (
            "" if tier is OcrQualityTier.RECOMMENDED and int(source_total_pages) == 600
            else "requires an authorized real 600-page recommended-tier run"
        ),
    }
    contract.update(requested_contract)
    frozen_config = {
        "api_backend": str(api_backend or ""),
        "ocr_model": str(ocr_model or ""),
        "quality_tier": tier.value,
        "initial_dpi": initial_dpi,
        "max_retries": max_retries,
        "batch_size": batch_size,
        "concurrency_limit": concurrency_limit,
        "pipeline_contract": contract,
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
        pipeline_contract=contract,
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
    source_evidence_sha256: str = ""
    raw_tex: str = ""
    cleaned_tex: str = ""
    tex_sha256: str = ""
    started_at: str = ""
    ended_at: str = ""
    elapsed_seconds: float | None = None
    retry_count: int = 0
    quality_issues: tuple[Mapping[str, object], ...] = ()
    host_quality_flags: tuple[Mapping[str, object], ...] = ()
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
        source_evidence_sha = _validate_sha256(
            self.source_evidence_sha256,
            "source_evidence_sha256",
            allow_empty=True,
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
        object.__setattr__(self, "source_evidence_sha256", source_evidence_sha)
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
        object.__setattr__(self, "host_quality_flags", tuple(
            _freeze(item) for item in self.host_quality_flags
        ))
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
            "source_evidence_sha256": self.source_evidence_sha256,
            "raw_tex": self.raw_tex,
            "cleaned_tex": self.cleaned_tex,
            "tex_sha256": self.tex_sha256,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_seconds": self.elapsed_seconds,
            "retry_count": self.retry_count,
            "quality_issues": thaw_json(self.quality_issues),
            "host_quality_flags": thaw_json(self.host_quality_flags),
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
            source_evidence_sha256=value.get("source_evidence_sha256", ""),
            raw_tex=value.get("raw_tex", ""),
            cleaned_tex=value.get("cleaned_tex", ""),
            tex_sha256=value.get("tex_sha256", ""),
            started_at=value.get("started_at", ""),
            ended_at=value.get("ended_at", ""),
            elapsed_seconds=value.get("elapsed_seconds"),
            retry_count=value.get("retry_count", 0),
            quality_issues=tuple(value.get("quality_issues") or ()),
            host_quality_flags=tuple(value.get("host_quality_flags") or ()),
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
            (directory / "source-evidence").mkdir(exist_ok=True)
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
        # Windows does not allow ``os.replace`` to replace a file while another
        # thread still has that file open for reading.  API polling and recovery
        # writes share one store instance, so reads must participate in the same
        # lock as ``persist_record`` instead of racing its atomic commit marker.
        with self._lock:
            try:
                value = json.loads(
                    self._record_path(run_id, page_id).read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise OcrStoreError(
                    f"OCR page record is missing or corrupt: {page_id}"
                ) from exc
            record = OcrPageRecord.from_dict(value)
            self._validate_record_identity(self.load_snapshot(run_id), record)
            return record

    def list_records(self, run_id: str) -> list[OcrPageRecord]:
        # Hold the lock across the whole list so public job snapshots cannot mix
        # page records from opposite sides of a concurrent recovery commit.
        # ``RLock`` keeps the nested ``load_record`` calls safe and re-entrant.
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            return [
                self.load_record(run_id, make_page_id(index))
                for index in range(1, len(snapshot.selected_pages) + 1)
            ]

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

    def persist_page_source_evidence(
        self,
        run_id: str,
        record: OcrPageRecord,
        evidence: Mapping[str, object],
    ) -> str:
        """Append one hash-addressed host evidence snapshot for a page attempt.

        Source inventories are extracted before the provider call and may grow
        on a later retry (for example when formula crops are enabled).  Each
        version is therefore append-only; the page record atomically points to
        the exact version used by its current attempt.
        """
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            self._validate_record_identity(snapshot, record)
            body = dict(evidence or {})
            body.update({
                "schema_version": OCR_PAGE_SOURCE_EVIDENCE_SCHEMA,
                "run_id": snapshot.run_id,
                "page_id": record.page_id,
                "source_page": record.source_page,
                "task_index": record.task_index,
            })
            data = _canonical_json(body)
            if len(data) > 2_000_000:
                raise OcrStoreError("OCR page source evidence exceeds the 2 MB safety bound")
            digest = _sha256_bytes(data)
            path = self.run_dir(run_id) / "source-evidence" / (
                f"{record.page_id}-{digest}.json"
            )
            if path.exists():
                if path.is_symlink() or path.read_bytes() != data:
                    raise OcrStoreError("immutable OCR source evidence hash collision")
            else:
                self._atomic_write(path, data)
            return digest

    def load_page_source_evidence(
        self,
        run_id: str,
        record: OcrPageRecord,
    ) -> dict[str, object]:
        """Load and hash-check the source inventories used by this page record."""
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            self._validate_record_identity(snapshot, record)
            digest = record.source_evidence_sha256
            if not digest:
                raise OcrStoreError("OCR page record has no source evidence binding")
            path = self.run_dir(run_id) / "source-evidence" / (
                f"{record.page_id}-{digest}.json"
            )
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise OcrStoreError("OCR page source evidence is missing") from exc
            if (
                path.is_symlink()
                or len(data) > 2_000_000
                or not hmac.compare_digest(_sha256_bytes(data), digest)
            ):
                raise OcrStoreError("OCR page source evidence SHA-256 verification failed")
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise OcrStoreError("OCR page source evidence is corrupt") from exc
            if not isinstance(value, dict) or any(
                value.get(key) != expected
                for key, expected in {
                    "schema_version": OCR_PAGE_SOURCE_EVIDENCE_SCHEMA,
                    "run_id": snapshot.run_id,
                    "page_id": record.page_id,
                    "source_page": record.source_page,
                    "task_index": record.task_index,
                }.items()
            ):
                raise OcrStoreError("OCR page source evidence identity mismatch")
            return value

    def load_raw_response(self, run_id: str, record: OcrPageRecord) -> object:
        """Return a successful page's exact saved response after hash checking."""
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            self._validate_record_identity(snapshot, record)
            if not record.raw_response_sha256:
                raise OcrStoreError("OCR page record has no raw response binding")
            path = self.run_dir(run_id) / "responses" / (
                f"{record.page_id}-{record.raw_response_sha256}.json"
            )
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise OcrStoreError("saved OCR response is missing") from exc
            if (
                path.is_symlink()
                or not hmac.compare_digest(
                    _sha256_bytes(data), record.raw_response_sha256
                )
            ):
                raise OcrStoreError("saved OCR response SHA-256 mismatch")
            try:
                return json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise OcrStoreError("saved OCR response is corrupt") from exc

    def verify_saved_response(
        self,
        run_id: str,
        record: OcrPageRecord,
    ) -> Mapping[str, object]:
        """Verify a final page response and bind its raw and cleaned layers.

        New v2 pages persist a host-owned envelope: the exact provider payload
        remains under ``model_raw_response`` while ``transport_response`` is the
        strict, cleaned four-field page object that was committed.  Legacy
        standard runs may still contain that four-field object at the root.
        """
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            self._validate_record_identity(snapshot, record)
            payload = self.load_raw_response(run_id, record)
            transport = payload
            host_envelope = False
            if (
                isinstance(payload, Mapping)
                and payload.get("schema_version")
                == "latexstruct-ocr-visual-response-v1"
            ):
                host_envelope = True
                expected_keys = {
                    "schema_version",
                    "page_id",
                    "source_page",
                    "task_index",
                    "call_index",
                    "gate_applied",
                    "source_evidence_sha256",
                    "candidate_tex",
                    "candidate_tex_sha256",
                    "verification_batch_id",
                    "verification_response_sha256",
                    "model_raw_response",
                    "verification_page",
                    "visual_mode",
                    "patched_block_ids",
                    "transport_response",
                    "host_quality_flags",
                }
                if set(payload) != expected_keys or any(
                    payload.get(key) != expected
                    for key, expected in {
                        "page_id": record.page_id,
                        "source_page": record.source_page,
                        "task_index": record.task_index,
                        "call_index": record.call_index,
                        "source_evidence_sha256": record.source_evidence_sha256,
                    }.items()
                ):
                    raise OcrStoreError(
                        f"saved visual verifier envelope identity mismatch: {record.page_id}"
                    )
                if payload.get("gate_applied") is not True:
                    raise OcrStoreError(
                        f"saved visual verifier page lacks its host gate: {record.page_id}"
                    )
                candidate_tex = str(payload.get("candidate_tex") or "")
                if (
                    candidate_tex != record.raw_tex
                    or not hmac.compare_digest(
                        str(payload.get("candidate_tex_sha256") or ""),
                        _sha256_bytes(candidate_tex.encode("utf-8")),
                    )
                ):
                    raise OcrStoreError(
                        f"saved visual candidate TEX binding mismatch: {record.page_id}"
                    )
                model_raw_response = payload.get("model_raw_response")
                if not hmac.compare_digest(
                    str(payload.get("verification_response_sha256") or ""),
                    _sha256_bytes(_canonical_json(model_raw_response)),
                ):
                    raise OcrStoreError(
                        f"saved visual response hash mismatch: {record.page_id}"
                    )
                verification_page = payload.get("verification_page")
                if (
                    not isinstance(verification_page, Mapping)
                    or verification_page.get("page_id") != record.page_id
                    or str(verification_page.get("verdict") or "")
                    not in {"PASS", "PATCH"}
                    or verification_page.get("reading_order_ok") is not True
                    or verification_page.get("coverage_ok") is not True
                ):
                    raise OcrStoreError(
                        f"saved visual verifier verdict is not acceptable: {record.page_id}"
                    )
                if thaw_json(record.host_quality_flags) != list(
                    payload.get("host_quality_flags") or []
                ):
                    raise OcrStoreError(
                        f"saved visual verifier flags mismatch: {record.page_id}"
                    )
                transport = payload.get("transport_response")
            elif (
                isinstance(payload, Mapping)
                and payload.get("schema_version")
                == "latexstruct-ocr-host-response-v1"
            ):
                host_envelope = True
                expected_keys = {
                    "schema_version",
                    "page_id",
                    "source_page",
                    "task_index",
                    "call_index",
                    "gate_applied",
                    "source_evidence_sha256",
                    "model_raw_latex",
                    "model_raw_response",
                    "transport_response",
                    "host_quality_flags",
                    "formula_evidence",
                    "batch_parent",
                }
                if set(payload) != expected_keys or any(
                    payload.get(key) != expected
                    for key, expected in {
                        "page_id": record.page_id,
                        "source_page": record.source_page,
                        "task_index": record.task_index,
                        "call_index": record.call_index,
                        "source_evidence_sha256": record.source_evidence_sha256,
                    }.items()
                ):
                    raise OcrStoreError(
                        f"saved OCR host envelope identity mismatch: {record.page_id}"
                    )
                if (
                    snapshot.quality_tier == OcrQualityTier.HIGH
                    and payload.get("gate_applied") is not True
                ):
                    raise OcrStoreError(
                        f"high-quality OCR page lacks its host gate: {record.page_id}"
                    )
                if str(payload.get("model_raw_latex") or "") != record.raw_tex:
                    raise OcrStoreError(
                        f"saved OCR raw TEX binding mismatch: {record.page_id}"
                    )
                if thaw_json(record.host_quality_flags) != list(
                    payload.get("host_quality_flags") or []
                ):
                    raise OcrStoreError(
                        f"saved OCR host quality flags mismatch: {record.page_id}"
                    )
                transport = payload.get("transport_response")
            elif (
                snapshot.quality_tier == OcrQualityTier.HIGH
                and record.source_evidence_sha256
            ):
                raise OcrStoreError(
                    f"high-quality OCR page lacks its host response envelope: {record.page_id}"
                )

            try:
                validated = validate_ocr_batch_response(
                    transport,
                    [record.page_id],
                    page_context_by_page_id={record.page_id: {
                        "source_page": record.source_page,
                        "image_size_pixels": record.image_size_pixels,
                    }},
                )[0]
            except OcrBatchValidationError as exc:
                raise OcrStoreError(
                    f"saved OCR transport response is invalid: {record.page_id}"
                ) from exc
            if host_envelope and validated.latex != record.cleaned_tex:
                raise OcrStoreError(
                    f"saved OCR cleaned TEX binding mismatch: {record.page_id}"
                )
            if (
                not host_envelope
                and isinstance(transport, Mapping)
                and str(transport.get("latex") or "") != record.raw_tex
            ):
                raise OcrStoreError(
                    f"saved legacy OCR raw TEX binding mismatch: {record.page_id}"
                )
            if thaw_json(validated.unresolved_regions) != thaw_json(
                record.unresolved_regions
            ):
                raise OcrStoreError(
                    f"saved OCR unresolved-region binding mismatch: {record.page_id}"
                )
            if not isinstance(transport, Mapping):
                raise OcrStoreError(
                    f"saved OCR transport response is not an object: {record.page_id}"
                )
            return transport

    def materialize_figure_assets(
        self,
        run_id: str,
    ) -> tuple[dict[str, bytes], dict[str, object]]:
        """Crop host-validated figures from exact persisted model inputs.

        Logical TeX paths are model output only until this host step binds them
        to immutable PNG bytes.  The resulting mapping is the exact extra-file
        closure passed to both baseline compile executions.
        """
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            assets: dict[str, bytes] = {}
            rows: list[dict[str, object]] = []
            for record in self.list_records(run_id):
                if record.status != OcrPageStatus.SUCCESS:
                    raise OcrStoreError(
                        f"figure assets require a successful page: {record.page_id}"
                    )
                raw_response = self.verify_saved_response(run_id, record)
                try:
                    validated = validate_ocr_batch_response(
                        raw_response,
                        [record.page_id],
                        page_context_by_page_id={record.page_id: {
                            "source_page": record.source_page,
                            "image_size_pixels": record.image_size_pixels,
                        }},
                    )[0]
                except OcrBatchValidationError as exc:
                    raise OcrStoreError(
                        f"saved OCR figure evidence is invalid: {record.page_id}"
                    ) from exc
                if not validated.figures:
                    continue
                image_path = self.verify_page_image(run_id, record)
                image_bytes = image_path.read_bytes()
                for figure in validated.figures:
                    logical_path = str(figure["path"])
                    if logical_path in assets:
                        raise OcrStoreError(f"duplicate OCR figure path: {logical_path}")
                    crop_bytes, crop_size = _crop_ocr_figure_png(
                        image_bytes,
                        tuple(int(item) for item in figure["bbox_pixels"]),
                        record.image_size_pixels,
                    )
                    crop_sha = _sha256_bytes(crop_bytes)
                    target = self.run_dir(run_id) / "artifacts" / Path(logical_path)
                    if target.exists():
                        if target.is_symlink() or target.read_bytes() != crop_bytes:
                            raise OcrStoreError(
                                f"immutable OCR figure already exists with different bytes: {logical_path}"
                            )
                    else:
                        self._atomic_write(target, crop_bytes)
                    assets[logical_path] = crop_bytes
                    rows.append({
                        "path": logical_path,
                        "page_id": record.page_id,
                        "source_page": record.source_page,
                        "source_image_sha256": record.image_sha256,
                        "bbox_normalized": thaw_json(figure["bbox_normalized"]),
                        "bbox_pixels": thaw_json(figure["bbox_pixels"]),
                        "crop_size_pixels": list(crop_size),
                        "bytes": len(crop_bytes),
                        "sha256": crop_sha,
                    })
            body = {
                "schema_version": "latexstruct-ocr-figures-v1",
                "run_id": snapshot.run_id,
                "figures": rows,
            }
            body_sha = _sha256_bytes(_canonical_json(body))
            manifest = {
                **body,
                "created_at": _utc_now(),
                "manifest_sha256": body_sha,
            }
            marker = self.run_dir(run_id) / "artifacts" / "figures-manifest.json"
            if marker.exists():
                try:
                    existing = json.loads(marker.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise OcrStoreError("OCR figure manifest is corrupt") from exc
                existing_body = {
                    key: existing.get(key) for key in ("schema_version", "run_id", "figures")
                }
                if (
                    _canonical_json(existing_body) != _canonical_json(body)
                    or existing.get("manifest_sha256") != body_sha
                ):
                    raise OcrStoreError("immutable OCR figure manifest already differs")
                manifest = existing
            else:
                self._atomic_write(marker, _canonical_json(manifest))
            return assets, manifest

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
                if record.status in {
                    OcrPageStatus.SUCCESS,
                    OcrPageStatus.NEEDS_REVIEW,
                }:
                    if not record.tex_sha256 or _sha256_bytes(
                        record.cleaned_tex.encode("utf-8")
                    ) != record.tex_sha256:
                        raise OcrStoreError(f"final page TEX hash mismatch: {record.page_id}")
                    self.verify_saved_response(run_id, record)
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
        figure_manifest: Mapping[str, object] | None = None,
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
                marker = "\n".join((
                    f"% Page {record.source_page}",
                    "% LaTeXStruct-Page: "
                    f"page_id={record.page_id} source_page={record.source_page}",
                ))
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
            if figure_manifest is not None:
                manifest["figure_manifest_sha256"] = str(
                    figure_manifest.get("manifest_sha256") or ""
                )
                manifest["figure_assets"] = thaw_json(
                    figure_manifest.get("figures") or []
                )
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
        extra_files: Mapping[str, bytes] | None = None,
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
                "extra_files": [
                    {
                        "path": str(path).replace("\\", "/"),
                        "bytes": len(data),
                        "sha256": _sha256_bytes(bytes(data)),
                    }
                    for path, data in sorted((extra_files or {}).items())
                ],
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

    def save_ocr_baseline_bundle(
        self,
        run_id: str,
        bundle: object,
    ) -> Path:
        """Commit a recomputable OCR baseline bundle as a write-once package.

        Artifact bytes are written independently and the canonical manifest is
        always the final commit marker.  An interrupted first write can be
        resumed only when every already-present byte is identical.  Once the
        manifest exists, missing, extra, renamed, or changed package content is
        treated as corruption rather than silently repaired.
        """
        from .ocr_manifest import (
            DEFAULT_MANIFEST_PATH,
            OcrBaselineManifestBundle,
            OcrBaselineManifestError,
            verify_ocr_baseline_manifest,
        )

        if not isinstance(bundle, OcrBaselineManifestBundle):
            raise TypeError("bundle must be an OcrBaselineManifestBundle")
        with self._lock:
            snapshot = self.load_snapshot(run_id)
            original_paths: set[str] = set()
            original_folded_paths: set[str] = set()
            for item in bundle.artifacts:
                if not isinstance(item, tuple) or len(item) != 2:
                    raise OcrStoreError("OCR baseline artifact entry is invalid")
                logical_path = _strict_ocr_bundle_relative_path(
                    item[0],
                    "OCR baseline artifact path",
                )
                if logical_path in original_paths:
                    raise OcrStoreError("OCR baseline bundle contains duplicate paths")
                if logical_path.casefold() in original_folded_paths:
                    raise OcrStoreError(
                        "OCR baseline bundle paths collide on a case-insensitive filesystem"
                    )
                original_paths.add(logical_path)
                original_folded_paths.add(logical_path.casefold())
            try:
                supplied = dict(bundle.files(DEFAULT_MANIFEST_PATH))
            except (TypeError, ValueError, OcrBaselineManifestError) as exc:
                raise OcrStoreError("OCR baseline bundle paths are invalid") from exc
            manifest_path = _strict_ocr_bundle_relative_path(
                DEFAULT_MANIFEST_PATH,
                "OCR baseline manifest path",
            )
            if manifest_path not in supplied:
                raise OcrStoreError("OCR baseline bundle is missing its manifest")

            files: dict[str, bytes] = {}
            casefolded_paths: set[str] = set()
            for raw_path, raw_data in supplied.items():
                logical_path = _strict_ocr_bundle_relative_path(
                    raw_path,
                    "OCR baseline bundle path",
                )
                folded = logical_path.casefold()
                if folded in casefolded_paths:
                    raise OcrStoreError(
                        "OCR baseline bundle paths collide on a case-insensitive filesystem"
                    )
                casefolded_paths.add(folded)
                if not isinstance(raw_data, bytes | bytearray | memoryview):
                    raise OcrStoreError("OCR baseline bundle values must be bytes")
                files[logical_path] = bytes(raw_data)

            manifest_bytes = files[manifest_path]
            artifact_bytes = {
                path: data for path, data in files.items() if path != manifest_path
            }
            try:
                verify_ocr_baseline_manifest(
                    manifest_bytes,
                    artifact_bytes,
                    expected_source_sha256=snapshot.source_sha256,
                )
            except OcrBaselineManifestError as exc:
                raise OcrStoreError("OCR baseline bundle failed verification") from exc

            artifacts_root = self.run_dir(run_id) / "artifacts"
            if (
                not artifacts_root.is_dir()
                or _path_is_reparse_point(artifacts_root)
            ):
                raise OcrStoreError("OCR artifacts root is not a plain directory")
            package_root = artifacts_root / _OCR_BASELINE_PACKAGE_DIRECTORY
            expected_files = set(files)
            try:
                package_root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise OcrStoreError(
                    "OCR baseline package directory cannot be created"
                ) from exc
            actual_files, _ = _scan_ocr_bundle_tree(
                package_root,
                expected_files=expected_files,
            )
            manifest_target = package_root.joinpath(*manifest_path.split("/"))

            if manifest_path in actual_files:
                if actual_files != expected_files:
                    raise OcrStoreError(
                        "committed OCR baseline package is missing required files"
                    )
                for logical_path, expected in files.items():
                    target = package_root.joinpath(*logical_path.split("/"))
                    if not target.is_file() or target.read_bytes() != expected:
                        raise OcrStoreError(
                            "immutable OCR baseline package already differs: "
                            f"{logical_path}"
                        )
                return manifest_target

            for logical_path in sorted(artifact_bytes):
                target = package_root.joinpath(*logical_path.split("/"))
                if target.exists():
                    if (
                        not target.is_file()
                        or _path_is_reparse_point(target)
                        or target.read_bytes() != artifact_bytes[logical_path]
                    ):
                        raise OcrStoreError(
                            "uncommitted OCR baseline artifact already differs: "
                            f"{logical_path}"
                        )
                    continue
                self._atomic_write(target, artifact_bytes[logical_path])

            # Recheck every staged artifact immediately before the manifest
            # becomes the immutable package commit marker.
            for logical_path, expected in artifact_bytes.items():
                target = package_root.joinpath(*logical_path.split("/"))
                if (
                    not target.is_file()
                    or _path_is_reparse_point(target)
                    or target.read_bytes() != expected
                ):
                    raise OcrStoreError(
                        f"OCR baseline artifact changed before commit: {logical_path}"
                    )
            if manifest_target.exists():
                raise OcrStoreError("OCR baseline manifest appeared during package commit")
            self._atomic_write(manifest_target, manifest_bytes)
            return manifest_target

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


def _split_graphics_options(options: str) -> list[str]:
    """Split a graphicx option list without breaking commas in braces."""
    result: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(str(options or "")):
        if character == "{" and (index == 0 or options[index - 1] != "\\"):
            depth += 1
        elif character == "}" and (index == 0 or options[index - 1] != "\\"):
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            value = options[start:index].strip()
            if value:
                result.append(value)
            start = index + 1
    value = options[start:].strip()
    if value:
        result.append(value)
    return result


def _validated_figure_width_ratio(figure: Mapping[str, object]) -> float:
    """Convert a host-validated page bbox to a bounded text-block width."""
    bbox = tuple(figure.get("bbox_normalized") or ())
    page_ratio = max(0.0, float(bbox[2]) - float(bbox[0]))
    body_ratio = page_ratio / _OCR_TARGET_TEXT_BLOCK_PAGE_RATIO
    return round(
        min(_OCR_FIGURE_WIDTH_MAX, max(_OCR_FIGURE_WIDTH_MIN, body_ratio)),
        2,
    )


def _normalize_validated_figure_layout(
    latex: str,
    figures: Sequence[Mapping[str, object]],
) -> tuple[str, list[Mapping[str, object]]]:
    """Apply deterministic, page-bounded sizing to validated active figures."""
    if not figures:
        return latex, list(figures)
    matches = list(_OCR_INCLUDEGRAPHICS_RE.finditer(latex))
    if len(matches) != len(figures):
        raise OcrBatchValidationError(
            "INVALID_FIGURES", "validated figure count no longer matches LaTeX",
        )
    normalized: list[Mapping[str, object]] = []
    edits: list[tuple[int, int, str]] = []
    for match, raw_figure in zip(matches, figures):
        figure = dict(raw_figure)
        width_ratio = _validated_figure_width_ratio(figure)
        figure["display_width_ratio"] = width_ratio
        normalized.append(figure)

        command = match.group(0)
        options_match = re.search(r"\[(?P<options>[^\]\r\n]*)\]", command)
        options = _split_graphics_options(
            options_match.group("options") if options_match else "",
        )
        options = [
            option for option in options
            if not re.match(r"^\s*(?:width|height)\s*=", option, re.I)
            and not re.match(r"^\s*keepaspectratio(?:\s*=.*)?$", option, re.I)
        ]
        bounded = [
            f"width={width_ratio:.2f}\\linewidth",
            f"height={_OCR_FIGURE_HEIGHT_MAX:.2f}\\textheight",
            "keepaspectratio",
            *options,
        ]
        path = match.group(1)
        replacement = rf"\includegraphics[{','.join(bounded)}]{{{path}}}"
        edits.append((match.start(), match.end(), replacement))
    for start, end, replacement in reversed(edits):
        latex = latex[:start] + replacement + latex[end:]
    return latex, normalized


def _boundary_folio_candidates(reference_text: str, source_page: int | None) -> set[str]:
    """Return only host-supported decimal folios for one physical source page."""
    candidates = {str(source_page)} if source_page is not None and source_page > 0 else set()
    reference_lines = [
        line.strip() for line in str(reference_text or "").splitlines() if line.strip()
    ]
    for value in reference_lines[:1] + reference_lines[-1:]:
        if _OCR_BOUNDARY_DECIMAL_RE.fullmatch(value):
            candidates.add(value)
    return candidates


def _strip_host_supported_boundary_folios(
    latex: str,
    *,
    source_page: int | None,
    reference_text: str,
) -> tuple[str, tuple[str, ...]]:
    """Remove model-copied outer folios without touching interior numeric text."""
    lines = str(latex or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    candidates = _boundary_folio_candidates(reference_text, source_page)
    removed: list[str] = []
    while True:
        active = [
            index for index, line in enumerate(lines)
            if line.strip() and not line.lstrip().startswith("%")
        ]
        if not active:
            break
        changed = False
        for index in dict.fromkeys((active[0], active[-1])):
            value = lines[index].strip()
            if value in candidates and _OCR_BOUNDARY_DECIMAL_RE.fullmatch(value):
                removed.append(value)
                lines[index] = ""
                changed = True
        if not changed:
            break
    return "\n".join(lines).strip(), tuple(removed)


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
    page_context_by_page_id: Mapping[str, Mapping[str, object]] | None = None,
    minimum_nonspace_chars: int = 8,
) -> list[ValidatedOcrPage]:
    """Require exact page-id coverage and validate every page independently."""
    expected = tuple(str(item) for item in expected_page_ids)
    if not expected or len(expected) > 3 or len(set(expected)) != len(expected):
        raise ValueError("expected_page_ids must contain 1-3 unique IDs")
    if any(_PAGE_ID_RE.fullmatch(item) is None for item in expected):
        raise ValueError("expected_page_ids contains an invalid page_id")
    payload = _model_payload(response)
    unknown_top_level = False
    if isinstance(payload, Mapping) and isinstance(payload.get("pages"), list):
        unknown_top_level = set(payload) != {"pages"}
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
    if unknown_top_level:
        raise OcrBatchValidationError(
            "TOP_LEVEL_SCHEMA", "OCR response contains unknown top-level properties"
        )
    by_id = {str(item["page_id"]): item for item in values}
    references = dict(reference_text_by_page_id or {})
    page_contexts = dict(page_context_by_page_id or {})
    output: list[ValidatedOcrPage] = []
    for page_id in expected:
        item = by_id[page_id]
        allowed_page_keys = {
            "page_id", "latex", "figures", "unresolved_regions",
        }
        if set(item) != allowed_page_keys:
            raise OcrBatchValidationError(
                "TOP_LEVEL_SCHEMA",
                f"{page_id} contains unknown or missing page properties",
            )
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
        page_context = page_contexts.get(page_id)
        figures = list(_validate_ocr_page_figures(
            page_id,
            latex,
            figures,
            page_context,
        ))
        latex, figures = _normalize_validated_figure_layout(latex, figures)
        source_page = (
            page_context.get("source_page")
            if isinstance(page_context, Mapping)
            and isinstance(page_context.get("source_page"), int)
            and not isinstance(page_context.get("source_page"), bool)
            else None
        )
        latex, removed_folios = _strip_host_supported_boundary_folios(
            latex,
            source_page=source_page,
            reference_text=references.get(page_id, ""),
        )
        issues = inspect_latex_fragment(
            latex,
            reference_text=references.get(page_id, ""),
            minimum_nonspace_chars=minimum_nonspace_chars,
        )
        if removed_folios:
            issues.append(OcrValidationIssue(
                "BOUNDARY_FOLIO_REMOVED",
                "info",
                f"host removed {len(removed_folios)} supported boundary folio line(s)",
                False,
            ))
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


def _validate_ocr_page_figures(
    page_id: str,
    latex: str,
    figures: Sequence[Mapping[str, object]],
    context: Mapping[str, object] | None,
) -> tuple[Mapping[str, object], ...]:
    """Bind every model figure to one host-owned path and a sane page crop."""
    if len(figures) > 32:
        raise OcrBatchValidationError(
            "INVALID_FIGURES", f"{page_id} contains too many figure records",
        )
    references = [
        match.group(1).replace("\\", "/").strip()
        for match in _OCR_INCLUDEGRAPHICS_RE.finditer(latex)
    ]
    if not figures:
        if references:
            raise OcrBatchValidationError(
                "INVALID_FIGURES", f"{page_id} references an image without figure evidence",
            )
        return ()
    if not isinstance(context, Mapping):
        raise OcrBatchValidationError(
            "INVALID_FIGURES", f"{page_id} figure evidence lacks host page context",
        )
    source_page = context.get("source_page")
    size = tuple(context.get("image_size_pixels") or ())
    if (
        not isinstance(source_page, int)
        or isinstance(source_page, bool)
        or source_page < 1
        or len(size) != 2
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 1
            for item in size
        )
    ):
        raise OcrBatchValidationError(
            "INVALID_FIGURES", f"{page_id} figure evidence has invalid host page context",
        )
    image_width, image_height = size
    validated: list[Mapping[str, object]] = []
    expected_paths: list[str] = []
    for position, raw in enumerate(figures, start=1):
        expected_path = f"figures/page_{source_page:04d}_figure_{position:02d}.png"
        path = str(raw.get("path") or "").replace("\\", "/").strip()
        index = raw.get("index")
        normalized = raw.get("bbox_normalized")
        pixels = raw.get("bbox_pixels")
        if path != expected_path or index != position:
            raise OcrBatchValidationError(
                "INVALID_FIGURES",
                f"{page_id} figure {position} must use host path {expected_path}",
            )
        if not isinstance(normalized, (list, tuple)) or len(normalized) != 4:
            raise OcrBatchValidationError(
                "INVALID_FIGURES", f"{page_id} figure {position} has invalid normalized bbox",
            )
        if not isinstance(pixels, (list, tuple)) or len(pixels) != 4:
            raise OcrBatchValidationError(
                "INVALID_FIGURES", f"{page_id} figure {position} has invalid pixel bbox",
            )
        if any(
            isinstance(item, bool) or not isinstance(item, (int, float))
            for item in normalized
        ) or any(
            isinstance(item, bool) or not isinstance(item, int)
            for item in pixels
        ):
            raise OcrBatchValidationError(
                "INVALID_FIGURES", f"{page_id} figure {position} bbox values are invalid",
            )
        nx0, ny0, nx1, ny1 = [float(item) for item in normalized]
        px0, py0, px1, py1 = [int(item) for item in pixels]
        if not (
            all(math.isfinite(item) for item in (nx0, ny0, nx1, ny1))
            and 0 <= nx0 < nx1 <= 1
            and 0 <= ny0 < ny1 <= 1
            and 0 <= px0 < px1 <= image_width
            and 0 <= py0 < py1 <= image_height
        ):
            raise OcrBatchValidationError(
                "INVALID_FIGURES", f"{page_id} figure {position} bbox is outside the page",
            )
        width_ratio = nx1 - nx0
        height_ratio = ny1 - ny0
        if (
            width_ratio < 0.01
            or height_ratio < 0.01
            or width_ratio * height_ratio > 0.88
            or (width_ratio > 0.96 and height_ratio > 0.90)
        ):
            raise OcrBatchValidationError(
                "INVALID_FIGURES", f"{page_id} figure {position} is not a bounded local crop",
            )
        tolerance_x = max(4, int(round(image_width * 0.02)))
        tolerance_y = max(4, int(round(image_height * 0.02)))
        expected_pixels = (
            nx0 * image_width, ny0 * image_height,
            nx1 * image_width, ny1 * image_height,
        )
        if (
            abs(px0 - expected_pixels[0]) > tolerance_x
            or abs(px1 - expected_pixels[2]) > tolerance_x
            or abs(py0 - expected_pixels[1]) > tolerance_y
            or abs(py1 - expected_pixels[3]) > tolerance_y
        ):
            normalized_evidence = [
                round(value, 6) for value in (nx0, ny0, nx1, ny1)
            ]
            expected_evidence = [
                round(value, 2) for value in expected_pixels
            ]
            raise OcrBatchValidationError(
                "INVALID_FIGURES",
                f"{page_id} figure {position} normalized/pixel bboxes disagree: "
                f"bbox_normalized={normalized_evidence}, "
                f"bbox_pixels={[px0, py0, px1, py1]}, "
                f"image_size_pixels={[image_width, image_height]}, "
                f"expected_pixels={expected_evidence}, "
                f"tolerance_pixels={[tolerance_x, tolerance_y]}",
            )
        expected_paths.append(expected_path)
        validated.append(_freeze({
            "path": expected_path,
            "index": position,
            "bbox_normalized": [nx0, ny0, nx1, ny1],
            "bbox_pixels": [px0, py0, px1, py1],
            "image_size_pixels": [image_width, image_height],
            "source": "host_validated_structured_vision",
        }))
    if references != expected_paths:
        raise OcrBatchValidationError(
            "INVALID_FIGURES",
            f"{page_id} includegraphics references do not exactly match figure evidence",
        )
    return tuple(validated)


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
    if any(token in text for token in (
        "quota", "额度耗尽", "额度已耗尽", "insufficient balance", "余额不足",
    )):
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
        "http 503", "http 504", "temporary", "temporarily", "网络", "临时", "超时",
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
    image_size_pixels: tuple[int, int] = ()

    def __post_init__(self) -> None:
        if self.page_id != make_page_id(self.task_index):
            raise ValueError("OCR request page_id/task_index mismatch")
        if self.source_page < 1 or not self.image_bytes:
            raise ValueError("OCR request requires source page and image bytes")
        if not 72 <= int(self.dpi) <= 600:
            raise ValueError("OCR request DPI is outside 72..600")
        if len(self.crops) > 4 or any(not crop for crop in self.crops):
            raise ValueError("OCR request supports at most four non-empty crops")
        size = tuple(self.image_size_pixels or ())
        if size and (
            len(size) != 2
            or any(
                not isinstance(item, int) or isinstance(item, bool) or item < 1
                for item in size
            )
        ):
            raise ValueError("OCR request image_size_pixels must contain two positive integers")
        object.__setattr__(self, "correction_instruction", str(self.correction_instruction or "")[:1600])
        object.__setattr__(self, "retry_state", _freeze(dict(self.retry_state or {})))
        object.__setattr__(self, "image_size_pixels", size)

    def public_payload(self) -> dict[str, object]:
        return {
            "page_id": self.page_id,
            "source_page": self.source_page,
            "task_index": self.task_index,
            "dpi": self.dpi,
            "image_sha256": _sha256_bytes(self.image_bytes),
            "crop_count": len(self.crops),
            "image_size_pixels": list(self.image_size_pixels),
        }


@dataclass(frozen=True, slots=True)
class OcrExecutionResult:
    request: OcrPageRequest
    page: ValidatedOcrPage | None
    raw_response: object | None = field(default=None, repr=False)
    error: str = ""
    error_category: OcrErrorCategory | None = None
    retry_instruction: str = ""
    retry_state: Mapping[str, object] = field(default_factory=dict, repr=False)
    batch_id: str = ""
    batch_size: int = 1
    used_batch: bool = False
    fell_back_to_single: bool = False


_BATCH_EVIDENCE_SECRET_KEY_RE = re.compile(
    r"(?:api[_ -]?key|authorization|password|secret|access[_ -]?token|"
    r"refresh[_ -]?token|codex[_ -]?(?:login|token))",
    re.I,
)
_BATCH_EVIDENCE_CREDENTIAL_RE = re.compile(
    r"(?i)(?:\bBearer\s+)[A-Za-z0-9._~+/=-]+|"
    r"\bsk-[A-Za-z0-9_-]{8,}|"
    r"\b(?:api[_ -]?key|authorization|password|secret|access[_ -]?token)"
    r"\s*[:=]\s*[^\s,;\]\}\"']+",
)
_BATCH_EVIDENCE_WINDOWS_PATH_RE = re.compile(
    r"(?ix)(?<![A-Za-z0-9_])(?:"
    # Common Windows roots may contain spaces and are safe to identify without
    # confusing a TeX control sequence such as ``C:\\mathcal`` for a path.
    r"[A-Z]:[\\/](?:Users|Documents[ ]and[ ]Settings|Windows|ProgramData|"
    r"Program[ ]Files(?:[ ]\(x86\))?|Temp|tmp)(?:[\\/][^\r\n\t\"'<>|{}]*)?"
    r"|"
    # For arbitrary drive roots, require a filename extension.  This covers
    # diagnostic files while preserving mathematical text such as
    # ``u\\in V:\\lvert N(u)\\cap B\\rvert``.
    r"[A-Z]:[\\/][^\r\n\t\"'<>|{}\s,;]+(?:[\\/][^\r\n\t\"'<>|{}\s,;]+)*"
    r"\.[A-Za-z0-9]{1,16}"
    r"|"
    # A UNC path must contain both a server and a share component; a bare TeX
    # line break followed by a command therefore cannot match this branch.
    r"\\\\[A-Za-z0-9._-]+[\\/][A-Za-z0-9$._ -]+"
    r"(?:[\\/][^\r\n\t\"'<>|{}]*)?"
    r")",
)
_BATCH_EVIDENCE_POSIX_PATH_RE = re.compile(
    r"(?<![:A-Za-z0-9_.-])/(?:"
    r"(?:Users|home|root|tmp|var|etc|opt|mnt|private)(?:/[^\r\n\t\"'<>]*)?"
    r"|(?:[^/\r\n\t\"'<>\s]+/)+[^/\r\n\t\"'<>\s]*"
    r")",
    re.I,
)


def _redact_batch_evidence_text(value: object) -> str:
    """Remove credentials and host absolute paths from batch-attempt evidence."""
    text = str(value or "")
    text = _BATCH_EVIDENCE_CREDENTIAL_RE.sub("[REDACTED_CREDENTIAL]", text)
    text = _BATCH_EVIDENCE_WINDOWS_PATH_RE.sub("[REDACTED_ABSOLUTE_PATH]", text)
    return _BATCH_EVIDENCE_POSIX_PATH_RE.sub("[REDACTED_ABSOLUTE_PATH]", text)


def _batch_evidence_digest(value: object) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8", errors="replace")
    else:
        try:
            payload = _canonical_json(value)
        except (TypeError, ValueError):
            payload = repr(value).encode("utf-8", errors="replace")
    return _sha256_bytes(payload)


def _sanitize_batch_evidence_value(value: object) -> object:
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, item in value.items():
            name = str(key)
            if _BATCH_EVIDENCE_SECRET_KEY_RE.search(name):
                output[name] = "[REDACTED_CREDENTIAL]"
            else:
                output[name] = _sanitize_batch_evidence_value(item)
        return output
    if isinstance(value, (list, tuple)):
        return [_sanitize_batch_evidence_value(item) for item in value]
    if isinstance(value, bytes):
        return _redact_batch_evidence_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, str):
        return _redact_batch_evidence_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_batch_evidence_text(repr(value))


@dataclass(frozen=True, slots=True)
class OcrBatchAttemptEvidence:
    """Immutable, privacy-clean evidence for one shared batch fallback.

    Validation failures retain a sanitized copy of the provider response plus
    the SHA-256 of the exact response.  Provider failures retain only a
    sanitized error summary plus its SHA-256.  The host receives this object
    before any single-page fallback starts, allowing all resulting page
    records to reference the same ``batch_id`` without guessing provenance.
    """

    batch_id: str
    page_ids: tuple[str, ...]
    classification: str
    fallback_to_single: bool
    raw_response: object | None = field(default=None, repr=False)
    raw_response_sha256: str = ""
    error_summary: str = ""
    error_sha256: str = ""

    def __post_init__(self) -> None:
        batch_id = str(self.batch_id or "").strip()
        page_ids = tuple(str(item) for item in self.page_ids)
        if not batch_id.startswith("ocr-batch-"):
            raise ValueError("batch evidence requires a host-issued batch_id")
        if not page_ids or len(page_ids) > 3 or len(set(page_ids)) != len(page_ids):
            raise ValueError("batch evidence requires 1-3 unique page_ids")
        if any(_PAGE_ID_RE.fullmatch(item) is None for item in page_ids):
            raise ValueError("batch evidence contains an invalid page_id")
        classification = str(self.classification or "").strip()
        if not classification:
            raise ValueError("batch evidence requires a classification")
        raw_response_sha256 = _validate_sha256(
            self.raw_response_sha256,
            "batch raw_response_sha256",
            allow_empty=True,
        )
        error_sha256 = _validate_sha256(
            self.error_sha256,
            "batch error_sha256",
            allow_empty=True,
        )
        error_summary = _redact_batch_evidence_text(self.error_summary)[:1000]
        raw_response = self.raw_response
        if raw_response is not None:
            raw_response = _freeze(_sanitize_batch_evidence_value(raw_response))
        if not raw_response_sha256 and not error_sha256:
            raise ValueError("batch evidence requires a response or error SHA-256")
        if error_summary and not error_sha256:
            raise ValueError("batch error summary requires error_sha256")
        object.__setattr__(self, "batch_id", batch_id)
        object.__setattr__(self, "page_ids", page_ids)
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "fallback_to_single", bool(self.fallback_to_single))
        object.__setattr__(self, "raw_response", raw_response)
        object.__setattr__(self, "raw_response_sha256", raw_response_sha256)
        object.__setattr__(self, "error_summary", error_summary)
        object.__setattr__(self, "error_sha256", error_sha256)

    @classmethod
    def validation_failure(
        cls,
        *,
        batch_id: str,
        page_ids: Sequence[str],
        response: object,
        validation_code: str,
    ) -> "OcrBatchAttemptEvidence":
        return cls(
            batch_id=batch_id,
            page_ids=tuple(page_ids),
            classification=f"VALIDATION:{validation_code}",
            fallback_to_single=True,
            raw_response=response,
            raw_response_sha256=_batch_evidence_digest(response),
        )

    @classmethod
    def provider_failure(
        cls,
        *,
        batch_id: str,
        page_ids: Sequence[str],
        error: object,
        category: OcrErrorCategory,
    ) -> "OcrBatchAttemptEvidence":
        raw_error = str(error or "")
        return cls(
            batch_id=batch_id,
            page_ids=tuple(page_ids),
            classification=f"PROVIDER:{category.value}",
            fallback_to_single=True,
            error_summary=_redact_batch_evidence_text(raw_error)[:1000],
            error_sha256=_sha256_bytes(raw_error.encode("utf-8", errors="replace")),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "batch_id": self.batch_id,
            "page_ids": list(self.page_ids),
            "classification": self.classification,
            "fallback_to_single": self.fallback_to_single,
            "raw_response": thaw_json(self.raw_response),
            "raw_response_sha256": self.raw_response_sha256,
            "error_summary": self.error_summary,
            "error_sha256": self.error_sha256,
        }


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
        on_batch_attempt: Callable[[OcrBatchAttemptEvidence], None] | None = None,
    ) -> list[OcrExecutionResult]:
        if len({request.page_id for request in requests}) != len(requests):
            raise ValueError("OCR request page_id values must be unique")
        # A one-page request must always use the single-page contract.  Apart
        # from avoiding pointless batch schema overhead, this ensures a generic
        # local-runtime failure becomes a page result which the host can retry
        # at 300 DPI instead of escaping from the batch exception path.
        if len(requests) <= 1 or batch_call is None or self.batch_size == 1:
            results = self._run_singles(
                requests,
                single_call,
                False,
                "",
                on_result=on_result,
            )
            return sorted(results, key=lambda item: item.request.task_index)
        results: list[OcrExecutionResult] = []
        for offset in range(0, len(requests), self.batch_size):
            batch = tuple(requests[offset:offset + self.batch_size])
            batch_id = f"ocr-batch-{uuid.uuid4().hex[:12]}"
            emitted_incrementally = False
            raw: object | None = None
            try:
                raw = batch_call(batch)
                pages = validate_ocr_batch_response(
                    raw,
                    [request.page_id for request in batch],
                    reference_text_by_page_id={
                        request.page_id: request.text_layer_hint for request in batch
                    },
                    page_context_by_page_id={
                        request.page_id: {
                            "source_page": request.source_page,
                            "image_size_pixels": request.image_size_pixels,
                        }
                        for request in batch
                    },
                )
                by_id = {page.page_id: page for page in pages}
                current = [
                    OcrExecutionResult(
                        request=request,
                        page=by_id[request.page_id],
                        raw_response=thaw_json(by_id[request.page_id].raw_object),
                        batch_id=batch_id,
                        batch_size=len(batch),
                        used_batch=True,
                    )
                    for request in batch
                ]
            except OcrBatchValidationError as exc:
                if exc.code not in _BATCH_FALLBACK_CODES:
                    raise
                self._emit_batch_attempt(
                    OcrBatchAttemptEvidence.validation_failure(
                        batch_id=batch_id,
                        page_ids=tuple(request.page_id for request in batch),
                        response=raw,
                        validation_code=exc.code,
                    ),
                    on_batch_attempt,
                )
                current = self._run_singles(
                    batch,
                    single_call,
                    True,
                    batch_id,
                    on_result=on_result,
                )
                emitted_incrementally = True
            except Exception as exc:  # provider categories are host policy, not model policy
                category = classify_ocr_error(exc)
                if category not in _BATCH_FALLBACK_CATEGORIES:
                    if category in {
                        OcrErrorCategory.AUTH, OcrErrorCategory.QUOTA, OcrErrorCategory.CONFIG,
                        OcrErrorCategory.REFUSAL, OcrErrorCategory.CANCELLED,
                    }:
                        raise OcrRunPaused(category, str(exc)) from exc
                    raise
                self._emit_batch_attempt(
                    OcrBatchAttemptEvidence.provider_failure(
                        batch_id=batch_id,
                        page_ids=tuple(request.page_id for request in batch),
                        error=exc,
                        category=category,
                    ),
                    on_batch_attempt,
                )
                current = self._run_singles(
                    batch,
                    single_call,
                    True,
                    batch_id,
                    on_result=on_result,
                )
                emitted_incrementally = True
            results.extend(current)
            if not emitted_incrementally:
                self._emit(current, on_result)
        return sorted(results, key=lambda item: item.request.task_index)

    def _run_singles(
        self,
        requests: Sequence[OcrPageRequest],
        single_call: Callable[[OcrPageRequest], object],
        fallback: bool,
        batch_id: str,
        *,
        on_result: Callable[[OcrExecutionResult], None] | None = None,
    ) -> list[OcrExecutionResult]:
        def invoke(request: OcrPageRequest) -> OcrExecutionResult:
            raw: object | None = None
            try:
                raw = single_call(request)
                page = validate_ocr_batch_response(
                    raw,
                    [request.page_id],
                    reference_text_by_page_id={request.page_id: request.text_layer_hint},
                    page_context_by_page_id={request.page_id: {
                        "source_page": request.source_page,
                        "image_size_pixels": request.image_size_pixels,
                    }},
                )[0]
                return OcrExecutionResult(
                    request=request,
                    page=page,
                    raw_response=raw,
                    batch_id=batch_id,
                    batch_size=1,
                    used_batch=False,
                    fell_back_to_single=fallback,
                )
            except OcrBatchValidationError as exc:
                return OcrExecutionResult(
                    request=request,
                    page=None,
                    raw_response=raw,
                    error=str(exc)[:1000],
                    error_category=OcrErrorCategory.UNKNOWN,
                    retry_instruction=(
                        "上一响应未通过宿主结构校验。只重新识别本页并严格修正 "
                        f"{exc.code}；不得省略可见内容，不得猜测坐标或文件路径。"
                    ),
                    retry_state=_freeze({"validation_code": exc.code}),
                    batch_id=batch_id,
                    batch_size=1,
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
                    raw_response=(
                        getattr(exc, "model_raw_response", None)
                        or ({
                            "latex": str(getattr(exc, "model_raw_latex", "") or ""),
                        } if getattr(exc, "model_raw_latex", "") else None)
                    ),
                    error=str(exc)[:1000],
                    error_category=category,
                    retry_instruction=str(getattr(exc, "retry_instruction", "") or "")[:1600],
                    retry_state=_freeze(
                        getattr(exc, "retry_state", {})
                        if isinstance(getattr(exc, "retry_state", {}), Mapping)
                        else {}
                    ),
                    batch_id=batch_id,
                    batch_size=1,
                    used_batch=False,
                    fell_back_to_single=fallback,
                )

        if len(requests) <= 1:
            if not requests:
                return []
            result = invoke(requests[0])
            self._emit((result,), on_result)
            return [result]
        output: list[OcrExecutionResult] = []
        paused: OcrRunPaused | None = None
        with ThreadPoolExecutor(max_workers=min(self.concurrency_limit, len(requests))) as pool:
            futures: dict[Future[OcrExecutionResult], OcrPageRequest] = {
                pool.submit(invoke, request): request for request in requests
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                except OcrRunPaused as exc:
                    # Authentication/quota/config failures stop new work, but
                    # sibling calls were already in flight.  Drain them and
                    # persist every paid-for success before surfacing the pause;
                    # otherwise recovery repeats successful model calls.
                    if paused is None:
                        paused = exc
                    continue
                output.append(result)
                # Persist/observe a completed page before a slower sibling
                # finishes.  This bounds crash loss to the currently running
                # calls instead of the whole concurrency group.
                self._emit((result,), on_result)
        if paused is not None:
            raise paused
        return output

    @staticmethod
    def _emit(
        results: Sequence[OcrExecutionResult],
        callback: Callable[[OcrExecutionResult], None] | None,
    ) -> None:
        if callback is not None:
            for result in results:
                callback(result)

    @staticmethod
    def _emit_batch_attempt(
        attempt: OcrBatchAttemptEvidence,
        callback: Callable[[OcrBatchAttemptEvidence], None] | None,
    ) -> None:
        if callback is not None:
            callback(attempt)


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
    result_pages = (
        counts[OcrPageStatus.SUCCESS.value]
        + counts[OcrPageStatus.NEEDS_REVIEW.value]
    )
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
    attempt_progress = finalized / total if total else 0.0
    recognition_progress = result_pages / total if total else 0.0
    all_pages_recognized = bool(total) and result_pages == total
    # Host callers may have a partial, downloadable raw preview after the first
    # successful page.  That is not evidence that the selected page range was
    # merged or frozen.  Keep every post-recognition milestone fail-closed when
    # FAILED/CANCELLED/PENDING pages remain, even if a stale or legacy caller
    # passes optimistic flags.
    effective_merge_complete = bool(merge_complete and all_pages_recognized)
    effective_raw_frozen = bool(raw_frozen and effective_merge_complete)
    # Explicit milestones keep log/snapshot writes from pretending the run is
    # complete.  A compiled preview is necessary but not sufficient: the host
    # must also attest the merge and immutable raw freeze before reaching 100%.
    overall = 0.02 + 0.88 * recognition_progress
    if effective_merge_complete:
        overall = max(overall, 0.93)
    if effective_raw_frozen:
        overall = max(overall, 0.95)
    normalized_compile = None
    if compile_status is not None:
        normalized_compile = _enum_value(OcrPreviewStatus, compile_status, "OCR preview status")
        if normalized_compile == OcrPreviewStatus.COMPILED and all_pages_recognized:
            if effective_merge_complete and effective_raw_frozen:
                overall = 1.0
            else:
                overall = max(overall, 0.99)
        elif (
            normalized_compile == OcrPreviewStatus.PARTIAL_COMPILED
            and all_pages_recognized
        ):
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
        "attempt_progress": round(attempt_progress, 6),
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
        "merge_complete": effective_merge_complete,
        "raw_frozen": effective_raw_frozen,
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
同一路径、从 1 开始的 index、完整页归一化坐标和像素坐标；bbox_pixels 必须严格使用
本次 page_request.image_size_pixels 所声明的原始整页栅格尺寸，不得使用模型内部缩放尺寸、
0..1000 坐标系或上一轮 DPI 的尺寸；不要把整页当作插图。
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
        if request.image_size_pixels:
            item["image_size_pixels"] = list(request.image_size_pixels)
            item["bbox_pixel_policy"] = (
                "bbox_pixels 使用该原始整页栅格的左上-右下像素坐标；"
                "不得使用内部缩放、0..1000 坐标或其他 DPI 尺寸"
            )
        if request.text_layer_hint:
            item["untrusted_pdf_text_reference"] = request.text_layer_hint[:12000]
            item["reference_policy"] = "仅辅助拼写与顺序；页面像素冲突时以像素为准"
        if request.correction_instruction:
            item["retry_correction"] = request.correction_instruction
            item["retry_policy"] = "只修复列出的可定位问题；仍须忠实转写当前页面像素"
        if request.retry_state:
            item["host_verified_retry_evidence"] = thaw_json(request.retry_state)
        if request.crops:
            item["formula_crop_evidence"] = [
                {
                    "image_index": index + 1,
                    "sha256": _sha256_bytes(crop),
                    "policy": "local evidence only; do not transcribe as another page",
                }
                for index, crop in enumerate(request.crops, start=1)
            ]
        pages.append(item)
    return json.dumps({"page_requests": pages}, ensure_ascii=False, separators=(",", ":"))

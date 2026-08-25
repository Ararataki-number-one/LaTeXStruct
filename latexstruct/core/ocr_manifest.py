# -*- coding: utf-8 -*-
"""Recomputable, OCR-only baseline manifest contracts.

This module is deliberately independent from the OCR store.  It consumes exact
artifact bytes, derives every status and coverage counter from those bytes, and
returns a bundle which a caller can atomically persist.  It never opens local
paths, invokes a model, compiles TeX, or grants authority to a producer claim.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .compilecheck import COMPILE_INPUT_MANIFEST_SCHEMA, COMPILE_WORKDIR_ID_PREFIX
from .ocr_metrics import (
    COST_REPORT_SCHEMA,
    PERFORMANCE_METRICS_SCHEMA,
    OcrStrategy,
    PageFinalStatus,
    RequestKind,
    canonical_metrics_json_bytes,
)
from .ocr_page_evidence import (
    PAGE_RECORDS_SCHEMA_VERSION,
    PageCoverageRecord,
    build_page_summaries,
    parse_page_records,
)
from .ocr_page_map import (
    OCR_PAGE_MAP_SCHEMA,
    OcrPageMapError,
    extract_page_anchors,
    verify_page_map_json,
)
from .ocr_scheduler import OcrStage


OCR_BASELINE_MANIFEST_SCHEMA = "latexstruct-ocr-baseline-v2"
OCR_PAGE_RECORDS_SCHEMA = PAGE_RECORDS_SCHEMA_VERSION
OCR_RUNTIME_PAGE_RECORDS_SCHEMA = "latexstruct-ocr-page-records-v1"
OCR_PERFORMANCE_SCHEMA = PERFORMANCE_METRICS_SCHEMA
OCR_COST_SCHEMA = COST_REPORT_SCHEMA
OCR_PRODUCER_SCHEMA = "latexstruct-ocr-producer-v1"
DEFAULT_MANIFEST_PATH = "baseline/ocr_baseline_manifest.json"

RUN_STATUSES = frozenset({"SUCCESS", "PARTIAL", "FAILED", "CANCELLED"})
OCR_STATUSES = frozenset({"COMPLETED", "COMPLETED_WITH_REVIEW", "INCOMPLETE"})
COMPILE_STATUSES = frozenset({"COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"})

ROLE_RUN_SNAPSHOT = "RUN_SNAPSHOT"
ROLE_SOURCE = "SOURCE"
ROLE_RAW_OCR_TEX = "RAW_OCR_TEX"
ROLE_RAW_OCR_FREEZE = "RAW_OCR_FREEZE"
ROLE_SYNTAX_BASELINE_TEX = "SYNTAX_BASELINE_TEX"
ROLE_EVIDENCE_BASELINE_TEX = "EVIDENCE_CORRECTED_BASELINE_TEX"
ROLE_EVIDENCE_CORRECTION_REPORT = "EVIDENCE_CORRECTION_REPORT"
ROLE_BASELINE_TEX = "BASELINE_TEX"
ROLE_BASELINE_PDF = "BASELINE_PDF"
ROLE_PAGE_MAP = "PAGE_MAP"
ROLE_PAGE_RECORDS = "PAGE_RECORDS"
ROLE_RUNTIME_PAGE_RECORDS = "RUNTIME_PAGE_RECORDS"
ROLE_LANE_ROUTES = "LANE_ROUTES"
ROLE_PAGE_EVIDENCE_BINDINGS = "OCR_PAGE_EVIDENCE_BINDINGS"
ROLE_BLOCK_INVENTORY = "OCR_BLOCK_INVENTORY"
ROLE_PERFORMANCE = "PERFORMANCE_METRICS"
ROLE_COST = "COST_METRICS"
_COMPILE_INPUT_ROLE_PREFIX = "COMPILE_INPUT_PASS_"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
_ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_UNC_PATH_RE = re.compile(r"^(?:\\\\|//)[^/\\]+[/\\]")
_COMPILE_WORKDIR_RE = re.compile(
    re.escape(COMPILE_WORKDIR_ID_PREFIX) + r"[0-9a-f]{64}"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bsk-[A-Za-z0-9_-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_SECRET_KEYS = frozenset({
    "api_key",
    "apikey",
    "authorization",
    "password",
    "passwd",
    "secret",
    "access_token",
    "refresh_token",
    "private_key",
})

_FIXED_BINDING_ROLES = {
    "snapshot": ROLE_RUN_SNAPSHOT,
    "source": ROLE_SOURCE,
    "raw_ocr": ROLE_RAW_OCR_TEX,
    "raw_freeze": ROLE_RAW_OCR_FREEZE,
    "syntax_baseline": ROLE_SYNTAX_BASELINE_TEX,
    "baseline_tex": ROLE_BASELINE_TEX,
    "page_records": ROLE_PAGE_RECORDS,
    "runtime_page_records": ROLE_RUNTIME_PAGE_RECORDS,
    "performance": ROLE_PERFORMANCE,
    "cost": ROLE_COST,
}

_TOP_LEVEL_KEYS = frozenset({
    "schema_version",
    "manifest_kind",
    "run_id",
    "created_at",
    "status",
    "artifacts",
    "bindings",
    "source",
    "raw_ocr",
    "lineage",
    "compile",
    "coverage",
    "strategies",
    "performance",
    "cost",
    "producer",
})

_SNAPSHOT_KEYS = frozenset({
    "schema_version",
    "run_id",
    "source_type",
    "original_filename",
    "source_sha256",
    "source_total_pages",
    "selected_pages",
    "page_range",
    "ocr_model",
    "api_backend",
    "app_version",
    "quality_tier",
    "initial_dpi",
    "max_retries",
    "batch_size",
    "concurrency_limit",
    "started_at",
    "text_layer_status",
    "bookmarks",
    "page_sizes",
    "source_images",
    "visual_source_sha256",
    "config_sha256",
    "pipeline_contract",
})

_PAGE_RECORD_KEYS = frozenset({
    "schema_version",
    "page_id",
    "source_page",
    "task_index",
    "status",
    "image_sha256",
    "image_size_pixels",
    "dpi",
    "model",
    "call_index",
    "batch_call",
    "batch_id",
    "raw_response_sha256",
    "source_evidence_sha256",
    "raw_tex",
    "cleaned_tex",
    "tex_sha256",
    "started_at",
    "ended_at",
    "elapsed_seconds",
    "retry_count",
    "quality_issues",
    "host_quality_flags",
    "unresolved_regions",
    "usage",
    "error_reason",
    "updated_at",
})

_RAW_FREEZE_KEYS = frozenset({
    "schema_version",
    "run_id",
    "created_at",
    "raw_ocr_sha256",
    "selected_pages",
    "page_records",
    "ocr_model",
    "api_backend",
    "usage",
    "unresolved_regions",
    "error_pages",
    "merge_version",
    "figure_manifest_sha256",
    "figure_assets",
})


class OcrBaselineManifestError(ValueError):
    """Raised when OCR baseline evidence is incomplete or contradictory."""


def _fail(message: str) -> None:
    raise OcrBaselineManifestError(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    """Return the one canonical encoding accepted for a manifest."""
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(data: bytes, label: str) -> object:
    if not isinstance(data, bytes | bytearray | memoryview) or not data:
        _fail(f"{label} must contain non-empty JSON bytes")
    try:
        return json.loads(
            bytes(data).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: _fail(f"{label} contains non-finite {value}"),
        )
    except OcrBaselineManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OcrBaselineManifestError(f"{label} is not valid UTF-8 JSON") from exc


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str] | frozenset[str], label: str) -> None:
    actual = set(value)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        extra = sorted(actual - set(expected))
        _fail(f"{label} keys mismatch; missing={missing}, extra={extra}")


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"{label} must be a non-negative integer")
    return value


def _positive_int(value: object, label: str) -> int:
    result = _nonnegative_int(value, label)
    if result < 1:
        _fail(f"{label} must be a positive integer")
    return result


def _finite_nonnegative(value: object, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        _fail(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result <= 0):
        _fail(f"{label} must be finite and {'positive' if positive else 'non-negative'}")
    return result


def _relative_path(value: object, label: str) -> str:
    path = str(value or "")
    if (
        not path
        or "\\" in path
        or path.startswith("/")
        or _DRIVE_PATH_RE.match(path)
        or _UNC_PATH_RE.match(path)
        or "://" in path
        or "\x00" in path
    ):
        _fail(f"{label} must be a relative POSIX path")
    pure = PurePosixPath(path)
    if path != pure.as_posix() or any(part in {"", ".", ".."} for part in pure.parts):
        _fail(f"{label} must be a normalized relative POSIX path")
    return path


def _is_absolute_path_text(value: str) -> bool:
    stripped = value.strip()
    return bool(
        stripped.startswith("/")
        or _DRIVE_PATH_RE.match(stripped)
        or _UNC_PATH_RE.match(stripped)
        or stripped.lower().startswith("file://")
    )


def _command_token_contains_absolute_path(value: str) -> bool:
    token = str(value)
    return bool(
        _is_absolute_path_text(token)
        or re.search(r"(?i)(?:^|=)[A-Z]:[\\/]", token)
        or re.search(r"(?:^|=)(?:/|\\\\)", token)
        or "file://" in token.lower()
    )


def _compile_command_tokens(value: object, label: str) -> list[str]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(f"{label} must be an array of command tokens")
    tokens: list[str] = []
    for index, raw_token in enumerate(value):
        if not isinstance(raw_token, str) or not raw_token or "\x00" in raw_token:
            _fail(f"{label}[{index}] is not a non-empty string token")
        if _command_token_contains_absolute_path(raw_token):
            _fail(f"{label}[{index}] contains an absolute path")
        if index == 0 and ("/" in raw_token or "\\" in raw_token):
            _fail(f"{label} executable must be a basename")
        if _SECRET_VALUE_RE.search(raw_token):
            _fail(f"{label}[{index}] contains secret-like material")
        tokens.append(raw_token)
    return tokens


def _compile_command_history(value: object, label: str) -> list[list[str]]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(f"{label} must be an array of commands")
    return [
        _compile_command_tokens(command, f"{label}[{index}]")
        for index, command in enumerate(value)
    ]


def _compile_input_inventory(value: object, label: str) -> list[dict[str, object]]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(f"{label} must be an array")
    inventory: list[dict[str, object]] = []
    for index, raw_item in enumerate(value):
        if not isinstance(raw_item, Mapping):
            _fail(f"{label}[{index}] must be an object")
        item = dict(raw_item)
        _exact_keys(item, {"path", "bytes", "sha256"}, f"{label}[{index}]")
        path = _relative_path(item["path"], f"{label}[{index}].path")
        byte_count = _nonnegative_int(item["bytes"], f"{label}[{index}].bytes")
        digest = str(item["sha256"] or "").lower()
        if not _SHA256_RE.fullmatch(digest):
            _fail(f"{label}[{index}].sha256 is invalid")
        inventory.append({"path": path, "bytes": byte_count, "sha256": digest})
    paths = [str(item["path"]) for item in inventory]
    if paths != sorted(paths):
        _fail(f"{label} paths must be sorted")
    if len(paths) != len(set(paths)) or len(paths) != len({path.casefold() for path in paths}):
        _fail(f"{label} paths must be unique")
    return inventory


def _compile_input_files(
    value: object,
    label: str,
) -> list[tuple[str, bytes]]:
    """Normalize the exact bytes materialized for one compiler invocation."""
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _fail(f"{label} must be an array of path/bytes pairs")
    files: list[tuple[str, bytes]] = []
    for index, raw_item in enumerate(value):
        if (
            isinstance(raw_item, (str, bytes, bytearray))
            or not isinstance(raw_item, Sequence)
            or len(raw_item) != 2
        ):
            _fail(f"{label}[{index}] must be a path/bytes pair")
        path = _relative_path(raw_item[0], f"{label}[{index}].path")
        raw_data = raw_item[1]
        if not isinstance(raw_data, bytes | bytearray | memoryview):
            _fail(f"{label}[{index}].data must be bytes")
        files.append((path, bytes(raw_data)))
    paths = [path for path, _data in files]
    if paths != sorted(paths):
        _fail(f"{label} paths must be sorted")
    if len(paths) != len(set(paths)) or len(paths) != len({path.casefold() for path in paths}):
        _fail(f"{label} paths must be unique")
    return files


def _compile_inventory_sha256(inventory: Sequence[Mapping[str, object]]) -> str:
    body = {
        "schema": COMPILE_INPUT_MANIFEST_SCHEMA,
        "file_count": len(inventory),
        "files": [dict(item) for item in inventory],
    }
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(canonical)


def _compile_execution_evidence(
    *,
    command: object,
    command_history: object,
    compile_workdir: object,
    input_inventory: object,
    compile_input_sha256: object,
    input_tex_sha256: str,
    label: str,
    require_canonical_empty: bool = False,
) -> tuple[dict[str, object], bool]:
    command_value = _compile_command_tokens(command, f"{label}.command")
    history_value = _compile_command_history(
        command_history,
        f"{label}.command_history",
    )
    inventory_value = _compile_input_inventory(
        input_inventory,
        f"{label}.input_inventory",
    )
    if (
        compile_workdir is not None
        and compile_workdir != ""
        and not isinstance(compile_workdir, str)
    ):
        _fail(f"{label}.compile_workdir must be a string or null")
    workdir_value = str(compile_workdir or "")
    if (
        compile_input_sha256 is not None
        and compile_input_sha256 != ""
        and not isinstance(compile_input_sha256, str)
    ):
        _fail(f"{label}.compile_input_sha256 must be a string or null")
    input_set_sha = str(compile_input_sha256 or "").lower()
    measured = bool(
        command_value
        or history_value
        or workdir_value
        or inventory_value
        or input_set_sha
    )
    if not measured:
        if require_canonical_empty and (
            command != []
            or command_history != []
            or compile_workdir is not None
            or input_inventory != []
            or compile_input_sha256 is not None
        ):
            _fail(f"{label} unmeasured evidence must use canonical null/empty values")
        return {
            "command": [],
            "command_history": [],
            "compile_workdir": None,
            "input_inventory": [],
            "compile_input_sha256": None,
        }, False
    if not (
        command_value
        and history_value
        and workdir_value
        and inventory_value
        and input_set_sha
    ):
        _fail(f"{label} measured compile evidence is incomplete")
    if not _COMPILE_WORKDIR_RE.fullmatch(workdir_value):
        _fail(f"{label}.compile_workdir identifier is invalid")
    if not _SHA256_RE.fullmatch(input_set_sha):
        _fail(f"{label}.compile_input_sha256 is invalid")
    if command_value not in history_value:
        _fail(f"{label}.command is absent from command_history")
    if _compile_inventory_sha256(inventory_value) != input_set_sha:
        _fail(f"{label} input inventory digest does not match compile_input_sha256")
    main_tex = next(
        (item for item in inventory_value if item["path"] == "main.tex"),
        None,
    )
    if main_tex is None or main_tex["sha256"] != input_tex_sha256:
        _fail(f"{label} input inventory does not bind input_tex_sha256")
    return {
        "command": command_value,
        "command_history": history_value,
        "compile_workdir": workdir_value,
        "input_inventory": inventory_value,
        "compile_input_sha256": input_set_sha,
    }, True


def _strategies_from_performance(performance: Mapping[str, object]) -> dict[str, int]:
    distribution = _object(
        performance["strategy_distribution"],
        "performance strategy_distribution",
    )
    return {
        "born_digital_verified": int(
            distribution.get(OcrStrategy.OBJECT_LAYER_VERIFIED.value, 0)
        ),
        "full_visual_ocr": int(distribution.get(OcrStrategy.FULL_VISUAL_OCR.value, 0)),
        "high_resolution_retry": int(
            distribution.get(OcrStrategy.HIGH_RESOLUTION_RETRY.value, 0)
        ),
        "crop_review": int(distribution.get(OcrStrategy.CROP_REVIEW.value, 0)),
    }


def _actual_pdf_page_count(data: bytes, label: str) -> int:
    try:
        import pymupdf
    except ImportError:  # pragma: no cover - declared runtime dependency
        import fitz as pymupdf  # type: ignore

    try:
        with pymupdf.open(stream=bytes(data), filetype="pdf") as document:
            page_count = int(document.page_count)
    except Exception as exc:  # noqa: BLE001 - malformed PDF evidence must fail closed
        raise OcrBaselineManifestError(f"{label} is not a readable PDF") from exc
    if page_count < 1:
        _fail(f"{label} must contain at least one page")
    return page_count


def _scan_public_metadata(value: object, label: str = "manifest") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _SECRET_KEYS:
                _fail(f"{label} contains forbidden secret field {key!r}")
            _scan_public_metadata(item, f"{label}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _scan_public_metadata(item, f"{label}[{index}]")
    elif isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            _fail(f"{label} contains secret-like material")
        if _is_absolute_path_text(value):
            _fail(f"{label} contains an absolute path")


def _utc_timestamp(value: object, label: str) -> str:
    text = str(value or "")
    if not text.endswith("Z"):
        _fail(f"{label} must be a UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise OcrBaselineManifestError(f"{label} is not an ISO-8601 timestamp") from exc
    return text


@dataclass(frozen=True, slots=True)
class ArtifactInput:
    """One caller-owned artifact, identified only by role and relative path."""

    role: str
    path: str
    data: bytes


@dataclass(frozen=True, slots=True)
class CompilePassInput:
    """One real compile invocation, including any pre-repair candidate hashes.

    Hashes and execution metadata remain optional only for legacy callers.  If
    any execution field is supplied, all commands, the opaque workdir ID and
    the complete measured input inventory become mandatory and recomputable.
    """

    log_path: str
    log_bytes: bytes
    exit_code: int
    input_tex_sha256: str | None = None
    output_pdf_sha256: str | None = None
    command: Sequence[str] = ()
    command_history: Sequence[Sequence[str]] = ()
    compile_workdir: str | None = None
    input_inventory: Sequence[Mapping[str, object]] = ()
    compile_input_sha256: str | None = None
    input_files: Sequence[tuple[str, bytes]] = ()


@dataclass(frozen=True, slots=True)
class OcrBaselineManifest:
    """Canonical immutable bytes of a successfully verified manifest."""

    canonical_bytes: bytes

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    def to_dict(self) -> dict[str, Any]:
        value = _load_json(self.canonical_bytes, "OCR baseline manifest")
        return _object(value, "OCR baseline manifest")


@dataclass(frozen=True, slots=True)
class OcrBaselineManifestBundle:
    """Pure byte bundle suitable for an outer store's atomic commit."""

    manifest: OcrBaselineManifest
    artifacts: tuple[tuple[str, bytes], ...]

    def artifact_bytes(self) -> Mapping[str, bytes]:
        return MappingProxyType({path: bytes(data) for path, data in self.artifacts})

    def files(self, manifest_path: str = DEFAULT_MANIFEST_PATH) -> Mapping[str, bytes]:
        path = _relative_path(manifest_path, "manifest_path")
        files = dict(self.artifacts)
        if path in files:
            _fail("manifest path conflicts with an artifact path")
        files[path] = self.manifest.canonical_bytes
        return MappingProxyType(files)


def _artifact_descriptor(
    artifact: ArtifactInput,
    *,
    allow_empty: bool = False,
) -> tuple[dict[str, object], bytes]:
    role = str(artifact.role or "")
    if not _ROLE_RE.fullmatch(role):
        _fail(f"invalid artifact role: {role!r}")
    path = _relative_path(artifact.path, f"{role} path")
    if not isinstance(artifact.data, bytes | bytearray | memoryview):
        _fail(f"{role} must provide bytes")
    data = bytes(artifact.data)
    if not data and not allow_empty:
        _fail(f"{role} artifact cannot be empty")
    return {
        "role": role,
        "path": path,
        "bytes": len(data),
        "sha256": _sha256(data),
    }, data


def _parse_snapshot(data: bytes) -> tuple[dict[str, Any], Any]:
    value = _object(_load_json(data, "run snapshot"), "run snapshot")
    _exact_keys(value, _SNAPSHOT_KEYS, "run snapshot")
    try:
        # Lazy import keeps this module usable from a future ocr_runtime integration.
        from latexstruct.core.ocr_runtime import OcrRunSnapshot

        snapshot = OcrRunSnapshot.from_dict(value)
    except (TypeError, ValueError) as exc:
        raise OcrBaselineManifestError("run snapshot violates OcrRunSnapshot") from exc
    return value, snapshot


def _parse_page_records(
    data: bytes,
    snapshot: Any,
) -> tuple[tuple[PageCoverageRecord, ...], dict[str, object]]:
    """Parse canonical eight-check page coverage as completion authority."""

    try:
        run_id, source_sha256, records = parse_page_records(data)
        rebuilt = build_page_summaries(
            records,
            run_id=run_id,
            source_sha256=source_sha256,
            expected_source_pages=snapshot.selected_pages,
        )
    except (TypeError, ValueError) as exc:
        raise OcrBaselineManifestError(
            "page records violate the page coverage contract"
        ) from exc
    if bytes(data) != rebuilt.page_records_bytes:
        _fail("page records are not canonical/recomputable")
    if run_id != snapshot.run_id or source_sha256 != snapshot.source_sha256:
        _fail("page records run/source binding does not match the snapshot")
    return records, dict(rebuilt.coverage)


def _parse_runtime_page_records(data: bytes, snapshot: Any) -> list[Any]:
    """Parse legacy runtime records without granting them completion authority."""

    wrapper = _object(_load_json(data, "page records"), "page records")
    _exact_keys(wrapper, {"schema_version", "run_id", "pages"}, "page records")
    if (
        wrapper["schema_version"] != OCR_RUNTIME_PAGE_RECORDS_SCHEMA
        or wrapper["run_id"] != snapshot.run_id
    ):
        _fail("runtime page records schema/run_id does not match the snapshot")
    raw_pages = wrapper["pages"]
    if not isinstance(raw_pages, list):
        _fail("runtime page records pages must be an array")
    try:
        from latexstruct.core.ocr_runtime import OcrPageRecord

        records = []
        for index, raw in enumerate(raw_pages, start=1):
            page = _object(raw, f"runtime page record {index}")
            _exact_keys(page, _PAGE_RECORD_KEYS, f"runtime page record {index}")
            records.append(OcrPageRecord.from_dict(page))
    except (TypeError, ValueError) as exc:
        raise OcrBaselineManifestError("runtime page records violate OcrPageRecord") from exc
    if len(records) != len(snapshot.selected_pages):
        _fail("runtime page records do not cover every selected page")
    for index, record in enumerate(records, start=1):
        if record.task_index != index or (record.page_id, record.source_page) != snapshot.page_identity(index):
            _fail("runtime page record identity/order does not match selected_pages")
    return records


def _bind_page_record_authorities(
    coverage_records: Sequence[PageCoverageRecord],
    runtime_records: Sequence[Any],
) -> None:
    if len(coverage_records) != len(runtime_records):
        _fail("coverage/runtime page record counts differ")
    terminal = {"SUCCESS", "NEEDS_REVIEW", "FAILED", "CANCELLED"}
    for coverage_record, runtime_record in zip(
        coverage_records, runtime_records, strict=True,
    ):
        if (
            coverage_record.page_id != runtime_record.page_id
            or coverage_record.source_page_number != runtime_record.source_page
            or coverage_record.selected_index != runtime_record.task_index
        ):
            _fail("coverage/runtime page identities differ")
        coverage_status = (
            coverage_record.final_status.value
            if coverage_record.final_status is not None
            else None
        )
        runtime_status = runtime_record.status.value
        if coverage_status is None:
            if runtime_status in terminal:
                _fail("terminal runtime page is missing a coverage final_status")
        elif coverage_status != runtime_status:
            _fail("coverage/runtime page terminal statuses differ")
        if coverage_record.completed:
            page_tex_sha = coverage_record.artifact_hashes.get("page.tex")
            if not runtime_record.tex_sha256 or runtime_record.tex_sha256 != page_tex_sha:
                _fail("completed page.tex differs from the runtime TeX binding")


def _verify_compiled_page_map(
    data: bytes,
    snapshot: Any,
    *,
    raw_ocr_data: bytes,
    baseline_pdf_data: bytes,
    claimed_pdf_page_count: int,
) -> None:
    """Recompute the map from host anchors and exact compiled PDF bytes.

    The map deliberately has no ``run_id`` field.  Its exact raw/PDF inputs are
    already bound to this manifest, whose own ``run_id`` is checked against the
    immutable snapshot.  Adding a caller-provided run wrapper here would only
    create a second, non-authoritative identity claim.
    """

    try:
        raw_tex = bytes(raw_ocr_data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OcrBaselineManifestError("RAW_OCR_TEX must be UTF-8") from exc
    try:
        anchors = extract_page_anchors(
            raw_tex,
            expected_selected_pages=snapshot.selected_pages,
        )
        if len(anchors) != len(snapshot.selected_pages):
            _fail("COMPILED page map requires one host anchor per selected page")
        recomputed = verify_page_map_json(data, baseline_pdf_data, anchors)
    except OcrPageMapError as exc:
        raise OcrBaselineManifestError(
            f"compiled page map is not recomputable: {exc}"
        ) from exc
    if recomputed.baseline_pdf_page_count != claimed_pdf_page_count:
        _fail("compile pdf_page_count differs from the recomputed page map")


def _parse_raw_freeze(data: bytes, snapshot: Any, raw_sha: str, records: Sequence[Any]) -> None:
    value = _object(_load_json(data, "raw OCR freeze"), "raw OCR freeze")
    unknown = set(value) - _RAW_FREEZE_KEYS
    required = _RAW_FREEZE_KEYS - {"figure_manifest_sha256", "figure_assets"}
    missing = required - set(value)
    if unknown or missing:
        _fail(f"raw OCR freeze keys mismatch; missing={sorted(missing)}, extra={sorted(unknown)}")
    if (
        value["schema_version"] != "latexstruct-raw-ocr-freeze-v1"
        or value["run_id"] != snapshot.run_id
        or value["raw_ocr_sha256"] != raw_sha
        or value["selected_pages"] != list(snapshot.selected_pages)
        or value["ocr_model"] != snapshot.ocr_model
        or value["api_backend"] != snapshot.api_backend
    ):
        _fail("raw OCR freeze is not bound to snapshot/raw OCR bytes")
    frozen_records = value["page_records"]
    if not isinstance(frozen_records, list) or len(frozen_records) != len(records):
        _fail("raw OCR freeze page coverage mismatch")
    for frozen, record in zip(frozen_records, records, strict=True):
        entry = _object(frozen, "raw OCR freeze page record")
        _exact_keys(entry, {"page_id", "source_page", "status", "tex_sha256", "raw_response_sha256"}, "raw OCR freeze page record")
        expected = {
            "page_id": record.page_id,
            "source_page": record.source_page,
            "status": record.status.value,
            "tex_sha256": record.tex_sha256 or None,
            "raw_response_sha256": record.raw_response_sha256 or None,
        }
        if entry != expected:
            _fail("raw OCR freeze page record differs from page_records")
    expected_errors = [
        record.source_page for record in records if record.status.value in {"FAILED", "CANCELLED"}
    ]
    if value["error_pages"] != expected_errors:
        _fail("raw OCR freeze error_pages is not derivable from page_records")


def _nullable_nonnegative_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, label)


def _nullable_nonnegative_number(value: object, label: str) -> float | None:
    if value is None:
        return None
    return _finite_nonnegative(value, label)


def _parse_measurement_coverage(
    value: object,
    *,
    total: int,
    label: str,
) -> tuple[int, bool]:
    coverage = _object(value, label)
    _exact_keys(coverage, {"measured", "total", "complete"}, label)
    measured = _nonnegative_int(coverage["measured"], f"{label}.measured")
    if coverage["total"] != total or measured > total:
        _fail(f"{label} count differs from the request total")
    expected_complete = measured == total and bool(total)
    if coverage["complete"] is not expected_complete:
        _fail(f"{label}.complete is not recomputable")
    return measured, expected_complete


def _parse_counter(
    value: object,
    *,
    allowed: set[str],
    label: str,
) -> dict[str, int]:
    counter = _object(value, label)
    if not set(counter).issubset(allowed):
        _fail(f"{label} contains an unsupported key")
    parsed: dict[str, int] = {}
    for key, item in counter.items():
        count = _positive_int(item, f"{label}.{key}")
        parsed[str(key)] = count
    return parsed


def _require_metric_authority(
    value: object,
    observed: int,
    complete: bool,
    label: str,
) -> None:
    if complete:
        if value != observed:
            _fail(f"{label} differs from its complete measured total")
    elif value is not None:
        _fail(f"incomplete {label} measurement must remain null")


def _parse_performance(
    data: bytes,
    run_id: str,
    coverage: Mapping[str, object],
    runtime_records: Sequence[Any],
) -> dict[str, object]:
    value = _object(_load_json(data, "performance metrics"), "performance metrics")
    if bytes(data) != canonical_metrics_json_bytes(value):
        _fail("performance metrics are not canonical collector output")
    _exact_keys(
        value,
        {
            "schema_version",
            "run_id",
            "elapsed_ms",
            "pages",
            "stages",
            "throughput",
            "strategy_distribution",
            "strategy_measurement",
            "dpi_pages",
            "requests",
            "usage",
            "resources",
        },
        "performance metrics",
    )
    if value["schema_version"] != OCR_PERFORMANCE_SCHEMA or value["run_id"] != run_id:
        _fail("performance metrics schema/run_id mismatch")
    elapsed_ms = _finite_nonnegative(value["elapsed_ms"], "elapsed_ms")

    pages = _object(value["pages"], "performance pages")
    _exact_keys(
        pages,
        {"selected", "coverage_completed", "remaining", "by_final_status"},
        "performance pages",
    )
    selected = int(coverage["selected"])
    if pages["selected"] != selected:
        _fail("performance selected page count differs from coverage")
    runtime_counts: dict[str, int] = {}
    metric_statuses = {item.value for item in PageFinalStatus}
    for record in runtime_records:
        status = record.status.value
        if status in metric_statuses:
            runtime_counts[status] = runtime_counts.get(status, 0) + 1
    expected_statuses = {key: count for key, count in sorted(runtime_counts.items()) if count}
    page_statuses = _parse_counter(
        pages["by_final_status"],
        allowed=metric_statuses,
        label="performance final statuses",
    )
    if page_statuses != expected_statuses:
        _fail("performance final statuses differ from runtime page records")
    observed_pages = sum(page_statuses.values())
    if (
        pages["coverage_completed"] != observed_pages
        or pages["remaining"] != selected - observed_pages
    ):
        _fail("performance page observation counts are not recomputable")

    stages = _object(value["stages"], "performance stages")
    expected_stage_names = {stage.value for stage in OcrStage}
    _exact_keys(stages, expected_stage_names, "performance stages")
    for stage_name, raw_stage in stages.items():
        stage = _object(raw_stage, f"performance stage {stage_name}")
        _exact_keys(
            stage,
            {"submitted", "started", "completed", "failed", "queued", "in_flight", "latency_ms"},
            f"performance stage {stage_name}",
        )
        submitted = _nonnegative_int(stage["submitted"], f"{stage_name}.submitted")
        started = _nonnegative_int(stage["started"], f"{stage_name}.started")
        completed = _nonnegative_int(stage["completed"], f"{stage_name}.completed")
        failed = _nonnegative_int(stage["failed"], f"{stage_name}.failed")
        if started > submitted or completed + failed > started:
            _fail(f"performance stage {stage_name} counts are impossible")
        if stage["queued"] != submitted - started or stage["in_flight"] != started - completed - failed:
            _fail(f"performance stage {stage_name} derived counts are stale")
        latency = _object(stage["latency_ms"], f"{stage_name}.latency_ms")
        _exact_keys(latency, {"samples", "p50", "p95"}, f"{stage_name}.latency_ms")
        samples = _nonnegative_int(latency["samples"], f"{stage_name}.latency samples")
        for percentile in ("p50", "p95"):
            measured = _nullable_nonnegative_number(
                latency[percentile], f"{stage_name}.latency {percentile}",
            )
            if (samples == 0) != (measured is None):
                _fail(f"{stage_name}.latency {percentile} coverage is contradictory")

    throughput = _object(value["throughput"], "performance throughput")
    _exact_keys(
        throughput,
        {
            "average_pages_per_minute",
            "recent_pages_per_minute",
            "recent_window_seconds",
            "eta_seconds",
            "eta_basis",
        },
        "performance throughput",
    )
    average = _nullable_nonnegative_number(
        throughput["average_pages_per_minute"], "average_pages_per_minute",
    )
    expected_average = (
        observed_pages * 60000.0 / elapsed_ms
        if elapsed_ms > 0 and observed_pages
        else None
    )
    if (average is None) != (expected_average is None) or (
        average is not None
        and expected_average is not None
        and not math.isclose(average, expected_average, rel_tol=1e-9, abs_tol=1e-9)
    ):
        _fail("average throughput is not recomputable")
    recent_window = _finite_nonnegative(
        throughput["recent_window_seconds"], "recent_window_seconds",
    )
    if not math.isclose(recent_window, min(60.0, elapsed_ms / 1000.0), abs_tol=1e-9):
        _fail("recent throughput window differs from elapsed time")
    _nullable_nonnegative_number(
        throughput["recent_pages_per_minute"], "recent_pages_per_minute",
    )
    remaining = selected - observed_pages
    expected_eta = (
        0.0
        if remaining == 0
        else remaining / (average / 60.0)
        if average is not None and average > 0
        else None
    )
    eta = _nullable_nonnegative_number(throughput["eta_seconds"], "eta_seconds")
    if (eta is None) != (expected_eta is None) or (
        eta is not None
        and expected_eta is not None
        and not math.isclose(eta, expected_eta, rel_tol=1e-9, abs_tol=1e-9)
    ):
        _fail("ETA is not recomputable")
    expected_eta_basis = (
        "complete" if remaining == 0 else "measured_average_throughput" if eta is not None else None
    )
    if throughput["eta_basis"] != expected_eta_basis:
        _fail("ETA basis is not recomputable")

    strategies = _parse_counter(
        value["strategy_distribution"],
        allowed={item.value for item in OcrStrategy},
        label="strategy distribution",
    )
    strategy_measurement = _object(value["strategy_measurement"], "strategy measurement")
    _exact_keys(
        strategy_measurement,
        {"classified", "total_completed", "complete"},
        "strategy measurement",
    )
    classified = sum(strategies.values())
    if (
        strategy_measurement["classified"] != classified
        or strategy_measurement["total_completed"] != observed_pages
        or strategy_measurement["complete"] is not (classified == observed_pages and bool(observed_pages))
    ):
        _fail("strategy measurement is not recomputable")
    dpi_pages = _object(value["dpi_pages"], "dpi_pages")
    for dpi, count in dpi_pages.items():
        if not str(dpi).isdigit() or int(dpi) < 1:
            _fail("dpi_pages keys must be positive integer strings")
        _positive_int(count, f"dpi_pages.{dpi}")

    requests = _object(value["requests"], "performance requests")
    request_keys = {
        "total",
        "pages_in_requests",
        "by_kind",
        "by_dpi",
        "http_429",
        "http_5xx",
        "status_code_coverage",
        "automatic_retries",
        "observed_automatic_retries",
        "retry_coverage",
        "output_truncations",
        "observed_output_truncations",
        "truncation_rate",
        "truncation_coverage",
        "strong_model_calls",
        "observed_strong_model_calls",
        "strong_model_coverage",
        "latency_ms",
    }
    _exact_keys(requests, request_keys, "performance requests")
    request_total = _nonnegative_int(requests["total"], "request total")
    _nonnegative_int(requests["pages_in_requests"], "pages_in_requests")
    by_kind = _parse_counter(
        requests["by_kind"],
        allowed={item.value for item in RequestKind},
        label="requests by_kind",
    )
    if sum(by_kind.values()) != request_total:
        _fail("requests by_kind does not sum to request total")
    by_dpi = _object(requests["by_dpi"], "requests by_dpi")
    dpi_request_count = 0
    for dpi, count in by_dpi.items():
        if not str(dpi).isdigit() or int(dpi) < 1:
            _fail("requests by_dpi keys must be positive integer strings")
        dpi_request_count += _positive_int(count, f"requests by_dpi.{dpi}")
    if dpi_request_count > request_total:
        _fail("requests by_dpi exceeds request total")
    _nonnegative_int(requests["http_429"], "http_429")
    _nonnegative_int(requests["http_5xx"], "http_5xx")
    status_measured, _ = _parse_measurement_coverage(
        requests["status_code_coverage"], total=request_total, label="status code coverage",
    )
    if requests["http_429"] + requests["http_5xx"] > status_measured:
        _fail("HTTP error counts exceed measured status codes")
    for value_key, observed_key, coverage_key, label in (
        ("automatic_retries", "observed_automatic_retries", "retry_coverage", "automatic retries"),
        ("output_truncations", "observed_output_truncations", "truncation_coverage", "output truncations"),
        ("strong_model_calls", "observed_strong_model_calls", "strong_model_coverage", "strong model calls"),
    ):
        observed = _nonnegative_int(requests[observed_key], observed_key)
        measured, complete = _parse_measurement_coverage(
            requests[coverage_key], total=request_total, label=coverage_key,
        )
        if observed > measured:
            _fail(f"{label} exceed measured observations")
        _require_metric_authority(requests[value_key], observed, complete, label)
    truncation_rate = _nullable_nonnegative_number(
        requests["truncation_rate"], "truncation_rate",
    )
    trunc_complete = bool(_object(requests["truncation_coverage"], "truncation coverage")["complete"])
    expected_rate = (
        requests["observed_output_truncations"] / request_total
        if trunc_complete
        else None
    )
    if truncation_rate != expected_rate:
        _fail("truncation_rate is not recomputable")
    request_latency = _object(requests["latency_ms"], "request latency")
    _exact_keys(request_latency, {"samples", "p50", "p95"}, "request latency")
    if request_latency["samples"] != request_total:
        _fail("request latency samples differ from request total")
    for percentile in ("p50", "p95"):
        measured = _nullable_nonnegative_number(
            request_latency[percentile], f"request latency {percentile}",
        )
        if (request_total == 0) != (measured is None):
            _fail("request latency percentile coverage is contradictory")

    usage = _object(value["usage"], "performance usage")
    _exact_keys(
        usage,
        {
            "input_tokens",
            "observed_input_tokens",
            "input_token_coverage",
            "output_tokens",
            "observed_output_tokens",
            "output_token_coverage",
            "cost",
            "observed_cost",
            "currency",
            "cost_coverage",
        },
        "performance usage",
    )
    for value_key, observed_key, coverage_key, label in (
        ("input_tokens", "observed_input_tokens", "input_token_coverage", "input tokens"),
        ("output_tokens", "observed_output_tokens", "output_token_coverage", "output tokens"),
    ):
        observed = _nonnegative_int(usage[observed_key], observed_key)
        _measured, complete = _parse_measurement_coverage(
            usage[coverage_key], total=request_total, label=coverage_key,
        )
        _nullable_nonnegative_int(usage[value_key], label)
        _require_metric_authority(usage[value_key], observed, complete, label)
    observed_cost = _finite_nonnegative(usage["observed_cost"], "observed cost")
    _measured_cost, cost_complete = _parse_measurement_coverage(
        usage["cost_coverage"], total=request_total, label="cost coverage",
    )
    actual_cost = _nullable_nonnegative_number(usage["cost"], "actual cost")
    if cost_complete:
        if actual_cost is None or not math.isclose(actual_cost, observed_cost, abs_tol=1e-12):
            _fail("actual cost differs from complete measurements")
    elif actual_cost is not None:
        _fail("incomplete cost measurement must remain null")
    currency = usage["currency"]
    if currency is not None and not re.fullmatch(r"[A-Z]{3}", str(currency)):
        _fail("metrics currency must be null or a three-letter code")

    resources = _object(value["resources"], "performance resources")
    _exact_keys(
        resources,
        {"peak_memory_bytes", "peak_cpu_percent", "samples", "memory_samples", "cpu_samples"},
        "performance resources",
    )
    samples = _nonnegative_int(resources["samples"], "resource samples")
    memory_samples = _nonnegative_int(resources["memory_samples"], "memory samples")
    cpu_samples = _nonnegative_int(resources["cpu_samples"], "CPU samples")
    if memory_samples > samples or cpu_samples > samples:
        _fail("resource measurement counts exceed total samples")
    peak_memory = _nullable_nonnegative_int(resources["peak_memory_bytes"], "peak memory")
    peak_cpu = _nullable_nonnegative_number(resources["peak_cpu_percent"], "peak CPU")
    if (memory_samples == 0) != (peak_memory is None):
        _fail("unknown peak memory must remain null")
    if (cpu_samples == 0) != (peak_cpu is None):
        _fail("unknown peak CPU must remain null")
    return value


def _parse_cost(data: bytes, run_id: str, performance: Mapping[str, object]) -> dict[str, object]:
    value = _object(_load_json(data, "cost metrics"), "cost metrics")
    if bytes(data) != canonical_metrics_json_bytes(value):
        _fail("cost metrics are not canonical collector output")
    _exact_keys(
        value,
        {
            "schema_version",
            "run_id",
            "actual",
            "observed_partial",
            "measurement_coverage",
            "limits",
            "ratios",
        },
        "cost metrics",
    )
    if value["schema_version"] != OCR_COST_SCHEMA or value["run_id"] != run_id:
        _fail("cost metrics schema/run_id mismatch")
    requests = _object(performance["requests"], "performance requests")
    usage = _object(performance["usage"], "performance usage")
    actual = _object(value["actual"], "cost actual")
    actual_keys = {
        "requests", "strong_model_calls", "input_tokens", "output_tokens", "cost", "currency",
    }
    _exact_keys(actual, actual_keys, "cost actual")
    expected_actual = {
        "requests": requests["total"],
        "strong_model_calls": requests["strong_model_calls"],
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "cost": usage["cost"],
        "currency": usage["currency"],
    }
    if actual != expected_actual:
        _fail("cost actual values differ from performance metrics")
    observed = _object(value["observed_partial"], "cost observed_partial")
    observed_keys = {"strong_model_calls", "input_tokens", "output_tokens", "cost", "currency"}
    _exact_keys(observed, observed_keys, "cost observed_partial")
    expected_observed = {
        "strong_model_calls": requests["observed_strong_model_calls"],
        "input_tokens": usage["observed_input_tokens"],
        "output_tokens": usage["observed_output_tokens"],
        "cost": usage["observed_cost"],
        "currency": usage["currency"],
    }
    if observed != expected_observed:
        _fail("cost observed_partial differs from performance metrics")
    measurement = _object(value["measurement_coverage"], "cost measurement coverage")
    _exact_keys(
        measurement,
        {"strong_model_calls", "input_tokens", "output_tokens", "cost"},
        "cost measurement coverage",
    )
    expected_measurement = {
        "strong_model_calls": requests["strong_model_coverage"],
        "input_tokens": usage["input_token_coverage"],
        "output_tokens": usage["output_token_coverage"],
        "cost": usage["cost_coverage"],
    }
    if measurement != expected_measurement:
        _fail("cost measurement coverage differs from performance metrics")

    limits = _object(value["limits"], "cost limits")
    limit_keys = {
        "max_input_tokens",
        "max_output_tokens",
        "max_requests",
        "max_strong_model_calls",
        "max_cost",
        "max_wall_time_minutes",
    }
    _exact_keys(limits, limit_keys, "cost limits")
    for key in ("max_input_tokens", "max_output_tokens", "max_requests", "max_strong_model_calls"):
        item = limits[key]
        if item is not None:
            _positive_int(item, f"cost limit {key}")
    for key in ("max_cost", "max_wall_time_minutes"):
        item = limits[key]
        if item is not None:
            _finite_nonnegative(item, f"cost limit {key}", positive=True)
    ratios = _object(value["ratios"], "cost ratios")
    ratio_to_values = {
        "requests": (actual["requests"], limits["max_requests"]),
        "strong_model_calls": (
            actual["strong_model_calls"], limits["max_strong_model_calls"],
        ),
        "input_tokens": (actual["input_tokens"], limits["max_input_tokens"]),
        "output_tokens": (actual["output_tokens"], limits["max_output_tokens"]),
        "cost": (actual["cost"], limits["max_cost"]),
    }
    _exact_keys(ratios, set(ratio_to_values), "cost ratios")
    for key, (used, limit) in ratio_to_values.items():
        ratio = _nullable_nonnegative_number(ratios[key], f"cost ratio {key}")
        expected = None if used is None or limit is None else float(used) / float(limit)
        if (ratio is None) != (expected is None) or (
            ratio is not None
            and expected is not None
            and not math.isclose(ratio, expected, rel_tol=1e-9, abs_tol=1e-9)
        ):
            _fail(f"cost ratio {key} is not recomputable")
    return value


def _parse_producer(value: object, snapshot: Any) -> dict[str, object]:
    producer = _object(value, "producer")
    keys = {
        "schema_version",
        "app_version",
        "git_commit",
        "build_id",
        "ocr_model",
        "verification_model",
        "prompt_version",
        "api_backend",
    }
    _exact_keys(producer, keys, "producer")
    if producer["schema_version"] != OCR_PRODUCER_SCHEMA:
        _fail("producer schema is unsupported")
    if not _GIT_COMMIT_RE.fullmatch(str(producer["git_commit"] or "")):
        _fail("producer git_commit must be a 40-character lowercase commit")
    for key in ("build_id", "verification_model", "prompt_version"):
        text = str(producer[key] or "").strip()
        if not text or len(text) > 160:
            _fail(f"producer {key} is required and bounded")
    if (
        producer["app_version"] != snapshot.app_version
        or producer["ocr_model"] != snapshot.ocr_model
        or producer["api_backend"] != snapshot.api_backend
    ):
        _fail("producer does not match the immutable run snapshot")
    _scan_public_metadata(producer, "producer")
    return producer


def _derived_status(coverage: Mapping[str, int], compile_status: str) -> tuple[str, str]:
    if coverage["completed"] == coverage["selected"]:
        ocr_status = "COMPLETED" if coverage["needs_review"] == 0 else "COMPLETED_WITH_REVIEW"
    else:
        ocr_status = "INCOMPLETE"
    if coverage["cancelled"]:
        run_status = "CANCELLED"
    elif ocr_status == "COMPLETED" and compile_status == "COMPILED":
        run_status = "SUCCESS"
    elif coverage["completed"]:
        run_status = "PARTIAL"
    else:
        run_status = "FAILED"
    return run_status, ocr_status


def _trailing_successes(passes: Sequence[Mapping[str, object]]) -> int:
    count = 0
    for item in reversed(passes):
        if item["exit_code"] != 0:
            break
        count += 1
    return count


def _validate_compile(
    compile_value: Mapping[str, object],
    *,
    status: str,
    descriptors: Mapping[str, Mapping[str, object]],
    artifact_bytes: Mapping[str, bytes],
    bindings: Mapping[str, object],
) -> None:
    keys = {
        "engine",
        "input_tex_sha256",
        "selected_baseline",
        "successful_passes",
        "passes",
        "pdf_page_count",
        "fatal_error",
        "error_lines",
    }
    _exact_keys(compile_value, keys, "compile")
    if not str(compile_value["engine"] or "").strip():
        _fail("compile engine is required")
    baseline_role = bindings["baseline_tex"]
    baseline_sha = descriptors[baseline_role]["sha256"]
    if compile_value["input_tex_sha256"] != baseline_sha:
        _fail("compile input hash differs from BASELINE_TEX")
    selected_role = compile_value["selected_baseline"]
    if selected_role not in {ROLE_SYNTAX_BASELINE_TEX, ROLE_EVIDENCE_BASELINE_TEX}:
        _fail("compile selected_baseline is invalid")
    if descriptors[selected_role]["sha256"] != baseline_sha:
        _fail("BASELINE_TEX bytes differ from the selected syntax/evidence baseline")
    passes = compile_value["passes"]
    if not isinstance(passes, list) or not passes:
        _fail("compile must bind at least one real invocation log")
    expected_log_roles = bindings["compile_logs"]
    if not isinstance(expected_log_roles, list) or len(expected_log_roles) != len(passes):
        _fail("compile log bindings do not cover every pass")
    base_pass_keys = {
        "index",
        "exit_code",
        "input_tex_sha256",
        "log_role",
        "output_pdf_sha256",
    }
    execution_evidence_keys = {
        "command",
        "command_history",
        "compile_workdir",
        "input_inventory",
        "compile_input_sha256",
        "input_artifact_roles",
    }
    measured_passes: list[bool] = []
    expected_compile_input_roles: set[str] = set()
    for index, item_raw in enumerate(passes, start=1):
        item = _object(item_raw, f"compile pass {index}")
        actual_keys = set(item)
        if actual_keys not in {frozenset(base_pass_keys), frozenset(
            base_pass_keys | execution_evidence_keys
        )}:
            _fail(f"compile pass {index} keys mismatch")
        role = f"COMPILE_LOG_PASS_{index:02d}"
        if (
            item["index"] != index
            or item["log_role"] != role
            or expected_log_roles[index - 1] != role
            or role not in descriptors
        ):
            _fail("compile pass identity/log binding mismatch")
        input_sha = str(item["input_tex_sha256"] or "")
        if not _SHA256_RE.fullmatch(input_sha):
            _fail("compile pass input_tex_sha256 is invalid")
        if execution_evidence_keys <= actual_keys:
            normalized, measured = _compile_execution_evidence(
                command=item["command"],
                command_history=item["command_history"],
                compile_workdir=item["compile_workdir"],
                input_inventory=item["input_inventory"],
                compile_input_sha256=item["compile_input_sha256"],
                input_tex_sha256=input_sha,
                label=f"compile pass {index}",
                require_canonical_empty=True,
            )
            raw_input_roles = item["input_artifact_roles"]
            if not isinstance(raw_input_roles, list) or any(
                not isinstance(input_role, str) for input_role in raw_input_roles
            ):
                _fail(f"compile pass {index}.input_artifact_roles must be an array")
            if measured:
                inventory = normalized["input_inventory"]
                if len(raw_input_roles) != len(inventory):
                    _fail(
                        f"compile pass {index} exact input roles do not cover inventory"
                    )
                for file_index, (input_role, inventory_item) in enumerate(
                    zip(raw_input_roles, inventory, strict=True),
                    start=1,
                ):
                    expected_role = (
                        f"{_COMPILE_INPUT_ROLE_PREFIX}{index:02d}_{file_index:04d}"
                    )
                    if input_role != expected_role or input_role not in descriptors:
                        _fail(
                            f"compile pass {index} exact input artifact role is invalid"
                        )
                    descriptor = descriptors[input_role]
                    expected_path = (
                        f"compile/inputs/pass-{index:02d}/{inventory_item['path']}"
                    )
                    if (
                        descriptor["path"] != expected_path
                        or descriptor["bytes"] != inventory_item["bytes"]
                        or descriptor["sha256"] != inventory_item["sha256"]
                    ):
                        _fail(
                            f"compile pass {index} exact input artifact bytes are misbound"
                        )
                    expected_compile_input_roles.add(input_role)
            elif raw_input_roles:
                _fail(
                    f"compile pass {index} unmeasured evidence cannot bind input artifacts"
                )
        else:
            measured = False
        measured_passes.append(measured)
        if not isinstance(item["exit_code"], int) or isinstance(item["exit_code"], bool):
            _fail("compile pass exit_code must be an integer")
        path = str(descriptors[role]["path"])
        if not artifact_bytes[path]:
            _fail("compile pass log cannot be empty")
        output_sha = item["output_pdf_sha256"]
        if output_sha is not None and not _SHA256_RE.fullmatch(str(output_sha)):
            _fail("compile pass output_pdf_sha256 is invalid")
        expected_pdf = (
            descriptors.get(ROLE_BASELINE_PDF, {}).get("sha256")
            if index == len(passes)
            else None
        )
        if index == len(passes) and output_sha != expected_pdf:
            _fail("final compile pass PDF binding mismatch")
    actual_compile_input_roles = {
        role for role in descriptors if role.startswith(_COMPILE_INPUT_ROLE_PREFIX)
    }
    if actual_compile_input_roles != expected_compile_input_roles:
        _fail("compile input artifact descriptors differ from pass bindings")
    if any(measured_passes) and not all(measured_passes):
        _fail("measured compile execution evidence must cover every pass")
    trailing = _trailing_successes(passes)
    if compile_value["successful_passes"] != trailing:
        _fail("successful_passes is not the trailing successful pass count")
    pdf_count = _nonnegative_int(compile_value["pdf_page_count"], "pdf_page_count")
    pdf_role = bindings["baseline_pdf"]
    pdf_data = None
    if pdf_role is not None:
        if pdf_role != ROLE_BASELINE_PDF or pdf_role not in descriptors:
            _fail("baseline PDF binding is invalid")
        pdf_data = artifact_bytes[str(descriptors[pdf_role]["path"])]
        if not pdf_data.startswith(b"%PDF-"):
            _fail("baseline PDF artifact lacks the PDF magic header")
    if status == "COMPILED":
        final_two = passes[-2:]
        if (
            trailing < 2
            or len(final_two) != 2
            or any(item["exit_code"] != 0 for item in final_two)
            or any(item["input_tex_sha256"] != baseline_sha for item in final_two)
            or pdf_data is None
            or pdf_count < 1
        ):
            _fail(
                "COMPILED requires two trailing successful passes on the exact final "
                "BASELINE_TEX and a real PDF"
            )
        if compile_value["fatal_error"] or compile_value["error_lines"]:
            _fail("COMPILED cannot retain a fatal compile error")
    elif status == "PARTIAL_COMPILED":
        if trailing != 0 or passes[-1]["exit_code"] == 0 or pdf_data is None or pdf_count < 1:
            _fail("PARTIAL_COMPILED requires a failed final pass and a real partial PDF")
        if not str(compile_value["fatal_error"] or "").strip():
            _fail("PARTIAL_COMPILED requires the fatal error")
    else:
        if pdf_data is not None or pdf_count != 0 or passes[-1]["exit_code"] == 0:
            _fail("SOURCE_PREVIEW must not bind or claim a PDF")
        if not str(compile_value["fatal_error"] or "").strip():
            _fail("SOURCE_PREVIEW requires the compile failure reason")
    if not isinstance(compile_value["error_lines"], list):
        _fail("compile error_lines must be an array")
    _scan_public_metadata(
        {
            "engine": compile_value["engine"],
            "fatal_error": compile_value["fatal_error"],
            "error_lines": compile_value["error_lines"],
            "passes": passes,
        },
        "compile",
    )


def _verify_payload(
    payload: dict[str, Any],
    artifacts: Mapping[str, bytes],
    *,
    expected_source_sha256: str | None,
) -> None:
    _exact_keys(payload, _TOP_LEVEL_KEYS, "OCR baseline manifest")
    if payload["schema_version"] != OCR_BASELINE_MANIFEST_SCHEMA or payload["manifest_kind"] != "OCR_ONLY":
        _fail("unsupported OCR baseline manifest schema/kind")
    run_id = str(payload["run_id"] or "")
    if not _RUN_ID_RE.fullmatch(run_id):
        _fail("manifest run_id is invalid")
    _utc_timestamp(payload["created_at"], "created_at")
    status = _object(payload["status"], "status")
    _exact_keys(status, {"run_status", "ocr_status", "compile_status"}, "status")
    if status["run_status"] not in RUN_STATUSES or status["ocr_status"] not in OCR_STATUSES or status["compile_status"] not in COMPILE_STATUSES:
        _fail("manifest contains an unsupported terminal status")

    descriptors_raw = payload["artifacts"]
    if not isinstance(descriptors_raw, list) or not descriptors_raw:
        _fail("artifacts must be a non-empty array")
    descriptors: dict[str, dict[str, object]] = {}
    paths: set[str] = set()
    for raw in descriptors_raw:
        item = _object(raw, "artifact descriptor")
        _exact_keys(item, {"role", "path", "bytes", "sha256"}, "artifact descriptor")
        role = str(item["role"] or "")
        if not _ROLE_RE.fullmatch(role) or role in descriptors:
            _fail("artifact roles must be valid and unique")
        path = _relative_path(item["path"], f"{role} path")
        if path in paths:
            _fail("artifact paths must be unique")
        paths.add(path)
        if role.startswith(_COMPILE_INPUT_ROLE_PREFIX):
            _nonnegative_int(item["bytes"], f"{role} bytes")
        else:
            _positive_int(item["bytes"], f"{role} bytes")
        digest = str(item["sha256"] or "")
        if not _SHA256_RE.fullmatch(digest):
            _fail(f"{role} sha256 is invalid")
        descriptors[role] = item
    supplied_paths = set(artifacts)
    if supplied_paths != paths:
        _fail("supplied artifact paths differ from the manifest")
    artifact_bytes: dict[str, bytes] = {}
    for role, descriptor in descriptors.items():
        path = str(descriptor["path"])
        raw_data = artifacts[path]
        if not isinstance(raw_data, bytes | bytearray | memoryview):
            _fail(f"{role} supplied artifact is not bytes")
        data = bytes(raw_data)
        artifact_bytes[path] = data
        if len(data) != descriptor["bytes"] or _sha256(data) != descriptor["sha256"]:
            _fail(f"{role} artifact bytes/hash mismatch")

    bindings = _object(payload["bindings"], "bindings")
    legacy_binding_keys = set(_FIXED_BINDING_ROLES) | {
        "evidence_corrected_baseline",
        "baseline_pdf",
        "page_map",
        "compile_logs",
    }
    optional_binding_keys = {
        "lane_routes",
        "page_evidence_bindings",
        "evidence_correction_report",
        "block_inventory",
    }
    if (
        not legacy_binding_keys.issubset(bindings)
        or not set(bindings).issubset(legacy_binding_keys | optional_binding_keys)
    ):
        _fail("bindings keys mismatch")
    for key, expected_role in _FIXED_BINDING_ROLES.items():
        if bindings[key] != expected_role or expected_role not in descriptors:
            _fail(f"required binding {key} is absent or misbound")
    evidence_role = bindings["evidence_corrected_baseline"]
    if evidence_role not in {None, ROLE_EVIDENCE_BASELINE_TEX}:
        _fail("evidence corrected baseline binding is invalid")
    if (evidence_role is None) != (ROLE_EVIDENCE_BASELINE_TEX not in descriptors):
        _fail("evidence corrected baseline descriptor/binding mismatch")
    correction_report_role = bindings.get("evidence_correction_report")
    if correction_report_role not in {None, ROLE_EVIDENCE_CORRECTION_REPORT}:
        _fail("evidence correction report binding is invalid")
    if (correction_report_role is None) != (
        ROLE_EVIDENCE_CORRECTION_REPORT not in descriptors
    ):
        _fail("evidence correction report descriptor/binding mismatch")
    lane_routes_role = bindings.get("lane_routes")
    if lane_routes_role not in {None, ROLE_LANE_ROUTES}:
        _fail("lane routes binding is invalid")
    if (lane_routes_role is None) != (ROLE_LANE_ROUTES not in descriptors):
        _fail("lane routes descriptor/binding mismatch")
    page_evidence_bindings_role = bindings.get("page_evidence_bindings")
    if page_evidence_bindings_role not in {None, ROLE_PAGE_EVIDENCE_BINDINGS}:
        _fail("OCR page evidence bindings binding is invalid")
    if (page_evidence_bindings_role is None) != (
        ROLE_PAGE_EVIDENCE_BINDINGS not in descriptors
    ):
        _fail("OCR page evidence bindings descriptor/binding mismatch")
    if (lane_routes_role is None) != (page_evidence_bindings_role is None):
        _fail(
            "exact lane routes and OCR page evidence bindings must be present together"
        )
    block_inventory_role = bindings.get("block_inventory")
    if block_inventory_role not in {None, ROLE_BLOCK_INVENTORY}:
        _fail("OCR block inventory binding is invalid")
    if (block_inventory_role is None) != (
        ROLE_BLOCK_INVENTORY not in descriptors
    ):
        _fail("OCR block inventory descriptor/binding mismatch")
    page_map_role = bindings["page_map"]
    if status["compile_status"] == "COMPILED":
        if page_map_role != ROLE_PAGE_MAP or ROLE_PAGE_MAP not in descriptors:
            _fail("COMPILED requires a bound recomputable page map")
    elif page_map_role is not None or ROLE_PAGE_MAP in descriptors:
        _fail(f"{status['compile_status']} must not bind or claim a page map")

    snapshot_data = artifact_bytes[str(descriptors[ROLE_RUN_SNAPSHOT]["path"])]
    snapshot_value, snapshot = _parse_snapshot(snapshot_data)
    if snapshot.run_id != run_id:
        _fail("manifest run_id differs from the snapshot")
    source_data = artifact_bytes[str(descriptors[ROLE_SOURCE]["path"])]
    if _sha256(source_data) != snapshot.source_sha256:
        _fail("source artifact differs from the immutable snapshot")
    if snapshot.source_type == "pdf":
        if not source_data.startswith(b"%PDF-"):
            _fail("PDF source artifact lacks the PDF magic header")
        actual_source_pages = _actual_pdf_page_count(source_data, "PDF source artifact")
        if actual_source_pages != snapshot.source_total_pages:
            _fail("PDF source page count differs from the immutable snapshot")
    if expected_source_sha256 is not None:
        expected = str(expected_source_sha256).lower()
        if not _SHA256_RE.fullmatch(expected) or expected != snapshot.source_sha256:
            _fail("source artifact differs from the independently expected SHA-256")
    if block_inventory_role is not None:
        from .ocr_block_inventory import parse_ocr_block_inventory

        contract = snapshot.pipeline_contract
        snapshot_pages = (
            contract.get("page_strategies")
            if isinstance(contract, Mapping)
            else None
        )
        try:
            parse_ocr_block_inventory(
                artifact_bytes[str(descriptors[ROLE_BLOCK_INVENTORY]["path"])],
                expected_run_id=run_id,
                expected_source_sha256=snapshot.source_sha256,
                expected_selected_pages=snapshot.selected_pages,
                expected_snapshot_pages=snapshot_pages or None,
            )
        except (TypeError, ValueError) as exc:
            raise OcrBaselineManifestError(
                "OCR block inventory artifact is invalid or stale"
            ) from exc
    lane_routes = ()
    if lane_routes_role is not None:
        from .ocr_lane_routes import parse_lane_routes_artifact

        try:
            lane_routes = parse_lane_routes_artifact(
                artifact_bytes[str(descriptors[ROLE_LANE_ROUTES]["path"])],
                expected_run_id=run_id,
                expected_selected_pages=snapshot.selected_pages,
            )
        except (TypeError, ValueError) as exc:
            raise OcrBaselineManifestError(
                "lane routes artifact is invalid or stale"
            ) from exc
    page_evidence_bindings = ()
    if page_evidence_bindings_role is not None:
        from .ocr_page_evidence_bindings import (
            parse_ocr_page_evidence_bindings,
        )

        try:
            page_evidence_bindings = parse_ocr_page_evidence_bindings(
                artifact_bytes[
                    str(descriptors[ROLE_PAGE_EVIDENCE_BINDINGS]["path"])
                ],
                expected_run_id=run_id,
                expected_source_sha256=snapshot.source_sha256,
                expected_selected_pages=snapshot.selected_pages,
            )
        except (TypeError, ValueError) as exc:
            raise OcrBaselineManifestError(
                "OCR page evidence bindings artifact is invalid or stale"
            ) from exc
    source = _object(payload["source"], "source")
    _exact_keys(source, {"sha256", "page_count", "selected_pages"}, "source")
    if source != {
        "sha256": snapshot.source_sha256,
        "page_count": snapshot.source_total_pages,
        "selected_pages": list(snapshot.selected_pages),
    }:
        _fail("manifest source facts differ from the snapshot")

    records_data = artifact_bytes[str(descriptors[ROLE_PAGE_RECORDS]["path"])]
    records, recomputed_coverage = _parse_page_records(records_data, snapshot)
    runtime_records_data = artifact_bytes[
        str(descriptors[ROLE_RUNTIME_PAGE_RECORDS]["path"])
    ]
    runtime_records = _parse_runtime_page_records(runtime_records_data, snapshot)
    _bind_page_record_authorities(records, runtime_records)
    if page_evidence_bindings:
        from .ocr_lane_routes import OcrLaneOwner
        from .ocr_page_evidence_bindings import OcrPageTerminalMode

        if not (
            len(records)
            == len(runtime_records)
            == len(lane_routes)
            == len(page_evidence_bindings)
        ):
            _fail("page evidence bindings do not cover all page authorities")
        for coverage_record, runtime_record, route, binding in zip(
            records,
            runtime_records,
            lane_routes,
            page_evidence_bindings,
            strict=True,
        ):
            runtime_record_sha = _sha256(json.dumps(
                runtime_record.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"))
            if (
                binding.page_id != runtime_record.page_id
                or binding.source_page != runtime_record.source_page
                or binding.selected_index != runtime_record.task_index
                or binding.terminal_status != runtime_record.status.value
                or binding.runtime_record_sha256 != runtime_record_sha
                or binding.runtime_source_evidence_sha256
                != runtime_record.source_evidence_sha256
                or binding.runtime_raw_response_sha256
                != runtime_record.raw_response_sha256
                or binding.terminal_cleaned_tex_sha256
                != runtime_record.tex_sha256
            ):
                _fail("OCR page evidence binding differs from runtime page records")
            page_hashes = coverage_record.artifact_hashes
            expected_page_hashes = {
                "source.json": binding.page_evidence_source_sha256,
                "candidate.json": binding.page_evidence_candidate_sha256,
                "verification.json": binding.page_evidence_verification_sha256,
                "raw-response.json": binding.page_evidence_raw_response_sha256,
                "page.tex": binding.page_evidence_tex_sha256,
            }
            if dict(page_hashes) != expected_page_hashes:
                _fail("OCR page evidence file hashes differ from page coverage")
            expected_coverage_mode = (
                "VERIFIER"
                if binding.terminal_mode is OcrPageTerminalMode.VISUAL
                else binding.terminal_mode.value
            )
            if coverage_record.visual_mode.value != expected_coverage_mode:
                _fail("OCR page evidence terminal mode differs from page coverage")
            if route.candidate_sha256 != binding.initial_candidate_tex_sha256:
                _fail("lane route initial candidate hash is not independently bound")
            if route.owner is OcrLaneOwner.TERMINAL_VISUAL:
                if (
                    binding.terminal_mode is not OcrPageTerminalMode.VISUAL
                    or route.verifier_response_sha256
                    != binding.visual_verification_response_sha256
                ):
                    _fail(
                        "terminal visual lane lacks its exact verifier response binding"
                    )
            elif route.owner is OcrLaneOwner.TERMINAL_FULL_OCR:
                if (
                    binding.terminal_mode is OcrPageTerminalMode.VISUAL
                    or binding.visual_verification_response_sha256 is not None
                ):
                    _fail("terminal full OCR is misbound as a visual response")
            elif route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED:
                if binding.terminal_status != "NEEDS_REVIEW":
                    _fail("unresolved lane must bind a NEEDS_REVIEW page record")
            else:
                _fail("page evidence binding cannot attest a non-terminal lane")
    coverage = _object(payload["coverage"], "coverage")
    _exact_keys(coverage, set(recomputed_coverage), "coverage")
    if coverage != recomputed_coverage:
        _fail("coverage does not match recomputed page record counts")
    run_status, ocr_status = _derived_status(coverage, str(status["compile_status"]))
    if status["run_status"] != run_status or status["ocr_status"] != ocr_status:
        _fail("terminal statuses contradict page coverage/compile status")
    if run_status == "SUCCESS" and any(
        route.owner.value == "TERMINAL_UNRESOLVED" for route in lane_routes
    ):
        _fail("successful OCR manifest cannot bind an unresolved lane route")

    raw_data = artifact_bytes[str(descriptors[ROLE_RAW_OCR_TEX]["path"])]
    raw = _object(payload["raw_ocr"], "raw_ocr")
    _exact_keys(raw, {"sha256", "immutable"}, "raw_ocr")
    if raw != {"sha256": _sha256(raw_data), "immutable": True}:
        _fail("raw OCR immutable binding mismatch")
    raw_freeze_data = artifact_bytes[str(descriptors[ROLE_RAW_OCR_FREEZE]["path"])]
    _parse_raw_freeze(raw_freeze_data, snapshot, _sha256(raw_data), runtime_records)

    lineage = _object(payload["lineage"], "lineage")
    legacy_lineage_keys = {
        "raw_ocr_sha256",
        "syntax_baseline_sha256",
        "evidence_baseline_sha256",
        "baseline_tex_sha256",
    }
    if set(lineage) not in {
        frozenset(legacy_lineage_keys),
        frozenset(legacy_lineage_keys | {"evidence_correction_report_sha256"}),
    }:
        _fail("lineage keys mismatch")
    syntax_sha = str(descriptors[ROLE_SYNTAX_BASELINE_TEX]["sha256"])
    evidence_sha = str(descriptors[ROLE_EVIDENCE_BASELINE_TEX]["sha256"]) if evidence_role else None
    correction_report_sha = (
        str(descriptors[ROLE_EVIDENCE_CORRECTION_REPORT]["sha256"])
        if correction_report_role else None
    )
    baseline_sha = str(descriptors[ROLE_BASELINE_TEX]["sha256"])
    expected_lineage = {
        "raw_ocr_sha256": _sha256(raw_data),
        "syntax_baseline_sha256": syntax_sha,
        "evidence_baseline_sha256": evidence_sha,
        "baseline_tex_sha256": baseline_sha,
    }
    if correction_report_role:
        expected_lineage["evidence_correction_report_sha256"] = correction_report_sha
    if lineage != expected_lineage:
        _fail("raw/syntax/evidence/baseline lineage hashes are stale")
    decoded_tex: dict[str, str] = {}
    for role in (ROLE_RAW_OCR_TEX, ROLE_SYNTAX_BASELINE_TEX, ROLE_BASELINE_TEX):
        data = artifact_bytes[str(descriptors[role]["path"])]
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OcrBaselineManifestError(f"{role} must be UTF-8") from exc
        if not text.strip():
            _fail(f"{role} cannot be blank")
        decoded_tex[role] = text
    evidence_text: str | None = None
    if evidence_role:
        try:
            evidence_text = artifact_bytes[str(descriptors[evidence_role]["path"])].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OcrBaselineManifestError("evidence baseline must be UTF-8") from exc
        if not evidence_text.strip():
            _fail("evidence baseline cannot be blank")
    if correction_report_role:
        from .ocr_evidence_correction import (
            EvidenceCorrectionStatus,
            verify_evidence_correction_report_bytes,
        )

        try:
            correction_report = verify_evidence_correction_report_bytes(
                artifact_bytes[
                    str(descriptors[ROLE_EVIDENCE_CORRECTION_REPORT]["path"])
                ],
                raw_ocr_tex=decoded_tex[ROLE_RAW_OCR_TEX],
                syntax_baseline_tex=decoded_tex[ROLE_SYNTAX_BASELINE_TEX],
                evidence_tex=evidence_text,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OcrBaselineManifestError(
                "evidence correction report is invalid or stale"
            ) from exc
        if correction_report["status"] == EvidenceCorrectionStatus.FAILED.value:
            _fail("FAILED evidence correction report cannot select a baseline")

    compile_value = _object(payload["compile"], "compile")
    _validate_compile(
        compile_value,
        status=str(status["compile_status"]),
        descriptors=descriptors,
        artifact_bytes=artifact_bytes,
        bindings=bindings,
    )
    if status["compile_status"] == "COMPILED":
        pdf_role = bindings["baseline_pdf"]
        if pdf_role != ROLE_BASELINE_PDF:
            _fail("COMPILED page map lacks its bound baseline PDF")
        _verify_compiled_page_map(
            artifact_bytes[str(descriptors[ROLE_PAGE_MAP]["path"])],
            snapshot,
            raw_ocr_data=raw_data,
            baseline_pdf_data=artifact_bytes[str(descriptors[pdf_role]["path"])],
            claimed_pdf_page_count=int(compile_value["pdf_page_count"]),
        )

    performance = _parse_performance(
        artifact_bytes[str(descriptors[ROLE_PERFORMANCE]["path"])],
        run_id,
        coverage,
        runtime_records,
    )
    if payload["performance"] != performance:
        _fail("performance summary differs from its bound artifact")
    cost = _parse_cost(
        artifact_bytes[str(descriptors[ROLE_COST]["path"])], run_id, performance,
    )
    if payload["cost"] != cost:
        _fail("cost summary differs from its bound artifact")
    strategies = _object(payload["strategies"], "strategies")
    _exact_keys(
        strategies,
        {"born_digital_verified", "full_visual_ocr", "high_resolution_retry", "crop_review"},
        "strategies",
    )
    for key, value in strategies.items():
        _nonnegative_int(value, f"strategy {key}")
        if value > coverage["selected"]:
            _fail(f"strategy {key} exceeds selected pages")
    if strategies != _strategies_from_performance(performance):
        _fail("strategies differ from performance strategy_distribution")
    _parse_producer(payload["producer"], snapshot)
    _scan_public_metadata(
        {
            "created_at": payload["created_at"],
            "status": status,
            "artifacts": descriptors_raw,
            "bindings": bindings,
            "producer": payload["producer"],
        }
    )
    # Keep the validated snapshot object live until all comparisons above finish.
    del snapshot_value


def verify_ocr_baseline_manifest(
    manifest_bytes: bytes,
    artifacts: Mapping[str, bytes],
    *,
    expected_source_sha256: str | None = None,
) -> OcrBaselineManifest:
    """Recompute and validate a manifest against exact artifact bytes.

    Extra, missing, renamed, tampered, absolute-path, or non-canonical evidence
    fails closed.  ``expected_source_sha256`` is the optional independent trust
    anchor supplied by the importer rather than by the manifest itself.
    """
    value = _object(_load_json(manifest_bytes, "OCR baseline manifest"), "OCR baseline manifest")
    canonical = canonical_json_bytes(value)
    if bytes(manifest_bytes) != canonical:
        _fail("OCR baseline manifest is not in canonical JSON encoding")
    _verify_payload(value, artifacts, expected_source_sha256=expected_source_sha256)
    return OcrBaselineManifest(canonical)


def build_ocr_baseline_manifest(
    *,
    snapshot: ArtifactInput,
    source: ArtifactInput,
    raw_ocr: ArtifactInput,
    raw_freeze: ArtifactInput,
    syntax_baseline: ArtifactInput,
    baseline_tex: ArtifactInput,
    page_map: ArtifactInput | None,
    page_records: ArtifactInput,
    runtime_page_records: ArtifactInput,
    performance_metrics: ArtifactInput,
    cost_metrics: ArtifactInput,
    compile_passes: Sequence[CompilePassInput],
    compile_status: str,
    compile_engine: str,
    pdf_page_count: int,
    producer: Mapping[str, object],
    created_at: str,
    baseline_pdf: ArtifactInput | None = None,
    evidence_corrected_baseline: ArtifactInput | None = None,
    evidence_correction_report: ArtifactInput | None = None,
    lane_routes: ArtifactInput | None = None,
    page_evidence_bindings: ArtifactInput | None = None,
    block_inventory: ArtifactInput | None = None,
    strategies: Mapping[str, int] | None = None,
    fatal_error: str = "",
    error_lines: Sequence[Mapping[str, object]] = (),
    run_status: str | None = None,
    ocr_status: str | None = None,
) -> OcrBaselineManifestBundle:
    """Build, self-verify, and return a deterministic manifest byte bundle."""
    status = str(compile_status or "")
    if status not in COMPILE_STATUSES:
        _fail("compile_status is unsupported")
    required = {
        "snapshot": (snapshot, ROLE_RUN_SNAPSHOT),
        "source": (source, ROLE_SOURCE),
        "raw_ocr": (raw_ocr, ROLE_RAW_OCR_TEX),
        "raw_freeze": (raw_freeze, ROLE_RAW_OCR_FREEZE),
        "syntax_baseline": (syntax_baseline, ROLE_SYNTAX_BASELINE_TEX),
        "baseline_tex": (baseline_tex, ROLE_BASELINE_TEX),
        "page_records": (page_records, ROLE_PAGE_RECORDS),
        "runtime_page_records": (runtime_page_records, ROLE_RUNTIME_PAGE_RECORDS),
        "performance": (performance_metrics, ROLE_PERFORMANCE),
        "cost": (cost_metrics, ROLE_COST),
    }
    artifacts: list[ArtifactInput] = []
    for label, (artifact, expected_role) in required.items():
        if artifact.role != expected_role:
            _fail(f"{label} must use role {expected_role}")
        artifacts.append(artifact)
    if evidence_corrected_baseline is not None:
        if evidence_corrected_baseline.role != ROLE_EVIDENCE_BASELINE_TEX:
            _fail(f"evidence baseline must use role {ROLE_EVIDENCE_BASELINE_TEX}")
        artifacts.append(evidence_corrected_baseline)
    if evidence_correction_report is not None:
        if evidence_correction_report.role != ROLE_EVIDENCE_CORRECTION_REPORT:
            _fail(
                "evidence correction report must use role "
                f"{ROLE_EVIDENCE_CORRECTION_REPORT}"
            )
        artifacts.append(evidence_correction_report)
    if evidence_corrected_baseline is not None and evidence_correction_report is None:
        _fail("evidence baseline requires its hash-bound correction report")
    if lane_routes is not None:
        if lane_routes.role != ROLE_LANE_ROUTES:
            _fail(f"lane routes must use role {ROLE_LANE_ROUTES}")
        artifacts.append(lane_routes)
    if page_evidence_bindings is not None:
        if page_evidence_bindings.role != ROLE_PAGE_EVIDENCE_BINDINGS:
            _fail(
                "OCR page evidence bindings must use role "
                f"{ROLE_PAGE_EVIDENCE_BINDINGS}"
            )
        artifacts.append(page_evidence_bindings)
    if (lane_routes is None) != (page_evidence_bindings is None):
        _fail(
            "exact lane routes and OCR page evidence bindings must be supplied together"
        )
    if block_inventory is not None:
        if block_inventory.role != ROLE_BLOCK_INVENTORY:
            _fail(f"OCR block inventory must use role {ROLE_BLOCK_INVENTORY}")
        artifacts.append(block_inventory)
    if status == "COMPILED":
        if page_map is None or page_map.role != ROLE_PAGE_MAP:
            _fail(f"COMPILED requires role {ROLE_PAGE_MAP}")
        artifacts.append(page_map)
    elif page_map is not None:
        _fail(f"{status} cannot accept a page map")
    if status == "SOURCE_PREVIEW":
        if baseline_pdf is not None:
            _fail("SOURCE_PREVIEW cannot accept a baseline PDF")
    else:
        if baseline_pdf is None or baseline_pdf.role != ROLE_BASELINE_PDF:
            _fail(f"{status} requires role {ROLE_BASELINE_PDF}")
        artifacts.append(baseline_pdf)
    if not compile_passes:
        _fail("at least one compile pass is required")
    pass_inputs: list[ArtifactInput] = []
    compile_input_roles: list[list[str]] = []
    for index, compile_pass in enumerate(compile_passes, start=1):
        if not isinstance(compile_pass.exit_code, int) or isinstance(compile_pass.exit_code, bool):
            _fail("compile pass exit_code must be an integer")
        pass_inputs.append(ArtifactInput(
            role=f"COMPILE_LOG_PASS_{index:02d}",
            path=compile_pass.log_path,
            data=compile_pass.log_bytes,
        ))
        inventory = _compile_input_inventory(
            compile_pass.input_inventory,
            f"compile pass {index}.input_inventory",
        )
        input_files = _compile_input_files(
            compile_pass.input_files,
            f"compile pass {index}.input_files",
        )
        if bool(inventory) != bool(input_files):
            _fail(
                f"compile pass {index} measured inventory requires exact input bytes"
            )
        if len(inventory) != len(input_files):
            _fail(f"compile pass {index} input byte coverage differs from inventory")
        roles: list[str] = []
        for file_index, (inventory_item, input_file) in enumerate(
            zip(inventory, input_files, strict=True),
            start=1,
        ):
            input_path, input_data = input_file
            if (
                input_path != inventory_item["path"]
                or len(input_data) != inventory_item["bytes"]
                or _sha256(input_data) != inventory_item["sha256"]
            ):
                _fail(
                    f"compile pass {index} exact input bytes differ from inventory"
                )
            role = f"{_COMPILE_INPUT_ROLE_PREFIX}{index:02d}_{file_index:04d}"
            roles.append(role)
            pass_inputs.append(ArtifactInput(
                role=role,
                path=f"compile/inputs/pass-{index:02d}/{input_path}",
                data=input_data,
            ))
        compile_input_roles.append(roles)
    artifacts.extend(pass_inputs)

    descriptors: list[dict[str, object]] = []
    data_by_path: dict[str, bytes] = {}
    descriptor_by_role: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        descriptor, data = _artifact_descriptor(
            artifact,
            allow_empty=str(artifact.role).startswith(_COMPILE_INPUT_ROLE_PREFIX),
        )
        role = str(descriptor["role"])
        path = str(descriptor["path"])
        if role in descriptor_by_role or path in data_by_path:
            _fail("artifact roles and paths must be unique")
        descriptor_by_role[role] = descriptor
        data_by_path[path] = data
        descriptors.append(descriptor)
    descriptors.sort(key=lambda item: str(item["role"]))

    _snapshot_value, snapshot_object = _parse_snapshot(data_by_path[snapshot.path])
    records, coverage = _parse_page_records(data_by_path[page_records.path], snapshot_object)
    runtime_records = _parse_runtime_page_records(
        data_by_path[runtime_page_records.path], snapshot_object,
    )
    _bind_page_record_authorities(records, runtime_records)
    derived_run, derived_ocr = _derived_status(coverage, status)
    if run_status is not None and run_status != derived_run:
        _fail("requested run_status contradicts page/compile evidence")
    if ocr_status is not None and ocr_status != derived_ocr:
        _fail("requested ocr_status contradicts page evidence")
    perf = _parse_performance(
        data_by_path[performance_metrics.path],
        snapshot_object.run_id,
        coverage,
        runtime_records,
    )
    cost = _parse_cost(data_by_path[cost_metrics.path], snapshot_object.run_id, perf)
    producer_value = _parse_producer(dict(producer), snapshot_object)

    baseline_sha = str(descriptor_by_role[ROLE_BASELINE_TEX]["sha256"])
    pdf_sha = (
        str(descriptor_by_role[ROLE_BASELINE_PDF]["sha256"])
        if baseline_pdf is not None
        else None
    )
    compile_records: list[dict[str, object]] = []
    measured_compile_passes: list[bool] = []
    for index, compile_pass in enumerate(compile_passes, start=1):
        input_sha = compile_pass.input_tex_sha256 or baseline_sha
        if not _SHA256_RE.fullmatch(str(input_sha)):
            _fail(f"compile pass {index} input_tex_sha256 is invalid")
        if (
            compile_pass.output_pdf_sha256 is not None
            and not _SHA256_RE.fullmatch(str(compile_pass.output_pdf_sha256))
        ):
            _fail(f"compile pass {index} output_pdf_sha256 is invalid")
        output_sha = compile_pass.output_pdf_sha256
        if output_sha is None and index == len(compile_passes):
            output_sha = pdf_sha
        execution_evidence, measured = _compile_execution_evidence(
            command=compile_pass.command,
            command_history=compile_pass.command_history,
            compile_workdir=compile_pass.compile_workdir,
            input_inventory=compile_pass.input_inventory,
            compile_input_sha256=compile_pass.compile_input_sha256,
            input_tex_sha256=str(input_sha),
            label=f"compile pass {index}",
        )
        measured_compile_passes.append(measured)
        compile_records.append({
            "index": index,
            "exit_code": compile_pass.exit_code,
            "input_tex_sha256": input_sha,
            "log_role": f"COMPILE_LOG_PASS_{index:02d}",
            "output_pdf_sha256": output_sha,
            "input_artifact_roles": compile_input_roles[index - 1],
            **execution_evidence,
        })
    if any(measured_compile_passes) and not all(measured_compile_passes):
        _fail("measured compile execution evidence must cover every pass")
    evidence_role = ROLE_EVIDENCE_BASELINE_TEX if evidence_corrected_baseline else None
    selected_baseline = evidence_role or ROLE_SYNTAX_BASELINE_TEX
    bindings: dict[str, object] = {
        **_FIXED_BINDING_ROLES,
        "evidence_corrected_baseline": evidence_role,
        "evidence_correction_report": (
            ROLE_EVIDENCE_CORRECTION_REPORT if evidence_correction_report else None
        ),
        "lane_routes": ROLE_LANE_ROUTES if lane_routes else None,
        "page_evidence_bindings": (
            ROLE_PAGE_EVIDENCE_BINDINGS if page_evidence_bindings else None
        ),
        "block_inventory": ROLE_BLOCK_INVENTORY if block_inventory else None,
        "baseline_pdf": ROLE_BASELINE_PDF if baseline_pdf else None,
        "page_map": ROLE_PAGE_MAP if page_map else None,
        "compile_logs": [item["log_role"] for item in compile_records],
    }
    strategy_value = _strategies_from_performance(perf)
    if strategies is not None:
        claimed_strategies = dict(strategies)
        _exact_keys(claimed_strategies, set(strategy_value), "strategies")
        for key, value in claimed_strategies.items():
            _nonnegative_int(value, f"strategy {key}")
        if claimed_strategies != strategy_value:
            _fail("strategies differ from performance strategy_distribution")
    payload = {
        "schema_version": OCR_BASELINE_MANIFEST_SCHEMA,
        "manifest_kind": "OCR_ONLY",
        "run_id": snapshot_object.run_id,
        "created_at": _utc_timestamp(created_at, "created_at"),
        "status": {
            "run_status": derived_run,
            "ocr_status": derived_ocr,
            "compile_status": status,
        },
        "artifacts": descriptors,
        "bindings": bindings,
        "source": {
            "sha256": snapshot_object.source_sha256,
            "page_count": snapshot_object.source_total_pages,
            "selected_pages": list(snapshot_object.selected_pages),
        },
        "raw_ocr": {
            "sha256": str(descriptor_by_role[ROLE_RAW_OCR_TEX]["sha256"]),
            "immutable": True,
        },
        "lineage": {
            "raw_ocr_sha256": str(descriptor_by_role[ROLE_RAW_OCR_TEX]["sha256"]),
            "syntax_baseline_sha256": str(descriptor_by_role[ROLE_SYNTAX_BASELINE_TEX]["sha256"]),
            "evidence_baseline_sha256": (
                str(descriptor_by_role[ROLE_EVIDENCE_BASELINE_TEX]["sha256"])
                if evidence_role else None
            ),
            "baseline_tex_sha256": baseline_sha,
            **({
                "evidence_correction_report_sha256": str(
                    descriptor_by_role[ROLE_EVIDENCE_CORRECTION_REPORT]["sha256"]
                ),
            } if evidence_correction_report else {}),
        },
        "compile": {
            "engine": str(compile_engine or "").strip(),
            "input_tex_sha256": baseline_sha,
            "selected_baseline": selected_baseline,
            "successful_passes": _trailing_successes(compile_records),
            "passes": compile_records,
            "pdf_page_count": pdf_page_count,
            "fatal_error": str(fatal_error or ""),
            "error_lines": [dict(item) for item in error_lines],
        },
        "coverage": coverage,
        "strategies": strategy_value,
        "performance": perf,
        "cost": cost,
        "producer": producer_value,
    }
    manifest_bytes = canonical_json_bytes(payload)
    verified = verify_ocr_baseline_manifest(manifest_bytes, data_by_path)
    # Ensure raw freeze validation happened before the returned bundle becomes writable.
    del records, runtime_records
    return OcrBaselineManifestBundle(
        manifest=verified,
        artifacts=tuple(sorted(data_by_path.items())),
    )


__all__ = [
    "ArtifactInput",
    "CompilePassInput",
    "DEFAULT_MANIFEST_PATH",
    "OCR_BASELINE_MANIFEST_SCHEMA",
    "ROLE_BLOCK_INVENTORY",
    "ROLE_PAGE_EVIDENCE_BINDINGS",
    "OCR_COST_SCHEMA",
    "OCR_PAGE_MAP_SCHEMA",
    "OCR_PAGE_RECORDS_SCHEMA",
    "OCR_PERFORMANCE_SCHEMA",
    "OCR_PRODUCER_SCHEMA",
    "OCR_RUNTIME_PAGE_RECORDS_SCHEMA",
    "OcrBaselineManifest",
    "OcrBaselineManifestBundle",
    "OcrBaselineManifestError",
    "build_ocr_baseline_manifest",
    "canonical_json_bytes",
    "verify_ocr_baseline_manifest",
]

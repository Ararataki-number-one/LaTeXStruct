# -*- coding: utf-8 -*-
"""Freeze an existing pipeline result as an immutable v2 analysis run.

This module is intentionally an adapter, not another analysis pipeline.  It
does not call a model, compile LaTeX, reinterpret a missing check as a pass, or
mutate any source artifact.  Its only job is to bind already-produced bytes
and machine evidence to host-owned identities and commit a portable audit tree
with one same-volume rename.
"""

from __future__ import annotations

import difflib
import json
import math
import os
import re
import shutil
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from ..pricing import estimate_call_cost
from .analysis_budget import (
    ActualUsage,
    AnalysisBudget,
    BudgetClaim,
    BudgetUsage,
)
from .analysis_runtime import (
    AnalysisQualityRuntime,
    CandidateRecord,
    ConservationReport,
    IssueLedger,
    PatchApplication,
    decide_final_status,
)
from .analysis_orchestrator import PageAnalysisInput
from .analysis_inventory import (
    AnalysisInventoryBundle,
    AnalysisInventoryGate,
    InventoryStatus,
    build_analysis_inventory_bundle,
    build_host_inventory_authorizations,
    coerce_analysis_inventory_authorizations,
    coerce_analysis_native_source_blocks,
    evaluate_analysis_inventory_gate,
)
from .analysis_risk import (
    PageRiskPreflightInput,
    build_page_risk_admission,
    coerce_page_risk_admission,
)
from .analysis_schema import (
    ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT,
    ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS,
    ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
    AnalysisCacheKey,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CompileState,
    IndependentReviewPass,
    IssueProposal,
    IssueStatus,
    ModelBinding,
    PageMapEntry,
    PageRisk,
    PageRiskAdmission,
    PageRiskRouteClosure,
    PageRouteCallKey,
    PageRouteRecord,
    PageStatus,
    PageUnit,
    PerformanceTargetStatus,
    QualityVector,
    ReviewResult,
    Severity,
    TexAnchor,
    VerificationDecision,
    VerificationEvidence,
    canonical_json_bytes,
    sha256_bytes,
    sha256_text,
)
from .invariants import check_invariants


_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
_SHA256_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


@dataclass(frozen=True, slots=True)
class AnalysisRunArtifacts:
    """Exact artifacts already produced by the host pipeline.

    Empty bytes/text mean that the artifact does not exist.  The adapter keeps
    that absence explicit instead of manufacturing a preview, PDF, log, or
    verification result.
    """

    source_pdf: bytes = b""
    source_tex: str = ""
    raw_ocr_tex: str = ""
    baseline_tex: str = ""
    baseline_pdf: bytes = b""
    baseline_compile_log: str = ""
    current_tex: str = ""
    current_pdf: bytes = b""
    current_compile_log: str = ""
    verification: Mapping[str, Any] = field(default_factory=dict)
    decision_items: Sequence[Mapping[str, Any]] = ()
    report_md: str = ""
    rollback_history: Sequence[Mapping[str, Any]] = ()


@dataclass(frozen=True, slots=True)
class AnalysisRunArchiveResult:
    run_id: str
    run_directory: Path
    status: AnalysisFinalStatus
    verified: bool
    failures: tuple[str, ...]
    snapshot_sha256: str
    artifact_count: int
    sha256s_relative_path: str = "audit/SHA256SUMS"
    runtime_executed: bool = False
    best_candidate_id: str = ""
    candidate_count: int = 0
    rollback_count: int = 0
    review_pass_count: int = 0
    evidence_source: str = "missing-or-legacy"


@dataclass(frozen=True, slots=True)
class ProductionAnalysisArchiveEvidence:
    """Exact typed production evidence admitted by the archive boundary.

    This object is deliberately separate from the legacy ``verification``
    dictionary.  An authoritative snapshot may only be archived when the
    caller supplies the same production snapshot, deterministic risk
    admission inputs and result, exact page inputs, route closure, and the
    unhashed configuration whose digest is already bound into the snapshot.
    """

    snapshot: AnalysisRunSnapshot
    page_risk_admission: PageRiskAdmission
    page_inputs: tuple[PageAnalysisInput, ...]
    page_route_closure: PageRiskRouteClosure
    analysis_configuration: Mapping[str, object]
    analysis_configuration_sha256: str
    risk_preflight: tuple[PageRiskPreflightInput, ...]
    baseline_inventory: AnalysisInventoryBundle | None = None
    final_inventory: AnalysisInventoryBundle | None = None
    inventory_gate: AnalysisInventoryGate | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, AnalysisRunSnapshot):
            raise TypeError("production archive snapshot has an invalid type")
        if not isinstance(self.page_risk_admission, PageRiskAdmission):
            raise TypeError("production page-risk admission has an invalid type")
        page_inputs = tuple(self.page_inputs)
        if not page_inputs or any(
            not isinstance(item, PageAnalysisInput) for item in page_inputs
        ):
            raise TypeError("production page inputs must be typed and non-empty")
        risk_preflight = tuple(self.risk_preflight)
        if not risk_preflight or any(
            not isinstance(item, PageRiskPreflightInput)
            for item in risk_preflight
        ):
            raise TypeError("production risk preflight must be typed and non-empty")
        if not isinstance(self.page_route_closure, PageRiskRouteClosure):
            raise TypeError("production page-route closure has an invalid type")
        if not isinstance(self.analysis_configuration, Mapping):
            raise TypeError("production analysis configuration must be an object")
        digest = str(self.analysis_configuration_sha256 or "").lower()
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("production analysis configuration hash is invalid")
        inventories = (
            self.baseline_inventory,
            self.final_inventory,
            self.inventory_gate,
        )
        if any(item is not None for item in inventories) and not all(
            item is not None for item in inventories
        ):
            raise TypeError("production inventory evidence must be supplied as one closure")
        if self.baseline_inventory is not None and (
            not isinstance(self.baseline_inventory, AnalysisInventoryBundle)
            or not isinstance(self.final_inventory, AnalysisInventoryBundle)
            or not isinstance(self.inventory_gate, AnalysisInventoryGate)
        ):
            raise TypeError("production inventory evidence has an invalid type")
        if self.final_inventory is not None and (
            evaluate_analysis_inventory_gate(self.final_inventory).as_dict()
            != self.inventory_gate.as_dict()
        ):
            raise ValueError("production inventory gate differs from its final bundle")
        object.__setattr__(self, "page_inputs", page_inputs)
        object.__setattr__(self, "risk_preflight", risk_preflight)
        object.__setattr__(self, "analysis_configuration_sha256", digest)


class AnalysisArchiveError(ValueError):
    """The existing run cannot be frozen without violating audit integrity."""


class _ArchiveBuilder:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.roles: dict[str, str] = {}

    @staticmethod
    def _relative_path(value: str) -> str:
        raw = str(value or "").replace("\\", "/")
        path = PurePosixPath(raw)
        if (
            not raw
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(":" in part or "\x00" in part for part in path.parts)
        ):
            raise AnalysisArchiveError(f"unsafe archive path: {value!r}")
        return path.as_posix()

    def add_bytes(self, path: str, payload: bytes, *, role: str) -> None:
        relative = self._relative_path(path)
        if relative in self.files:
            raise AnalysisArchiveError(f"duplicate archive path: {relative}")
        self.files[relative] = bytes(payload)
        self.roles[relative] = str(role)

    def add_text(self, path: str, text: str, *, role: str) -> None:
        self.add_bytes(path, str(text).encode("utf-8"), role=role)

    def add_json(self, path: str, value: object, *, role: str) -> None:
        self.add_bytes(path, _pretty_json_bytes(value), role=role)

    def add_canonical_json(self, path: str, value: object, *, role: str) -> None:
        self.add_bytes(path, canonical_json_bytes(value), role=role)

    def add_local_sums(self, directory: str) -> None:
        prefix = self._relative_path(directory).rstrip("/") + "/"
        name = prefix + "SHA256SUMS"
        entries = {
            path[len(prefix):]: payload
            for path, payload in self.files.items()
            if path.startswith(prefix) and path != name
        }
        if not entries:
            raise AnalysisArchiveError(f"cannot hash an empty artifact directory: {directory}")
        content = "".join(
            f"{sha256_bytes(payload)}  {path}\n"
            for path, payload in sorted(entries.items())
        )
        self.add_text(name, content, role="DIRECTORY_SHA256SUMS")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return {"bytes": len(payload), "sha256": sha256_bytes(payload)}
    if isinstance(value, Path):
        # Host paths are never authoritative audit content.
        return value.name
    return value


def _pretty_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            _jsonable(value), ensure_ascii=False, indent=2, sort_keys=True, default=str
        )
        + "\n"
    ).encode("utf-8")


_PRODUCTION_ARCHIVE_FILES = {
    "audit/page_risk_admission.json",
    "audit/page_inputs.json",
    "audit/page_route_closure.json",
    "audit/analysis_configuration.json",
    "audit/risk_preflight.json",
}
_PAGE_INPUTS_SCHEMA = "latexstruct-production-page-inputs-archive-v2"
_RISK_PREFLIGHT_SCHEMA = "latexstruct-page-risk-preflight-archive-v2"
_ANALYSIS_CONFIGURATION_SCHEMA = (
    "latexstruct-production-analysis-configuration-archive-v2"
)


def _strict_json_value(value: object, *, label: str) -> Any:
    """Return a detached JSON-native value or reject non-canonical evidence."""

    try:
        return json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AnalysisArchiveError(f"{label} is not strict JSON evidence") from exc


def _risk_preflight_page_payload(value: PageRiskPreflightInput) -> dict[str, Any]:
    payload = _strict_json_value(asdict(value), label="page-risk preflight input")
    if not isinstance(payload, dict):  # pragma: no cover - dataclass root invariant
        raise AnalysisArchiveError("page-risk preflight input is not an object")
    return payload


def _risk_preflight_archive_payload(
    values: Sequence[PageRiskPreflightInput],
) -> dict[str, Any]:
    pages = [_risk_preflight_page_payload(item) for item in values]
    return {
        "schema": _RISK_PREFLIGHT_SCHEMA,
        "pages": pages,
        "risk_preflight_sha256": sha256_bytes(canonical_json_bytes(pages)),
    }


def _coerce_risk_preflight_archive(
    value: object,
) -> tuple[PageRiskPreflightInput, ...]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "pages",
        "risk_preflight_sha256",
    }:
        raise AnalysisArchiveError("archived risk preflight fields are not exact")
    if value.get("schema") != _RISK_PREFLIGHT_SCHEMA:
        raise AnalysisArchiveError("archived risk preflight schema is unsupported")
    pages = value.get("pages")
    if not isinstance(pages, list) or not pages:
        raise AnalysisArchiveError("archived risk preflight pages are missing")
    if value.get("risk_preflight_sha256") != sha256_bytes(
        canonical_json_bytes(pages)
    ):
        raise AnalysisArchiveError("archived risk preflight digest is forged")
    field_names = set(PageRiskPreflightInput.__dataclass_fields__)
    output: list[PageRiskPreflightInput] = []
    for raw in pages:
        if not isinstance(raw, Mapping) or set(raw) != field_names:
            raise AnalysisArchiveError("archived risk preflight page fields are not exact")
        item = dict(raw)
        for name in (
            "unresolved_region_hashes",
            "candidate_pdf_page_ids",
        ):
            source = item[name]
            if not isinstance(source, list):
                raise AnalysisArchiveError(
                    f"archived risk preflight {name} must be a list"
                )
            item[name] = tuple(source)
        for name in (
            "ocr_quality_issues",
            "host_quality_flags",
            "machine_visual_anomalies",
        ):
            source = item[name]
            if source is not None:
                if not isinstance(source, list):
                    raise AnalysisArchiveError(
                        f"archived risk preflight {name} must be a list or null"
                    )
                item[name] = tuple(source)
        checks = item["ocr_coverage_checks"]
        if checks is not None and not isinstance(checks, Mapping):
            raise AnalysisArchiveError(
                "archived risk preflight coverage checks are invalid"
            )
        try:
            output.append(PageRiskPreflightInput(**item))
        except (TypeError, ValueError) as exc:
            raise AnalysisArchiveError(
                "archived risk preflight page is invalid"
            ) from exc
    return tuple(output)


def _page_input_payload(value: PageAnalysisInput) -> dict[str, Any]:
    page_unit = _strict_json_value(
        _jsonable(value.page_unit), label="production PageUnit"
    )
    if not isinstance(page_unit, dict):  # pragma: no cover - dataclass root invariant
        raise AnalysisArchiveError("production PageUnit is not an object")
    source_page = bytes(value.source_pdf_page)
    candidate_ids = list(value.page_unit.candidate_pdf_page_ids)
    core = {
        "page_unit": page_unit,
        "source_pdf_page": {
            "bytes": len(source_page),
            "sha256": sha256_bytes(source_page),
        },
        "baseline_tex_region": value.baseline_tex_region,
        "baseline_tex_region_sha256": sha256_text(value.baseline_tex_region),
        "source_text_layer_sha256": sha256_text(value.page_unit.source_text_layer),
        "candidate_pdf_page_ids_sha256": sha256_bytes(
            canonical_json_bytes(candidate_ids)
        ),
    }
    return {
        **core,
        "page_input_sha256": sha256_bytes(canonical_json_bytes(core)),
    }


def _page_inputs_archive_payload(
    values: Sequence[PageAnalysisInput],
) -> dict[str, Any]:
    pages = [_page_input_payload(item) for item in values]
    return {
        "schema": _PAGE_INPUTS_SCHEMA,
        "pages": pages,
        "page_inputs_sha256": sha256_bytes(canonical_json_bytes(pages)),
    }


def _analysis_configuration_archive_payload(
    configuration: Mapping[str, object],
    claimed_sha256: str,
) -> dict[str, Any]:
    canonical = _strict_json_value(
        configuration, label="production analysis configuration"
    )
    if not isinstance(canonical, dict):
        raise AnalysisArchiveError("production analysis configuration is not an object")
    digest = sha256_bytes(canonical_json_bytes(canonical))
    if claimed_sha256 != digest:
        raise AnalysisArchiveError("production analysis configuration hash is forged")
    return {
        "schema": _ANALYSIS_CONFIGURATION_SCHEMA,
        "analysis_configuration": canonical,
        "analysis_configuration_sha256": digest,
    }


def _coerce_page_route_closure(value: object) -> PageRiskRouteClosure:
    if isinstance(value, PageRiskRouteClosure):
        return value
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "admission_sha256",
        "final_candidate_hash",
        "pages",
        "pages_sha256",
        "risk_counts",
        "route_call_keys",
        "route_call_keys_sha256",
        "closure_sha256",
    }:
        raise AnalysisArchiveError("archived page-route closure fields are not exact")
    raw_pages = value.get("pages")
    raw_calls = value.get("route_call_keys")
    if not isinstance(raw_pages, list) or not isinstance(raw_calls, list):
        raise AnalysisArchiveError("archived page-route closure arrays are invalid")
    try:
        pages = tuple(
            PageRouteRecord(
                **{
                    **dict(item),
                    "anomaly_reasons": tuple(item["anomaly_reasons"]),
                }
            )
            for item in raw_pages
            if isinstance(item, Mapping)
        )
        calls = tuple(
            PageRouteCallKey(**dict(item))
            for item in raw_calls
            if isinstance(item, Mapping)
        )
        if len(pages) != len(raw_pages) or len(calls) != len(raw_calls):
            raise ValueError("route arrays contain non-object members")
        closure = PageRiskRouteClosure(
            schema_version=str(value["schema_version"]),
            admission_sha256=str(value["admission_sha256"]),
            final_candidate_hash=str(value["final_candidate_hash"]),
            pages=pages,
            route_call_keys=calls,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AnalysisArchiveError("archived page-route closure is invalid") from exc
    if closure.to_dict() != dict(value):
        raise AnalysisArchiveError("archived page-route closure derivations are forged")
    return closure


def _validate_page_input_archive(
    value: object,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "pages",
        "page_inputs_sha256",
    }:
        raise AnalysisArchiveError("archived production page-input fields are not exact")
    if value.get("schema") != _PAGE_INPUTS_SCHEMA:
        raise AnalysisArchiveError("archived production page-input schema is unsupported")
    pages = value.get("pages")
    if not isinstance(pages, list) or not pages:
        raise AnalysisArchiveError("archived production page inputs are missing")
    if value.get("page_inputs_sha256") != sha256_bytes(
        canonical_json_bytes(pages)
    ):
        raise AnalysisArchiveError("archived production page-input digest is forged")
    page_fields = {
        "page_unit",
        "source_pdf_page",
        "baseline_tex_region",
        "baseline_tex_region_sha256",
        "source_text_layer_sha256",
        "candidate_pdf_page_ids_sha256",
        "page_input_sha256",
    }
    unit_fields = set(PageUnit.__dataclass_fields__)
    validated: list[Mapping[str, Any]] = []
    for raw in pages:
        if not isinstance(raw, Mapping) or set(raw) != page_fields:
            raise AnalysisArchiveError("archived production page-input page is malformed")
        core = {key: raw[key] for key in page_fields if key != "page_input_sha256"}
        if raw["page_input_sha256"] != sha256_bytes(canonical_json_bytes(core)):
            raise AnalysisArchiveError("archived production page-input hash is forged")
        unit = raw["page_unit"]
        source_page = raw["source_pdf_page"]
        region = raw["baseline_tex_region"]
        if (
            not isinstance(unit, Mapping)
            or set(unit) != unit_fields
            or not isinstance(source_page, Mapping)
            or set(source_page) != {"bytes", "sha256"}
            or type(source_page["bytes"]) is not int
            or source_page["bytes"] < 1
            or re.fullmatch(r"[0-9a-f]{64}", str(source_page["sha256"] or ""))
            is None
            or not isinstance(region, str)
            or raw["baseline_tex_region_sha256"] != sha256_text(region)
            or unit.get("source_page_hash") != source_page["sha256"]
            or raw["source_text_layer_sha256"]
            != sha256_text(str(unit.get("source_text_layer", "")))
        ):
            raise AnalysisArchiveError("archived production page-input evidence is invalid")
        candidate_ids = unit.get("candidate_pdf_page_ids")
        if (
            not isinstance(candidate_ids, list)
            or raw["candidate_pdf_page_ids_sha256"]
            != sha256_bytes(canonical_json_bytes(candidate_ids))
        ):
            raise AnalysisArchiveError(
                "archived production candidate page-map hash is invalid"
            )
        validated.append(raw)
    return tuple(validated)


def _validate_production_archive_payloads(
    *,
    snapshot: Mapping[str, Any],
    page_risk_admission: PageRiskAdmission,
    page_inputs_archive: Mapping[str, Any],
    page_route_closure: PageRiskRouteClosure,
    analysis_configuration_archive: Mapping[str, Any],
    risk_preflight_archive: Mapping[str, Any],
    source_pdf_hash: str,
    baseline_tex_hash: str,
    baseline_pdf_hash: str,
    current_tex_hash: str,
) -> None:
    """Independently rederive all production-only archive bindings."""

    if not isinstance(snapshot, Mapping):
        raise AnalysisArchiveError("production archive snapshot is invalid")
    evidence_hashes = snapshot.get("evidence_hashes")
    page_map = snapshot.get("page_map")
    if not isinstance(evidence_hashes, Mapping) or not isinstance(page_map, list):
        raise AnalysisArchiveError("production snapshot lacks typed evidence or page map")
    if (
        snapshot.get("source_pdf_hash") != source_pdf_hash
        or snapshot.get("baseline_tex_hash") != baseline_tex_hash
        or snapshot.get("baseline_pdf_hash") != baseline_pdf_hash
        or page_risk_admission.source_pdf_sha256 != source_pdf_hash
        or page_risk_admission.baseline_tex_sha256 != baseline_tex_hash
        or page_risk_admission.baseline_pdf_sha256 != baseline_pdf_hash
        or evidence_hashes.get("ocr_page_records_hash")
        != page_risk_admission.ocr_page_records_sha256
        or evidence_hashes.get("page_risk_admission_hash")
        != page_risk_admission.digest
    ):
        raise AnalysisArchiveError("production page-risk admission is snapshot-stale")

    if not isinstance(analysis_configuration_archive, Mapping) or set(
        analysis_configuration_archive
    ) != {
        "schema",
        "analysis_configuration",
        "analysis_configuration_sha256",
    }:
        raise AnalysisArchiveError("production analysis configuration archive is malformed")
    if (
        analysis_configuration_archive.get("schema")
        != _ANALYSIS_CONFIGURATION_SCHEMA
    ):
        raise AnalysisArchiveError("production analysis configuration schema is unsupported")
    configuration = analysis_configuration_archive.get("analysis_configuration")
    if not isinstance(configuration, Mapping):
        raise AnalysisArchiveError("production analysis configuration is missing")
    configuration_sha256 = sha256_bytes(canonical_json_bytes(configuration))
    if (
        analysis_configuration_archive.get("analysis_configuration_sha256")
        != configuration_sha256
        or snapshot.get("config_hash") != configuration_sha256
        or evidence_hashes.get("analysis_config_hash") != configuration_sha256
    ):
        raise AnalysisArchiveError("production analysis configuration binding is forged")

    risk_preflight = _coerce_risk_preflight_archive(risk_preflight_archive)
    try:
        rebuilt_admission = build_page_risk_admission(
            source_pdf_sha256=page_risk_admission.source_pdf_sha256,
            ocr_page_records_sha256=page_risk_admission.ocr_page_records_sha256,
            ocr_runtime_page_records_sha256=(
                page_risk_admission.ocr_runtime_page_records_sha256
            ),
            baseline_tex_sha256=page_risk_admission.baseline_tex_sha256,
            baseline_pdf_sha256=page_risk_admission.baseline_pdf_sha256,
            page_inputs=risk_preflight,
        )
    except (TypeError, ValueError) as exc:
        raise AnalysisArchiveError(
            "production risk preflight cannot reproduce the admission"
        ) from exc
    if (
        rebuilt_admission.canonical_payload()
        != page_risk_admission.canonical_payload()
    ):
        raise AnalysisArchiveError(
            "production risk classification or low-risk sample is forged"
        )

    page_input_payloads = _validate_page_input_archive(page_inputs_archive)
    if not page_map or len(page_map) != len(risk_preflight) or len(page_map) != len(
        page_input_payloads
    ) or len(page_map) != len(page_risk_admission.pages):
        raise AnalysisArchiveError("production page evidence coverage is incomplete")
    admission_by_id = {
        item.summary.source_page_id: item for item in page_risk_admission.pages
    }
    preflight_by_id = {item.source_page_id: item for item in risk_preflight}
    input_by_id: dict[str, Mapping[str, Any]] = {}
    expected_ids: list[str] = []
    for entry in page_map:
        if not isinstance(entry, Mapping):
            raise AnalysisArchiveError("production snapshot page-map entry is invalid")
        page_id = str(entry.get("source_page_id") or "")
        page_number = entry.get("source_page_number")
        candidate_ids = entry.get("candidate_pdf_page_ids")
        if (
            not page_id
            or type(page_number) is not int
            or not isinstance(candidate_ids, list)
            or page_id in expected_ids
        ):
            raise AnalysisArchiveError("production snapshot page-map identity is invalid")
        expected_ids.append(page_id)
    for raw in page_input_payloads:
        unit = raw["page_unit"]
        page_id = str(unit.get("source_page_id") or "")
        if not page_id or page_id in input_by_id:
            raise AnalysisArchiveError("production page-input identity is duplicated")
        input_by_id[page_id] = raw
    if (
        list(admission_by_id) != expected_ids
        or list(preflight_by_id) != expected_ids
        or list(input_by_id) != expected_ids
    ):
        raise AnalysisArchiveError("production page identities or ordering differ")

    sampled_ids = set(
        page_risk_admission.low_risk_sampling.selected_page_ids
    )
    for entry in page_map:
        page_id = str(entry["source_page_id"])
        page_number = int(entry["source_page_number"])
        candidate_ids = list(entry["candidate_pdf_page_ids"])
        admitted = admission_by_id[page_id]
        preflight = preflight_by_id[page_id]
        archived_input = input_by_id[page_id]
        unit = archived_input["page_unit"]
        source_text = preflight.source_pdf_text or ""
        if (
            admitted.summary.source_page_number != page_number
            or preflight.source_page_number != page_number
            or unit.get("source_page_number") != page_number
            or tuple(candidate_ids) != tuple(preflight.candidate_pdf_page_ids)
            or candidate_ids != unit.get("candidate_pdf_page_ids")
            or admitted.summary.candidate_page_ids_hash
            != sha256_bytes(canonical_json_bytes(candidate_ids))
            or admitted.summary.source_page_object_hash
            != str(preflight.source_page_object_hash or "").lower()
            or admitted.summary.source_pdf_text_hash != sha256_text(source_text)
            or archived_input["baseline_tex_region"]
            != preflight.baseline_tex_region
            or admitted.summary.baseline_tex_region_hash
            != archived_input["baseline_tex_region_sha256"]
            or unit.get("baseline_tex_start_anchor")
            != entry.get("tex_page_marker")
            or unit.get("risk_level") != admitted.risk_level.value
            or unit.get("risk_reasons") != list(admitted.risk_reasons)
        ):
            raise AnalysisArchiveError(
                f"production page-input binding differs for {page_id}"
            )

    closure = page_route_closure
    if (
        closure.admission_sha256 != page_risk_admission.digest
        or closure.final_candidate_hash != current_tex_hash
        or len(closure.pages) != len(expected_ids)
    ):
        raise AnalysisArchiveError("production page-route closure is stale")
    closure_ids = [item.source_page_id for item in closure.pages]
    if closure_ids != expected_ids:
        raise AnalysisArchiveError("production page-route coverage is incomplete")
    for item in closure.pages:
        admitted = admission_by_id[item.source_page_id]
        if (
            item.source_page_number != admitted.summary.source_page_number
            or item.admitted_risk != admitted.risk_level
            or item.sampled_low_risk != (item.source_page_id in sampled_ids)
            or item.final_candidate_hash != current_tex_hash
        ):
            raise AnalysisArchiveError(
                f"production page-route risk/sample binding differs for {item.source_page_id}"
            )
    snapshot_hash = snapshot.get("snapshot_hash")
    for item in closure.route_call_keys:
        if (
            item.source_page_id not in admission_by_id
            or item.snapshot_hash != snapshot_hash
        ):
            raise AnalysisArchiveError("production page-route call identity is stale")


def _validated_typed_production_archive_evidence(
    *,
    evidence: ProductionAnalysisArchiveEvidence,
    authoritative_snapshot: AnalysisRunSnapshot,
    source_pdf_hash: str,
    baseline_tex_hash: str,
    baseline_pdf_hash: str,
    current_tex_hash: str,
) -> dict[str, Mapping[str, Any]]:
    if evidence.snapshot.to_dict() != authoritative_snapshot.to_dict():
        raise AnalysisArchiveError(
            "production archive evidence snapshot differs from the authority"
        )
    admission_payload = evidence.page_risk_admission.to_dict()
    page_inputs_payload = _page_inputs_archive_payload(evidence.page_inputs)
    route_payload = evidence.page_route_closure.to_dict()
    configuration_payload = _analysis_configuration_archive_payload(
        evidence.analysis_configuration,
        evidence.analysis_configuration_sha256,
    )
    risk_preflight_payload = _risk_preflight_archive_payload(
        evidence.risk_preflight
    )
    snapshot_payload = _strict_json_value(
        authoritative_snapshot.to_dict(), label="authoritative production snapshot"
    )
    if not isinstance(snapshot_payload, dict):  # pragma: no cover - typed root
        raise AnalysisArchiveError("authoritative production snapshot is not an object")
    _validate_production_archive_payloads(
        snapshot=snapshot_payload,
        page_risk_admission=evidence.page_risk_admission,
        page_inputs_archive=page_inputs_payload,
        page_route_closure=evidence.page_route_closure,
        analysis_configuration_archive=configuration_payload,
        risk_preflight_archive=risk_preflight_payload,
        source_pdf_hash=source_pdf_hash,
        baseline_tex_hash=baseline_tex_hash,
        baseline_pdf_hash=baseline_pdf_hash,
        current_tex_hash=current_tex_hash,
    )
    return {
        "page_risk_admission": admission_payload,
        "page_inputs": page_inputs_payload,
        "page_route_closure": route_payload,
        "analysis_configuration": configuration_payload,
        "risk_preflight": risk_preflight_payload,
    }


def stable_source_page_id(source_pdf_sha256: str, page_number: int) -> str:
    """Return the host-owned page identity used by generated v2 page maps."""

    digest = str(source_pdf_sha256 or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or int(page_number) < 1:
        raise ValueError("stable page identity requires a PDF hash and positive page")
    return f"src-{digest[:12]}-p{int(page_number):06d}"


def _inventory_source_page_map(
    page_entries: Sequence[PageMapEntry],
    production_evidence: ProductionAnalysisArchiveEvidence | None,
) -> Mapping[int, tuple[int, ...]]:
    if (
        production_evidence is not None
        and production_evidence.baseline_inventory is not None
    ):
        source_map = dict(production_evidence.baseline_inventory.source_page_map)
        if tuple(source_map) != tuple(
            item.source_page_number for item in page_entries
        ):
            raise AnalysisArchiveError(
                "production inventory page map differs from the snapshot"
            )
        return source_map

    parsed: dict[int, tuple[int, ...]] = {}
    all_numeric = True
    for entry in page_entries:
        pages: list[int] = []
        for page_id in entry.candidate_pdf_page_ids:
            match = re.fullmatch(r"candidate-page-([1-9][0-9]*)", page_id)
            if match is None:
                all_numeric = False
                break
            pages.append(int(match.group(1)))
        if not all_numeric:
            break
        parsed[entry.source_page_number] = tuple(pages)
    if all_numeric:
        return parsed

    # Legacy PageMapEntry ids were opaque.  Preserve their multiplicity and
    # ordering with a deterministic local numbering; they cannot claim to be
    # the native production inventory because no typed closure was supplied.
    fallback: dict[int, tuple[int, ...]] = {}
    cursor = 1
    for entry in page_entries:
        count = len(entry.candidate_pdf_page_ids)
        fallback[entry.source_page_number] = tuple(range(cursor, cursor + count))
        cursor += count
    return fallback


def _inventory_closure(
    *,
    baseline_tex: str,
    current_tex: str,
    page_entries: Sequence[PageMapEntry],
    production_evidence: ProductionAnalysisArchiveEvidence | None,
) -> tuple[AnalysisInventoryBundle, AnalysisInventoryBundle, AnalysisInventoryGate]:
    source_map = _inventory_source_page_map(page_entries, production_evidence)
    configuration = (
        production_evidence.analysis_configuration
        if production_evidence is not None else {}
    )
    if (
        production_evidence is not None
        and production_evidence.baseline_inventory is not None
    ):
        native_blocks = production_evidence.baseline_inventory.native_source_blocks
        native_blocks_supplied = (
            production_evidence.baseline_inventory.native_source_blocks_supplied
        )
        authorizations = production_evidence.baseline_inventory.authorizations
        require_native = (
            production_evidence.baseline_inventory.native_heading_inventory_required
        )
    else:
        raw_blocks = configuration.get("native_source_blocks", ())
        raw_authorizations = configuration.get("inventory_authorizations", ())
        if (
            not isinstance(raw_blocks, (list, tuple))
            or not isinstance(raw_authorizations, (list, tuple))
        ):
            raise AnalysisArchiveError(
                "production inventory configuration is malformed"
            )
        try:
            native_blocks = coerce_analysis_native_source_blocks(raw_blocks)
            authorizations = coerce_analysis_inventory_authorizations(
                raw_authorizations
            )
        except (TypeError, ValueError) as exc:
            raise AnalysisArchiveError(
                "production inventory configuration is invalid"
            ) from exc
        require_native = bool(
            configuration.get("native_heading_inventory_required", False)
        )
        raw_supplied = configuration.get(
            "native_source_blocks_supplied",
            "native_source_blocks" in configuration,
        )
        if type(raw_supplied) is not bool:
            raise AnalysisArchiveError(
                "production native inventory supplied flag is malformed"
            )
        native_blocks_supplied = raw_supplied
    authorization_source = configuration.get("inventory_authorization_source")
    if authorization_source is not None:
        if authorization_source not in {
            "HOST_REQUIRED_POLICY", "CALLER_FROZEN_HOST_POLICY"
        }:
            raise AnalysisArchiveError(
                "production inventory authorization source is invalid"
            )
        if authorization_source == "HOST_REQUIRED_POLICY":
            if configuration.get("inventory_policy_schema") != (
                "latexstruct-host-inventory-policy-v1"
            ):
                raise AnalysisArchiveError(
                    "production host inventory policy schema is invalid"
                )
            try:
                expected_authorizations = build_host_inventory_authorizations(
                    native_blocks,
                    ocr_manifest_sha256=str(configuration.get(
                        "inventory_policy_ocr_manifest_sha256", ""
                    )),
                    generated_toc_required=True,
                )
            except (TypeError, ValueError) as exc:
                raise AnalysisArchiveError(
                    "production host inventory policy binding is invalid"
                ) from exc
            if expected_authorizations != authorizations:
                raise AnalysisArchiveError(
                    "production host inventory authorizations are forged"
                )
    try:
        baseline = build_analysis_inventory_bundle(
            baseline_tex,
            baseline_tex,
            source_map,
            native_source_blocks=(native_blocks if native_blocks_supplied else None),
            authorizations=authorizations,
            require_native_heading_inventory=require_native,
        )
        final = build_analysis_inventory_bundle(
            baseline_tex,
            current_tex,
            source_map,
            native_source_blocks=(native_blocks if native_blocks_supplied else None),
            authorizations=authorizations,
            require_native_heading_inventory=require_native,
        )
    except (TypeError, ValueError) as exc:
        raise AnalysisArchiveError(
            f"analysis inventory cannot be rebuilt from archived artifacts: {exc}"
        ) from exc
    gate = evaluate_analysis_inventory_gate(final)
    baseline_hash = sha256_text(baseline_tex)
    current_hash = sha256_text(current_tex)
    if (
        baseline.baseline_tex_sha256 != baseline_hash
        or baseline.current_tex_sha256 != baseline_hash
        or final.baseline_tex_sha256 != baseline_hash
        or final.current_tex_sha256 != current_hash
    ):
        raise AnalysisArchiveError("analysis inventory TeX artifact binding is stale")

    if production_evidence is not None:
        configuration = production_evidence.analysis_configuration
        claimed_digest = configuration.get("baseline_inventory_digest")
        claimed_json_hash = configuration.get("baseline_inventory_json_sha256")
        baseline_json_hash = sha256_bytes(canonical_json_bytes(baseline.as_dict()))
        if (claimed_digest is not None or claimed_json_hash is not None) and (
            claimed_digest != baseline.digest
            or claimed_json_hash != baseline_json_hash
        ):
            raise AnalysisArchiveError(
                "production configuration inventory binding is forged"
            )
        if production_evidence.baseline_inventory is not None:
            supplied = (
                production_evidence.baseline_inventory,
                production_evidence.final_inventory,
                production_evidence.inventory_gate,
            )
            rebuilt = (baseline, final, gate)
            if any(
                canonical_json_bytes(left.as_dict())
                != canonical_json_bytes(right.as_dict())
                for left, right in zip(supplied, rebuilt)
            ):
                raise AnalysisArchiveError(
                    "production inventory evidence differs from archived TeX"
                )
    return baseline, final, gate


def _apply_inventory_decision_gate(
    decision: VerificationDecision,
    gate: AnalysisInventoryGate,
    *,
    processing_failed: bool,
) -> VerificationDecision:
    if gate.passed and gate.status is InventoryStatus.PASS:
        return decision
    scan_failed = gate.status is InventoryStatus.FAILED
    status = (
        AnalysisFinalStatus.FAILED_BEST_RETAINED
        if scan_failed
        or processing_failed
        or decision.status is AnalysisFinalStatus.FAILED_BEST_RETAINED
        else AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    reason = (
        "analysis_inventory_scan_failed"
        if scan_failed
        else "analysis_inventory_residual"
    )
    blockers = tuple(
        f"analysis_inventory_blocked:{category}"
        for category in gate.blocked_categories
    )
    return VerificationDecision(
        status=status,
        verified=False,
        failures=tuple(dict.fromkeys((*decision.failures, reason, *blockers))),
    )


def _coerce_models(values: Sequence[ModelBinding | Mapping[str, Any]]) -> tuple[ModelBinding, ...]:
    models = []
    for value in values:
        if isinstance(value, ModelBinding):
            models.append(value)
            continue
        item = dict(value)
        item["capabilities"] = tuple(item.get("capabilities", ()))
        models.append(ModelBinding(**item))
    if not models:
        raise AnalysisArchiveError("at least one real model binding is required")
    return tuple(models)


def _coerce_page_map(
    *,
    value: Sequence[PageMapEntry | Mapping[str, Any]] | None,
    source_pdf_hash: str,
    candidate_pdf_hash: str,
    page_range: tuple[int, ...],
) -> tuple[PageMapEntry, ...]:
    if value:
        entries = []
        for raw in value:
            if isinstance(raw, PageMapEntry):
                entries.append(raw)
                continue
            item = dict(raw)
            item["candidate_pdf_page_ids"] = tuple(item.get("candidate_pdf_page_ids", ()))
            entries.append(PageMapEntry(**item))
        return tuple(entries)
    candidate_root = candidate_pdf_hash[:12] if candidate_pdf_hash else "source-preview"
    return tuple(
        PageMapEntry(
            source_page_id=stable_source_page_id(source_pdf_hash, page),
            source_page_number=page,
            tex_page_marker=f"page:{page}",
            candidate_pdf_page_ids=(f"cand-{candidate_root}-p{index:06d}",),
        )
        for index, page in enumerate(page_range, 1)
    )


def _coerce_verification_evidence(
    value: VerificationEvidence | Mapping[str, Any] | None,
) -> VerificationEvidence | None:
    if value is None:
        return None
    if isinstance(value, VerificationEvidence):
        return value
    item = dict(value)
    try:
        item["expected_page_ids"] = tuple(item.get("expected_page_ids", ()))
        item["checked_page_ids"] = tuple(item.get("checked_page_ids", ()))
        reviews = []
        for review in item.get("final_reviews", ()):
            if isinstance(review, IndependentReviewPass):
                reviews.append(review)
            else:
                review_item = dict(review)
                review_item["checked_page_ids"] = tuple(
                    review_item.get("checked_page_ids", ())
                )
                reviews.append(IndependentReviewPass(**review_item))
        item["final_reviews"] = tuple(reviews)
        return VerificationEvidence(**item)
    except (KeyError, TypeError, ValueError):
        return None


def _line_anchor(text: str, line_number: int, candidate_id: str) -> TexAnchor | None:
    if line_number < 1:
        return None
    lines = text.splitlines(keepends=True)
    if line_number > len(lines):
        return None
    start = sum(len(item) for item in lines[: line_number - 1])
    line = lines[line_number - 1]
    body = line.rstrip("\r\n")
    end = start + len(body)
    seed = canonical_json_bytes({
        "candidate_id": candidate_id,
        "line": line_number,
        "start": start,
        "end": end,
        "text_hash": sha256_text(body),
    })
    return TexAnchor(
        anchor_id=f"anchor-{sha256_bytes(seed)[:16]}",
        start_offset=start,
        end_offset=end,
        text_hash=sha256_text(body),
    )


def _severity(value: object) -> Severity:
    raw = str(value or "MEDIUM").strip().upper()
    try:
        return Severity(raw)
    except ValueError:
        return Severity.MEDIUM


def _bind_decision_page(
    item: Mapping[str, Any], page_map: tuple[PageMapEntry, ...]
) -> str:
    by_id = {entry.source_page_id: entry.source_page_id for entry in page_map}
    by_number = {entry.source_page_number: entry.source_page_id for entry in page_map}
    explicit = str(item.get("source_page_id") or item.get("page_id") or "")
    if explicit in by_id:
        return explicit
    for key in ("source_page_number", "page_number", "pdf_page", "page"):
        try:
            number = int(item.get(key))
        except (TypeError, ValueError):
            continue
        if number in by_number:
            return by_number[number]
    return ""


def _ledger_from_decisions(
    *,
    decision_items: Sequence[Mapping[str, Any]],
    page_map: tuple[PageMapEntry, ...],
    baseline_hash: str,
    candidate_hash: str,
    current_tex: str,
) -> tuple[IssueLedger, list[dict[str, Any]]]:
    ledger = IssueLedger()
    unbound: list[dict[str, Any]] = []
    desired: dict[str, tuple[str, str]] = {}
    priority = {"REJECTED": 0, "FIXED": 1, "OPEN": 2, "BLOCKED": 3}
    for index, raw in enumerate(decision_items):
        item = dict(raw)
        candidate_id = str(item.get("candidate_id") or f"decision-{index + 1}")
        page_id = _bind_decision_page(item, page_map)
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        anchor = _line_anchor(current_tex, line, candidate_id)
        if not page_id or anchor is None:
            unbound.append({
                "candidate_id": candidate_id,
                "reason": "missing stable page binding or exact TeX line anchor",
                "record_sha256": sha256_bytes(canonical_json_bytes(_jsonable(item))),
            })
            continue
        status = str(item.get("status") or "ambiguous").strip().casefold()
        description = str(item.get("reason") or item.get("title") or candidate_id)
        proposal = IssueProposal(
            issue_type=str(item.get("kind") or item.get("issue_type") or "STRUCTURE_DECISION"),
            severity=_severity(item.get("severity")),
            source_page_ids=(page_id,),
            tex_anchors=(anchor,),
            detector_role=str(item.get("source") or "pipeline"),
            evidence_hashes=(sha256_bytes(canonical_json_bytes(_jsonable(item))),),
            baseline_hash=baseline_hash,
            candidate_hash=candidate_hash,
            description=description,
            blocker_reason=description if status in {"ambiguous", "rejected"} else "",
        )
        record = ledger.upsert(proposal, round_index=0)
        if status == "applied":
            target = "FIXED"
        elif status in {"preserved", "none", "rejected_false_positive"}:
            target = "REJECTED"
        elif status == "rejected":
            target = "BLOCKED"
        else:
            target = "OPEN"
        previous = desired.get(record.issue_id)
        if previous is None or priority[target] > priority[previous[0]]:
            desired[record.issue_id] = (target, description)

    for issue_id, (target, reason) in desired.items():
        if target == "FIXED":
            ledger.transition(
                issue_id, IssueStatus.FIXING, round_index=1, patch_id=f"PATCH-{issue_id[4:]}"
            )
            ledger.transition(
                issue_id,
                IssueStatus.FIXED_PENDING_REVIEW,
                round_index=1,
                candidate_hash=candidate_hash,
            )
        elif target == "BLOCKED":
            ledger.transition(
                issue_id, IssueStatus.BLOCKED, round_index=1, blocker_reason=reason
            )
        elif target == "REJECTED":
            ledger.transition(issue_id, IssueStatus.REJECTED_FALSE_POSITIVE, round_index=1)
    return ledger, unbound


def _compile_state(pdf: bytes, verification_record: object) -> CompileState:
    record = verification_record if isinstance(verification_record, Mapping) else {}
    if pdf and record.get("ok") is True:
        return CompileState.COMPILED
    if pdf:
        return CompileState.PARTIAL_COMPILED
    return CompileState.SOURCE_PREVIEW


def _quality_payload(
    quality: QualityVector | Mapping[str, Any] | None,
    *,
    current_pdf: bytes,
    verification: Mapping[str, Any],
    ledger: IssueLedger,
) -> tuple[QualityVector, dict[str, Any]]:
    if isinstance(quality, QualityVector):
        vector = quality
        complete = True
        unknown: list[str] = []
    elif isinstance(quality, Mapping):
        vector = QualityVector(**dict(quality))
        complete = True
        unknown = []
    else:
        compile_after = verification.get("compile_after")
        compile_ok = bool(
            current_pdf
            and isinstance(compile_after, Mapping)
            and compile_after.get("ok") is True
        )
        counts = ledger.counts()
        formal = verification.get("final_formal_inventory")
        formal_errors = 0
        if isinstance(formal, Mapping):
            findings = formal.get("findings")
            formal_errors = len(findings) if isinstance(findings, list) else 0
        vector = QualityVector(
            fully_compiled=compile_ok,
            open_critical=sum(
                record.current_status not in {
                    IssueStatus.VERIFIED_CLOSED,
                    IssueStatus.REJECTED_FALSE_POSITIVE,
                }
                and record.severity == Severity.CRITICAL
                for record in ledger.records
            ),
            open_high=sum(
                record.current_status not in {
                    IssueStatus.VERIFIED_CLOSED,
                    IssueStatus.REJECTED_FALSE_POSITIVE,
                }
                and record.severity == Severity.HIGH
                for record in ledger.records
            ),
            formal_errors=formal_errors,
        )
        complete = False
        unknown = [
            "silent_page_omissions",
            "silent_text_losses",
            "unauthorized_math_changes",
            "structure_reference_errors",
            "footnote_figure_equation_errors",
            "severe_visual_errors",
            "ordinary_layout_errors",
        ]
        if counts.get(IssueStatus.BLOCKED.value, 0):
            unknown.append("blocked_issue_impact")
    return vector, {
        "schema": "latexstruct-analysis-quality-vector-v2",
        "evidence_complete": complete,
        "unknown_fields": unknown,
        "vector": _jsonable(vector),
        "priority_key": list(vector.priority_key),
    }


def _successful_compile_passes(record: object) -> int:
    """Read an explicit successful-pass count; never infer it from ``ok``."""

    if not isinstance(record, Mapping) or record.get("ok") is not True:
        return 0
    for key in ("successful_passes", "passes_completed"):
        try:
            value = int(record.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            return value
    return 0


def _formal_error_count(record: object) -> int:
    if not isinstance(record, Mapping):
        return 1
    findings = record.get("findings")
    if not isinstance(findings, list):
        return 1
    return sum(
        str(item.get("kind") or "") in {"missing", "wrong-env", "overwide", "duplicate"}
        for item in findings
        if isinstance(item, Mapping)
    )


def _coerce_review_passes(
    value: object,
    *,
    page_map: tuple[PageMapEntry, ...],
) -> list[IndependentReviewPass]:
    """Accept only explicit, hash-bound review records from the host pipeline."""

    if not isinstance(value, (list, tuple)):
        return []
    by_number = {entry.source_page_number: entry.source_page_id for entry in page_map}
    output: list[IndependentReviewPass] = []
    for raw in value:
        if isinstance(raw, IndependentReviewPass):
            output.append(raw)
            continue
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        checked = []
        for page in item.get("checked_page_ids", ()):
            text = str(page or "")
            if text:
                checked.append(text)
        if not checked:
            for page in item.get("checked_source_pages", ()):
                try:
                    page_id = by_number.get(int(page))
                except (TypeError, ValueError):
                    page_id = None
                if page_id:
                    checked.append(page_id)
        item["checked_page_ids"] = tuple(dict.fromkeys(checked))
        try:
            output.append(IndependentReviewPass(**item))
        except (KeyError, TypeError, ValueError):
            continue
    return output


def _visual_review_pass(
    verification: Mapping[str, Any],
    *,
    page_map: tuple[PageMapEntry, ...],
    candidate_hash: str,
    pass_number: int,
    content_ok: bool,
    math_ok: bool,
    formal_ok: bool,
) -> IndependentReviewPass | None:
    """Bind the last real page audit to the exact final candidate hash.

    This is at most one review context.  It never fabricates the second context
    required by :func:`decide_final_status`.
    """

    loop = verification.get("visual_quality_loop")
    if not isinstance(loop, Mapping):
        return None
    if (
        loop.get("checked") is not True
        or loop.get("ok") is not True
        or loop.get("invalid")
        or loop.get("unresolved")
    ):
        return None
    rounds = loop.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        return None
    final_round = rounds[-1]
    if not isinstance(final_round, Mapping):
        return None
    if str(final_round.get("tex_sha256") or "") != candidate_hash:
        return None
    audit = final_round.get("ai_audit")
    compile_record = final_round.get("compile")
    if not isinstance(audit, Mapping) or not isinstance(compile_record, Mapping):
        return None
    if (
        audit.get("checked") is not True
        or audit.get("ok") is not True
        or audit.get("invalid")
        or audit.get("unresolved")
        or audit.get("suggestions")
    ):
        return None
    by_number = {entry.source_page_number: entry.source_page_id for entry in page_map}
    checked = []
    pages = audit.get("pages")
    if isinstance(pages, list):
        for page in pages:
            if not isinstance(page, Mapping):
                continue
            try:
                page_id = by_number.get(int(page.get("source_page")))
            except (TypeError, ValueError):
                page_id = None
            if page_id:
                checked.append(page_id)
    expected = tuple(entry.source_page_id for entry in page_map)
    checked_ids = tuple(dict.fromkeys(checked))
    if set(checked_ids) != set(expected):
        return None
    context_payload = {
        "schema": audit.get("schema"),
        "alignment_sha256": audit.get("alignment_sha256"),
        "candidate_hash": candidate_hash,
        "checked_page_ids": checked_ids,
    }
    return IndependentReviewPass(
        pass_number=pass_number,
        context_id=f"visual-{sha256_bytes(canonical_json_bytes(context_payload))[:16]}",
        candidate_hash=candidate_hash,
        checked_page_ids=checked_ids,
        compile_passes=_successful_compile_passes(compile_record),
        content_conservation_ok=content_ok,
        math_conservation_ok=math_ok,
        formal_inventory_ok=formal_ok,
        visual_review_ok=True,
        new_high_risk_issues=0,
        prior_pass_conclusion_visible=False,
    )


def _host_verification_evidence(
    *,
    verification: Mapping[str, Any],
    artifacts: AnalysisRunArtifacts,
    page_map: tuple[PageMapEntry, ...],
    candidate_hash: str,
    candidate_pdf: bytes,
    ledger: IssueLedger,
    pipeline_current: bool,
) -> VerificationEvidence:
    """Produce conservative v2 evidence from real legacy pipeline records."""

    expected = tuple(entry.source_page_id for entry in page_map)
    invariants = verification.get("invariants")
    invariants = invariants if isinstance(invariants, Mapping) else {}
    body = invariants.get("body_text")
    body = body if isinstance(body, Mapping) else {}
    math = invariants.get("math")
    math = math if isinstance(math, Mapping) else {}
    content_ok = bool(
        verification.get("content_invariant") is True
        and (body.get("equal") is True or body.get("checked") is not True)
    )
    math_ok = math.get("equal") is True
    formal_record = verification.get(
        "final_formal_inventory" if pipeline_current else "formal_inventory"
    )
    formal_errors = _formal_error_count(formal_record)
    formal_ok = formal_errors == 0
    compile_record = verification.get("compile_after" if pipeline_current else "compile_before")

    reviews = _coerce_review_passes(
        verification.get("v2_review_passes"), page_map=page_map
    ) if pipeline_current else []
    used_numbers = {item.pass_number for item in reviews}
    next_number = 1 if 1 not in used_numbers else 2 if 2 not in used_numbers else 0
    if pipeline_current and next_number:
        visual = _visual_review_pass(
            verification,
            page_map=page_map,
            candidate_hash=candidate_hash,
            pass_number=next_number,
            content_ok=content_ok,
            math_ok=math_ok,
            formal_ok=formal_ok,
        )
        if visual is not None and all(
            item.context_id != visual.context_id for item in reviews
        ):
            reviews.append(visual)
    reviews = sorted(reviews, key=lambda item: item.pass_number)
    fully_covered = bool(reviews) and all(
        set(item.checked_page_ids) == set(expected) for item in reviews
    )
    checked = expected if fully_covered else ()
    counts = ledger.counts()
    outline = verification.get("ocr_structure")
    outline = outline if isinstance(outline, Mapping) else {}
    display = verification.get("display_tags")
    display = display if isinstance(display, Mapping) else {}
    no_reference_loss = all(
        isinstance(invariants.get(name), Mapping)
        and invariants[name].get("equal") is True
        for name in ("labels", "refs", "cites")
    )
    raw_frozen = bool(
        artifacts.raw_ocr_tex
        and verification.get("raw_ocr_mutable") is not True
    )
    return VerificationEvidence(
        raw_ocr_frozen=raw_frozen,
        baseline_compile_passes=_successful_compile_passes(
            verification.get("compile_before")
        ),
        best_compile_passes=_successful_compile_passes(compile_record),
        best_pdf_openable=bool(candidate_pdf.startswith(b"%PDF-")),
        expected_page_ids=expected,
        checked_page_ids=checked,
        silent_page_omissions=0 if fully_covered else len(expected),
        silent_text_losses=0 if content_ok else 1,
        unauthorized_math_changes=0 if math_ok else 1,
        formal_errors=formal_errors,
        toc_complete_and_ordered=bool(
            outline.get("checked") is True and outline.get("ok") is True
        ),
        severe_equation_number_errors=0 if display.get("ok") is True else 1,
        silent_footnote_losses=0 if content_ok and fully_covered else 1,
        silent_figure_caption_losses=0 if content_ok and fully_covered else 1,
        silent_bibliography_losses=0 if content_ok and no_reference_loss else 1,
        open_critical=sum(
            record.current_status not in {
                IssueStatus.VERIFIED_CLOSED,
                IssueStatus.REJECTED_FALSE_POSITIVE,
            }
            and record.severity == Severity.CRITICAL
            for record in ledger.records
        ),
        open_high=sum(
            record.current_status not in {
                IssueStatus.VERIFIED_CLOSED,
                IssueStatus.REJECTED_FALSE_POSITIVE,
            }
            and record.severity == Severity.HIGH
            for record in ledger.records
        ),
        regressions=counts.get(IssueStatus.REGRESSION.value, 0),
        candidate_hash=candidate_hash,
        current_candidate_hash=candidate_hash,
        final_reviews=tuple(reviews),
    )


def _evidence_quality(evidence: VerificationEvidence) -> QualityVector:
    return QualityVector(
        fully_compiled=bool(
            evidence.best_compile_passes >= 2 and evidence.best_pdf_openable
        ),
        silent_page_omissions=evidence.silent_page_omissions,
        silent_text_losses=evidence.silent_text_losses,
        unauthorized_math_changes=evidence.unauthorized_math_changes,
        open_critical=evidence.open_critical,
        open_high=evidence.open_high,
        formal_errors=evidence.formal_errors,
        structure_reference_errors=evidence.silent_bibliography_losses,
        footnote_figure_equation_errors=(
            evidence.severe_equation_number_errors
            + evidence.silent_footnote_losses
            + evidence.silent_figure_caption_losses
        ),
        severe_visual_errors=0 if evidence.checked_page_ids else 1,
    )


def _reviews_close_fixed_issues(evidence: VerificationEvidence) -> bool:
    reviews = sorted(evidence.final_reviews, key=lambda item: item.pass_number)
    return bool(
        len(reviews) == 2
        and [item.pass_number for item in reviews] == [1, 2]
        and len({item.context_id for item in reviews}) == 2
        and all(
            item.candidate_hash == evidence.candidate_hash
            and set(item.checked_page_ids) == set(evidence.expected_page_ids)
            and item.compile_passes >= 2
            and item.content_conservation_ok
            and item.math_conservation_ok
            and item.formal_inventory_ok
            and item.visual_review_ok
            and item.new_high_risk_issues == 0
            and not item.prior_pass_conclusion_visible
            for item in reviews
        )
    )


def _derive_final_decision(
    *,
    evidence: VerificationEvidence | None,
    page_map: tuple[PageMapEntry, ...],
    current_tex_hash: str,
    artifacts: AnalysisRunArtifacts,
    processing_failed: bool,
    unbound_decisions: Sequence[Mapping[str, Any]],
    runtime: AnalysisQualityRuntime | None = None,
) -> tuple[VerificationDecision, str]:
    missing = []
    if not artifacts.source_pdf:
        missing.append("source_pdf_missing")
    if not artifacts.raw_ocr_tex:
        missing.append("raw_ocr_tex_missing")
    if not artifacts.baseline_tex:
        missing.append("baseline_tex_missing")
    if not artifacts.baseline_pdf:
        missing.append("baseline_pdf_missing")
    if not artifacts.current_tex:
        missing.append("current_tex_missing")
    if not artifacts.current_pdf:
        missing.append("current_pdf_missing")
    if unbound_decisions:
        missing.append("decision_items_not_page_bound")
    if processing_failed:
        missing.append("processing_failed")

    if evidence is None:
        failures = tuple(dict.fromkeys(["v2_verification_evidence_missing", *missing]))
        status = (
            AnalysisFinalStatus.FAILED_BEST_RETAINED
            if processing_failed
            else AnalysisFinalStatus.COMPLETED_WITH_ISSUES
        )
        return VerificationDecision(status, False, failures), "missing-or-legacy"

    # Bind existing machine evidence to the exact bytes being archived.  Only
    # current_candidate_hash is host-updated; the machine's candidate_hash is
    # left untouched so stale evidence fails closed.
    bound = replace(evidence, current_candidate_hash=current_tex_hash)
    base = (
        runtime.final_decision(bound, processing_failed=processing_failed)
        if runtime is not None
        else decide_final_status(bound, processing_failed=processing_failed)
    )
    failures = list(base.failures)
    expected = {entry.source_page_id for entry in page_map}
    if set(evidence.expected_page_ids) != expected:
        failures.append("snapshot_page_ids_mismatch")
    if evidence.candidate_hash != current_tex_hash:
        failures.append("candidate_hash_not_current_artifact")
    failures.extend(missing)
    failures = list(dict.fromkeys(failures))
    if failures:
        status = (
            AnalysisFinalStatus.FAILED_BEST_RETAINED
            if processing_failed
            else AnalysisFinalStatus.COMPLETED_WITH_ISSUES
        )
        return VerificationDecision(status, False, tuple(failures)), "v2-machine-evidence"
    return base, "v2-machine-evidence"


def _candidate_payloads(
    *,
    tex: str,
    pdf: bytes,
    compile_log: str,
    parent_hash: str,
    ledger: Mapping[str, Any],
    quality: Mapping[str, Any],
    review: Mapping[str, Any],
    diff: str,
    round_index: int,
    disposition: str,
) -> dict[str, bytes]:
    tex_hash = sha256_text(tex)
    payloads = {
        "candidate.tex": tex.encode("utf-8"),
        "compile.log": compile_log.encode("utf-8"),
        "patch.json": _pretty_json_bytes({
            "available": bool(diff),
            "parent_tex_sha256": parent_hash,
            "candidate_tex_sha256": tex_hash,
            "note": "captured from an existing pipeline result; no model was called by adapter",
        }),
        "candidate.diff": diff.encode("utf-8"),
        "issue_ledger.json": _pretty_json_bytes(ledger),
        "quality_vector.json": _pretty_json_bytes(quality),
        "review.json": _pretty_json_bytes(review),
        "candidate.json": _pretty_json_bytes({
            "schema": "latexstruct-analysis-candidate-v2",
            "round_index": round_index,
            "tex_sha256": tex_hash,
            "pdf_sha256": sha256_bytes(pdf) if pdf else "",
            "parent_tex_sha256": parent_hash,
            "disposition": disposition,
        }),
    }
    if pdf:
        payloads["candidate.pdf"] = bytes(pdf)
    return payloads


def _add_candidate_directory(
    builder: _ArchiveBuilder,
    directory: str,
    payloads: Mapping[str, bytes],
) -> None:
    for name, payload in payloads.items():
        builder.add_bytes(
            f"{directory}/{name}", payload, role=f"CANDIDATE_{name.upper()}"
        )
    builder.add_local_sums(directory)


def _performance_payload(
    value: Mapping[str, Any] | object | None,
    *,
    total_pages: int,
    decision: VerificationDecision,
) -> dict[str, Any]:
    page_count_eligible = total_pages == ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT
    if value is None:
        return {
            "schema": "latexstruct-analysis-performance-v2",
            "available": False,
            "total_pages": total_pages,
            "final_status": decision.status.value,
            "target_seconds": ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS,
            "benchmark_page_count": ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT,
            "benchmark_eligible": page_count_eligible,
            "target_status": PerformanceTargetStatus.NOT_EVALUATED.value,
            "target_evaluated": False,
            "target_met": None,
            "input_tokens": None,
            "output_tokens": None,
            "cached_tokens": None,
            "total_tokens": None,
            "usage_complete": False,
            "cache_status": "DISABLED",
            "cache_hits": 0,
            "cache_misses": 0,
            "estimated_cost_cny": None,
            "cost_status": "UNKNOWN",
            "missing": ["real_timing_and_model_usage_metrics"],
        }
    raw = _jsonable(value)
    if not isinstance(raw, dict):
        raw = {"recorded": raw}
    previous = raw.get("final_status")
    if previous and previous != decision.status.value:
        raw["recorded_final_status"] = previous
    raw["final_status"] = decision.status.value
    raw.setdefault("schema", "latexstruct-analysis-performance-v2")
    raw["available"] = raw.get("available") is True
    recorded_total_pages = raw.get("total_pages")
    if recorded_total_pages is not None and recorded_total_pages != total_pages:
        raw["recorded_total_pages"] = recorded_total_pages
    raw["total_pages"] = total_pages
    usage_complete = raw.get("usage_complete") is True
    token_fields = ("input_tokens", "output_tokens", "cached_tokens", "total_tokens")
    tokens_are_integers = not any(
        type(raw.get(field)) is not int or raw.get(field) < 0
        for field in token_fields
    )
    token_algebra_valid = bool(
        tokens_are_integers
        and raw.get("total_tokens")
        == raw.get("input_tokens") + raw.get("output_tokens")
        and raw.get("cached_tokens") <= raw.get("input_tokens")
    )
    if not usage_complete or not token_algebra_valid:
        invalid_reasons = []
        if usage_complete and tokens_are_integers:
            if raw.get("total_tokens") != (
                raw.get("input_tokens") + raw.get("output_tokens")
            ):
                invalid_reasons.append("total_tokens_mismatch")
            if raw.get("cached_tokens") > raw.get("input_tokens"):
                invalid_reasons.append("cached_tokens_exceed_input_tokens")
        elif usage_complete:
            invalid_reasons.append("token_counts_are_not_non_negative_integers")
        for field in token_fields:
            recorded = raw.get(field)
            if recorded is not None:
                raw.setdefault(f"recorded_{field}", recorded)
            raw[field] = None
        raw["usage_complete"] = False
        if invalid_reasons:
            raw["usage_validation_errors"] = invalid_reasons
    cache_status = str(raw.get("cache_status") or "DISABLED").strip().upper()
    if cache_status not in {"DISABLED", "ENABLED"}:
        raw["recorded_cache_status"] = raw.get("cache_status")
        cache_status = "DISABLED"
    raw["cache_status"] = cache_status
    if cache_status == "DISABLED":
        raw["cache_hits"] = 0
        raw["cache_misses"] = 0
    if (
        raw.get("usage_complete") is not True
        or raw.get("cost_status") != "ESTIMATED"
        or not isinstance(raw.get("estimated_cost_cny"), (int, float))
        or isinstance(raw.get("estimated_cost_cny"), bool)
        or not math.isfinite(float(raw.get("estimated_cost_cny") or 0.0))
        or raw.get("estimated_cost_cny") < 0
        or raw.get("billing_mode") == "chatgpt_subscription"
    ):
        recorded_cost = raw.get("estimated_cost_cny")
        if recorded_cost is not None:
            raw.setdefault("recorded_estimated_cost_cny", recorded_cost)
        raw["estimated_cost_cny"] = None
        raw["cost_status"] = "UNKNOWN"
    recorded_target_seconds = raw.get("target_seconds")
    raw.setdefault("target_seconds", ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS)
    raw["benchmark_page_count"] = ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT

    recorded_benchmark_eligible = raw.get("benchmark_eligible")
    benchmark_eligible = bool(
        page_count_eligible
        and recorded_target_seconds == ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS
    )
    raw["benchmark_eligible"] = benchmark_eligible
    recorded_target_met = raw.get("target_met")
    recorded_target_status = raw.get("target_status")
    checked_pages = raw.get("checked_pages")
    elapsed_seconds = raw.get("elapsed_seconds")
    elapsed_is_real = (
        isinstance(elapsed_seconds, (int, float))
        and not isinstance(elapsed_seconds, bool)
        and math.isfinite(elapsed_seconds)
        and elapsed_seconds > 0
    )
    measurement_complete = bool(
        raw["available"]
        and recorded_benchmark_eligible is True
        and benchmark_eligible
        and checked_pages == ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT
        and elapsed_is_real
    )
    if not measurement_complete:
        if recorded_target_met is not None:
            raw["recorded_target_met"] = recorded_target_met
        if recorded_target_status not in {None, PerformanceTargetStatus.NOT_EVALUATED.value}:
            raw["recorded_target_status"] = recorded_target_status
        raw["target_status"] = PerformanceTargetStatus.NOT_EVALUATED.value
        raw["target_evaluated"] = False
        raw["target_met"] = None
        return raw

    target_met = bool(
        elapsed_seconds <= ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS
        and decision.status in {
            AnalysisFinalStatus.VERIFIED,
            AnalysisFinalStatus.COMPLETED_WITH_ISSUES,
        }
    )
    computed_status = (
        PerformanceTargetStatus.PASSED.value
        if target_met
        else PerformanceTargetStatus.FAILED.value
    )
    if recorded_target_met is not None and recorded_target_met is not target_met:
        raw["recorded_target_met"] = recorded_target_met
    if recorded_target_status not in {None, computed_status}:
        raw["recorded_target_status"] = recorded_target_status
    raw["target_status"] = computed_status
    raw["target_evaluated"] = True
    raw["target_met"] = target_met
    return raw


def _material_hash_pairs(value: object) -> tuple[tuple[str, str], ...] | None:
    if isinstance(value, Mapping):
        items = tuple(sorted((str(key), str(item)) for key, item in value.items()))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        normalized = []
        for item in value:
            if (
                not isinstance(item, Sequence)
                or isinstance(item, (str, bytes))
                or len(item) != 2
            ):
                return None
            normalized.append((str(item[0]), str(item[1])))
        items = tuple(sorted(normalized))
    else:
        return None
    if not items or len({key for key, _value in items}) != len(items):
        return None
    if any(not re.fullmatch(r"[0-9a-f]{64}", digest) for _key, digest in items):
        return None
    return items


def _audit_usage_mapping(value: object) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    result: dict[str, Any] = {}
    for item in value:
        if (
            not isinstance(item, Sequence)
            or isinstance(item, (str, bytes))
            or len(item) != 2
            or not isinstance(item[0], str)
            or item[0] in result
        ):
            return None
        result[item[0]] = item[1]
    return result


def _audit_usage_value(
    usage: Mapping[str, Any],
    *names: str,
) -> tuple[int | None, bool, bool]:
    values = [usage[name] for name in names if name in usage]
    if not values:
        return None, False, True
    if any(type(value) is not int or value < 0 for value in values):
        return None, True, False
    if len(set(values)) != 1:
        return None, True, False
    return int(values[0]), True, True


def _audit_strict_usage(
    usage: Mapping[str, Any],
) -> tuple[dict[str, int | None], bool]:
    input_tokens, input_present, input_valid = _audit_usage_value(
        usage, "input_tokens", "prompt_tokens"
    )
    output_tokens, output_present, output_valid = _audit_usage_value(
        usage, "output_tokens", "completion_tokens"
    )
    cached_tokens, cached_present, cached_valid = _audit_usage_value(
        usage, "cached_input_tokens", "cached_tokens"
    )
    details = usage.get("prompt_tokens_details")
    if details is not None:
        if not isinstance(details, Mapping):
            cached_valid = False
        elif "cached_tokens" in details:
            nested, nested_present, nested_valid = _audit_usage_value(
                details, "cached_tokens"
            )
            cached_valid = cached_valid and nested_valid
            if nested_present:
                if cached_present and cached_tokens != nested:
                    cached_valid = False
                else:
                    cached_tokens = nested
                    cached_present = True
    total_tokens, total_present, total_valid = _audit_usage_value(
        usage, "total_tokens"
    )
    complete = bool(
        input_present
        and output_present
        and input_valid
        and output_valid
        and cached_valid
        and total_valid
    )
    cached_tokens = 0 if cached_tokens is None else cached_tokens
    if input_tokens is not None and cached_tokens > input_tokens:
        complete = False
    derived_total = (
        input_tokens + output_tokens
        if input_tokens is not None and output_tokens is not None
        else None
    )
    if total_present:
        if derived_total is None or total_tokens != derived_total:
            complete = False
    else:
        total_tokens = derived_total
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_tokens": cached_tokens if cached_valid else None,
        "total_tokens": total_tokens if total_valid else None,
    }, complete


_PRODUCTION_USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "total_tokens",
    "usage_complete",
    "observed_input_tokens",
    "observed_output_tokens",
    "observed_cached_tokens",
    "observed_total_tokens",
    "transport_call_count",
    "usage_observed_call_count",
    "usage_missing_call_count",
    "transport_attempt_count",
    "observed_transport_attempt_count",
    "usage_observed_attempt_count",
    "usage_missing_attempt_count",
    "attempt_evidence_complete",
    "cache_hits",
    "cache_misses",
    "cache_status",
    "estimated_cost_cny",
    "cost_status",
    "pricing_sources",
    "billing_mode",
    "role_call_counts",
)

_PRODUCTION_CACHE_CLOSURE_FIELDS = (
    "orchestration_invocation_count",
    "cache_hit_evidence_count",
)

_PRODUCTION_ATTEMPT_FAILURE_STAGES = frozenset(
    {
        "",
        "http_error",
        "invalid_json",
        "invalid_response_envelope",
        "missing_turn_evidence",
        "network_error",
        "runtime_failure_without_turn_evidence",
        "timeout",
        "turn_failed",
    }
)

_CACHE_ROLE_OPERATIONS = {
    "AI-1": "structure-findings",
    "AI-2": "content-math-findings",
    "AI-3": "visual-findings",
}
_CACHE_ELIGIBLE_OPERATIONS = frozenset(_CACHE_ROLE_OPERATIONS.values())


def _validate_performance_accounting(
    recorded: object,
    recomputed: Mapping[str, Any],
    *,
    label: str,
) -> None:
    if not isinstance(recorded, Mapping):
        raise AnalysisArchiveError(f"{label} performance accounting is missing")
    mismatches = [
        field
        for field in _PRODUCTION_USAGE_FIELDS
        if recorded.get(field) != recomputed.get(field)
    ]
    # Old immutable artifacts predate explicit cache-hit evidence.  Once a
    # producer records either closure counter, both become mandatory and are
    # recomputed from the archived invocation evidence rather than trusted.
    if any(field in recorded for field in _PRODUCTION_CACHE_CLOSURE_FIELDS):
        mismatches.extend(
            field
            for field in _PRODUCTION_CACHE_CLOSURE_FIELDS
            if recorded.get(field) != recomputed.get(field)
        )
    if mismatches:
        raise AnalysisArchiveError(
            f"{label} performance accounting differs from transport attempts: "
            + ",".join(mismatches)
        )


def _recompute_transport_accounting(
    *,
    transports: Sequence[Mapping[str, Any]],
    invocations: Sequence[Mapping[str, Any]],
    snapshot: Mapping[str, Any],
    cache_hits: Sequence[Mapping[str, Any]] = (),
    cache_enabled: bool = False,
) -> dict[str, Any]:
    observed_input = observed_output = observed_cached = observed_total = 0
    observed_attempts = complete_attempts = complete_calls = 0
    attempt_closure_complete = True
    normalized_attempts: list[tuple[str, dict[str, Any]]] = []
    billing_modes: set[str] = set()
    role_counts: Counter[str] = Counter(
        str(item.get("binding", {}).get("role") or "")
        for item in invocations
        if isinstance(item.get("binding"), Mapping)
    )

    for transport in transports:
        role = str(transport.get("role") or "")
        top_usage = _audit_usage_mapping(transport.get("usage"))
        attempts = transport.get("attempts")
        closure_flag = transport.get("attempt_evidence_complete")
        if top_usage is None or not isinstance(attempts, list) or type(closure_flag) is not bool:
            raise AnalysisArchiveError("production transport usage evidence is malformed")
        parsed_attempts: list[tuple[Mapping[str, Any], dict[str, Any]]] = []
        for expected_number, attempt in enumerate(attempts, 1):
            failure_stage = attempt.get("failure_stage") if isinstance(attempt, Mapping) else None
            if (
                not isinstance(attempt, Mapping)
                or type(attempt.get("attempt_number")) is not int
                or attempt.get("attempt_number") != expected_number
                or type(attempt.get("succeeded")) is not bool
                or type(attempt.get("usage_complete")) is not bool
                or not isinstance(failure_stage, str)
                or failure_stage not in _PRODUCTION_ATTEMPT_FAILURE_STAGES
                or (attempt.get("succeeded") is True and failure_stage != "")
                or (attempt.get("succeeded") is False and failure_stage == "")
            ):
                raise AnalysisArchiveError("production transport attempt is malformed")
            usage = _audit_usage_mapping(attempt.get("usage"))
            if usage is None:
                raise AnalysisArchiveError("production transport attempt usage is malformed")
            _normalized, strictly_complete = _audit_strict_usage(usage)
            if attempt.get("usage_complete") is True and not strictly_complete:
                raise AnalysisArchiveError("production transport attempt usage closure is forged")
            parsed_attempts.append((attempt, usage))
        computed_closure = bool(
            parsed_attempts
            and parsed_attempts[-1][0].get("succeeded") is True
            and not any(
                attempt.get("succeeded") is True for attempt, _usage in parsed_attempts[:-1]
            )
            and parsed_attempts[-1][1] == top_usage
        )
        if closure_flag is not computed_closure:
            raise AnalysisArchiveError("production transport attempt closure is stale or forged")
        call_complete = computed_closure
        if not call_complete:
            attempt_closure_complete = False

        observed_attempts += len(parsed_attempts)
        for attempt, usage in parsed_attempts:
            normalized, strictly_complete = _audit_strict_usage(usage)
            attempt_complete = bool(attempt.get("usage_complete") is True and strictly_complete)
            call_complete = call_complete and attempt_complete
            if attempt_complete:
                complete_attempts += 1
            input_tokens = normalized["input_tokens"]
            output_tokens = normalized["output_tokens"]
            cached_tokens = normalized["cached_tokens"]
            total_tokens = normalized["total_tokens"]
            if input_tokens is not None:
                observed_input += input_tokens
            if output_tokens is not None:
                observed_output += output_tokens
            if cached_tokens is not None:
                observed_cached += cached_tokens
            if total_tokens is not None:
                observed_total += total_tokens
            elif input_tokens is not None or output_tokens is not None:
                observed_total += (input_tokens or 0) + (output_tokens or 0)
            normalized_attempts.append((role, {**usage, **normalized}))
            billing_mode = str(usage.get("billing_mode") or "").strip()
            if billing_mode:
                billing_modes.add(billing_mode)
        if call_complete:
            complete_calls += 1

    expected_calls = len(invocations)
    transport_calls = len(transports)
    calls_succeeded = all(item.get("succeeded") is True for item in invocations)
    usage_complete = bool(
        expected_calls > 0
        and calls_succeeded
        and attempt_closure_complete
        and complete_calls == transport_calls
        and expected_calls == transport_calls + len(cache_hits)
    )
    input_total = observed_input if usage_complete else None
    output_total = observed_output if usage_complete else None
    cached_total = observed_cached if usage_complete else None
    total = observed_total if usage_complete else None

    model_ids = {
        str(item.get("role")): str(item.get("model_id") or "")
        for item in snapshot.get("models", [])
        if isinstance(item, Mapping)
    }
    cost_total = 0.0
    pricing_sources: set[str] = set()
    cost_complete = usage_complete
    for role, normalized_usage in normalized_attempts:
        if str(normalized_usage.get("billing_mode") or "").strip() == (
            "chatgpt_subscription"
        ):
            cost_complete = False
            continue
        estimate = estimate_call_cost(model_ids.get(role, ""), normalized_usage)
        if estimate is None:
            cost_complete = False
            continue
        cost_total += float(estimate["cny"])
        pricing_sources.add(str(estimate["source"]))

    billing_mode: str | None
    if len(billing_modes) == 1:
        billing_mode = next(iter(billing_modes))
    elif billing_modes:
        billing_mode = "MIXED"
    else:
        billing_mode = None
    missing_calls = max(
        transport_calls - complete_calls,
        expected_calls - len(cache_hits) - complete_calls,
        0,
    )
    cache_misses = (
        sum(
            str(item.get("operation") or "") in _CACHE_ELIGIBLE_OPERATIONS
            for item in transports
        )
        if cache_enabled
        else 0
    )
    return {
        "input_tokens": input_total,
        "output_tokens": output_total,
        "cached_tokens": cached_total,
        "total_tokens": total,
        "usage_complete": usage_complete,
        "observed_input_tokens": observed_input,
        "observed_output_tokens": observed_output,
        "observed_cached_tokens": observed_cached,
        "observed_total_tokens": observed_total,
        "orchestration_invocation_count": expected_calls,
        "transport_call_count": transport_calls,
        "usage_observed_call_count": complete_calls,
        "usage_missing_call_count": max(0, missing_calls),
        "transport_attempt_count": (
            observed_attempts if attempt_closure_complete else None
        ),
        "observed_transport_attempt_count": observed_attempts,
        "usage_observed_attempt_count": complete_attempts,
        "usage_missing_attempt_count": (
            max(0, observed_attempts - complete_attempts)
            if attempt_closure_complete else None
        ),
        "attempt_evidence_complete": attempt_closure_complete,
        "cache_hits": len(cache_hits) if cache_enabled else 0,
        "cache_misses": cache_misses,
        "cache_hit_evidence_count": len(cache_hits),
        "cache_status": "ENABLED" if cache_enabled else "DISABLED",
        "estimated_cost_cny": round(cost_total, 6) if cost_complete else None,
        "cost_status": "ESTIMATED" if cost_complete else "UNKNOWN",
        "pricing_sources": sorted(pricing_sources) if cost_complete else [],
        "billing_mode": billing_mode,
        "role_call_counts": [list(item) for item in sorted(role_counts.items())],
    }


_BUDGET_REPLAY_INTEGER_FIELDS = (
    "observed_input_tokens",
    "observed_output_tokens",
    "accounted_input_tokens",
    "accounted_output_tokens",
    "requests",
    "strong_model_calls",
    "unknown_input_token_requests",
    "unknown_output_token_requests",
    "unknown_cost_requests",
    "committed_reservations",
)
_BUDGET_REPLAY_FLOAT_FIELDS = ("observed_cost", "accounted_cost")


def _actual_usage_equal(left: ActualUsage, right: ActualUsage) -> bool:
    return (
        left.input_tokens == right.input_tokens
        and left.output_tokens == right.output_tokens
        and (
            left.cost is None
            and right.cost is None
            or (
                left.cost is not None
                and right.cost is not None
                and math.isclose(
                    left.cost,
                    right.cost,
                    rel_tol=1e-12,
                    abs_tol=1e-12,
                )
            )
        )
    )


def _closed_transport_actual_usage(
    transport: Mapping[str, Any],
    *,
    snapshot: Mapping[str, Any],
) -> ActualUsage:
    """Independently derive one closed transport settlement from every attempt."""

    attempts = transport.get("attempts")
    if transport.get("attempt_evidence_complete") is not True or not isinstance(
        attempts, list
    ):
        raise AnalysisArchiveError("production transport budget settlement is not closed")
    model_ids = {
        str(item.get("role")): str(item.get("model_id") or "")
        for item in snapshot.get("models", [])
        if isinstance(item, Mapping)
    }
    model_id = model_ids.get(str(transport.get("role") or ""), "")
    if not model_id:
        raise AnalysisArchiveError("production transport budget model binding is missing")

    input_values: list[int] = []
    output_values: list[int] = []
    cost_values: list[float] = []
    input_complete = output_complete = cost_complete = True
    for attempt in attempts:
        if not isinstance(attempt, Mapping):  # guarded by transport validation
            raise AnalysisArchiveError("production transport budget attempt is malformed")
        usage = _audit_usage_mapping(attempt.get("usage"))
        if usage is None:
            raise AnalysisArchiveError("production transport budget usage is malformed")
        normalized, strictly_complete = _audit_strict_usage(usage)
        input_tokens = normalized["input_tokens"]
        output_tokens = normalized["output_tokens"]
        if input_tokens is None:
            input_complete = False
        else:
            input_values.append(input_tokens)
        if output_tokens is None:
            output_complete = False
        else:
            output_values.append(output_tokens)
        if (
            not strictly_complete
            or str(usage.get("billing_mode") or "").strip()
            == "chatgpt_subscription"
        ):
            cost_complete = False
            continue
        estimate = estimate_call_cost(model_id, {**usage, **normalized})
        if estimate is None:
            cost_complete = False
        else:
            cost_values.append(float(estimate["cny"]))
    return ActualUsage(
        input_tokens=sum(input_values) if input_complete else None,
        output_tokens=sum(output_values) if output_complete else None,
        cost=sum(cost_values) if cost_complete else None,
    )


def _validate_production_budget_semantics(
    *,
    analysis_v2: Mapping[str, Any],
    transports: Sequence[Mapping[str, Any]],
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind terminal budget aggregates to strict per-transport settlements."""

    state_present = "budget_state" in analysis_v2
    usage_present = "budget_usage" in analysis_v2
    if not state_present and not usage_present:
        return {
            "budget_evidence_present": False,
            "budget_closure_complete": False,
            "budget_closure_failures": ["analysis_budget_evidence_missing"],
        }
    if state_present is not usage_present:
        raise AnalysisArchiveError("production budget state/usage evidence is incomplete")
    raw_state = analysis_v2.get("budget_state")
    raw_usage = analysis_v2.get("budget_usage")
    if not isinstance(raw_state, Mapping) or not isinstance(raw_usage, Mapping):
        raise AnalysisArchiveError("production budget state/usage evidence is malformed")
    try:
        budget = AnalysisBudget.from_dict(dict(raw_state), clock=lambda: 0.0)
        usage = BudgetUsage.from_dict(dict(raw_usage))
    except (TypeError, ValueError) as exc:
        raise AnalysisArchiveError("production budget state/usage evidence is malformed") from exc
    normalized_state = budget.to_dict()
    if dict(raw_state) != normalized_state or raw_state.get("usage") != dict(raw_usage):
        raise AnalysisArchiveError("production budget state and usage disagree")

    totals: dict[str, int | float] = {
        name: 0 for name in _BUDGET_REPLAY_INTEGER_FIELDS
    }
    totals.update({name: 0.0 for name in _BUDGET_REPLAY_FLOAT_FIELDS})
    expected_unbounded: set[str] = set()
    limits = budget.limits
    for transport in transports:
        raw_claim = transport.get("budget_claim")
        raw_actual = transport.get("budget_actual_usage")
        if not isinstance(raw_claim, Mapping) or not isinstance(raw_actual, Mapping):
            raise AnalysisArchiveError(
                "production transport budget claim/settlement evidence is missing"
            )
        try:
            claim = BudgetClaim.from_dict(dict(raw_claim))
            actual = ActualUsage.from_dict(dict(raw_actual))
        except (TypeError, ValueError) as exc:
            raise AnalysisArchiveError(
                "production transport budget claim/settlement evidence is malformed"
            ) from exc
        attempts = transport.get("attempts")
        if (
            not isinstance(attempts, list)
            or len(attempts) > claim.requests
            or claim.strong_model_calls
            != (claim.requests if transport.get("role") == "AI-6" else 0)
        ):
            raise AnalysisArchiveError(
                "production transport budget claim conflicts with attempt/role evidence"
            )
        if transport.get("attempt_evidence_complete") is True:
            expected_actual = _closed_transport_actual_usage(
                transport,
                snapshot=snapshot,
            )
            if not _actual_usage_equal(actual, expected_actual):
                raise AnalysisArchiveError(
                    "production transport budget settlement differs from attempt usage"
                )

        totals["requests"] += claim.requests
        totals["strong_model_calls"] += claim.strong_model_calls
        totals["committed_reservations"] += 1
        for dimension, observed_name, accounted_name, unknown_name, limit_name in (
            (
                "input_tokens",
                "observed_input_tokens",
                "accounted_input_tokens",
                "unknown_input_token_requests",
                "max_input_tokens",
            ),
            (
                "output_tokens",
                "observed_output_tokens",
                "accounted_output_tokens",
                "unknown_output_token_requests",
                "max_output_tokens",
            ),
            (
                "cost",
                "observed_cost",
                "accounted_cost",
                "unknown_cost_requests",
                "max_cost",
            ),
        ):
            actual_value = getattr(actual, dimension)
            if actual_value is None:
                claim_value = getattr(claim, dimension)
                totals[accounted_name] += claim_value
                totals[unknown_name] += claim.requests
                if claim_value == 0 and getattr(limits, limit_name) > 0:
                    expected_unbounded.add(dimension)
            else:
                totals[observed_name] += actual_value
                totals[accounted_name] += actual_value

    replayed = BudgetUsage(
        **totals,
        cancelled_reservations=0,
        wall_time_minutes=usage.wall_time_minutes,
    )
    if (
        usage.cancelled_reservations != 0
        or any(
            getattr(replayed, name) != getattr(usage, name)
            for name in _BUDGET_REPLAY_INTEGER_FIELDS
        )
        or any(
            not math.isclose(
                getattr(replayed, name),
                getattr(usage, name),
                rel_tol=1e-12,
                abs_tol=1e-12,
            )
            for name in _BUDGET_REPLAY_FLOAT_FIELDS
        )
    ):
        raise AnalysisArchiveError(
            "production budget usage does not close over transport settlements"
        )
    if set(normalized_state["unbounded_unknown_dimensions"]) != expected_unbounded:
        raise AnalysisArchiveError(
            "production budget uncertainty does not close over transport settlements"
        )

    failures: list[str] = []
    if normalized_state["reservations"]:
        failures.append("analysis_budget_reservations_not_terminal")
    if normalized_state["stop_reason"] is not None:
        failures.append("analysis_budget_stop_recorded")
    for usage_name, limit_name in (
        ("accounted_input_tokens", "max_input_tokens"),
        ("accounted_output_tokens", "max_output_tokens"),
        ("accounted_cost", "max_cost"),
        ("requests", "max_requests"),
        ("strong_model_calls", "max_strong_model_calls"),
        ("wall_time_minutes", "max_wall_time_minutes"),
    ):
        maximum = getattr(limits, limit_name)
        if maximum > 0 and getattr(usage, usage_name) > maximum:
            failures.append(f"analysis_budget_limit_exceeded:{usage_name}")
    return {
        "budget_evidence_present": True,
        "budget_closure_complete": not failures,
        "budget_closure_failures": failures,
        "budget_usage": usage.to_dict(),
    }


def _production_transport_closure_failures(
    accounting: Mapping[str, object],
) -> tuple[str, ...]:
    """Return stable reasons when provider-call accounting cannot prove closure."""

    failures: list[str] = []
    if accounting.get("usage_complete") is not True:
        failures.append("analysis_transport_usage_incomplete")
    if accounting.get("attempt_evidence_complete") is not True:
        failures.append("analysis_transport_attempt_evidence_incomplete")
    missing_calls = accounting.get("usage_missing_call_count")
    if type(missing_calls) is not int or missing_calls != 0:
        failures.append("analysis_transport_call_closure_incomplete")
    missing_attempts = accounting.get("usage_missing_attempt_count")
    if type(missing_attempts) is not int or missing_attempts != 0:
        failures.append("analysis_transport_attempt_usage_incomplete")
    transport_count = accounting.get("transport_call_count")
    attempt_count = accounting.get("transport_attempt_count")
    if (
        type(transport_count) is not int
        or transport_count < 1
        or type(attempt_count) is not int
        or attempt_count < transport_count
    ):
        failures.append("analysis_transport_count_closure_incomplete")
    budget_failures = accounting.get("budget_closure_failures")
    if accounting.get("budget_closure_complete") is not True:
        failures.append("analysis_budget_evidence_incomplete")
        if isinstance(budget_failures, list) and all(
            isinstance(item, str) for item in budget_failures
        ):
            failures.extend(budget_failures)
    return tuple(dict.fromkeys(failures))


def _apply_production_transport_closure(
    decision: VerificationDecision,
    accounting: Mapping[str, object],
) -> VerificationDecision:
    closure_failures = _production_transport_closure_failures(accounting)
    if not closure_failures:
        return decision
    status = (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
        if decision.status == AnalysisFinalStatus.VERIFIED
        else decision.status
    )
    return replace(
        decision,
        status=status,
        verified=False,
        failures=tuple(
            dict.fromkeys(
                (
                    *decision.failures,
                    "analysis_transport_evidence_incomplete",
                    *closure_failures,
                )
            )
        ),
    )


def _apply_production_authority_gate(
    decision: VerificationDecision,
    *,
    authoritative_snapshot_present: bool,
) -> VerificationDecision:
    """Never promote supplied/nested evidence without the host snapshot authority."""

    if authoritative_snapshot_present or not decision.verified:
        return decision
    return replace(
        decision,
        status=AnalysisFinalStatus.COMPLETED_WITH_ISSUES,
        verified=False,
        failures=tuple(
            dict.fromkeys(
                (*decision.failures, "analysis_production_authority_missing")
            )
        ),
    )


def _production_transport_identity(
    operation: object,
    value: Mapping[str, Any],
) -> tuple[object, ...] | None:
    material_hashes = _material_hash_pairs(value.get("material_hashes"))
    if material_hashes is None:
        return None
    fields = tuple(
        value.get(name)
        for name in (
            "role",
            "candidate_hash",
            "source_page_id",
            "issue_id",
            "snapshot_hash",
            "prompt_version",
            "response_schema_version",
        )
    )
    if any(not isinstance(item, str) or not item for item in fields):
        return None
    return (str(operation), *fields[:4], material_hashes, *fields[4:])


def _validate_cache_hit_evidence(
    value: Mapping[str, Any],
    *,
    snapshot: Mapping[str, Any],
) -> tuple[object, ...]:
    operation = value.get("operation")
    role = value.get("role")
    if (
        _CACHE_ROLE_OPERATIONS.get(str(role)) != operation
        or value.get("binding_echo_validated") is not True
    ):
        raise AnalysisArchiveError("production cache-hit role or validation is forged")
    identity = _production_transport_identity(operation, value)
    if identity is None:
        raise AnalysisArchiveError("production cache-hit identity is malformed")
    material_pairs = _material_hash_pairs(value.get("material_hashes"))
    if material_pairs is None:
        raise AnalysisArchiveError("production cache-hit materials are malformed")
    material_hashes = dict(material_pairs)
    required_materials = {
        "source_pdf_page_hash",
        "baseline_tex_region_hash",
        "current_tex_region_hash",
        "current_pdf_page_hash",
    }
    if set(material_hashes) != required_materials:
        raise AnalysisArchiveError("production cache-hit materials are incomplete")
    model_ids = {
        str(item.get("role")): str(item.get("model_id") or "")
        for item in snapshot.get("models", [])
        if isinstance(item, Mapping)
    }
    model_id = value.get("model_id")
    tool_version = value.get("tool_version")
    if (
        not isinstance(model_id, str)
        or not model_id
        or model_ids.get(str(role)) != model_id
        or not isinstance(tool_version, str)
        or tool_version != snapshot.get("application_version")
    ):
        raise AnalysisArchiveError("production cache-hit model or tool binding is stale")
    try:
        key = AnalysisCacheKey(
            snapshot_hash=str(value.get("snapshot_hash") or ""),
            source_page_id=str(value.get("source_page_id") or ""),
            source_page_hash=material_hashes["source_pdf_page_hash"],
            baseline_tex_region_hash=material_hashes[
                "baseline_tex_region_hash"
            ],
            current_tex_region_hash=material_hashes["current_tex_region_hash"],
            current_render_hash=material_hashes["current_pdf_page_hash"],
            prompt_version=str(value.get("prompt_version") or ""),
            response_schema_version=str(
                value.get("response_schema_version") or ""
            ),
            model_id=model_id,
            tool_version=tool_version,
            audit_role=f"{role}:{operation}",
        )
    except (TypeError, ValueError) as exc:
        raise AnalysisArchiveError("production cache-hit key is malformed") from exc
    if (
        value.get("cache_key_sha256") != key.digest
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("response_sha256") or ""))
        is None
    ):
        raise AnalysisArchiveError("production cache-hit digest is forged")
    return identity


def _validate_production_analysis_semantics(
    *,
    authoritative_snapshot: Mapping[str, Any],
    analysis_v2: object,
) -> dict[str, Any]:
    """Require a full snapshot/call closure, not merely matching file hashes."""

    if not isinstance(analysis_v2, Mapping):
        raise AnalysisArchiveError("production analysis_v2 evidence is missing")
    recorded_snapshot = analysis_v2.get("snapshot")
    if not isinstance(recorded_snapshot, Mapping) or dict(recorded_snapshot) != dict(
        authoritative_snapshot
    ):
        raise AnalysisArchiveError(
            "recorded production snapshot differs field-by-field from authority"
        )

    snapshot_hash = authoritative_snapshot.get("snapshot_hash")
    prompt_version = authoritative_snapshot.get("prompt_version")
    run_id = authoritative_snapshot.get("run_id")
    if not all(
        isinstance(value, str) and value
        for value in (snapshot_hash, prompt_version, run_id)
    ):
        raise AnalysisArchiveError("authoritative production snapshot is incomplete")

    transports = analysis_v2.get("transport_invocations")
    invocations = analysis_v2.get("invocations")
    cache_evidence_present = "cache_hit_evidence" in analysis_v2
    cache_hits = analysis_v2.get("cache_hit_evidence", [])
    if not isinstance(transports, list):
        raise AnalysisArchiveError("production transport evidence is malformed")
    if not isinstance(cache_hits, list):
        raise AnalysisArchiveError("production cache-hit evidence is malformed")
    if not transports and not cache_hits:
        raise AnalysisArchiveError(
            "production transport/cache evidence is empty"
            if cache_evidence_present
            else "production transport evidence is empty"
        )
    if not isinstance(invocations, list) or not invocations:
        raise AnalysisArchiveError("production orchestration invocation evidence is empty")

    transport_identities = []
    for item in transports:
        if not isinstance(item, Mapping):
            raise AnalysisArchiveError("production transport evidence is malformed")
        operation = item.get("operation")
        expected_schema = ANALYSIS_RESPONSE_SCHEMA_VERSIONS.get(str(operation))
        if (
            expected_schema is None
            or item.get("snapshot_hash") != snapshot_hash
            or item.get("prompt_version") != prompt_version
            or item.get("response_schema_version") != expected_schema
        ):
            raise AnalysisArchiveError(
                "production transport snapshot, prompt, or response schema binding is stale"
            )
        identity = _production_transport_identity(operation, item)
        if identity is None:
            raise AnalysisArchiveError("production transport identity is malformed")
        transport_identities.append(identity)

    cache_hit_identities = []
    for item in cache_hits:
        if not isinstance(item, Mapping):
            raise AnalysisArchiveError("production cache-hit evidence is malformed")
        operation = item.get("operation")
        expected_schema = ANALYSIS_RESPONSE_SCHEMA_VERSIONS.get(str(operation))
        if (
            expected_schema is None
            or item.get("snapshot_hash") != snapshot_hash
            or item.get("prompt_version") != prompt_version
            or item.get("response_schema_version") != expected_schema
        ):
            raise AnalysisArchiveError(
                "production cache-hit snapshot, prompt, or response schema binding is stale"
            )
        cache_hit_identities.append(
            _validate_cache_hit_evidence(item, snapshot=authoritative_snapshot)
        )

    invocation_identities = []
    for item in invocations:
        if not isinstance(item, Mapping):
            raise AnalysisArchiveError("production invocation evidence is malformed")
        operation = item.get("operation")
        binding = item.get("binding")
        expected_schema = ANALYSIS_RESPONSE_SCHEMA_VERSIONS.get(str(operation))
        if (
            not isinstance(binding, Mapping)
            or expected_schema is None
            or binding.get("run_id") != run_id
            or binding.get("snapshot_hash") != snapshot_hash
            or binding.get("prompt_version") != prompt_version
            or binding.get("response_schema_version") != expected_schema
        ):
            raise AnalysisArchiveError(
                "production invocation snapshot, prompt, or response schema binding is stale"
            )
        identity = _production_transport_identity(operation, binding)
        if identity is None:
            raise AnalysisArchiveError("production invocation identity is malformed")
        invocation_identities.append(identity)

    if (
        Counter(transport_identities) + Counter(cache_hit_identities)
        != Counter(invocation_identities)
    ):
        raise AnalysisArchiveError(
            "production transport/cache evidence does not close over orchestration invocations"
        )
    accounting = _recompute_transport_accounting(
        transports=transports,
        invocations=invocations,
        snapshot=authoritative_snapshot,
        cache_hits=cache_hits,
        cache_enabled=cache_evidence_present,
    )
    accounting.update(
        _validate_production_budget_semantics(
            analysis_v2=analysis_v2,
            transports=transports,
            snapshot=authoritative_snapshot,
        )
    )
    _validate_performance_accounting(
        analysis_v2.get("performance"),
        accounting,
        label="recorded production",
    )
    return accounting


def _atomic_commit(builder: _ArchiveBuilder, destination: Path) -> None:
    root = destination.parent
    root.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"immutable analysis run already exists: {destination.name}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=root))
    try:
        for relative, payload in sorted(builder.files.items()):
            path = temporary.joinpath(*PurePosixPath(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        if destination.exists():
            raise FileExistsError(
                f"immutable analysis run already exists: {destination.name}"
            )
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def freeze_pipeline_analysis_run(
    *,
    project_dir: str | Path,
    run_id: str,
    project_id: str,
    artifacts: AnalysisRunArtifacts,
    page_range: Sequence[int],
    page_count: int,
    models: Sequence[ModelBinding | Mapping[str, Any]],
    application_version: str,
    verification_evidence: VerificationEvidence | Mapping[str, Any] | None = None,
    page_map: Sequence[PageMapEntry | Mapping[str, Any]] | None = None,
    page_risks: Mapping[int, PageRisk | str] | None = None,
    source_page_hashes: Mapping[int, str] | None = None,
    quality_vector: QualityVector | Mapping[str, Any] | None = None,
    performance_metrics: Mapping[str, Any] | object | None = None,
    authoritative_snapshot: AnalysisRunSnapshot | None = None,
    production_evidence: ProductionAnalysisArchiveEvidence | None = None,
    processing_failed: bool = False,
    workflow_version: str = "analysis-loop-v2",
    prompt_version: str = "analysis-prompts-v2",
    latex_engine: str = "xelatex",
    concurrency_limit: int = 3,
    started_at: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> AnalysisRunArchiveResult:
    """Atomically freeze one real pipeline run under ``analysis-runs/<run_id>``.

    The caller supplies bytes that already exist and optional *machine-produced*
    ``VerificationEvidence``.  A legacy ``verification`` dictionary is retained
    as evidence but can never by itself produce ``VERIFIED``.  Reusing ``run_id``
    raises ``FileExistsError`` and leaves the prior archive untouched.
    """

    if not _RUN_ID_RE.fullmatch(str(run_id or "")):
        raise AnalysisArchiveError("run_id must be a portable host-generated identifier")
    if not str(project_id or "").strip():
        raise AnalysisArchiveError("project_id is required")
    selected = tuple(int(page) for page in page_range)
    if (
        not selected
        or tuple(sorted(selected)) != selected
        or len(selected) != len(set(selected))
        or selected[0] < 1
        or selected[-1] > int(page_count)
    ):
        raise AnalysisArchiveError("page_range must be unique, ordered, and within page_count")

    source_pdf = bytes(artifacts.source_pdf)
    baseline_pdf = bytes(artifacts.baseline_pdf)
    current_pdf = bytes(artifacts.current_pdf)
    source_pdf_hash = sha256_bytes(source_pdf)
    raw_hash = sha256_text(artifacts.raw_ocr_tex)
    baseline_hash = sha256_text(artifacts.baseline_tex)
    current_hash = sha256_text(artifacts.current_tex)
    baseline_pdf_hash = sha256_bytes(baseline_pdf)
    current_pdf_hash = sha256_bytes(current_pdf) if current_pdf else ""
    model_bindings = _coerce_models(models)
    production_archive_payloads: dict[str, Mapping[str, Any]] | None = None
    if authoritative_snapshot is not None:
        if not isinstance(authoritative_snapshot, AnalysisRunSnapshot):
            raise AnalysisArchiveError("authoritative_snapshot has an invalid type")
        snapshot = authoritative_snapshot
        stale = snapshot.stale_reasons(
            source_pdf_hash=source_pdf_hash,
            raw_ocr_tex_hash=raw_hash,
            baseline_tex_hash=baseline_hash,
            page_range=selected,
        )
        if (
            stale
            or snapshot.run_id != run_id
            or snapshot.project_id != project_id
            or snapshot.page_count != int(page_count)
            or snapshot.baseline_pdf_hash != baseline_pdf_hash
            or snapshot.evidence_hashes is None
            or not snapshot.page_map
        ):
            raise AnalysisArchiveError(
                "authoritative production snapshot differs from archive inputs: "
                + ",".join(stale or ("identity_or_evidence",))
            )
        page_entries = tuple(snapshot.page_map)
        if not isinstance(production_evidence, ProductionAnalysisArchiveEvidence):
            raise AnalysisArchiveError(
                "authoritative production snapshot requires typed production_evidence"
            )
        try:
            production_archive_payloads = (
                _validated_typed_production_archive_evidence(
                    evidence=production_evidence,
                    authoritative_snapshot=snapshot,
                    source_pdf_hash=source_pdf_hash,
                    baseline_tex_hash=baseline_hash,
                    baseline_pdf_hash=baseline_pdf_hash,
                    current_tex_hash=current_hash,
                )
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, AnalysisArchiveError):
                raise
            raise AnalysisArchiveError(
                "authoritative production archive evidence is invalid"
            ) from exc
    else:
        if production_evidence is not None:
            raise AnalysisArchiveError(
                "production_evidence requires an authoritative_snapshot"
            )
        page_entries = _coerce_page_map(
            value=page_map,
            source_pdf_hash=source_pdf_hash,
            candidate_pdf_hash=current_pdf_hash,
            page_range=selected,
        )

    ledger, unbound_decisions = _ledger_from_decisions(
        decision_items=tuple(artifacts.decision_items),
        page_map=page_entries,
        baseline_hash=baseline_hash,
        candidate_hash=current_hash,
        current_tex=artifacts.current_tex,
    )
    verification_dict = dict(artifacts.verification or {})
    production_accounting: dict[str, Any] | None = None
    if authoritative_snapshot is not None:
        production_accounting = _validate_production_analysis_semantics(
            authoritative_snapshot=snapshot.to_dict(),
            analysis_v2=verification_dict.get("analysis_v2"),
        )
    if verification_evidence is not None:
        supplied_evidence = _coerce_verification_evidence(verification_evidence)
    else:
        supplied_evidence = _coerce_verification_evidence(
            verification_dict.get("v2_verification_evidence")
        )
        analysis_v2 = verification_dict.get("analysis_v2")
        if supplied_evidence is None and isinstance(analysis_v2, Mapping):
            supplied_evidence = _coerce_verification_evidence(
                analysis_v2.get("verification_evidence")
            )

    baseline_compile = verification_dict.get("compile_before")
    initial_compile_state = _compile_state(baseline_pdf, baseline_compile)
    initial_ledger_payload = ledger.to_dict()
    initial_ledger_counts = ledger.counts()
    configuration = {
        "workflow_version": workflow_version,
        "prompt_version": prompt_version,
        "application_version": application_version,
        "latex_engine": latex_engine,
        "concurrency_limit": concurrency_limit,
        "models": _jsonable(model_bindings),
        "caller_config": _jsonable(config or {}),
    }
    if authoritative_snapshot is None:
        snapshot = AnalysisRunSnapshot(
            run_id=run_id,
            project_id=project_id,
            workflow_version=workflow_version,
            prompt_version=prompt_version,
            application_version=application_version,
            source_pdf_hash=source_pdf_hash,
            raw_ocr_tex_hash=raw_hash,
            baseline_tex_hash=baseline_hash,
            baseline_pdf_hash=baseline_pdf_hash,
            page_count=int(page_count),
            page_range=selected,
            latex_engine=latex_engine,
            models=model_bindings,
            concurrency_limit=int(concurrency_limit),
            started_at=started_at or datetime.now(timezone.utc).isoformat(),
            page_map=page_entries,
            initial_compile_state=initial_compile_state,
            initial_issue_counts=tuple(initial_ledger_counts.items()),
            config_hash=sha256_bytes(canonical_json_bytes(configuration)),
        )

    if production_evidence is not None:
        # Preserve the exact production PageUnits.  The authoritative path may
        # not replace missing classifier output with adapter-invented R3 pages.
        runtime_page_units = [
            item.page_unit for item in production_evidence.page_inputs
        ]
    else:
        risks = dict(page_risks or {})
        supplied_page_hashes = dict(source_page_hashes or {})
        runtime_page_units = []
        for entry in page_entries:
            risk_supplied = entry.source_page_number in risks
            risk_value = risks.get(entry.source_page_number, PageRisk.R3)
            risk = (
                risk_value
                if isinstance(risk_value, PageRisk)
                else PageRisk(str(risk_value))
            )
            risk_reasons = (
                (() if risk == PageRisk.R0 else ("host-supplied risk",))
                if risk_supplied
                else (
                    "page risk classifier unavailable",
                    "full page review required",
                )
            )
            page_hash = supplied_page_hashes.get(entry.source_page_number)
            if not page_hash:
                page_hash = sha256_bytes(canonical_json_bytes({
                    "source_pdf_sha256": source_pdf_hash,
                    "source_page_number": entry.source_page_number,
                }))
            runtime_page_units.append(PageUnit(
                source_page_id=entry.source_page_id,
                source_page_number=entry.source_page_number,
                source_page_hash=page_hash,
                baseline_tex_start_anchor=f"baseline:{baseline_hash[:16]}:{entry.source_page_id}:start",
                baseline_tex_end_anchor=f"baseline:{baseline_hash[:16]}:{entry.source_page_id}:end",
                current_tex_start_anchor=f"current:{current_hash[:16]}:{entry.source_page_id}:start",
                current_tex_end_anchor=f"current:{current_hash[:16]}:{entry.source_page_id}:end",
                candidate_pdf_page_ids=entry.candidate_pdf_page_ids,
                current_render_paths=("candidates/best/candidate.pdf",) if current_pdf else (),
                risk_level=risk,
                risk_reasons=risk_reasons,
                current_status=PageStatus.PENDING,
            ))

    attempted_evidence = supplied_evidence or _host_verification_evidence(
        verification=verification_dict,
        artifacts=artifacts,
        page_map=page_entries,
        candidate_hash=current_hash,
        candidate_pdf=current_pdf,
        ledger=ledger,
        pipeline_current=True,
    )
    evidence_source = (
        "v2-machine-evidence"
        if supplied_evidence is not None
        else "host-derived-pipeline-evidence"
    )
    if _reviews_close_fixed_issues(attempted_evidence):
        for record in tuple(ledger.records):
            if record.current_status != IssueStatus.FIXED_PENDING_REVIEW:
                continue
            ledger.close_after_review(
                record.issue_id,
                round_index=max(2, record.last_modified_round),
                candidate_hash=current_hash,
                review_result=ReviewResult.PASS,
                compile_ok=attempted_evidence.best_compile_passes >= 2,
                content_conservation_ok=attempted_evidence.silent_text_losses == 0,
                math_conservation_ok=attempted_evidence.unauthorized_math_changes == 0,
                visual_review_ok=True,
                new_high_priority_issues=0,
            )
        if supplied_evidence is None:
            attempted_evidence = _host_verification_evidence(
                verification=verification_dict,
                artifacts=artifacts,
                page_map=page_entries,
                candidate_hash=current_hash,
                candidate_pdf=current_pdf,
                ledger=ledger,
                pipeline_current=True,
            )

    if isinstance(quality_vector, QualityVector):
        current_vector = quality_vector
    elif isinstance(quality_vector, Mapping):
        current_vector = QualityVector(**dict(quality_vector))
    else:
        current_vector = _evidence_quality(attempted_evidence)
    baseline_evidence = _host_verification_evidence(
        verification=verification_dict,
        artifacts=artifacts,
        page_map=page_entries,
        candidate_hash=baseline_hash,
        candidate_pdf=baseline_pdf,
        ledger=IssueLedger.from_dict(initial_ledger_payload),
        pipeline_current=False,
    )
    baseline_vector = _evidence_quality(baseline_evidence)

    analysis_root = Path(project_dir) / "analysis-runs"
    analysis_root.mkdir(parents=True, exist_ok=True)
    runtime_stage = Path(tempfile.mkdtemp(prefix=f".{run_id}-runtime-", dir=analysis_root))
    runtime = AnalysisQualityRuntime(
        snapshot=snapshot,
        page_units=tuple(runtime_page_units),
        candidate_root=runtime_stage / "candidates",
        ledger=ledger,
    )
    runtime_records: list[CandidateRecord] = []
    runtime_payloads: dict[str, dict[str, bytes]] = {}
    try:
        baseline_record = runtime.candidates.save_baseline(
            tex=artifacts.baseline_tex,
            pdf=baseline_pdf,
            compile_log=artifacts.baseline_compile_log,
            quality=baseline_vector,
            issue_ledger=initial_ledger_payload,
        )
        runtime_records.append(baseline_record)
        attempted_record = baseline_record
        current_diff = "".join(difflib.unified_diff(
            artifacts.baseline_tex.splitlines(keepends=True),
            artifacts.current_tex.splitlines(keepends=True),
            fromfile="baseline/baseline.tex",
            tofile="candidates/current/candidate.tex",
        ))
        if artifacts.current_tex != artifacts.baseline_tex:
            invariant_checks = check_invariants(
                artifacts.baseline_tex,
                artifacts.current_tex,
                check_body_text=True,
            )
            unauthorized = tuple(
                name for name, result in invariant_checks.items()
                if name != "ok"
                and isinstance(result, Mapping)
                and result.get("equal") is not True
            )
            application = PatchApplication(
                patch_id=f"PATCH-{sha256_text(current_diff)[:16]}",
                parent_hash=baseline_hash,
                candidate_hash=current_hash,
                candidate_tex=artifacts.current_tex,
                diff=current_diff,
                affected_page_ids=tuple(entry.source_page_id for entry in page_entries),
                conservation=ConservationReport(
                    ok=not unauthorized,
                    checks=invariant_checks,
                    authorized_changes=(),
                    unauthorized_changes=unauthorized,
                ),
            )
            attempted_record = runtime.candidates.evaluate(
                application=application,
                round_index=1,
                pdf=current_pdf,
                compile_log=artifacts.current_compile_log,
                quality=current_vector,
                issue_ledger=ledger.to_dict(),
                review={"v2_verification_evidence": _jsonable(attempted_evidence)},
            )
            runtime_records.append(attempted_record)

        best_record = runtime.candidates.best
        if best_record is None:
            raise AnalysisArchiveError("quality runtime did not retain a best candidate")
        for record in runtime_records:
            directory = runtime.candidates.repository.root / record.candidate_id
            if not runtime.candidates.repository.verify(record.candidate_id):
                raise AnalysisArchiveError("quality runtime candidate hash verification failed")
            runtime_payloads[record.candidate_id] = {
                path.name: path.read_bytes()
                for path in directory.iterdir()
                if path.is_file()
            }
    finally:
        shutil.rmtree(runtime_stage, ignore_errors=True)

    best_is_current = best_record.tex_sha256 == current_hash
    best_tex = artifacts.current_tex if best_is_current else artifacts.baseline_tex
    best_pdf = current_pdf if best_is_current else baseline_pdf
    best_compile_log = (
        artifacts.current_compile_log if best_is_current else artifacts.baseline_compile_log
    )
    best_hash = best_record.tex_sha256
    if best_is_current:
        evidence = attempted_evidence
    else:
        evidence = _host_verification_evidence(
            verification=verification_dict,
            artifacts=artifacts,
            page_map=page_entries,
            candidate_hash=best_hash,
            candidate_pdf=best_pdf,
            ledger=ledger,
            pipeline_current=False,
        )
        evidence_source = "host-derived-history-best-evidence"

    effective_artifacts = replace(
        artifacts,
        current_tex=best_tex,
        current_pdf=best_pdf,
        current_compile_log=best_compile_log,
        rollback_history=tuple(artifacts.rollback_history) + tuple(
            _jsonable(item) for item in runtime.candidates.rollback_history
        ),
    )
    baseline_inventory, final_inventory, inventory_gate = _inventory_closure(
        baseline_tex=artifacts.baseline_tex,
        current_tex=best_tex,
        page_entries=page_entries,
        production_evidence=production_evidence,
    )
    decision, _derived_source = _derive_final_decision(
        evidence=evidence,
        page_map=page_entries,
        current_tex_hash=best_hash,
        artifacts=effective_artifacts,
        processing_failed=processing_failed,
        unbound_decisions=unbound_decisions,
        runtime=runtime,
    )
    decision = _apply_production_authority_gate(
        decision,
        authoritative_snapshot_present=authoritative_snapshot is not None,
    )
    if production_accounting is not None:
        # The adapter is a second trust boundary.  Do not let otherwise-complete
        # machine evidence promote a production run after its provider-call
        # attempt or usage closure has become incomplete in transit/archive.
        decision = _apply_production_transport_closure(
            decision,
            production_accounting,
        )
    decision = _apply_inventory_decision_gate(
        decision,
        inventory_gate,
        processing_failed=processing_failed,
    )
    checked_page_ids = set(evidence.checked_page_ids)
    page_units = []
    for unit in runtime_page_units:
        checked = unit.source_page_id in checked_page_ids
        page_units.append(replace(
            unit,
            current_tex_start_anchor=(
                f"current:{best_hash[:16]}:{unit.source_page_id}:start"
            ),
            current_tex_end_anchor=(
                f"current:{best_hash[:16]}:{unit.source_page_id}:end"
            ),
            current_render_paths=("candidates/best/candidate.pdf",) if best_pdf else (),
            last_checked_candidate_hash=best_hash if checked else "",
            current_status=(
                PageStatus.VERIFIED
                if checked and decision.verified
                else PageStatus.CHECKED
                if checked
                else PageStatus.PENDING
            ),
        ))

    vector = best_record.quality
    quality_payload = {
        "schema": "latexstruct-analysis-quality-vector-v2",
        "evidence_complete": not bool(decision.failures),
        "unknown_fields": [] if not decision.failures else list(decision.failures),
        "vector": _jsonable(vector),
        "priority_key": list(vector.priority_key),
        "candidate_id": best_record.candidate_id,
        "host_runtime_derived": True,
    }
    ledger_payload = ledger.to_dict()
    ledger_payload["unbound_decision_items"] = unbound_decisions
    ledger_payload["counts"] = ledger.counts()
    review_payload = verification_dict.get("full_document_review")
    if not isinstance(review_payload, Mapping):
        review_payload = verification_dict.get("ai_review")
    if not isinstance(review_payload, Mapping):
        review_payload = {"available": False}

    builder = _ArchiveBuilder()
    if source_pdf:
        builder.add_bytes("inputs/source.pdf", source_pdf, role="SOURCE_PDF")
    if artifacts.source_tex:
        builder.add_text("inputs/source.tex", artifacts.source_tex, role="SOURCE_TEX")
    if artifacts.raw_ocr_tex:
        builder.add_text("baseline/raw_ocr.tex", artifacts.raw_ocr_tex, role="RAW_OCR_TEX")
    if artifacts.baseline_tex:
        builder.add_text("baseline/baseline.tex", artifacts.baseline_tex, role="BASELINE_TEX")
    if baseline_pdf:
        builder.add_bytes("baseline/baseline.pdf", baseline_pdf, role="BASELINE_PDF")
    builder.add_text(
        "baseline/baseline_compile.log",
        artifacts.baseline_compile_log,
        role="BASELINE_COMPILE_LOG",
    )
    builder.add_json("baseline/page_map.json", page_entries, role="PAGE_MAP")
    builder.add_local_sums("baseline")

    def committed_payloads(record: CandidateRecord) -> dict[str, bytes]:
        return {
            name: payload
            for name, payload in runtime_payloads[record.candidate_id].items()
            if name != "SHA256SUMS"
        }

    round_zero = committed_payloads(baseline_record)
    _add_candidate_directory(builder, "candidates/round_000", round_zero)
    # A no-op analysis is still a real candidate evaluation.  Keep round_001
    # even when its bytes equal the baseline so its ledger/review evidence does
    # not disappear behind round_000's deliberately empty baseline metadata.
    round_one = (
        committed_payloads(attempted_record)
        if attempted_record.candidate_id != baseline_record.candidate_id
        else _candidate_payloads(
            tex=artifacts.current_tex,
            pdf=current_pdf,
            compile_log=artifacts.current_compile_log,
            parent_hash=baseline_hash,
            ledger=ledger_payload,
            quality=quality_payload,
            review=dict(review_payload),
            diff=current_diff,
            round_index=1,
            disposition="NO_OP_HISTORY_BEST",
        )
    )
    _add_candidate_directory(builder, "candidates/round_001", round_one)
    best_payloads = committed_payloads(best_record)
    _add_candidate_directory(builder, "candidates/best", best_payloads)

    formal_inventory = verification_dict.get("final_formal_inventory")
    if not isinstance(formal_inventory, Mapping):
        formal_inventory = verification_dict.get("formal_inventory")
    if not isinstance(formal_inventory, Mapping):
        formal_inventory = {"available": False}
    invariants = verification_dict.get("invariants")
    invariants = invariants if isinstance(invariants, Mapping) else {}
    content_payload = {
        "available": bool("content_invariant" in verification_dict or "body_text" in invariants),
        "content_invariant": verification_dict.get("content_invariant"),
        "body_text": invariants.get("body_text"),
    }
    math_payload = {
        "available": "math" in invariants,
        "math": invariants.get("math"),
    }
    visual_payload = verification_dict.get("visual_quality_loop")
    if not isinstance(visual_payload, Mapping):
        visual_payload = {"available": False}
    compile_history = {
        "baseline": verification_dict.get("compile_before", {"available": False}),
        "current": verification_dict.get("compile_after", {"available": False}),
        "baseline_log_path": "baseline/baseline_compile.log",
        "current_log_path": "candidates/best/compile.log",
    }
    final_decision_payload = {
        "schema": "latexstruct-analysis-final-decision-v2",
        "status": decision.status.value,
        "verified": decision.verified,
        "failures": list(decision.failures),
        "evidence_source": evidence_source,
        "host_derived": True,
        "legacy_safe_to_export": verification_dict.get("safe_to_export"),
        "note": "Legacy success flags are retained as evidence and never promote VERIFIED.",
        "quality_runtime_executed": True,
        "best_candidate_id": best_record.candidate_id,
        "attempted_candidate_id": attempted_record.candidate_id,
        "rollback_count": len(runtime.candidates.rollback_history),
        "baseline_inventory_digest": baseline_inventory.digest,
        "final_inventory_digest": final_inventory.digest,
        "inventory_gate_digest": inventory_gate.digest,
        "baseline_inventory_json_sha256": sha256_bytes(
            canonical_json_bytes(baseline_inventory.as_dict())
        ),
        "final_inventory_json_sha256": sha256_bytes(
            canonical_json_bytes(final_inventory.as_dict())
        ),
        "inventory_gate_json_sha256": sha256_bytes(
            canonical_json_bytes(inventory_gate.as_dict())
        ),
        "inventory_gate_status": inventory_gate.status.value,
    }
    performance_payload = _performance_payload(
        performance_metrics,
        total_pages=len(selected),
        decision=decision,
    )
    if production_accounting is not None:
        _validate_performance_accounting(
            performance_payload,
            production_accounting,
            label="archived",
        )
    builder.add_json(
        "audit/analysis_run_snapshot.json",
        snapshot.to_dict(),
        role="ANALYSIS_RUN_SNAPSHOT",
    )
    if production_archive_payloads is not None:
        builder.add_json(
            "audit/page_risk_admission.json",
            production_archive_payloads["page_risk_admission"],
            role="PAGE_RISK_ADMISSION",
        )
        builder.add_json(
            "audit/page_inputs.json",
            production_archive_payloads["page_inputs"],
            role="PRODUCTION_PAGE_INPUTS",
        )
        builder.add_json(
            "audit/page_route_closure.json",
            production_archive_payloads["page_route_closure"],
            role="PAGE_RISK_ROUTE_CLOSURE",
        )
        builder.add_json(
            "audit/analysis_configuration.json",
            production_archive_payloads["analysis_configuration"],
            role="ANALYSIS_CONFIGURATION",
        )
        builder.add_json(
            "audit/risk_preflight.json",
            production_archive_payloads["risk_preflight"],
            role="PAGE_RISK_PREFLIGHT",
        )
    builder.add_canonical_json(
        "audit/analysis_inventory_baseline.json",
        baseline_inventory.as_dict(),
        role="ANALYSIS_INVENTORY_BASELINE",
    )
    builder.add_canonical_json(
        "audit/analysis_inventory_final.json",
        final_inventory.as_dict(),
        role="ANALYSIS_INVENTORY_FINAL",
    )
    builder.add_canonical_json(
        "audit/analysis_inventory_gate.json",
        inventory_gate.as_dict(),
        role="ANALYSIS_INVENTORY_GATE",
    )
    builder.add_json("audit/page_units.json", page_units, role="PAGE_UNITS")
    builder.add_json("audit/issue_ledger.json", ledger_payload, role="ISSUE_LEDGER")
    builder.add_json("audit/formal_inventory.json", formal_inventory, role="FORMAL_INVENTORY")
    builder.add_json("audit/content_conservation.json", content_payload, role="CONTENT_CONSERVATION")
    builder.add_json("audit/math_token_report.json", math_payload, role="MATH_TOKEN_REPORT")
    builder.add_json("audit/visual_review.json", visual_payload, role="VISUAL_REVIEW")
    builder.add_json("audit/compile_history.json", compile_history, role="COMPILE_HISTORY")
    builder.add_json(
        "audit/rollback_history.json",
        {"items": list(effective_artifacts.rollback_history)},
        role="ROLLBACK_HISTORY",
    )
    builder.add_json(
        "audit/quality_runtime.json",
        {
            "schema": "latexstruct-analysis-quality-runtime-v2",
            "executed": True,
            "candidate_ids": [record.candidate_id for record in runtime_records],
            "best_candidate_id": best_record.candidate_id,
            "attempted_candidate_id": attempted_record.candidate_id,
            "rollback_count": len(runtime.candidates.rollback_history),
            "evidence_source": evidence_source,
            "review_pass_count": len(evidence.final_reviews),
        },
        role="QUALITY_RUNTIME_STATE",
    )
    builder.add_json("audit/quality_vector.json", quality_payload, role="QUALITY_VECTOR")
    builder.add_json(
        "audit/performance_metrics.json", performance_payload, role="PERFORMANCE_METRICS"
    )
    builder.add_json(
        "audit/verification.json", verification_dict, role="PIPELINE_MACHINE_VERIFICATION"
    )
    builder.add_json(
        "audit/v2_verification_evidence.json",
        _jsonable(evidence),
        role="V2_VERIFICATION_EVIDENCE",
    )
    builder.add_json(
        "audit/decision_items.json", list(artifacts.decision_items), role="DECISION_ITEMS"
    )
    builder.add_json("audit/final_decision.json", final_decision_payload, role="FINAL_DECISION")
    builder.add_text("audit/final_report.md", artifacts.report_md, role="FINAL_REPORT")

    manifest_entries = [
        {
            "path": path,
            "artifact_role": builder.roles[path],
            "sha256": sha256_bytes(payload),
            "bytes": len(payload),
        }
        for path, payload in sorted(builder.files.items())
    ]
    manifest = {
        "schema": "latexstruct-analysis-run-artifact-manifest-v2",
        "run_id": run_id,
        "project_id": project_id,
        "status": decision.status.value,
        "verified": decision.verified,
        "paths_are_relative": True,
        "artifacts": manifest_entries,
    }
    builder.add_json("audit/artifact_manifest.json", manifest, role="ARTIFACT_MANIFEST")
    root_sums = "".join(
        f"{sha256_bytes(payload)}  {path}\n"
        for path, payload in sorted(builder.files.items())
        if path != "audit/SHA256SUMS"
    )
    builder.add_text("audit/SHA256SUMS", root_sums, role="RUN_SHA256SUMS")

    destination = Path(project_dir) / "analysis-runs" / run_id
    _atomic_commit(builder, destination)
    snapshot_path = destination / "audit" / "analysis_run_snapshot.json"
    return AnalysisRunArchiveResult(
        run_id=run_id,
        run_directory=destination,
        status=decision.status,
        verified=decision.verified,
        failures=decision.failures,
        snapshot_sha256=sha256_bytes(snapshot_path.read_bytes()),
        artifact_count=len(builder.files),
        runtime_executed=True,
        best_candidate_id=best_record.candidate_id,
        candidate_count=len(runtime_records),
        rollback_count=len(runtime.candidates.rollback_history),
        review_pass_count=len(evidence.final_reviews),
        evidence_source=evidence_source,
    )


def verify_frozen_analysis_run(run_directory: str | Path) -> bool:
    """Recompute hashes and production snapshot/transport semantic closure."""

    root = Path(run_directory)
    manifest = root / "audit" / "SHA256SUMS"
    if not manifest.is_file():
        return False
    expected: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = _SHA256_LINE_RE.fullmatch(line)
            if not match:
                return False
            digest, raw_path = match.groups()
            relative = _ArchiveBuilder._relative_path(raw_path)
            if relative in expected or relative == "audit/SHA256SUMS":
                return False
            expected[relative] = digest
    except (OSError, UnicodeError, AnalysisArchiveError):
        return False
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest
    }
    if actual != set(expected):
        return False
    try:
        if not all(
            sha256_bytes((root / PurePosixPath(path)).read_bytes()) == digest
            for path, digest in expected.items()
        ):
            return False
        snapshot = json.loads(
            (root / "audit" / "analysis_run_snapshot.json").read_text(
                encoding="utf-8"
            )
        )
        verification = json.loads(
            (root / "audit" / "verification.json").read_text(encoding="utf-8")
        )
        performance = json.loads(
            (root / "audit" / "performance_metrics.json").read_text(
                encoding="utf-8"
            )
        )
        final_decision = json.loads(
            (root / "audit" / "final_decision.json").read_text(encoding="utf-8")
        )
        baseline_inventory_payload = json.loads(
            (root / "audit" / "analysis_inventory_baseline.json").read_text(
                encoding="utf-8"
            )
        )
        final_inventory_payload = json.loads(
            (root / "audit" / "analysis_inventory_final.json").read_text(
                encoding="utf-8"
            )
        )
        inventory_gate_payload = json.loads(
            (root / "audit" / "analysis_inventory_gate.json").read_text(
                encoding="utf-8"
            )
        )
        if (
            not isinstance(snapshot, dict)
            or not isinstance(verification, dict)
            or not isinstance(performance, dict)
            or not isinstance(final_decision, dict)
            or not isinstance(baseline_inventory_payload, dict)
            or not isinstance(final_inventory_payload, dict)
            or not isinstance(inventory_gate_payload, dict)
        ):
            return False
        stored_snapshot_hash = snapshot.get("snapshot_hash")
        canonical_snapshot = dict(snapshot)
        canonical_snapshot.pop("snapshot_hash", None)
        if (
            not isinstance(stored_snapshot_hash, str)
            or sha256_bytes(canonical_json_bytes(canonical_snapshot))
            != stored_snapshot_hash
        ):
            return False
        decision_status = final_decision.get("status")
        decision_verified = final_decision.get("verified")
        decision_failures = final_decision.get("failures")
        if (
            decision_status not in {item.value for item in AnalysisFinalStatus}
            or type(decision_verified) is not bool
            or not isinstance(decision_failures, list)
            or any(not isinstance(item, str) for item in decision_failures)
            or performance.get("final_status") != decision_status
            or decision_verified
            != (decision_status == AnalysisFinalStatus.VERIFIED.value)
        ):
            return False
        has_production_authority = snapshot.get("evidence_hashes") is not None
        configuration_archive = None
        authoritative_configuration = None
        if has_production_authority:
            configuration_archive = json.loads(
                (root / "audit" / "analysis_configuration.json").read_text(
                    encoding="utf-8"
                )
            )
            if not isinstance(configuration_archive, Mapping) or set(
                configuration_archive
            ) != {
                "schema", "analysis_configuration",
                "analysis_configuration_sha256",
            }:
                return False
            authoritative_configuration = configuration_archive.get(
                "analysis_configuration"
            )
            evidence_hashes = snapshot.get("evidence_hashes")
            if (
                configuration_archive.get("schema")
                != _ANALYSIS_CONFIGURATION_SCHEMA
                or not isinstance(authoritative_configuration, Mapping)
                or not isinstance(evidence_hashes, Mapping)
            ):
                return False
            configuration_sha256 = sha256_bytes(
                canonical_json_bytes(authoritative_configuration)
            )
            if (
                configuration_archive.get("analysis_configuration_sha256")
                != configuration_sha256
                or snapshot.get("config_hash") != configuration_sha256
                or evidence_hashes.get("analysis_config_hash")
                != configuration_sha256
            ):
                return False
            raw_map_entries = authoritative_configuration.get(
                "candidate_page_map"
            )
            if not isinstance(raw_map_entries, list):
                return False
            source_page_map: dict[int, tuple[int, ...]] = {}
            for entry in raw_map_entries:
                if (
                    not isinstance(entry, list)
                    or len(entry) != 2
                    or type(entry[0]) is not int
                    or not isinstance(entry[1], list)
                ):
                    return False
                source_page_map[entry[0]] = tuple(entry[1])
            if not source_page_map:
                return False
            raw_native_blocks = authoritative_configuration.get(
                "native_source_blocks"
            )
            native_blocks_supplied = authoritative_configuration.get(
                "native_source_blocks_supplied"
            )
            raw_authorizations = authoritative_configuration.get(
                "inventory_authorizations"
            )
            require_native = authoritative_configuration.get(
                "native_heading_inventory_required"
            )
        else:
            raw_source_map = baseline_inventory_payload.get("source_page_map")
            if not isinstance(raw_source_map, Mapping) or not raw_source_map:
                return False
            source_page_map = {}
            for raw_page, raw_pdf_pages in raw_source_map.items():
                if (
                    not isinstance(raw_page, str)
                    or not raw_page.isdigit()
                    or not isinstance(raw_pdf_pages, list)
                ):
                    return False
                source_page_map[int(raw_page)] = tuple(raw_pdf_pages)
            raw_native_blocks = baseline_inventory_payload.get(
                "native_source_blocks"
            )
            native_blocks_supplied = baseline_inventory_payload.get(
                "native_source_blocks_supplied"
            )
            raw_authorizations = baseline_inventory_payload.get("authorizations")
            require_native = baseline_inventory_payload.get(
                "native_heading_inventory_required"
            )
        if (
            not isinstance(raw_native_blocks, list)
            or not isinstance(raw_authorizations, list)
            or type(require_native) is not bool
            or type(native_blocks_supplied) is not bool
        ):
            return False
        native_blocks = coerce_analysis_native_source_blocks(raw_native_blocks)
        authorizations = coerce_analysis_inventory_authorizations(
            raw_authorizations
        )
        if has_production_authority:
            expected_source_map = {
                str(page): list(pdf_pages)
                for page, pdf_pages in source_page_map.items()
            }
            if (
                baseline_inventory_payload.get("source_page_map")
                != expected_source_map
                or baseline_inventory_payload.get("native_source_blocks")
                != [item.as_dict() for item in native_blocks]
                or baseline_inventory_payload.get("native_source_blocks_supplied")
                is not native_blocks_supplied
                or baseline_inventory_payload.get("authorizations")
                != [item.as_dict() for item in authorizations]
                or baseline_inventory_payload.get(
                    "native_heading_inventory_required"
                ) is not require_native
            ):
                return False
            authorization_source = authoritative_configuration.get(
                "inventory_authorization_source"
            )
            if authorization_source == "HOST_REQUIRED_POLICY":
                manifest_hash = authoritative_configuration.get(
                    "inventory_policy_ocr_manifest_sha256"
                )
                if (
                    authoritative_configuration.get("inventory_policy_schema")
                    != "latexstruct-host-inventory-policy-v1"
                    or manifest_hash
                    != snapshot["evidence_hashes"].get(
                        "ocr_baseline_manifest_hash"
                    )
                    or build_host_inventory_authorizations(
                        native_blocks,
                        ocr_manifest_sha256=str(manifest_hash or ""),
                        generated_toc_required=True,
                    ) != authorizations
                ):
                    return False
            elif authorization_source != "CALLER_FROZEN_HOST_POLICY":
                return False
        baseline_tex_value = (
            root / "baseline" / "baseline.tex"
        ).read_text(encoding="utf-8")
        best_tex_value = (
            root / "candidates" / "best" / "candidate.tex"
        ).read_text(encoding="utf-8")
        rebuilt_baseline = build_analysis_inventory_bundle(
            baseline_tex_value,
            baseline_tex_value,
            source_page_map,
            native_source_blocks=(native_blocks if native_blocks_supplied else None),
            authorizations=authorizations,
            require_native_heading_inventory=require_native,
        )
        rebuilt_final = build_analysis_inventory_bundle(
            baseline_tex_value,
            best_tex_value,
            source_page_map,
            native_source_blocks=(native_blocks if native_blocks_supplied else None),
            authorizations=authorizations,
            require_native_heading_inventory=require_native,
        )
        rebuilt_gate = evaluate_analysis_inventory_gate(rebuilt_final)
        if has_production_authority and (
            authoritative_configuration.get("baseline_inventory_digest")
            != rebuilt_baseline.digest
            or authoritative_configuration.get(
                "baseline_inventory_json_sha256"
            )
            != sha256_bytes(canonical_json_bytes(rebuilt_baseline.as_dict()))
        ):
            return False
        if (
            canonical_json_bytes(baseline_inventory_payload)
            != canonical_json_bytes(rebuilt_baseline.as_dict())
            or canonical_json_bytes(final_inventory_payload)
            != canonical_json_bytes(rebuilt_final.as_dict())
            or canonical_json_bytes(inventory_gate_payload)
            != canonical_json_bytes(rebuilt_gate.as_dict())
        ):
            return False
        if (
            final_decision.get("baseline_inventory_digest")
            != rebuilt_baseline.digest
            or final_decision.get("final_inventory_digest")
            != rebuilt_final.digest
            or final_decision.get("inventory_gate_digest") != rebuilt_gate.digest
            or final_decision.get("inventory_gate_status")
            != rebuilt_gate.status.value
            or final_decision.get("baseline_inventory_json_sha256")
            != sha256_bytes(canonical_json_bytes(rebuilt_baseline.as_dict()))
            or final_decision.get("final_inventory_json_sha256")
            != sha256_bytes(canonical_json_bytes(rebuilt_final.as_dict()))
            or final_decision.get("inventory_gate_json_sha256")
            != sha256_bytes(canonical_json_bytes(rebuilt_gate.as_dict()))
        ):
            return False
        # A non-inventory failure may also revoke VERIFIED.  The unsafe
        # direction is the converse: a blocked inventory can never be VERIFIED
        # and must remain explicit in the decision failure ledger.
        if not rebuilt_gate.passed and (
            decision_verified
            or not any(
                str(item).startswith("analysis_inventory_")
                for item in decision_failures
            )
        ):
            return False
        if not has_production_authority and (
            decision_status == AnalysisFinalStatus.VERIFIED.value
            or decision_verified is True
        ):
            return False
        present_production_files = {
            path for path in _PRODUCTION_ARCHIVE_FILES if (root / path).is_file()
        }
        if has_production_authority:
            if present_production_files != _PRODUCTION_ARCHIVE_FILES:
                return False
            admission = coerce_page_risk_admission(json.loads(
                (root / "audit" / "page_risk_admission.json").read_text(
                    encoding="utf-8"
                )
            ))
            page_inputs_archive = json.loads(
                (root / "audit" / "page_inputs.json").read_text(encoding="utf-8")
            )
            route_closure = _coerce_page_route_closure(json.loads(
                (root / "audit" / "page_route_closure.json").read_text(
                    encoding="utf-8"
                )
            ))
            risk_preflight_archive = json.loads(
                (root / "audit" / "risk_preflight.json").read_text(
                    encoding="utf-8"
                )
            )
            source_pdf_hash = sha256_bytes(
                (root / "inputs" / "source.pdf").read_bytes()
            )
            baseline_tex_hash = sha256_text(
                (root / "baseline" / "baseline.tex").read_text(encoding="utf-8")
            )
            baseline_pdf_hash = sha256_bytes(
                (root / "baseline" / "baseline.pdf").read_bytes()
            )
            current_tex_hash = sha256_text(
                (root / "candidates" / "round_001" / "candidate.tex").read_text(
                    encoding="utf-8"
                )
            )
            _validate_production_archive_payloads(
                snapshot=snapshot,
                page_risk_admission=admission,
                page_inputs_archive=page_inputs_archive,
                page_route_closure=route_closure,
                analysis_configuration_archive=configuration_archive,
                risk_preflight_archive=risk_preflight_archive,
                source_pdf_hash=source_pdf_hash,
                baseline_tex_hash=baseline_tex_hash,
                baseline_pdf_hash=baseline_pdf_hash,
                current_tex_hash=current_tex_hash,
            )
        elif present_production_files:
            return False
        if has_production_authority:
            accounting = _validate_production_analysis_semantics(
                authoritative_snapshot=snapshot,
                analysis_v2=verification.get("analysis_v2"),
            )
            _validate_performance_accounting(
                performance,
                accounting,
                label="archived",
            )
            closure_failures = _production_transport_closure_failures(accounting)
            required_failures = {
                "analysis_transport_evidence_incomplete",
                *closure_failures,
            }
            if closure_failures and (
                decision_status == AnalysisFinalStatus.VERIFIED.value
                or decision_verified is not False
                or not required_failures.issubset(decision_failures)
            ):
                return False
    except (
        OSError,
        UnicodeError,
        KeyError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
        AnalysisArchiveError,
    ):
        return False
    return True


__all__ = [
    "AnalysisArchiveError",
    "AnalysisRunArchiveResult",
    "AnalysisRunArtifacts",
    "ProductionAnalysisArchiveEvidence",
    "freeze_pipeline_analysis_run",
    "stable_source_page_id",
    "verify_frozen_analysis_run",
]

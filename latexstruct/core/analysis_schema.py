# -*- coding: utf-8 -*-
"""Host-owned contracts for the post-OCR continuous quality loop.

The objects in this module deliberately contain no model-facing authority.
Models may propose findings and patches, but the host creates identities,
binds every record to byte hashes, and derives the terminal status from
machine evidence.  Frozen dataclasses make a run snapshot and every page unit
safe to retain as immutable audit evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# This is a fixed acceptance benchmark, not a projection target for shorter
# books.  Keeping the policy host-owned prevents a fast sample run from being
# presented as evidence for the 600-page claim.
ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT = 600
ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS = 7200.0
ANALYSIS_RESPONSE_SCHEMA_VERSIONS = {
    "structure-findings": "latexstruct-analysis-finding-response-v2",
    "content-math-findings": "latexstruct-analysis-finding-response-v2",
    "visual-triage": "latexstruct-analysis-finding-response-v2",
    "visual-findings": "latexstruct-analysis-finding-response-v2",
    "structure-recheck": "latexstruct-analysis-finding-response-v2",
    "content-math-recheck": "latexstruct-analysis-finding-response-v2",
    "visual-recheck": "latexstruct-analysis-finding-response-v2",
    "local-patch": "latexstruct-analysis-patch-response-v2",
    "issue-review": "latexstruct-analysis-issue-review-response-v2",
    "final-review-1": "latexstruct-analysis-final-review-response-v2",
    "final-review-2": "latexstruct-analysis-final-review-response-v2",
    "adjudication": "latexstruct-analysis-adjudication-response-v2",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _require_digest(value: str, name: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _frozen_counts(value: Mapping[str, int] | Iterable[tuple[str, int]] | None) -> tuple:
    items = value.items() if isinstance(value, Mapping) else (value or ())
    output = []
    for key, count in items:
        if int(count) < 0:
            raise ValueError("counts cannot be negative")
        output.append((str(key), int(count)))
    return tuple(sorted(output))


class AnalysisFinalStatus(str, Enum):
    VERIFIED = "VERIFIED"
    COMPLETED_WITH_ISSUES = "COMPLETED_WITH_ISSUES"
    FAILED_BEST_RETAINED = "FAILED_BEST_RETAINED"


class PerformanceTargetStatus(str, Enum):
    NOT_EVALUATED = "NOT_EVALUATED"
    PASSED = "PASSED"
    FAILED = "FAILED"


class CompileState(str, Enum):
    COMPILED = "COMPILED"
    PARTIAL_COMPILED = "PARTIAL_COMPILED"
    SOURCE_PREVIEW = "SOURCE_PREVIEW"


class PageRisk(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


class PagePositionBand(str, Enum):
    FRONT = "FRONT"
    MIDDLE = "MIDDLE"
    BACK = "BACK"


class PageTriageOutcome(str, Enum):
    CLEAR = "CLEAR"
    ANOMALY = "ANOMALY"
    BLOCKED = "BLOCKED"


class PageStatus(str, Enum):
    PENDING = "PENDING"
    CHECKING = "CHECKING"
    CHECKED = "CHECKED"
    MODIFIED_PENDING_REVIEW = "MODIFIED_PENDING_REVIEW"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class IssueStatus(str, Enum):
    OPEN = "OPEN"
    FIXING = "FIXING"
    FIXED_PENDING_REVIEW = "FIXED_PENDING_REVIEW"
    VERIFIED_CLOSED = "VERIFIED_CLOSED"
    BLOCKED = "BLOCKED"
    REGRESSION = "REGRESSION"
    REJECTED_FALSE_POSITIVE = "REJECTED_FALSE_POSITIVE"


class ReviewResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNCERTAIN = "UNCERTAIN"
    REGRESSION = "REGRESSION"


class PatchOperationKind(str, Enum):
    REPLACE = "replace"
    INSERT_BEFORE = "insert_before"
    INSERT_AFTER = "insert_after"
    WRAP_ENVIRONMENT = "wrap_environment"
    UNWRAP_ENVIRONMENT = "unwrap_environment"


class CandidateDisposition(str, Enum):
    BASELINE = "BASELINE"
    ACCEPTED = "ACCEPTED"
    REJECTED_ROLLED_BACK = "REJECTED_ROLLED_BACK"


@dataclass(frozen=True, slots=True)
class ModelBinding:
    role: str
    model_id: str
    capabilities: tuple[str, ...] = ()
    reasoning_effort: str = ""

    def __post_init__(self) -> None:
        if not self.role.strip() or not self.model_id.strip():
            raise ValueError("model role and model_id are required")
        object.__setattr__(self, "capabilities", tuple(sorted(set(self.capabilities))))
        effort = str(self.reasoning_effort or "").strip().lower()
        if effort and effort not in {"low", "medium", "high", "xhigh"}:
            raise ValueError(
                "reasoning_effort must be low, medium, high, xhigh, or empty"
            )
        object.__setattr__(self, "reasoning_effort", effort)


@dataclass(frozen=True, slots=True)
class AnalysisTransportContract:
    """Sanitized, immutable transport semantics admitted into one run.

    The contract intentionally contains no endpoint, credential, local path, or
    prompt material.  It freezes only the non-secret facts needed to replay the
    role/operation binding and independently recompute conservative budget
    claims from the authoritative snapshot.
    """

    role: str
    model_id: str
    reasoning_effort: str
    operations: tuple[str, ...]
    client_type: str
    method: str
    max_retries: int
    max_tokens: int
    backend_authority_sha256: str
    backend_configuration_sha256: str

    def __post_init__(self) -> None:
        role = str(self.role or "").strip()
        model_id = str(self.model_id or "").strip()
        client_type = str(self.client_type or "").strip()
        method = str(self.method or "").strip()
        effort = str(self.reasoning_effort or "").strip().lower()
        if not role or not model_id or not client_type or not method:
            raise ValueError("transport role/model/client/method are required")
        if effort and effort not in {"low", "medium", "high", "xhigh"}:
            raise ValueError(
                "transport reasoning_effort must be low, medium, high, xhigh, or empty"
            )
        operations = tuple(str(item or "").strip() for item in self.operations)
        if (
            not operations
            or any(not item for item in operations)
            or len(operations) != len(set(operations))
            or operations != tuple(sorted(operations))
        ):
            raise ValueError("transport operations must be non-empty, unique, and sorted")
        for name in ("max_retries", "max_tokens"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"transport {name} must be a non-negative integer")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "model_id", model_id)
        object.__setattr__(self, "reasoning_effort", effort)
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "client_type", client_type)
        object.__setattr__(self, "method", method)
        object.__setattr__(
            self,
            "backend_authority_sha256",
            _require_digest(
                self.backend_authority_sha256, "backend_authority_sha256"
            ),
        )
        object.__setattr__(
            self,
            "backend_configuration_sha256",
            _require_digest(
                self.backend_configuration_sha256,
                "backend_configuration_sha256",
            ),
        )


@dataclass(frozen=True, slots=True)
class PageRiskInputSummary:
    """Content-free deterministic inputs used by the page-risk classifier."""

    source_page_id: str
    source_page_number: int
    source_page_object_hash: str
    source_pdf_text_hash: str
    baseline_tex_region_hash: str
    baseline_plain_text_hash: str
    baseline_tex_bytes: int
    candidate_page_count: int
    candidate_page_ids_hash: str
    ocr_coverage_hash: str
    ocr_coverage_all_pass: bool
    ocr_final_success: bool
    ocr_retry_count: int
    ocr_quality_issue_count: int
    ocr_quality_issues_hash: str
    host_quality_flag_count: int
    host_quality_flags_hash: str
    machine_visual_anomaly_count: int
    machine_visual_anomalies_hash: str
    section_id: str
    position_band: PagePositionBand
    syntax_balanced: bool
    compile_map_mismatch: bool
    compile_map_evidence_hash: str
    double_column: bool
    complex_layout: bool
    layout_evidence_hash: str
    required_evidence_missing: tuple[str, ...]
    source_text_token_count: int
    baseline_text_token_count: int
    source_text_covered_token_count: int
    source_text_coverage_ppm: int
    text_layer_unavailable: bool
    unresolved_region_count: int
    unresolved_region_hashes_hash: str
    math_region_count: int
    equation_number_count: int
    formal_candidate_count: int
    figure_table_count: int
    caption_count: int
    footnote_count: int
    cross_reference_count: int
    heading_count: int
    hard_page_break_count: int
    boundary_count: int

    def __post_init__(self) -> None:
        if not str(self.source_page_id or "").strip():
            raise ValueError("page-risk summary requires source_page_id")
        if type(self.source_page_number) is not int or self.source_page_number < 1:
            raise ValueError("page-risk summary requires a positive page number")
        for name in (
            "source_page_object_hash",
            "source_pdf_text_hash",
            "baseline_tex_region_hash",
            "baseline_plain_text_hash",
            "candidate_page_ids_hash",
            "compile_map_evidence_hash",
            "ocr_coverage_hash",
            "ocr_quality_issues_hash",
            "host_quality_flags_hash",
            "layout_evidence_hash",
            "machine_visual_anomalies_hash",
            "unresolved_region_hashes_hash",
        ):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))
        if not str(self.section_id or "").strip():
            raise ValueError("page-risk summary requires a stable section_id")
        object.__setattr__(self, "section_id", str(self.section_id).strip())
        try:
            band = (
                self.position_band
                if isinstance(self.position_band, PagePositionBand)
                else PagePositionBand(str(self.position_band))
            )
        except ValueError as exc:
            raise ValueError("page-risk position band is invalid") from exc
        object.__setattr__(self, "position_band", band)
        for name in (
            "syntax_balanced",
            "ocr_coverage_all_pass",
            "ocr_final_success",
            "compile_map_mismatch",
            "double_column",
            "complex_layout",
            "text_layer_unavailable",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"page-risk {name} must be a boolean")
        missing = tuple(str(item or "").strip() for item in self.required_evidence_missing)
        if any(not item for item in missing) or missing != tuple(sorted(set(missing))):
            raise ValueError(
                "page-risk missing evidence fields must be unique and sorted"
            )
        object.__setattr__(self, "required_evidence_missing", missing)
        for name in (
            "baseline_tex_bytes",
            "candidate_page_count",
            "ocr_retry_count",
            "ocr_quality_issue_count",
            "host_quality_flag_count",
            "machine_visual_anomaly_count",
            "source_text_token_count",
            "baseline_text_token_count",
            "source_text_covered_token_count",
            "source_text_coverage_ppm",
            "unresolved_region_count",
            "math_region_count",
            "equation_number_count",
            "formal_candidate_count",
            "figure_table_count",
            "caption_count",
            "footnote_count",
            "cross_reference_count",
            "heading_count",
            "hard_page_break_count",
            "boundary_count",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"page-risk {name} must be a non-negative integer")
        if self.source_text_coverage_ppm > 1_000_000:
            raise ValueError("page-risk source text coverage exceeds one million ppm")
        if self.source_text_covered_token_count > self.source_text_token_count:
            raise ValueError("page-risk covered source tokens exceed the source total")

    def canonical_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["position_band"] = self.position_band.value
        return payload

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class PageRiskAdmissionPage:
    summary: PageRiskInputSummary
    summary_sha256: str
    risk_level: PageRisk
    risk_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        summary = self.summary
        if not isinstance(summary, PageRiskInputSummary):
            if not isinstance(summary, Mapping):
                raise ValueError("page-risk admission summary is invalid")
            summary = PageRiskInputSummary(**dict(summary))
            object.__setattr__(self, "summary", summary)
        digest = _require_digest(self.summary_sha256, "summary_sha256")
        if digest != summary.digest:
            raise ValueError("page-risk admission summary hash is forged")
        object.__setattr__(self, "summary_sha256", digest)
        try:
            risk = (
                self.risk_level
                if isinstance(self.risk_level, PageRisk)
                else PageRisk(str(self.risk_level))
            )
        except ValueError as exc:
            raise ValueError("page-risk admission level is invalid") from exc
        reasons = tuple(str(item or "").strip() for item in self.risk_reasons)
        if not reasons or any(not item for item in reasons) or reasons != tuple(sorted(set(reasons))):
            raise ValueError("page-risk reasons must be non-empty, unique, and sorted")
        object.__setattr__(self, "risk_level", risk)
        object.__setattr__(self, "risk_reasons", reasons)

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "summary": self.summary.canonical_payload(),
            "summary_sha256": self.summary_sha256,
            "risk_level": self.risk_level.value,
            "risk_reasons": list(self.risk_reasons),
        }


@dataclass(frozen=True, slots=True)
class LowRiskSamplingPolicy:
    schema_version: str = "latexstruct-low-risk-sampling-policy-v1"
    rate_numerator: int = 5
    rate_denominator: int = 100
    minimum_pages: int = 30
    position_bands: tuple[str, ...] = ("FRONT", "MIDDLE", "BACK")
    selection_algorithm: str = "mandatory-strata-then-canonical-sha256-rank-v1"
    seed_algorithm: str = "canonical-json-sha256-v1"

    def __post_init__(self) -> None:
        if self.schema_version != "latexstruct-low-risk-sampling-policy-v1":
            raise ValueError("unsupported low-risk sampling policy")
        for name in ("rate_numerator", "rate_denominator", "minimum_pages"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"low-risk {name} must be a non-negative integer")
        if self.rate_denominator < 1 or self.rate_numerator > self.rate_denominator:
            raise ValueError("low-risk sampling rate is invalid")
        bands = tuple(str(item) for item in self.position_bands)
        if bands != tuple(item.value for item in PagePositionBand):
            raise ValueError("low-risk sampling must cover FRONT/MIDDLE/BACK")
        object.__setattr__(self, "position_bands", bands)
        if (
            self.selection_algorithm
            != "mandatory-strata-then-canonical-sha256-rank-v1"
            or self.seed_algorithm != "canonical-json-sha256-v1"
        ):
            raise ValueError("unsupported low-risk sampling algorithm")

    def canonical_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["position_bands"] = list(self.position_bands)
        return payload

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class LowRiskSamplingSeed:
    source_pdf_sha256: str
    ocr_page_records_sha256: str
    ocr_runtime_page_records_sha256: str
    baseline_tex_sha256: str
    classifier_policy_sha256: str
    page_ids_sha256: str
    schema_version: str = "latexstruct-low-risk-sampling-seed-v1"

    def __post_init__(self) -> None:
        if self.schema_version != "latexstruct-low-risk-sampling-seed-v1":
            raise ValueError("unsupported low-risk seed schema")
        for name in (
            "source_pdf_sha256",
            "ocr_page_records_sha256",
            "ocr_runtime_page_records_sha256",
            "baseline_tex_sha256",
            "classifier_policy_sha256",
            "page_ids_sha256",
        ):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))

    def canonical_payload(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class LowRiskSamplingEvidence:
    policy: LowRiskSamplingPolicy
    policy_sha256: str
    seed_material: LowRiskSamplingSeed
    seed_sha256: str
    population_page_ids: tuple[str, ...]
    population_page_ids_sha256: str
    mandatory_page_ids: tuple[str, ...]
    mandatory_page_ids_sha256: str
    target_count: int
    selected_page_ids: tuple[str, ...]
    selected_page_ids_sha256: str
    all_low_risk_selected: bool
    schema_version: str = "latexstruct-low-risk-sampling-evidence-v1"

    def __post_init__(self) -> None:
        if self.schema_version != "latexstruct-low-risk-sampling-evidence-v1":
            raise ValueError("unsupported low-risk sampling evidence")
        policy = self.policy
        if not isinstance(policy, LowRiskSamplingPolicy):
            if not isinstance(policy, Mapping):
                raise ValueError("low-risk policy is invalid")
            policy = LowRiskSamplingPolicy(**dict(policy))
            object.__setattr__(self, "policy", policy)
        seed = self.seed_material
        if not isinstance(seed, LowRiskSamplingSeed):
            if not isinstance(seed, Mapping):
                raise ValueError("low-risk seed material is invalid")
            seed = LowRiskSamplingSeed(**dict(seed))
            object.__setattr__(self, "seed_material", seed)
        if _require_digest(self.policy_sha256, "policy_sha256") != policy.digest:
            raise ValueError("low-risk policy hash is forged")
        if _require_digest(self.seed_sha256, "seed_sha256") != seed.digest:
            raise ValueError("low-risk seed hash is forged")
        object.__setattr__(self, "policy_sha256", policy.digest)
        object.__setattr__(self, "seed_sha256", seed.digest)
        population = tuple(self.population_page_ids)
        mandatory = tuple(self.mandatory_page_ids)
        selected = tuple(self.selected_page_ids)
        for name, values, digest in (
            ("population_page_ids", population, self.population_page_ids_sha256),
            ("mandatory_page_ids", mandatory, self.mandatory_page_ids_sha256),
            ("selected_page_ids", selected, self.selected_page_ids_sha256),
        ):
            if len(values) != len(set(values)) or any(not str(item).strip() for item in values):
                raise ValueError(f"{name} must contain unique non-empty ids")
            expected = sha256_bytes(canonical_json_bytes(list(values)))
            if _require_digest(digest, f"{name}_sha256") != expected:
                raise ValueError(f"{name} digest is forged")
            object.__setattr__(self, name, values)
            object.__setattr__(self, f"{name}_sha256", expected)
        if not set(mandatory).issubset(selected) or not set(selected).issubset(population):
            raise ValueError("low-risk sample sets are not nested")
        if type(self.target_count) is not int or self.target_count != len(selected):
            raise ValueError("low-risk target_count differs from the selected set")
        if type(self.all_low_risk_selected) is not bool or self.all_low_risk_selected != (
            len(selected) == len(population)
        ):
            raise ValueError("low-risk all-selected flag is invalid")

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy": self.policy.canonical_payload(),
            "policy_sha256": self.policy_sha256,
            "seed_material": self.seed_material.canonical_payload(),
            "seed_sha256": self.seed_sha256,
            "population_page_ids": list(self.population_page_ids),
            "population_page_ids_sha256": self.population_page_ids_sha256,
            "mandatory_page_ids": list(self.mandatory_page_ids),
            "mandatory_page_ids_sha256": self.mandatory_page_ids_sha256,
            "target_count": self.target_count,
            "selected_page_ids": list(self.selected_page_ids),
            "selected_page_ids_sha256": self.selected_page_ids_sha256,
            "all_low_risk_selected": self.all_low_risk_selected,
        }


@dataclass(frozen=True, slots=True)
class PageRiskAdmission:
    source_pdf_sha256: str
    ocr_page_records_sha256: str
    ocr_runtime_page_records_sha256: str
    baseline_tex_sha256: str
    baseline_pdf_sha256: str
    classifier_policy_sha256: str
    page_ids_sha256: str
    pages: tuple[PageRiskAdmissionPage, ...]
    low_risk_sampling: LowRiskSamplingEvidence
    schema_version: str = "latexstruct-analysis-page-risk-admission-v2"
    strategy: str = "deterministic-preflight-and-fixed-low-risk-sampling-v2"
    classifier_version: str = "latexstruct-page-risk-classifier-v2"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "latexstruct-analysis-page-risk-admission-v2"
            or self.strategy != "deterministic-preflight-and-fixed-low-risk-sampling-v2"
            or self.classifier_version != "latexstruct-page-risk-classifier-v2"
        ):
            raise ValueError("unsupported page-risk admission contract")
        for name in (
            "source_pdf_sha256",
            "ocr_page_records_sha256",
            "ocr_runtime_page_records_sha256",
            "baseline_tex_sha256",
            "baseline_pdf_sha256",
            "classifier_policy_sha256",
            "page_ids_sha256",
        ):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))
        pages: list[PageRiskAdmissionPage] = []
        for value in self.pages:
            if isinstance(value, PageRiskAdmissionPage):
                page = value
            elif isinstance(value, Mapping):
                raw = dict(value)
                page = PageRiskAdmissionPage(
                    summary=raw["summary"],
                    summary_sha256=raw["summary_sha256"],
                    risk_level=raw["risk_level"],
                    risk_reasons=tuple(raw["risk_reasons"]),
                )
            else:
                raise ValueError("page-risk admission page is invalid")
            pages.append(page)
        page_tuple = tuple(pages)
        numbers = tuple(item.summary.source_page_number for item in page_tuple)
        ids = tuple(item.summary.source_page_id for item in page_tuple)
        if (
            not page_tuple
            or numbers != tuple(sorted(numbers))
            or len(numbers) != len(set(numbers))
            or len(ids) != len(set(ids))
        ):
            raise ValueError("page-risk admission pages must be non-empty, unique, and ordered")
        expected_ids_hash = sha256_bytes(canonical_json_bytes(list(ids)))
        if self.page_ids_sha256 != expected_ids_hash:
            raise ValueError("page-risk page-id digest is forged")
        sample = self.low_risk_sampling
        if not isinstance(sample, LowRiskSamplingEvidence):
            if not isinstance(sample, Mapping):
                raise ValueError("low-risk sampling evidence is invalid")
            raw_sample = dict(sample)
            sample = LowRiskSamplingEvidence(**raw_sample)
            object.__setattr__(self, "low_risk_sampling", sample)
        low_ids = tuple(
            item.summary.source_page_id
            for item in page_tuple
            if item.risk_level in {PageRisk.R0, PageRisk.R1}
        )
        if sample.population_page_ids != low_ids:
            raise ValueError("low-risk population differs from admitted R0/R1 pages")
        if sample.seed_material.source_pdf_sha256 != self.source_pdf_sha256 or (
            sample.seed_material.ocr_page_records_sha256
            != self.ocr_page_records_sha256
        ) or sample.seed_material.baseline_tex_sha256 != self.baseline_tex_sha256 or (
            sample.seed_material.ocr_runtime_page_records_sha256
            != self.ocr_runtime_page_records_sha256
        ) or (
            sample.seed_material.classifier_policy_sha256
            != self.classifier_policy_sha256
        ) or sample.seed_material.page_ids_sha256 != self.page_ids_sha256:
            raise ValueError("low-risk seed is not bound to this admission")
        if sample.policy_sha256 != sample.policy.digest:
            raise ValueError("low-risk policy binding is invalid")
        object.__setattr__(self, "pages", page_tuple)
        object.__setattr__(self, "page_ids_sha256", expected_ids_hash)

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "strategy": self.strategy,
            "classifier_version": self.classifier_version,
            "source_pdf_sha256": self.source_pdf_sha256,
            "ocr_page_records_sha256": self.ocr_page_records_sha256,
            "ocr_runtime_page_records_sha256": (
                self.ocr_runtime_page_records_sha256
            ),
            "baseline_tex_sha256": self.baseline_tex_sha256,
            "baseline_pdf_sha256": self.baseline_pdf_sha256,
            "classifier_policy_sha256": self.classifier_policy_sha256,
            "page_ids_sha256": self.page_ids_sha256,
            "pages": [item.canonical_payload() for item in self.pages],
            "low_risk_sampling": self.low_risk_sampling.canonical_payload(),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        payload["admission_sha256"] = self.digest
        return payload

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class PageRouteCallKey:
    role: str
    operation: str
    source_page_id: str
    candidate_hash: str
    issue_id: str
    snapshot_hash: str
    response_schema_version: str
    succeeded: bool

    def __post_init__(self) -> None:
        for name in ("role", "operation", "source_page_id", "issue_id", "response_schema_version"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"route call {name} is required")
            object.__setattr__(self, name, value)
        for name in ("candidate_hash", "snapshot_hash"):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))
        if type(self.succeeded) is not bool:
            raise ValueError("route call succeeded must be a boolean")

    def canonical_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PageRouteRecord:
    source_page_id: str
    source_page_number: int
    admitted_risk: PageRisk
    triage_outcome: PageTriageOutcome
    triage_response_sha256: str
    effective_risk: PageRisk
    modified: bool
    anomaly_reasons: tuple[str, ...]
    sampled_low_risk: bool
    deep_review_required: bool
    final_candidate_hash: str

    def __post_init__(self) -> None:
        if not str(self.source_page_id or "").strip():
            raise ValueError("route record requires source_page_id")
        if type(self.source_page_number) is not int or self.source_page_number < 1:
            raise ValueError("route record requires a positive page number")
        try:
            admitted = (
                self.admitted_risk
                if isinstance(self.admitted_risk, PageRisk)
                else PageRisk(str(self.admitted_risk))
            )
            effective = (
                self.effective_risk
                if isinstance(self.effective_risk, PageRisk)
                else PageRisk(str(self.effective_risk))
            )
            triage = (
                self.triage_outcome
                if isinstance(self.triage_outcome, PageTriageOutcome)
                else PageTriageOutcome(str(self.triage_outcome))
            )
        except ValueError as exc:
            raise ValueError("route risk or triage outcome is invalid") from exc
        risk_order = {PageRisk.R0: 0, PageRisk.R1: 1, PageRisk.R2: 2, PageRisk.R3: 3}
        if risk_order[effective] < risk_order[admitted]:
            raise ValueError("triage may not downgrade an admitted page risk")
        if triage == PageTriageOutcome.ANOMALY and risk_order[effective] < 2:
            raise ValueError("an anomalous page must be at least R2")
        if triage == PageTriageOutcome.BLOCKED and effective != PageRisk.R3:
            raise ValueError("a blocked triage page must be R3")
        for name in ("modified", "sampled_low_risk", "deep_review_required"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"route {name} must be a boolean")
        reasons = tuple(str(item or "").strip() for item in self.anomaly_reasons)
        if any(not item for item in reasons) or reasons != tuple(sorted(set(reasons))):
            raise ValueError("route anomaly reasons must be unique and sorted")
        if triage != PageTriageOutcome.CLEAR and not reasons:
            raise ValueError("non-clear triage requires anomaly reasons")
        if self.deep_review_required != (
            effective in {PageRisk.R2, PageRisk.R3}
            or self.modified
            or self.sampled_low_risk
            or bool(reasons)
        ):
            raise ValueError("route deep-review flag is not host-derived")
        object.__setattr__(self, "admitted_risk", admitted)
        object.__setattr__(self, "effective_risk", effective)
        object.__setattr__(self, "triage_outcome", triage)
        object.__setattr__(self, "anomaly_reasons", reasons)
        object.__setattr__(
            self,
            "triage_response_sha256",
            _require_digest(self.triage_response_sha256, "triage_response_sha256"),
        )
        object.__setattr__(
            self,
            "final_candidate_hash",
            _require_digest(self.final_candidate_hash, "final_candidate_hash"),
        )

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "source_page_id": self.source_page_id,
            "source_page_number": self.source_page_number,
            "admitted_risk": self.admitted_risk.value,
            "triage_outcome": self.triage_outcome.value,
            "triage_response_sha256": self.triage_response_sha256,
            "effective_risk": self.effective_risk.value,
            "modified": self.modified,
            "anomaly_reasons": list(self.anomaly_reasons),
            "sampled_low_risk": self.sampled_low_risk,
            "deep_review_required": self.deep_review_required,
            "final_candidate_hash": self.final_candidate_hash,
        }


@dataclass(frozen=True, slots=True)
class PageRiskRouteClosure:
    admission_sha256: str
    final_candidate_hash: str
    pages: tuple[PageRouteRecord, ...]
    route_call_keys: tuple[PageRouteCallKey, ...]
    schema_version: str = "latexstruct-analysis-page-route-closure-v2"

    def __post_init__(self) -> None:
        if self.schema_version != "latexstruct-analysis-page-route-closure-v2":
            raise ValueError("unsupported page-route closure schema")
        object.__setattr__(
            self,
            "admission_sha256",
            _require_digest(self.admission_sha256, "admission_sha256"),
        )
        final_hash = _require_digest(self.final_candidate_hash, "final_candidate_hash")
        object.__setattr__(self, "final_candidate_hash", final_hash)
        pages = tuple(self.pages)
        numbers = tuple(item.source_page_number for item in pages)
        ids = tuple(item.source_page_id for item in pages)
        if (
            not pages
            or numbers != tuple(sorted(numbers))
            or len(numbers) != len(set(numbers))
            or len(ids) != len(set(ids))
            or any(item.final_candidate_hash != final_hash for item in pages)
        ):
            raise ValueError("route pages must be complete, ordered, and final-candidate bound")
        calls = tuple(self.route_call_keys)
        call_payloads = [item.canonical_payload() for item in calls]
        if call_payloads != sorted(
            call_payloads,
            key=lambda item: (
                item["role"],
                item["operation"],
                item["source_page_id"],
                item["candidate_hash"],
                item["issue_id"],
            ),
        ):
            raise ValueError("route call keys must use canonical order")
        object.__setattr__(self, "pages", pages)
        object.__setattr__(self, "route_call_keys", calls)

    @property
    def pages_sha256(self) -> str:
        return sha256_bytes(
            canonical_json_bytes([item.canonical_payload() for item in self.pages])
        )

    @property
    def route_call_keys_sha256(self) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                [item.canonical_payload() for item in self.route_call_keys]
            )
        )

    @property
    def risk_counts(self) -> dict[str, dict[str, int]]:
        admitted = {risk.value: 0 for risk in PageRisk}
        effective = {risk.value: 0 for risk in PageRisk}
        for item in self.pages:
            admitted[item.admitted_risk.value] += 1
            effective[item.effective_risk.value] += 1
        return {"admitted": admitted, "effective": effective}

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "admission_sha256": self.admission_sha256,
            "final_candidate_hash": self.final_candidate_hash,
            "pages": [item.canonical_payload() for item in self.pages],
            "pages_sha256": self.pages_sha256,
            "risk_counts": self.risk_counts,
            "route_call_keys": [
                item.canonical_payload() for item in self.route_call_keys
            ],
            "route_call_keys_sha256": self.route_call_keys_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        payload["closure_sha256"] = self.digest
        return payload

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class PageMapEntry:
    source_page_id: str
    source_page_number: int
    tex_page_marker: str
    candidate_pdf_page_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.source_page_id or self.source_page_number < 1:
            raise ValueError("page mapping requires a stable page id and positive number")
        if not self.tex_page_marker.strip():
            raise ValueError("page mapping requires a TeX page marker")
        pages = tuple(self.candidate_pdf_page_ids)
        if not pages or len(pages) != len(set(pages)):
            raise ValueError("candidate PDF page ids must be non-empty and unique")
        object.__setattr__(self, "candidate_pdf_page_ids", pages)


@dataclass(frozen=True, slots=True)
class AnalysisEvidenceHashes:
    """Hash-only closure of production evidence admitted into one run.

    Legacy/unit-test snapshots may omit this object.  The production bridge
    requires every member before it can create a model call.  Keeping the
    values in one typed object makes the snapshot digest bind both the native
    OCR package and the exact analysis configuration without copying local
    paths or mutable manifests into model requests.
    """

    ocr_baseline_manifest_hash: str
    ocr_page_records_hash: str
    ocr_runtime_page_records_hash: str
    ocr_page_map_hash: str
    ocr_baseline_compile_inputs_hash: str
    baseline_compile_inputs_hash: str
    build_identity_hash: str
    page_risk_admission_hash: str
    response_schema_hash: str
    analysis_config_hash: str
    budget_summary_hash: str

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))


@dataclass(frozen=True, slots=True)
class AnalysisRunSnapshot:
    """Immutable facts captured before any analysis model is called."""

    run_id: str
    project_id: str
    workflow_version: str
    prompt_version: str
    application_version: str
    source_pdf_hash: str
    raw_ocr_tex_hash: str
    baseline_tex_hash: str
    baseline_pdf_hash: str
    page_count: int
    page_range: tuple[int, ...]
    latex_engine: str
    models: tuple[ModelBinding, ...]
    concurrency_limit: int
    started_at: str
    performance_target_seconds: float = 7200.0
    max_input_tokens: int = 0
    max_output_tokens: int = 0
    max_cost: float = 0.0
    max_requests: int = 0
    max_strong_model_calls: int = 0
    max_wall_time_minutes: float = 120.0
    transport_contracts: tuple[AnalysisTransportContract, ...] = ()
    page_map: tuple[PageMapEntry, ...] = ()
    initial_compile_state: CompileState = CompileState.COMPILED
    initial_issue_counts: tuple[tuple[str, int], ...] = ()
    config_hash: str = ""
    evidence_hashes: AnalysisEvidenceHashes | None = None

    def __post_init__(self) -> None:
        if not self.run_id.strip() or not self.project_id.strip():
            raise ValueError("run_id and project_id are required")
        for name in (
            "source_pdf_hash",
            "raw_ocr_tex_hash",
            "baseline_tex_hash",
            "baseline_pdf_hash",
        ):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))
        if self.page_count < 1:
            raise ValueError("page_count must be positive")
        page_range = tuple(int(page) for page in self.page_range)
        if (
            not page_range
            or len(page_range) != len(set(page_range))
            or tuple(sorted(page_range)) != page_range
            or page_range[0] < 1
            or page_range[-1] > self.page_count
        ):
            raise ValueError("page_range must be unique, ordered, and within page_count")
        models = tuple(self.models)
        if not models or len({model.role for model in models}) != len(models):
            raise ValueError("models must contain one binding per role")
        if not 1 <= self.concurrency_limit <= 64:
            raise ValueError("concurrency_limit is outside the safe host range")
        if self.performance_target_seconds <= 0:
            raise ValueError("performance target must be positive")
        for name in (
            "max_input_tokens",
            "max_output_tokens",
            "max_requests",
            "max_strong_model_calls",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if isinstance(self.max_cost, bool) or not isinstance(self.max_cost, (int, float)):
            raise ValueError("max_cost must be a non-negative number")
        if not math.isfinite(float(self.max_cost)) or float(self.max_cost) < 0:
            raise ValueError("max_cost must be a non-negative finite number")
        if (
            isinstance(self.max_wall_time_minutes, bool)
            or not isinstance(self.max_wall_time_minutes, (int, float))
            or not math.isfinite(float(self.max_wall_time_minutes))
            or float(self.max_wall_time_minutes) <= 0
        ):
            raise ValueError("max_wall_time_minutes must be a positive finite number")
        object.__setattr__(self, "max_cost", float(self.max_cost))
        object.__setattr__(
            self, "max_wall_time_minutes", float(self.max_wall_time_minutes)
        )
        page_map = tuple(self.page_map)
        map_ids = [entry.source_page_id for entry in page_map]
        map_numbers = [entry.source_page_number for entry in page_map]
        if page_map and (
            len(map_ids) != len(set(map_ids))
            or len(map_numbers) != len(set(map_numbers))
            or set(map_numbers) != set(page_range)
        ):
            raise ValueError("page map must cover the frozen page range exactly once")
        object.__setattr__(self, "page_range", page_range)
        object.__setattr__(self, "models", models)
        contracts: list[AnalysisTransportContract] = []
        for value in self.transport_contracts:
            if isinstance(value, AnalysisTransportContract):
                contract = value
            elif isinstance(value, Mapping):
                contract = AnalysisTransportContract(**dict(value))
            else:
                raise ValueError(
                    "transport_contracts must contain AnalysisTransportContract objects"
                )
            contracts.append(contract)
        contract_tuple = tuple(contracts)
        contract_roles = [item.role for item in contract_tuple]
        if len(contract_roles) != len(set(contract_roles)):
            raise ValueError("transport contracts must contain one contract per role")
        model_by_role = {item.role: item for item in models}
        if contract_tuple and set(contract_roles) != set(model_by_role):
            raise ValueError("transport contracts must cover the frozen model roles exactly")
        for contract in contract_tuple:
            model = model_by_role[contract.role]
            if (
                contract.model_id != model.model_id
                or contract.reasoning_effort != model.reasoning_effort
            ):
                raise ValueError(
                    "transport contract differs from its frozen model binding"
                )
        object.__setattr__(self, "transport_contracts", contract_tuple)
        object.__setattr__(self, "page_map", page_map)
        object.__setattr__(self, "initial_issue_counts", _frozen_counts(self.initial_issue_counts))
        if self.config_hash:
            object.__setattr__(self, "config_hash", _require_digest(self.config_hash, "config_hash"))
        evidence = self.evidence_hashes
        if evidence is not None and not isinstance(evidence, AnalysisEvidenceHashes):
            if not isinstance(evidence, Mapping):
                raise ValueError("evidence_hashes must be an AnalysisEvidenceHashes object")
            evidence = AnalysisEvidenceHashes(**dict(evidence))
            object.__setattr__(self, "evidence_hashes", evidence)
        if evidence is not None:
            if not self.config_hash:
                raise ValueError("production evidence requires config_hash")
            if evidence.analysis_config_hash != self.config_hash:
                raise ValueError("analysis evidence config hash differs from snapshot config")
            if not contract_tuple:
                raise ValueError("production evidence requires transport contracts")

    def stale_reasons(
        self,
        *,
        source_pdf_hash: str,
        raw_ocr_tex_hash: str,
        baseline_tex_hash: str,
        page_range: Sequence[int],
    ) -> tuple[str, ...]:
        checks = (
            ("source_pdf_hash", self.source_pdf_hash, source_pdf_hash),
            ("raw_ocr_tex_hash", self.raw_ocr_tex_hash, raw_ocr_tex_hash),
            ("baseline_tex_hash", self.baseline_tex_hash, baseline_tex_hash),
        )
        reasons = [name for name, frozen, current in checks if frozen != str(current).lower()]
        if self.page_range != tuple(page_range):
            reasons.append("page_range")
        return tuple(reasons)

    @property
    def performance_benchmark_eligible(self) -> bool:
        """Whether this snapshot represents the complete fixed benchmark.

        The historical ``performance_target_seconds`` field remains readable
        for old snapshots.  Only a full 600-page run using the 120-minute
        threshold is eligible for the current benchmark conclusion.
        """

        return (
            self.page_count == ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT
            and len(self.page_range) == ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT
            and self.performance_target_seconds
            == ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS
        )

    def canonical_payload(self) -> dict[str, Any]:
        """Return the fields covered by :attr:`snapshot_hash`."""

        payload = asdict(self)
        payload["initial_compile_state"] = self.initial_compile_state.value
        return payload

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        payload["snapshot_hash"] = self.snapshot_hash
        return payload

    @property
    def snapshot_hash(self) -> str:
        """Canonical digest of every immutable snapshot fact."""

        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))

    def require_production_evidence(self) -> AnalysisEvidenceHashes:
        """Return the complete evidence closure or fail before model work."""

        evidence = self.evidence_hashes
        if evidence is None:
            raise ValueError("production analysis snapshot is missing evidence hashes")
        return evidence


@dataclass(frozen=True, slots=True)
class TexAnchor:
    anchor_id: str
    start_offset: int
    end_offset: int
    text_hash: str

    def __post_init__(self) -> None:
        if not self.anchor_id.strip() or self.start_offset < 0 or self.end_offset < self.start_offset:
            raise ValueError("invalid TeX anchor")
        object.__setattr__(self, "text_hash", _require_digest(self.text_hash, "text_hash"))

    def overlaps(self, other: "TexAnchor") -> bool:
        if self.anchor_id == other.anchor_id:
            return True
        return self.start_offset < other.end_offset and other.start_offset < self.end_offset


@dataclass(frozen=True, slots=True)
class PdfRegion:
    source_page_id: str
    x0: float
    y0: float
    x1: float
    y1: float

    def __post_init__(self) -> None:
        if not self.source_page_id or self.x1 <= self.x0 or self.y1 <= self.y0:
            raise ValueError("invalid PDF evidence region")

    def overlaps(self, other: "PdfRegion", *, threshold: float = 0.3) -> bool:
        if self.source_page_id != other.source_page_id:
            return False
        x = max(0.0, min(self.x1, other.x1) - max(self.x0, other.x0))
        y = max(0.0, min(self.y1, other.y1) - max(self.y0, other.y0))
        intersection = x * y
        smallest = min(
            (self.x1 - self.x0) * (self.y1 - self.y0),
            (other.x1 - other.x0) * (other.y1 - other.y0),
        )
        return bool(smallest and intersection / smallest >= threshold)


@dataclass(frozen=True, slots=True)
class PageUnit:
    source_page_id: str
    source_page_number: int
    source_page_hash: str
    baseline_tex_start_anchor: str
    baseline_tex_end_anchor: str
    current_tex_start_anchor: str
    current_tex_end_anchor: str
    candidate_pdf_page_ids: tuple[str, ...]
    source_text_layer: str = ""
    source_image_paths: tuple[str, ...] = ()
    current_render_paths: tuple[str, ...] = ()
    detected_headings: tuple[str, ...] = ()
    formal_candidates: tuple[str, ...] = ()
    formula_signatures: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    footnotes: tuple[str, ...] = ()
    risk_level: PageRisk = PageRisk.R0
    risk_reasons: tuple[str, ...] = ()
    last_checked_candidate_hash: str = ""
    current_status: PageStatus = PageStatus.PENDING

    def __post_init__(self) -> None:
        if not self.source_page_id or self.source_page_number < 1:
            raise ValueError("PageUnit requires a stable page id and page number")
        object.__setattr__(self, "source_page_hash", _require_digest(
            self.source_page_hash, "source_page_hash"
        ))
        for name in (
            "candidate_pdf_page_ids",
            "source_image_paths",
            "current_render_paths",
            "detected_headings",
            "formal_candidates",
            "formula_signatures",
            "labels",
            "references",
            "citations",
            "footnotes",
            "risk_reasons",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not self.baseline_tex_start_anchor or not self.baseline_tex_end_anchor:
            raise ValueError("baseline TeX anchors are required")
        if not self.current_tex_start_anchor or not self.current_tex_end_anchor:
            raise ValueError("current TeX anchors are required")
        if self.last_checked_candidate_hash:
            object.__setattr__(self, "last_checked_candidate_hash", _require_digest(
                self.last_checked_candidate_hash, "last_checked_candidate_hash"
            ))

    def checked(self, candidate_hash: str, *, verified: bool = False) -> "PageUnit":
        return replace(
            self,
            last_checked_candidate_hash=_require_digest(candidate_hash, "candidate_hash"),
            current_status=PageStatus.VERIFIED if verified else PageStatus.CHECKED,
        )


@dataclass(frozen=True, slots=True)
class IssueProposal:
    """A model proposal with deliberately no ``issue_id`` field."""

    issue_type: str
    severity: Severity
    source_page_ids: tuple[str, ...]
    tex_anchors: tuple[TexAnchor, ...]
    source_pdf_regions: tuple[PdfRegion, ...] = ()
    detector_role: str = ""
    evidence_hashes: tuple[str, ...] = ()
    baseline_hash: str = ""
    candidate_hash: str = ""
    description: str = ""
    blocker_reason: str = ""

    def __post_init__(self) -> None:
        if not self.issue_type.strip() or not self.detector_role.strip():
            raise ValueError("issue type and detector role are required")
        pages = tuple(sorted(set(self.source_page_ids)))
        if not pages:
            raise ValueError("an issue must be bound to at least one source page")
        anchors = tuple(self.tex_anchors)
        regions = tuple(self.source_pdf_regions)
        if not anchors and not regions:
            raise ValueError("an issue requires TeX anchors or a PDF evidence region")
        evidence = tuple(sorted({_require_digest(item, "evidence_hash") for item in self.evidence_hashes}))
        object.__setattr__(self, "source_page_ids", pages)
        object.__setattr__(self, "tex_anchors", anchors)
        object.__setattr__(self, "source_pdf_regions", regions)
        object.__setattr__(self, "evidence_hashes", evidence)
        object.__setattr__(self, "baseline_hash", _require_digest(self.baseline_hash, "baseline_hash"))
        object.__setattr__(self, "candidate_hash", _require_digest(self.candidate_hash, "candidate_hash"))


@dataclass(frozen=True, slots=True)
class IssueRecord:
    issue_id: str
    issue_type: str
    severity: Severity
    source_page_ids: tuple[str, ...]
    source_pdf_regions: tuple[PdfRegion, ...]
    tex_anchors: tuple[TexAnchor, ...]
    current_status: IssueStatus
    first_found_round: int
    last_modified_round: int
    detector_roles: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    baseline_hash: str
    candidate_hash: str
    proposed_patch_id: str = ""
    review_result: ReviewResult | None = None
    regression_count: int = 0
    retry_count: int = 0
    blocker_reason: str = ""
    related_issue_ids: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ISS-[0-9a-f]{12}(?:-[0-9]+)?", self.issue_id):
            raise ValueError("issue_id must be host-generated")
        if self.first_found_round < 0 or self.last_modified_round < self.first_found_round:
            raise ValueError("invalid issue round history")
        if self.regression_count < 0 or self.retry_count < 0:
            raise ValueError("issue counters cannot be negative")
        object.__setattr__(self, "baseline_hash", _require_digest(self.baseline_hash, "baseline_hash"))
        object.__setattr__(self, "candidate_hash", _require_digest(self.candidate_hash, "candidate_hash"))

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        payload["current_status"] = self.current_status.value
        payload["review_result"] = self.review_result.value if self.review_result else None
        return payload


@dataclass(frozen=True, slots=True)
class QualityVector:
    """A lower lexicographic key is always better; no averaging is allowed."""

    fully_compiled: bool
    silent_page_omissions: int = 0
    silent_text_losses: int = 0
    unauthorized_math_changes: int = 0
    open_critical: int = 0
    open_high: int = 0
    formal_errors: int = 0
    structure_reference_errors: int = 0
    footnote_figure_equation_errors: int = 0
    severe_visual_errors: int = 0
    ordinary_layout_errors: int = 0

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name != "fully_compiled" and int(value) < 0:
                raise ValueError("quality vector counts cannot be negative")

    @property
    def priority_key(self) -> tuple[int, ...]:
        return (
            0 if self.fully_compiled else 1,
            self.silent_page_omissions,
            self.silent_text_losses,
            self.unauthorized_math_changes,
            self.open_critical,
            self.open_high,
            self.formal_errors,
            self.structure_reference_errors,
            self.footnote_figure_equation_errors,
            self.severe_visual_errors,
            self.ordinary_layout_errors,
        )

    def better_than(self, other: "QualityVector") -> bool:
        return self.priority_key < other.priority_key

    def no_worse_than(self, other: "QualityVector") -> bool:
        return self.priority_key <= other.priority_key


@dataclass(frozen=True, slots=True)
class AnalysisCacheKey:
    snapshot_hash: str
    source_page_id: str
    source_page_hash: str
    baseline_tex_region_hash: str
    current_tex_region_hash: str
    current_render_hash: str
    prompt_version: str
    response_schema_version: str
    model_id: str
    tool_version: str
    audit_role: str

    def __post_init__(self) -> None:
        if not all((
            self.source_page_id,
            self.prompt_version,
            self.response_schema_version,
            self.model_id,
            self.tool_version,
            self.audit_role,
        )):
            raise ValueError("cache identity fields are required")
        for name in (
            "snapshot_hash",
            "source_page_hash",
            "baseline_tex_region_hash",
            "current_tex_region_hash",
            "current_render_hash",
        ):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class IndependentReviewPass:
    pass_number: int
    context_id: str
    candidate_hash: str
    checked_page_ids: tuple[str, ...]
    compile_passes: int
    content_conservation_ok: bool
    math_conservation_ok: bool
    formal_inventory_ok: bool
    visual_review_ok: bool
    new_high_risk_issues: int = 0
    prior_pass_conclusion_visible: bool = False

    def __post_init__(self) -> None:
        if self.pass_number not in {1, 2} or not self.context_id.strip():
            raise ValueError("review pass number and independent context are required")
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        pages = tuple(self.checked_page_ids)
        if not pages or len(pages) != len(set(pages)):
            raise ValueError("review must cover unique page ids")
        if self.compile_passes < 0 or self.new_high_risk_issues < 0:
            raise ValueError("review counters cannot be negative")
        object.__setattr__(self, "checked_page_ids", pages)


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    raw_ocr_frozen: bool
    baseline_compile_passes: int
    best_compile_passes: int
    best_pdf_openable: bool
    expected_page_ids: tuple[str, ...]
    checked_page_ids: tuple[str, ...]
    silent_page_omissions: int
    silent_text_losses: int
    unauthorized_math_changes: int
    formal_errors: int
    toc_complete_and_ordered: bool
    severe_equation_number_errors: int
    silent_footnote_losses: int
    silent_figure_caption_losses: int
    silent_bibliography_losses: int
    open_critical: int
    open_high: int
    regressions: int
    candidate_hash: str
    current_candidate_hash: str
    final_reviews: tuple[IndependentReviewPass, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        object.__setattr__(self, "current_candidate_hash", _require_digest(
            self.current_candidate_hash, "current_candidate_hash"
        ))
        expected = tuple(self.expected_page_ids)
        checked = tuple(self.checked_page_ids)
        if not expected or len(expected) != len(set(expected)):
            raise ValueError("expected page ids must be complete and unique")
        if len(checked) != len(set(checked)):
            raise ValueError("checked page ids must be unique")
        object.__setattr__(self, "expected_page_ids", expected)
        object.__setattr__(self, "checked_page_ids", checked)
        object.__setattr__(self, "final_reviews", tuple(self.final_reviews))
        for name, value in asdict(self).items():
            if isinstance(value, int) and not isinstance(value, bool) and value < 0:
                raise ValueError(f"{name} cannot be negative")


@dataclass(frozen=True, slots=True)
class VerificationDecision:
    status: AnalysisFinalStatus
    verified: bool
    failures: tuple[str, ...]


__all__ = [
    "ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT",
    "ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS",
    "ANALYSIS_RESPONSE_SCHEMA_VERSIONS",
    "AnalysisCacheKey",
    "AnalysisEvidenceHashes",
    "AnalysisFinalStatus",
    "AnalysisRunSnapshot",
    "AnalysisTransportContract",
    "CandidateDisposition",
    "CompileState",
    "IndependentReviewPass",
    "IssueProposal",
    "IssueRecord",
    "IssueStatus",
    "ModelBinding",
    "LowRiskSamplingEvidence",
    "LowRiskSamplingPolicy",
    "LowRiskSamplingSeed",
    "PageMapEntry",
    "PagePositionBand",
    "PageRisk",
    "PageRiskAdmission",
    "PageRiskAdmissionPage",
    "PageRiskInputSummary",
    "PageRiskRouteClosure",
    "PageRouteCallKey",
    "PageRouteRecord",
    "PageStatus",
    "PageTriageOutcome",
    "PageUnit",
    "PatchOperationKind",
    "PerformanceTargetStatus",
    "PdfRegion",
    "QualityVector",
    "ReviewResult",
    "SEVERITY_ORDER",
    "Severity",
    "TexAnchor",
    "VerificationDecision",
    "VerificationEvidence",
    "canonical_json_bytes",
    "sha256_bytes",
    "sha256_text",
]

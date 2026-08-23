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
import re
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
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


class CompileState(str, Enum):
    COMPILED = "COMPILED"
    PARTIAL_COMPILED = "PARTIAL_COMPILED"
    SOURCE_PREVIEW = "SOURCE_PREVIEW"


class PageRisk(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


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

    def __post_init__(self) -> None:
        if not self.role.strip() or not self.model_id.strip():
            raise ValueError("model role and model_id are required")
        object.__setattr__(self, "capabilities", tuple(sorted(set(self.capabilities))))


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
    performance_target_seconds: float = 10800.0
    page_map: tuple[PageMapEntry, ...] = ()
    initial_compile_state: CompileState = CompileState.COMPILED
    initial_issue_counts: tuple[tuple[str, int], ...] = ()
    config_hash: str = ""

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
        object.__setattr__(self, "page_map", page_map)
        object.__setattr__(self, "initial_issue_counts", _frozen_counts(self.initial_issue_counts))
        if self.config_hash:
            object.__setattr__(self, "config_hash", _require_digest(self.config_hash, "config_hash"))

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

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["initial_compile_state"] = self.initial_compile_state.value
        return payload


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
    source_page_id: str
    source_page_hash: str
    baseline_tex_region_hash: str
    current_tex_region_hash: str
    current_render_hash: str
    prompt_version: str
    model_id: str
    audit_role: str

    def __post_init__(self) -> None:
        if not self.source_page_id or not self.prompt_version or not self.model_id or not self.audit_role:
            raise ValueError("cache identity fields are required")
        for name in (
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
    "AnalysisCacheKey",
    "AnalysisFinalStatus",
    "AnalysisRunSnapshot",
    "CandidateDisposition",
    "CompileState",
    "IndependentReviewPass",
    "IssueProposal",
    "IssueRecord",
    "IssueStatus",
    "ModelBinding",
    "PageMapEntry",
    "PageRisk",
    "PageStatus",
    "PageUnit",
    "PatchOperationKind",
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

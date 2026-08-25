# -*- coding: utf-8 -*-
"""Executable, dependency-injected v2 analysis and review orchestration.

Unlike :mod:`analysis_adapter`, this module performs the production ordering
of the quality loop.  Models remain proposal-only callbacks: the host binds
every invocation to immutable evidence, owns issue identities, applies only
issue-scoped patches, compiles candidates through a real callback, retains
the history best, and derives ``VERIFIED`` exclusively from machine evidence.

The module contains no network or UI code.  A server integration supplies the
callbacks for configured models, TeX compilation, page rendering, region
extraction, and machine verification.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
import re
import threading
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable, Mapping, Sequence, TypeVar

from .analysis_runtime import (
    AnalysisQualityRuntime,
    CandidateRecord,
    IssueLedger,
    PatchPlan,
    PatchRejected,
    PatchScope,
    PerformanceMetrics,
    apply_patch_plan,
)
from .analysis_tasks import (
    AnalysisTaskStore,
    TaskLedgerPersistenceError,
    make_task_identity,
)
from .analysis_schema import (
    ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CompileState,
    IndependentReviewPass,
    IssueProposal,
    IssueRecord,
    IssueStatus,
    PageRisk,
    PageRiskAdmission,
    PageRiskRouteClosure,
    PageRouteCallKey,
    PageRouteRecord,
    PageTriageOutcome,
    PageUnit,
    QualityVector,
    ReviewResult,
    SEVERITY_ORDER,
    Severity,
    VerificationDecision,
    VerificationEvidence,
    canonical_json_bytes,
    sha256_bytes,
    sha256_text,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ISSUE_RE = re.compile(r"^ISS-[0-9a-f]{12}(?:-[0-9]+)?$")
_MODEL_ROLES = ("AI-1", "AI-2", "AI-3", "AI-4", "AI-5")
_MAX_PARALLEL_MODEL_CALLS = 3


class AnalysisOrchestrationError(RuntimeError):
    """Base class for a host/model orchestration contract failure."""


class StaleEvidenceError(AnalysisOrchestrationError):
    """A callback returned evidence for a candidate other than the current one."""


class CallbackContractError(AnalysisOrchestrationError):
    """A callback response violates its role-specific schema or authority."""


def _require_digest(value: str, name: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return digest


@dataclass(frozen=True, slots=True)
class FourMaterialHashes:
    """Hashes for the four pieces of evidence required by every AI call."""

    source_pdf_page_hash: str
    baseline_tex_region_hash: str
    current_tex_region_hash: str
    current_pdf_page_hash: str

    def __post_init__(self) -> None:
        for name in (
            "source_pdf_page_hash",
            "baseline_tex_region_hash",
            "current_tex_region_hash",
            "current_pdf_page_hash",
        ):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))


@dataclass(frozen=True, slots=True)
class PageMaterials:
    """The actual four materials supplied to one page-local model call."""

    source_page_id: str
    candidate_hash: str
    source_pdf_page: bytes
    baseline_tex_region: str
    current_tex_region: str
    current_pdf_page: bytes

    def __post_init__(self) -> None:
        if not self.source_page_id.strip():
            raise ValueError("source_page_id is required")
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        object.__setattr__(self, "source_pdf_page", bytes(self.source_pdf_page))
        object.__setattr__(self, "current_pdf_page", bytes(self.current_pdf_page))
        if not self.source_pdf_page or not self.current_pdf_page:
            raise ValueError("source and current PDF page evidence must be non-empty")

    @property
    def hashes(self) -> FourMaterialHashes:
        return FourMaterialHashes(
            source_pdf_page_hash=sha256_bytes(self.source_pdf_page),
            baseline_tex_region_hash=sha256_text(self.baseline_tex_region),
            current_tex_region_hash=sha256_text(self.current_tex_region),
            current_pdf_page_hash=sha256_bytes(self.current_pdf_page),
        )


@dataclass(frozen=True, slots=True)
class CallBinding:
    """Host-created identity attached to every model invocation.

    Discovery calls occur before an ``IssueLedger`` identity can exist.  They
    receive a deterministic ``DISCOVERY-*`` scope id; every repair, review,
    and adjudication call receives a real ``ISS-*`` id.
    """

    run_id: str
    role: str
    candidate_hash: str
    source_page_id: str
    issue_id: str
    material_hashes: FourMaterialHashes
    snapshot_hash: str
    prompt_version: str
    response_schema_version: str

    def __post_init__(self) -> None:
        if not self.run_id.strip() or not self.role.strip():
            raise ValueError("run_id and role are required")
        if not self.source_page_id.strip() or not self.issue_id.strip():
            raise ValueError("source_page_id and issue_id are required")
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        object.__setattr__(self, "snapshot_hash", _require_digest(
            self.snapshot_hash, "snapshot_hash"
        ))
        if not self.prompt_version.strip() or not self.response_schema_version.strip():
            raise ValueError("prompt and response schema versions are required")


@dataclass(frozen=True, slots=True)
class FindingRequest:
    binding: CallBinding
    materials: PageMaterials


@dataclass(frozen=True, slots=True)
class PatchRequest:
    binding: CallBinding
    materials: PageMaterials
    issue: IssueRecord
    scope: PatchScope


@dataclass(frozen=True, slots=True)
class IssueReviewRequest:
    binding: CallBinding
    materials: PageMaterials
    issue: IssueRecord
    patch_id: str
    compile_passes: int
    compile_state: CompileState


@dataclass(frozen=True, slots=True)
class IssuePageReviewResult:
    candidate_hash: str
    issue_id: str
    source_page_id: str
    result: ReviewResult
    content_conservation_ok: bool
    math_conservation_ok: bool
    visual_review_ok: bool
    new_high_priority_issues: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        if not _ISSUE_RE.fullmatch(self.issue_id):
            raise ValueError("issue review requires a host issue id")
        if not self.source_page_id.strip() or self.new_high_priority_issues < 0:
            raise ValueError("invalid issue review result")


@dataclass(frozen=True, slots=True)
class AdjudicationRequest:
    binding: CallBinding
    materials: PageMaterials
    reason: str
    issues: tuple[IssueRecord, ...]


@dataclass(frozen=True, slots=True)
class AdjudicationResult:
    candidate_hash: str
    issue_ids: tuple[str, ...]
    keep_issue_ids: tuple[str, ...]
    resolved: bool
    explanation: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        issue_ids = tuple(sorted(set(self.issue_ids)))
        keep = tuple(sorted(set(self.keep_issue_ids)))
        if not issue_ids or not set(keep).issubset(issue_ids):
            raise ValueError("adjudication ids are invalid")
        if not all(_ISSUE_RE.fullmatch(item) for item in issue_ids):
            raise ValueError("adjudication requires host issue ids")
        object.__setattr__(self, "issue_ids", issue_ids)
        object.__setattr__(self, "keep_issue_ids", keep)


@dataclass(frozen=True, slots=True)
class FinalPageReviewRequest:
    binding: CallBinding
    materials: PageMaterials
    pass_number: int
    context_id: str

    def __post_init__(self) -> None:
        if self.pass_number not in {1, 2} or not self.context_id.strip():
            raise ValueError("final review requires pass 1/2 and a context id")


@dataclass(frozen=True, slots=True)
class FinalPageReviewResult:
    candidate_hash: str
    source_page_id: str
    pass_number: int
    context_id: str
    content_conservation_ok: bool
    math_conservation_ok: bool
    formal_inventory_ok: bool
    visual_review_ok: bool
    new_high_risk_issues: int = 0
    prior_pass_conclusion_visible: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        if self.pass_number not in {1, 2} or not self.context_id.strip():
            raise ValueError("invalid final review pass")
        if not self.source_page_id.strip() or self.new_high_risk_issues < 0:
            raise ValueError("invalid final page review")


@dataclass(frozen=True, slots=True)
class CompileRequest:
    run_id: str
    candidate_hash: str
    tex: str
    round_index: int
    reason: str
    minimum_passes: int = 2

    def __post_init__(self) -> None:
        if not self.run_id.strip() or self.round_index < 0 or self.minimum_passes < 2:
            raise ValueError("invalid compile request")
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        if sha256_text(self.tex) != self.candidate_hash:
            raise ValueError("compile request TeX does not match candidate_hash")


@dataclass(frozen=True, slots=True)
class CompileResult:
    candidate_hash: str
    pdf: bytes
    compile_log: str
    compile_passes: int
    state: CompileState
    pdf_openable: bool
    page_pdf_bytes: tuple[tuple[str, bytes], ...]
    quality: QualityVector

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        object.__setattr__(self, "pdf", bytes(self.pdf))
        pages = tuple((str(page_id), bytes(payload)) for page_id, payload in self.page_pdf_bytes)
        ids = [page_id for page_id, _payload in pages]
        if self.compile_passes < 0 or len(ids) != len(set(ids)):
            raise ValueError("invalid compile result")
        if any(not page_id or not payload for page_id, payload in pages):
            raise ValueError("compiled page evidence must be named and non-empty")
        compiled_ok = (
            self.state == CompileState.COMPILED
            and self.compile_passes >= 2
            and self.pdf_openable
            and bool(self.pdf)
        )
        if self.quality.fully_compiled != compiled_ok:
            raise ValueError("quality vector compile state contradicts compile evidence")
        object.__setattr__(self, "page_pdf_bytes", pages)

    @property
    def compiled_ok(self) -> bool:
        return (
            self.state == CompileState.COMPILED
            and self.compile_passes >= 2
            and self.pdf_openable
            and bool(self.pdf)
        )

    @property
    def pdf_hash(self) -> str:
        return sha256_bytes(self.pdf) if self.pdf else ""

    def page_pdf(self, source_page_id: str) -> bytes:
        for page_id, payload in self.page_pdf_bytes:
            if page_id == source_page_id:
                return payload
        raise CallbackContractError(
            f"compile result has no page evidence for {source_page_id}"
        )


@dataclass(frozen=True, slots=True)
class PageAnalysisInput:
    page_unit: PageUnit
    source_pdf_page: bytes
    baseline_tex_region: str

    def __post_init__(self) -> None:
        payload = bytes(self.source_pdf_page)
        if not payload:
            raise ValueError("source PDF page evidence is required")
        if sha256_bytes(payload) != self.page_unit.source_page_hash:
            raise ValueError("source PDF page bytes do not match PageUnit hash")
        object.__setattr__(self, "source_pdf_page", payload)


@dataclass(frozen=True, slots=True)
class MachineVerificationRequest:
    run_id: str
    candidate_hash: str
    tex: str
    pdf: bytes
    compile_result: CompileResult
    issue_ledger: Mapping[str, object]
    final_reviews: tuple[IndependentReviewPass, ...]


@dataclass(frozen=True, slots=True)
class MachineVerificationFacts:
    candidate_hash: str
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))
        checked = tuple(self.checked_page_ids)
        if len(checked) != len(set(checked)):
            raise ValueError("machine checked page ids must be unique")
        object.__setattr__(self, "checked_page_ids", checked)
        for name, value in asdict(self).items():
            if isinstance(value, int) and not isinstance(value, bool) and value < 0:
                raise ValueError(f"{name} cannot be negative")


@dataclass(frozen=True, slots=True)
class InvocationRecord:
    ordinal: int
    operation: str
    binding: CallBinding
    elapsed_seconds: float
    succeeded: bool


@dataclass(frozen=True, slots=True)
class AnalysisCallbacks:
    ai1_structure: Callable[[FindingRequest], Sequence[IssueProposal]]
    ai2_content_math: Callable[[FindingRequest], Sequence[IssueProposal]]
    ai3_visual: Callable[[FindingRequest], Sequence[IssueProposal]]
    ai4_patch: Callable[[PatchRequest], PatchPlan | None]
    ai5_issue_review: Callable[[IssueReviewRequest], IssuePageReviewResult]
    ai5_final_review: Callable[[FinalPageReviewRequest], FinalPageReviewResult]
    compile_candidate: Callable[[CompileRequest], CompileResult]
    machine_verify: Callable[[MachineVerificationRequest], MachineVerificationFacts]
    tex_region: Callable[[PageUnit, str], str]
    patch_scope: Callable[[IssueRecord, str], PatchScope]
    ai6_adjudicate: Callable[[AdjudicationRequest], AdjudicationResult] | None = None
    ai3_triage: Callable[[FindingRequest], Sequence[IssueProposal]] | None = None
    ai1_recheck: Callable[[FindingRequest], Sequence[IssueProposal]] | None = None
    ai2_recheck: Callable[[FindingRequest], Sequence[IssueProposal]] | None = None
    ai3_recheck: Callable[[FindingRequest], Sequence[IssueProposal]] | None = None


@dataclass(frozen=True, slots=True)
class AnalysisOrchestrationResult:
    decision: VerificationDecision
    evidence: VerificationEvidence
    best_candidate: CandidateRecord
    current_tex: str
    current_pdf: bytes
    final_reviews: tuple[IndependentReviewPass, ...]
    ledger: tuple[IssueRecord, ...]
    invocations: tuple[InvocationRecord, ...]
    performance: PerformanceMetrics
    rollback_candidate_ids: tuple[str, ...]
    stop_reasons: tuple[str, ...] = ()
    task_summary: tuple[tuple[str, int], ...] = ()
    page_route_closure: PageRiskRouteClosure | None = None


@dataclass(frozen=True, slots=True)
class AnalysisResumeState:
    snapshot_hash: str
    round_index: int
    current_tex: str
    current_candidate_id: str
    current_candidate_hash: str
    best_candidate_id: str
    best_candidate_hash: str
    issue_ledger: Mapping[str, object]
    prior_invocations: tuple[InvocationRecord, ...] = ()
    prior_full_compile_count: int = 0
    prior_incremental_check_count: int = 0
    prior_rollback_candidate_ids: tuple[str, ...] = ()
    prior_modified_page_ids: tuple[str, ...] = ()
    prior_stop_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "snapshot_hash", _require_digest(self.snapshot_hash, "snapshot_hash")
        )
        for name in ("current_candidate_hash", "best_candidate_hash"):
            object.__setattr__(self, name, _require_digest(getattr(self, name), name))
        if self.round_index < 0 or not self.current_tex:
            raise ValueError("resume state round and TeX are invalid")
        if sha256_text(self.current_tex) != self.current_candidate_hash:
            raise ValueError("resume TeX differs from the current candidate hash")
        if self.current_candidate_id != self.best_candidate_id or (
            self.current_candidate_hash != self.best_candidate_hash
        ):
            raise ValueError("resume currently supports only the committed history best")
        if self.prior_full_compile_count < 0 or self.prior_incremental_check_count < 0:
            raise ValueError("resume counters cannot be negative")


@dataclass(frozen=True, slots=True)
class AnalysisCheckpointState:
    round_index: int
    current_tex: str
    current_compile: CompileResult
    current_candidate: CandidateRecord
    best_candidate: CandidateRecord
    issue_ledger: Mapping[str, object]
    task_ledger: Mapping[str, object]
    invocations: tuple[InvocationRecord, ...]
    full_compile_count: int
    incremental_check_count: int
    rollback_candidate_ids: tuple[str, ...]
    modified_page_ids: tuple[str, ...]
    stop_reasons: tuple[str, ...]


_T = TypeVar("_T")


def _overlap(left: IssueRecord, right: IssueRecord) -> bool:
    if not set(left.source_page_ids).intersection(right.source_page_ids):
        return False
    if any(a.overlaps(b) for a in left.tex_anchors for b in right.tex_anchors):
        return True
    return any(
        a.overlaps(b) for a in left.source_pdf_regions for b in right.source_pdf_regions
    )


class AnalysisOrchestrator:
    """Run the complete host-authoritative v2 analysis loop."""

    def __init__(
        self,
        *,
        snapshot: AnalysisRunSnapshot,
        page_inputs: Sequence[PageAnalysisInput],
        candidate_root: str | Path,
        callbacks: AnalysisCallbacks,
        raw_ocr_frozen: bool,
        final_review_context_ids: tuple[str, str],
        clock: Callable[[], float] = time.monotonic,
        risk_routing_enabled: bool = False,
        resilient_execution: bool | None = None,
        discovery_max_attempts: int = 2,
        macro_batching_enabled: bool | None = None,
        baseline_frozen_callback: Callable[[CompileResult], None] | None = None,
        checkpoint_callback: Callable[[AnalysisCheckpointState], None] | None = None,
        resume_state: AnalysisResumeState | None = None,
        page_risk_admission: PageRiskAdmission | None = None,
    ) -> None:
        inputs = tuple(page_inputs)
        ids = [item.page_unit.source_page_id for item in inputs]
        numbers = [item.page_unit.source_page_number for item in inputs]
        if len(ids) != len(set(ids)) or set(numbers) != set(snapshot.page_range):
            raise ValueError("page inputs must cover the immutable snapshot exactly once")
        bound_roles = {item.role for item in snapshot.models}
        missing = set(_MODEL_ROLES).difference(bound_roles)
        if missing:
            raise ValueError("snapshot is missing model roles: " + ", ".join(sorted(missing)))
        contexts = tuple(str(item).strip() for item in final_review_context_ids)
        if len(contexts) != 2 or not all(contexts) or len(set(contexts)) != 2:
            raise ValueError("two distinct final-review contexts are required")
        self.snapshot = snapshot
        self.page_inputs = inputs
        self._by_page = {item.page_unit.source_page_id: item for item in inputs}
        self.callbacks = callbacks
        self.raw_ocr_frozen = bool(raw_ocr_frozen)
        self.final_review_context_ids = contexts
        self.clock = clock
        self.risk_routing_enabled = bool(risk_routing_enabled)
        self.resilient_execution = (
            self.risk_routing_enabled
            if resilient_execution is None
            else bool(resilient_execution)
        )
        if type(discovery_max_attempts) is not int or discovery_max_attempts < 1:
            raise ValueError("discovery_max_attempts must be positive")
        self.discovery_max_attempts = discovery_max_attempts
        self.macro_batching_enabled = (
            self.risk_routing_enabled
            if macro_batching_enabled is None
            else bool(macro_batching_enabled)
        )
        if resume_state is not None and resume_state.snapshot_hash != snapshot.snapshot_hash:
            raise ValueError("resume state belongs to a different immutable snapshot")
        self.baseline_frozen_callback = baseline_frozen_callback
        self.checkpoint_callback = checkpoint_callback
        self.resume_state = resume_state
        if page_risk_admission is not None and not isinstance(
            page_risk_admission, PageRiskAdmission
        ):
            raise ValueError("page_risk_admission has an invalid type")
        self.page_risk_admission = page_risk_admission
        self._sampled_low_risk_page_ids = (
            frozenset(page_risk_admission.low_risk_sampling.selected_page_ids)
            if page_risk_admission is not None
            else frozenset()
        )
        if page_risk_admission is not None:
            if (
                page_risk_admission.source_pdf_sha256 != snapshot.source_pdf_hash
                or page_risk_admission.baseline_tex_sha256
                != snapshot.baseline_tex_hash
                or page_risk_admission.baseline_pdf_sha256
                != snapshot.baseline_pdf_hash
                or (
                    snapshot.evidence_hashes is not None
                    and (
                        page_risk_admission.ocr_page_records_sha256
                        != snapshot.evidence_hashes.ocr_page_records_hash
                        or page_risk_admission.digest
                        != snapshot.evidence_hashes.page_risk_admission_hash
                    )
                )
            ):
                raise ValueError("page-risk admission differs from the snapshot")
            admitted_by_id = {
                item.summary.source_page_id: item for item in page_risk_admission.pages
            }
            if set(admitted_by_id) != set(ids):
                raise ValueError("page-risk admission does not cover the page inputs")
            for item in inputs:
                admitted = admitted_by_id[item.page_unit.source_page_id]
                if (
                    admitted.summary.source_page_number
                    != item.page_unit.source_page_number
                    or admitted.summary.baseline_tex_region_hash
                    != sha256_text(item.baseline_tex_region)
                    or admitted.summary.candidate_page_ids_hash
                    != sha256_bytes(canonical_json_bytes(
                        list(item.page_unit.candidate_pdf_page_ids)
                    ))
                    or admitted.risk_level != item.page_unit.risk_level
                    or admitted.risk_reasons != item.page_unit.risk_reasons
                ):
                    raise ValueError("page input risk differs from the immutable admission")
        self.concurrency_limit = int(snapshot.concurrency_limit)
        if not 1 <= self.concurrency_limit <= _MAX_PARALLEL_MODEL_CALLS:
            raise ValueError(
                "analysis concurrency_limit must be in "
                f"1..{_MAX_PARALLEL_MODEL_CALLS}"
            )
        self.runtime = AnalysisQualityRuntime(
            snapshot=snapshot,
            page_units=[item.page_unit for item in inputs],
            candidate_root=candidate_root,
        )
        self._task_store = (
            AnalysisTaskStore(
                Path(candidate_root)
                / "_run"
                / snapshot.snapshot_hash[:16]
                / "tasks"
            )
            if self.resilient_execution
            else None
        )
        self._invocations: list[InvocationRecord] = list(
            resume_state.prior_invocations if resume_state is not None else ()
        )
        self._role_counts: dict[str, int] = {}
        self._role_elapsed: dict[str, float] = {}
        for invocation in self._invocations:
            self._role_counts[invocation.binding.role] = (
                self._role_counts.get(invocation.binding.role, 0) + 1
            )
            self._role_elapsed[invocation.binding.role] = (
                self._role_elapsed.get(invocation.binding.role, 0.0)
                + invocation.elapsed_seconds
            )
        self._invocation_lock = threading.Lock()
        self._next_invocation_ordinal = 1 + max(
            (item.ordinal for item in self._invocations), default=0
        )
        self._compile_history: list[CompileResult] = []
        self._attempted_candidate_hashes: set[str] = set()
        self._modified_pages: set[str] = set(
            resume_state.prior_modified_page_ids if resume_state is not None else ()
        )
        self._incremental_check_count = (
            resume_state.prior_incremental_check_count
            if resume_state is not None
            else 0
        )
        self._prior_full_compile_count = (
            resume_state.prior_full_compile_count if resume_state is not None else 0
        )
        self._prior_rollback_candidate_ids = (
            resume_state.prior_rollback_candidate_ids if resume_state is not None else ()
        )
        self._stop_reasons: list[str] = list(
            resume_state.prior_stop_reasons if resume_state is not None else ()
        )
        self._triage_outcomes: dict[str, PageTriageOutcome] = {}
        self._triage_response_hashes: dict[str, str] = {}
        self._triage_anomaly_reasons: dict[str, tuple[str, ...]] = {}
        if self.risk_routing_enabled:
            self._stop_reasons.extend(
                f"risk_r3_requires_adjudication:{item.page_unit.source_page_id}"
                for item in self.page_inputs
                if item.page_unit.risk_level == PageRisk.R3
            )
        self._run_started = 0.0

    def _binding(
        self,
        *,
        role: str,
        operation: str,
        issue_id: str,
        materials: PageMaterials,
    ) -> CallBinding:
        try:
            response_schema_version = ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation]
        except KeyError as exc:
            raise ValueError(f"unknown analysis response schema for {operation}") from exc
        return CallBinding(
            run_id=self.snapshot.run_id,
            role=role,
            candidate_hash=materials.candidate_hash,
            source_page_id=materials.source_page_id,
            issue_id=issue_id,
            material_hashes=materials.hashes,
            snapshot_hash=self.snapshot.snapshot_hash,
            prompt_version=self.snapshot.prompt_version,
            response_schema_version=response_schema_version,
        )

    def _invoke(
        self,
        operation: str,
        binding: CallBinding,
        callback: Callable[[object], _T],
        request: object,
        *,
        invocation_ordinal: int | None = None,
    ) -> _T:
        if invocation_ordinal is None:
            invocation_ordinal = self._reserve_invocation_ordinals(1)[0]
        started = self.clock()
        succeeded = False
        try:
            result = callback(request)
            succeeded = True
            return result
        finally:
            elapsed = max(0.0, self.clock() - started)
            with self._invocation_lock:
                self._role_counts[binding.role] = (
                    self._role_counts.get(binding.role, 0) + 1
                )
                self._role_elapsed[binding.role] = (
                    self._role_elapsed.get(binding.role, 0.0) + elapsed
                )
                self._invocations.append(InvocationRecord(
                    ordinal=invocation_ordinal,
                    operation=operation,
                    binding=binding,
                    elapsed_seconds=elapsed,
                    succeeded=succeeded,
                ))

    def _reserve_invocation_ordinals(self, count: int) -> tuple[int, ...]:
        """Reserve stable call identities before concurrent work starts."""

        if count < 1:
            return ()
        with self._invocation_lock:
            start = self._next_invocation_ordinal
            self._next_invocation_ordinal += count
        return tuple(range(start, start + count))

    def _parallel_invocations(
        self,
        calls: Sequence[Callable[[int], _T]],
    ) -> tuple[_T, ...]:
        """Run independent model calls concurrently and return plan order.

        The call plan is immutable and host-ordered.  Ordinals are reserved
        before submission, so neither invocation evidence nor later ledger
        identities depend on thread completion order.  On the first callback
        exception, work that has not started is cancelled, already-running
        calls are drained so their evidence is retained, and the earliest
        failure in plan order is re-raised.
        """

        planned = tuple(calls)
        if not planned:
            return ()
        ordinals = self._reserve_invocation_ordinals(len(planned))
        workers = min(self.concurrency_limit, len(planned))
        futures: list[Future[_T]] = []
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="latexstruct-analysis",
        ) as pool:
            futures = [
                pool.submit(call, ordinal)
                for call, ordinal in zip(planned, ordinals, strict=True)
            ]
            done, pending = wait(futures, return_when=FIRST_EXCEPTION)
            failed = any(
                not future.cancelled() and future.exception() is not None
                for future in done
            )
            if failed:
                for future in pending:
                    future.cancel()
            wait(futures)

        failures: list[tuple[int, BaseException]] = []
        results: list[_T | None] = [None] * len(futures)
        cancelled = False
        for index, future in enumerate(futures):
            if future.cancelled():
                cancelled = True
                continue
            try:
                results[index] = future.result()
            except BaseException as exc:  # preserve the callback's exact failure
                failures.append((index, exc))
        if failures:
            raise min(failures, key=lambda item: item[0])[1]
        if cancelled:
            raise AnalysisOrchestrationError(
                "parallel model calls were cancelled without a callback failure"
            )
        return tuple(item for item in results if item is not None)

    def _compile(self, tex: str, *, round_index: int, reason: str) -> CompileResult:
        candidate_hash = sha256_text(tex)
        result = self.callbacks.compile_candidate(CompileRequest(
            run_id=self.snapshot.run_id,
            candidate_hash=candidate_hash,
            tex=tex,
            round_index=round_index,
            reason=reason,
        ))
        if result.candidate_hash != candidate_hash:
            raise StaleEvidenceError("compile callback returned a stale candidate hash")
        expected = set(self._by_page)
        available = {page_id for page_id, _payload in result.page_pdf_bytes}
        if expected.difference(available):
            raise CallbackContractError("compile callback omitted rendered page evidence")
        self._compile_history.append(result)
        return result

    def _materials(
        self,
        source_page_id: str,
        tex: str,
        compiled: CompileResult,
    ) -> PageMaterials:
        candidate_hash = sha256_text(tex)
        if compiled.candidate_hash != candidate_hash:
            raise StaleEvidenceError("rendered page evidence belongs to a stale candidate")
        page = self._by_page[source_page_id]
        current_region = self.callbacks.tex_region(page.page_unit, tex)
        if not isinstance(current_region, str):
            raise CallbackContractError("tex_region callback must return text")
        if current_region not in tex:
            raise StaleEvidenceError(
                f"current TeX region for {source_page_id} is not part of the candidate"
            )
        return PageMaterials(
            source_page_id=source_page_id,
            candidate_hash=candidate_hash,
            source_pdf_page=page.source_pdf_page,
            baseline_tex_region=page.baseline_tex_region,
            current_tex_region=current_region,
            current_pdf_page=compiled.page_pdf(source_page_id),
        )

    def _validate_finding(
        self,
        proposal: IssueProposal,
        *,
        role: str,
        binding: CallBinding,
    ) -> None:
        if not isinstance(proposal, IssueProposal):
            raise CallbackContractError(f"{role} returned a non-IssueProposal finding")
        if proposal.candidate_hash != binding.candidate_hash:
            raise StaleEvidenceError(f"{role} finding belongs to a stale candidate")
        if proposal.baseline_hash != self.snapshot.baseline_tex_hash:
            raise StaleEvidenceError(f"{role} finding belongs to a stale baseline")
        if proposal.detector_role != role:
            raise CallbackContractError(f"{role} cannot impersonate another detector role")
        if binding.source_page_id not in proposal.source_page_ids:
            raise CallbackContractError(f"{role} finding is not bound to the inspected page")
        if not set(proposal.source_page_ids).issubset(self._by_page):
            raise CallbackContractError(f"{role} finding references an unknown source page")

    @staticmethod
    def _finding_to_dict(proposal: IssueProposal) -> dict[str, object]:
        return {
            "issue_type": proposal.issue_type,
            "severity": proposal.severity.value,
            "source_page_ids": list(proposal.source_page_ids),
            "tex_anchors": [asdict(item) for item in proposal.tex_anchors],
            "source_pdf_regions": [
                asdict(item) for item in proposal.source_pdf_regions
            ],
            "detector_role": proposal.detector_role,
            "evidence_hashes": list(proposal.evidence_hashes),
            "baseline_hash": proposal.baseline_hash,
            "candidate_hash": proposal.candidate_hash,
            "description": proposal.description,
            "blocker_reason": proposal.blocker_reason,
        }

    @staticmethod
    def _finding_from_dict(value: object) -> IssueProposal:
        from .analysis_schema import PdfRegion, TexAnchor

        if not isinstance(value, Mapping):
            raise CallbackContractError("persisted finding must be an object")
        expected = {
            "issue_type",
            "severity",
            "source_page_ids",
            "tex_anchors",
            "source_pdf_regions",
            "detector_role",
            "evidence_hashes",
            "baseline_hash",
            "candidate_hash",
            "description",
            "blocker_reason",
        }
        if set(value) != expected:
            raise CallbackContractError("persisted finding fields are not exact")
        try:
            anchors = tuple(TexAnchor(**item) for item in value["tex_anchors"])
            regions = tuple(PdfRegion(**item) for item in value["source_pdf_regions"])
            return IssueProposal(
                issue_type=str(value["issue_type"]),
                severity=Severity(str(value["severity"])),
                source_page_ids=tuple(str(item) for item in value["source_page_ids"]),
                tex_anchors=anchors,
                source_pdf_regions=regions,
                detector_role=str(value["detector_role"]),
                evidence_hashes=tuple(
                    str(item) for item in value["evidence_hashes"]
                ),
                baseline_hash=str(value["baseline_hash"]),
                candidate_hash=str(value["candidate_hash"]),
                description=str(value["description"]),
                blocker_reason=str(value["blocker_reason"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CallbackContractError("persisted finding is invalid") from exc

    def _roles_for_page(
        self,
        page: PageAnalysisInput,
    ) -> tuple[tuple[str, str, Callable[[FindingRequest], Sequence[IssueProposal]]], ...]:
        deep_roles = (
            ("AI-1", "structure-findings", self.callbacks.ai1_structure),
            ("AI-2", "content-math-findings", self.callbacks.ai2_content_math),
            ("AI-3", "visual-findings", self.callbacks.ai3_visual),
        )
        if not self.risk_routing_enabled:
            return deep_roles
        triage = (
            (
                "AI-3",
                "visual-triage",
                self.callbacks.ai3_triage or self.callbacks.ai3_visual,
            ),
        )
        risk = page.page_unit.risk_level
        if page.page_unit.source_page_id in self._sampled_low_risk_page_ids and risk in {
            PageRisk.R0,
            PageRisk.R1,
        }:
            risk = PageRisk.R2
        if risk == PageRisk.R0:
            return triage
        if risk == PageRisk.R1:
            return triage + deep_roles[:1]
        if risk == PageRisk.R2:
            return triage + deep_roles
        if risk == PageRisk.R3:
            # R3 means the host evidence is conflicting or the input closure
            # is unsafe.  Ordinary auditors cannot downgrade that condition;
            # a later host-created conflict may be sent to AI-6, otherwise the
            # page remains explicitly blocked by the stop reason installed in
            # __init__.
            return triage
        raise AnalysisOrchestrationError(f"unsupported page risk: {risk}")

    def _record_triage(
        self,
        *,
        source_page_id: str,
        proposals: Sequence[IssueProposal],
    ) -> None:
        payload = [self._finding_to_dict(item) for item in proposals]
        self._triage_response_hashes[source_page_id] = sha256_bytes(
            canonical_json_bytes(payload)
        )
        if any(item.severity == Severity.CRITICAL for item in proposals):
            outcome = PageTriageOutcome.BLOCKED
        elif proposals:
            outcome = PageTriageOutcome.ANOMALY
        else:
            outcome = PageTriageOutcome.CLEAR
        reasons = tuple(sorted({
            f"visual_triage:{item.issue_type}" for item in proposals
        }))
        self._triage_outcomes[source_page_id] = outcome
        self._triage_anomaly_reasons[source_page_id] = reasons
        if outcome == PageTriageOutcome.BLOCKED:
            self._stop_reasons.append(
                f"visual_triage_blocked:{source_page_id}"
            )

    def _discover_resilient(
        self,
        tex: str,
        compiled: CompileResult,
    ) -> None:
        if self._task_store is None:
            raise AnalysisOrchestrationError("resilient discovery has no task store")
        plans: list[
            tuple[
                str,
                CallBinding,
                Callable[[object], object],
                FindingRequest,
                str,
            ]
        ] = []
        page_task_ids: dict[str, list[str]] = {
            item.page_unit.source_page_id: [] for item in self.page_inputs
        }
        for page in self.page_inputs:
            page_id = page.page_unit.source_page_id
            materials = self._materials(page_id, tex, compiled)
            for role, operation, callback in self._roles_for_page(page):
                discovery_id = (
                    f"DISCOVERY-{role}-"
                    f"{sha256_text(self.snapshot.run_id + page_id)[:12]}"
                )
                binding = self._binding(
                    role=role,
                    operation=operation,
                    issue_id=discovery_id,
                    materials=materials,
                )
                request = FindingRequest(binding, materials)
                identity = make_task_identity(
                    snapshot_hash=self.snapshot.snapshot_hash,
                    candidate_hash=binding.candidate_hash,
                    operation=operation,
                    role=role,
                    source_page_id=page_id,
                    scope_id=discovery_id,
                    binding_payload=asdict(binding),
                )
                record = self._task_store.register(identity)
                page_task_ids[page_id].append(record.identity.task_id)
                plans.append((operation, binding, callback, request, identity.task_id))

        by_task: dict[str, tuple[IssueProposal, ...]] = {}
        plan_by_task = {plan[4]: plan for plan in plans}
        fatal_stop = threading.Event()
        for plan in plans:
            operation, binding, _callback, _request, task_id = plan
            record = self._task_store.get(task_id)
            if record.state == "COMPLETED":
                raw = self._task_store.response(task_id)
                if not isinstance(raw, list):
                    raise CallbackContractError(
                        f"persisted {operation} response must be a list"
                    )
                proposals = tuple(self._finding_from_dict(item) for item in raw)
                for proposal in proposals:
                    self._validate_finding(
                        proposal, role=binding.role, binding=binding
                    )
                by_task[task_id] = proposals

        unrecoverable_tasks: set[str] = set()
        while True:
            pending = [
                task_id
                for task_id in plan_by_task
                if self._task_store.get(task_id).state == "PENDING"
                and task_id not in unrecoverable_tasks
            ]
            if not pending:
                break
            # The first wave is concurrent.  Failed work is retried as single
            # atomic tasks, so one bad sibling can neither cancel nor replay a
            # successfully committed response.
            retry_wave = any(
                self._task_store.get(task_id).attempts > 0 for task_id in pending
            )
            workers = 1 if retry_wave else min(self.concurrency_limit, len(pending))
            ordinals = self._reserve_invocation_ordinals(len(pending))
            attempts_before = {
                task_id: self._task_store.get(task_id).attempts for task_id in pending
            }

            def run_one(task_id: str, ordinal: int) -> tuple[IssueProposal, ...]:
                operation, binding, callback, request, _task_id = plan_by_task[task_id]
                if fatal_stop.is_set():
                    raise AnalysisOrchestrationError(
                        "discovery cancelled after a fatal analysis fault"
                    )
                try:
                    self._task_store.start(
                        task_id,
                        max_attempts=self.discovery_max_attempts,
                    )
                    raw = self._invoke(
                        operation,
                        binding,
                        callback,
                        request,
                        invocation_ordinal=ordinal,
                    )
                    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
                        raise CallbackContractError(
                            f"{binding.role} must return a sequence of findings"
                        )
                    proposals = tuple(raw)
                    for proposal in proposals:
                        self._validate_finding(
                            proposal, role=binding.role, binding=binding
                        )
                    self._task_store.commit_success(
                        task_id,
                        [self._finding_to_dict(item) for item in proposals],
                    )
                    return proposals
                except TaskLedgerPersistenceError:
                    fatal_stop.set()
                    raise
                except Exception as exc:
                    if bool(getattr(exc, "fatal_analysis", False)):
                        # Budget/persistence authority is no longer trustworthy.
                        # It is unsafe to mutate the task ledger or issue another
                        # paid call in this analysis run.
                        fatal_stop.set()
                        raise
                    retryable = not isinstance(
                        exc, (CallbackContractError, StaleEvidenceError)
                    ) and bool(getattr(exc, "retryable", True))
                    if self._task_store.get(task_id).state == "RUNNING":
                        self._task_store.fail(
                            task_id,
                            f"{type(exc).__name__}: {exc}",
                            retryable=retryable,
                            max_attempts=self.discovery_max_attempts,
                        )
                    raise

            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="latexstruct-analysis-task",
            ) as pool:
                futures = {
                    task_id: pool.submit(run_one, task_id, ordinal)
                    for task_id, ordinal in zip(pending, ordinals, strict=True)
                }
                for task_id in pending:
                    try:
                        by_task[task_id] = futures[task_id].result()
                    except TaskLedgerPersistenceError:
                        # Durable task authority is uncertain.  Continuing in
                        # this process could repeat a paid call or omit work.
                        for future in futures.values():
                            future.cancel()
                        raise
                    except Exception as exc:
                        if bool(getattr(exc, "fatal_analysis", False)):
                            for future in futures.values():
                                future.cancel()
                            raise
                        # The task ledger contains the exact failure and decides
                        # whether the next loop retries or permanently blocks it.
                        record = self._task_store.get(task_id)
                        if record.state == "RUNNING" or (
                            record.state == "PENDING"
                            and record.attempts == attempts_before[task_id]
                        ):
                            # A task-state persistence failure cannot be retried
                            # safely in this process: doing so can spin forever
                            # or silently omit a planned task from final gates.
                            unrecoverable_tasks.add(task_id)

        for operation, binding, _callback, _request, task_id in plans:
            record = self._task_store.get(task_id)
            if record.state == "COMPLETED":
                proposals = by_task[task_id]
                if operation == "visual-triage":
                    self._record_triage(
                        source_page_id=binding.source_page_id,
                        proposals=proposals,
                    )
                else:
                    for proposal in proposals:
                        self.runtime.ledger.upsert(proposal, round_index=0)
            elif record.state == "BLOCKED":
                self._stop_reasons.append(
                    f"analysis_task_blocked:{binding.source_page_id}:"
                    f"{binding.role}:{task_id}"
                )
            else:
                self._stop_reasons.append(
                    f"analysis_task_incomplete:{binding.source_page_id}:"
                    f"{binding.role}:{task_id}:{record.state.lower()}"
                )

        elapsed = max(0.0, self.clock() - self._run_started)
        for page in self.page_inputs:
            page_id = page.page_unit.source_page_id
            task_ids = page_task_ids[page_id]
            if all(
                self._task_store.get(task_id).state == "COMPLETED"
                for task_id in task_ids
            ):
                self.runtime.performance.record_page_completion(page_id, elapsed)
        self._run_triage_escalations(tex, compiled)

    def _run_bound_finding_task(
        self,
        *,
        page: PageAnalysisInput,
        tex: str,
        compiled: CompileResult,
        role: str,
        operation: str,
        callback: Callable[[FindingRequest], Sequence[IssueProposal]],
        scope_prefix: str,
        round_index: int,
    ) -> tuple[IssueProposal, ...]:
        """Execute one deterministic follow-up task with atomic reuse."""

        page_id = page.page_unit.source_page_id
        materials = self._materials(page_id, tex, compiled)
        scope_id = (
            f"{scope_prefix}-{role}-"
            f"{sha256_text(self.snapshot.run_id + page_id + operation + sha256_text(tex))[:12]}"
        )
        binding = self._binding(
            role=role,
            operation=operation,
            issue_id=scope_id,
            materials=materials,
        )
        request = FindingRequest(binding, materials)
        if not self.resilient_execution:
            raw = self._invoke(operation, binding, callback, request)
            if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
                raise CallbackContractError(f"{role} must return a sequence of findings")
            proposals = tuple(raw)
            for proposal in proposals:
                self._validate_finding(proposal, role=role, binding=binding)
                self.runtime.ledger.upsert(proposal, round_index=round_index)
            return proposals
        if self._task_store is None:  # pragma: no cover - constructor invariant
            raise AnalysisOrchestrationError("follow-up task has no durable store")
        identity = make_task_identity(
            snapshot_hash=self.snapshot.snapshot_hash,
            candidate_hash=binding.candidate_hash,
            operation=operation,
            role=role,
            source_page_id=page_id,
            scope_id=scope_id,
            binding_payload=asdict(binding),
        )
        record = self._task_store.register(identity)
        proposals: tuple[IssueProposal, ...]
        if record.state == "COMPLETED":
            raw_saved = self._task_store.response(identity.task_id)
            if not isinstance(raw_saved, list):
                raise CallbackContractError("persisted follow-up response must be a list")
            proposals = tuple(self._finding_from_dict(item) for item in raw_saved)
        else:
            proposals = ()
            while self._task_store.get(identity.task_id).state == "PENDING":
                try:
                    self._task_store.start(
                        identity.task_id,
                        max_attempts=self.discovery_max_attempts,
                    )
                    raw = self._invoke(operation, binding, callback, request)
                    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
                        raise CallbackContractError(
                            f"{role} must return a sequence of findings"
                        )
                    proposals = tuple(raw)
                    for proposal in proposals:
                        self._validate_finding(proposal, role=role, binding=binding)
                    self._task_store.commit_success(
                        identity.task_id,
                        [self._finding_to_dict(item) for item in proposals],
                    )
                except TaskLedgerPersistenceError:
                    raise
                except Exception as exc:
                    if bool(getattr(exc, "fatal_analysis", False)):
                        raise
                    retryable = not isinstance(
                        exc, (CallbackContractError, StaleEvidenceError)
                    ) and bool(getattr(exc, "retryable", True))
                    if self._task_store.get(identity.task_id).state == "RUNNING":
                        self._task_store.fail(
                            identity.task_id,
                            f"{type(exc).__name__}: {exc}",
                            retryable=retryable,
                            max_attempts=self.discovery_max_attempts,
                        )
                    if self._task_store.get(identity.task_id).state == "BLOCKED":
                        self._stop_reasons.append(
                            f"analysis_task_blocked:{page_id}:{role}:{identity.task_id}"
                        )
                        return ()
        for proposal in proposals:
            self._validate_finding(proposal, role=role, binding=binding)
            self.runtime.ledger.upsert(proposal, round_index=round_index)
        return proposals

    def _run_triage_escalations(self, tex: str, compiled: CompileResult) -> None:
        if not self.risk_routing_enabled:
            return
        deep_roles = (
            ("AI-1", "structure-findings", self.callbacks.ai1_structure),
            ("AI-2", "content-math-findings", self.callbacks.ai2_content_math),
            ("AI-3", "visual-findings", self.callbacks.ai3_visual),
        )
        for page in self.page_inputs:
            page_id = page.page_unit.source_page_id
            if self._triage_outcomes.get(page_id) != PageTriageOutcome.ANOMALY:
                continue
            admitted = page.page_unit.risk_level
            if admitted == PageRisk.R3:
                # R3 is an input-authority conflict.  It is blocked (or may
                # be handled by a separately evidenced AI-6 adjudication),
                # never silently converted into ordinary deep review.
                continue
            already_full = admitted == PageRisk.R2 or (
                page_id in self._sampled_low_risk_page_ids
                and admitted in {PageRisk.R0, PageRisk.R1}
            )
            if already_full:
                continue
            roles = deep_roles[1:] if admitted == PageRisk.R1 else deep_roles
            for role, operation, callback in roles:
                self._run_bound_finding_task(
                    page=page,
                    tex=tex,
                    compiled=compiled,
                    role=role,
                    operation=operation,
                    callback=callback,
                    scope_prefix="TRIAGE-ESCALATION",
                    round_index=0,
                )

    def _recheck_modified_pages(
        self,
        tex: str,
        compiled: CompileResult,
        *,
        round_index: int,
    ) -> None:
        if not self.risk_routing_enabled or not self._modified_pages:
            return
        rechecks = (
            (
                "AI-1",
                "structure-recheck",
                self.callbacks.ai1_recheck or self.callbacks.ai1_structure,
            ),
            (
                "AI-2",
                "content-math-recheck",
                self.callbacks.ai2_recheck or self.callbacks.ai2_content_math,
            ),
            (
                "AI-3",
                "visual-recheck",
                self.callbacks.ai3_recheck or self.callbacks.ai3_visual,
            ),
        )
        for page_id in sorted(
            self._modified_pages,
            key=lambda value: self._by_page[value].page_unit.source_page_number,
        ):
            page = self._by_page[page_id]
            for role, operation, callback in rechecks:
                self._run_bound_finding_task(
                    page=page,
                    tex=tex,
                    compiled=compiled,
                    role=role,
                    operation=operation,
                    callback=callback,
                    scope_prefix="MODIFIED-RECHECK",
                    round_index=round_index,
                )

    def _build_page_route_closure(
        self,
        *,
        final_candidate_hash: str,
    ) -> PageRiskRouteClosure | None:
        admission = self.page_risk_admission
        if admission is None:
            return None
        admitted_by_id = {
            item.summary.source_page_id: item for item in admission.pages
        }
        page_records: list[PageRouteRecord] = []
        for page in self.page_inputs:
            page_id = page.page_unit.source_page_id
            admitted = admitted_by_id[page_id].risk_level
            triage = self._triage_outcomes.get(page_id)
            reasons = self._triage_anomaly_reasons.get(page_id, ())
            triage_hash = self._triage_response_hashes.get(page_id)
            if triage is None or triage_hash is None:
                triage = PageTriageOutcome.BLOCKED
                reasons = tuple(sorted({*reasons, "visual_triage:missing"}))
                triage_hash = sha256_bytes(canonical_json_bytes([]))
                self._stop_reasons.append(f"visual_triage_missing:{page_id}")
            if triage == PageTriageOutcome.BLOCKED:
                effective = PageRisk.R3
            elif triage == PageTriageOutcome.ANOMALY and admitted in {
                PageRisk.R0,
                PageRisk.R1,
            }:
                effective = PageRisk.R2
            else:
                effective = admitted
            modified = page_id in self._modified_pages
            sampled = page_id in self._sampled_low_risk_page_ids
            page_records.append(PageRouteRecord(
                source_page_id=page_id,
                source_page_number=page.page_unit.source_page_number,
                admitted_risk=admitted,
                triage_outcome=triage,
                triage_response_sha256=triage_hash,
                effective_risk=effective,
                modified=modified,
                anomaly_reasons=reasons,
                sampled_low_risk=sampled,
                deep_review_required=(
                    effective in {PageRisk.R2, PageRisk.R3}
                    or modified
                    or sampled
                    or bool(reasons)
                ),
                final_candidate_hash=final_candidate_hash,
            ))

        route_operations = {
            "visual-triage",
            "structure-findings",
            "content-math-findings",
            "visual-findings",
            "structure-recheck",
            "content-math-recheck",
            "visual-recheck",
            "local-patch",
            "issue-review",
            "final-review-1",
            "final-review-2",
            "adjudication",
        }
        call_keys = tuple(sorted(
            (
                PageRouteCallKey(
                    role=item.binding.role,
                    operation=item.operation,
                    source_page_id=item.binding.source_page_id,
                    candidate_hash=item.binding.candidate_hash,
                    issue_id=item.binding.issue_id,
                    snapshot_hash=item.binding.snapshot_hash,
                    response_schema_version=item.binding.response_schema_version,
                    succeeded=item.succeeded,
                )
                for item in self._invocations
                if item.operation in route_operations
            ),
            key=lambda item: (
                item.role,
                item.operation,
                item.source_page_id,
                item.candidate_hash,
                item.issue_id,
            ),
        ))

        expected_all = Counter(
            item.page_unit.source_page_id for item in self.page_inputs
        )

        def successful_pages(role: str, operation: str) -> Counter[str]:
            return Counter(
                item.source_page_id
                for item in call_keys
                if item.role == role
                and item.operation == operation
                and item.succeeded
            )

        def require_pages(
            role: str,
            operation: str,
            expected: Counter[str],
        ) -> None:
            if successful_pages(role, operation) != expected:
                self._stop_reasons.append(
                    f"route_coverage_incomplete:{role}:{operation}"
                )

        require_pages("AI-3", "visual-triage", expected_all)
        for operation in ("final-review-1", "final-review-2"):
            require_pages("AI-5", operation, expected_all)
            if any(
                item.role == "AI-5"
                and item.operation == operation
                and item.succeeded
                and item.candidate_hash != final_candidate_hash
                for item in call_keys
            ):
                self._stop_reasons.append(
                    f"route_candidate_stale:AI-5:{operation}"
                )

        effective_by_id = {item.source_page_id: item for item in page_records}
        ai1_expected: Counter[str] = Counter()
        deep_expected: Counter[str] = Counter()
        recheck_expected: Counter[str] = Counter()
        for page_id, record in effective_by_id.items():
            if record.effective_risk == PageRisk.R1:
                ai1_expected[page_id] = 1
            if record.effective_risk == PageRisk.R2 or record.sampled_low_risk:
                ai1_expected[page_id] = 1
                deep_expected[page_id] = 1
            if record.modified:
                recheck_expected[page_id] = 1
            if record.effective_risk == PageRisk.R3:
                self._stop_reasons.append(
                    f"risk_r3_requires_adjudication:{page_id}"
                )
        require_pages("AI-1", "structure-findings", ai1_expected)
        require_pages("AI-2", "content-math-findings", deep_expected)
        require_pages("AI-3", "visual-findings", deep_expected)
        for role, operation in (
            ("AI-1", "structure-recheck"),
            ("AI-2", "content-math-recheck"),
            ("AI-3", "visual-recheck"),
        ):
            require_pages(role, operation, recheck_expected)
            if any(
                item.role == role
                and item.operation == operation
                and item.succeeded
                and item.candidate_hash != final_candidate_hash
                for item in call_keys
            ):
                self._stop_reasons.append(
                    f"route_candidate_stale:{role}:{operation}"
                )
        return PageRiskRouteClosure(
            admission_sha256=admission.digest,
            final_candidate_hash=final_candidate_hash,
            pages=tuple(page_records),
            route_call_keys=call_keys,
        )

    def _discover(self, tex: str, compiled: CompileResult) -> None:
        if self.resilient_execution:
            self._discover_resilient(tex, compiled)
            return
        plans: list[tuple[str, CallBinding, Callable[[object], object], FindingRequest]] = []
        for page in self.page_inputs:
            materials = self._materials(page.page_unit.source_page_id, tex, compiled)
            for role, operation, callback in self._roles_for_page(page):
                discovery_id = (
                    f"DISCOVERY-{role}-{sha256_text(self.snapshot.run_id + materials.source_page_id)[:12]}"
                )
                binding = self._binding(
                    role=role,
                    operation=operation,
                    issue_id=discovery_id,
                    materials=materials,
                )
                plans.append(
                    (operation, binding, callback, FindingRequest(binding, materials))
                )

        calls = tuple(
            lambda ordinal, operation=operation, binding=binding,
            callback=callback, request=request: self._invoke(
                operation,
                binding,
                callback,
                request,
                invocation_ordinal=ordinal,
            )
            for operation, binding, callback, request in plans
        )
        raw_results = self._parallel_invocations(calls)
        validated: list[IssueProposal] = []
        for (operation, binding, _callback, _request), raw in zip(
            plans, raw_results, strict=True
        ):
            role = binding.role
            if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
                raise CallbackContractError(f"{role} must return a sequence of findings")
            proposals = tuple(raw)
            for proposal in proposals:
                self._validate_finding(proposal, role=role, binding=binding)
            if operation == "visual-triage":
                self._record_triage(
                    source_page_id=binding.source_page_id,
                    proposals=proposals,
                )
            else:
                validated.extend(proposals)
        # The only ledger mutation happens here, in immutable page/role order.
        for proposal in validated:
            self.runtime.ledger.upsert(proposal, round_index=0)
        for page in self.page_inputs:
            self.runtime.performance.record_page_completion(
                page.page_unit.source_page_id,
                max(0.0, self.clock() - self._run_started),
            )
        self._run_triage_escalations(tex, compiled)

    def _conflict_groups(self) -> tuple[tuple[IssueRecord, ...], ...]:
        records = [
            item for item in self.runtime.ledger.records
            if item.current_status == IssueStatus.OPEN
        ]
        adjacency: dict[str, set[str]] = {item.issue_id: set() for item in records}
        by_id = {item.issue_id: item for item in records}
        for index, left in enumerate(records):
            for right in records[index + 1:]:
                if left.issue_type.casefold() != right.issue_type.casefold() and _overlap(left, right):
                    adjacency[left.issue_id].add(right.issue_id)
                    adjacency[right.issue_id].add(left.issue_id)
        groups: list[tuple[IssueRecord, ...]] = []
        visited: set[str] = set()
        for issue_id, neighbours in adjacency.items():
            if issue_id in visited or not neighbours:
                continue
            stack = [issue_id]
            component: set[str] = set()
            while stack:
                current = stack.pop()
                if current in component:
                    continue
                component.add(current)
                stack.extend(adjacency[current])
            visited.update(component)
            groups.append(tuple(by_id[item] for item in sorted(component)))
        return tuple(groups)

    def _adjudicate(
        self,
        *,
        issues: Sequence[IssueRecord],
        reason: str,
        tex: str,
        compiled: CompileResult,
    ) -> None:
        callback = self.callbacks.ai6_adjudicate
        if callback is None or not issues:
            return
        live = tuple(self.runtime.ledger.get(item.issue_id) for item in issues)
        primary = live[0]
        page_id = primary.source_page_ids[0]
        materials = self._materials(page_id, tex, compiled)
        binding = self._binding(
            role="AI-6",
            operation="adjudication",
            issue_id=primary.issue_id,
            materials=materials,
        )
        result = self._invoke(
            "adjudication",
            binding,
            callback,
            AdjudicationRequest(binding, materials, reason, live),
        )
        if not isinstance(result, AdjudicationResult):
            raise CallbackContractError("AI-6 must return AdjudicationResult")
        if result.candidate_hash != binding.candidate_hash:
            raise StaleEvidenceError("AI-6 adjudication belongs to a stale candidate")
        expected = tuple(sorted(item.issue_id for item in live))
        if result.issue_ids != expected:
            raise CallbackContractError("AI-6 changed the host conflict set")
        if not result.resolved:
            return
        rejected = set(expected).difference(result.keep_issue_ids)
        for issue_id in sorted(rejected):
            record = self.runtime.ledger.get(issue_id)
            if record.current_status == IssueStatus.OPEN:
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.REJECTED_FALSE_POSITIVE,
                    round_index=max(0, record.last_modified_round),
                    candidate_hash=binding.candidate_hash,
                )

    def _review_issue(
        self,
        *,
        issue: IssueRecord,
        application_patch_id: str,
        candidate_tex: str,
        compiled: CompileResult,
    ) -> tuple[ReviewResult, bool, bool, bool, int, list[dict[str, object]]]:
        responses: list[IssuePageReviewResult] = []
        for page_id in issue.source_page_ids:
            materials = self._materials(page_id, candidate_tex, compiled)
            binding = self._binding(
                role="AI-5",
                operation="issue-review",
                issue_id=issue.issue_id,
                materials=materials,
            )
            response = self._invoke(
                "issue-review",
                binding,
                self.callbacks.ai5_issue_review,
                IssueReviewRequest(
                    binding,
                    materials,
                    issue,
                    application_patch_id,
                    compiled.compile_passes,
                    compiled.state,
                ),
            )
            if not isinstance(response, IssuePageReviewResult):
                raise CallbackContractError("AI-5 must return IssuePageReviewResult")
            if response.candidate_hash != binding.candidate_hash:
                raise StaleEvidenceError("AI-5 issue review belongs to a stale candidate")
            if response.issue_id != issue.issue_id or response.source_page_id != page_id:
                raise CallbackContractError("AI-5 issue review changed its host binding")
            responses.append(response)
        priority = {
            ReviewResult.REGRESSION: 0,
            ReviewResult.UNCERTAIN: 1,
            ReviewResult.FAIL: 2,
            ReviewResult.PASS: 3,
        }
        result = min((item.result for item in responses), key=priority.get)
        return (
            result,
            all(item.content_conservation_ok for item in responses),
            all(item.math_conservation_ok for item in responses),
            all(item.visual_review_ok for item in responses),
            sum(item.new_high_priority_issues for item in responses),
            [asdict(item) for item in responses],
        )

    def _selection_quality(
        self,
        machine_quality: QualityVector,
        *,
        provisionally_closed_issue_ids: Sequence[str] = (),
    ) -> QualityVector:
        """Bind model-owned issue counts into the host selection vector.

        Compilation callbacks own machine dimensions such as page omissions,
        conservation errors, and visual counts.  They cannot know the final
        state of the host ``IssueLedger``.  The orchestrator therefore replaces
        only ``open_critical`` and ``open_high`` from the ledger, optionally
        excluding the issue that the just-completed independent review would
        close.  This makes candidate improvement possible without allowing a
        callback to under-report high-risk findings.
        """

        provisionally_closed = set(provisionally_closed_issue_ids)
        unresolved = tuple(
            item for item in self.runtime.ledger.unresolved()
            if item.issue_id not in provisionally_closed
        )
        return replace(
            machine_quality,
            open_critical=sum(item.severity == Severity.CRITICAL for item in unresolved),
            open_high=sum(item.severity == Severity.HIGH for item in unresolved),
        )

    def _attempt_issue(
        self,
        *,
        issue_id: str,
        round_index: int,
        tex: str,
        compiled: CompileResult,
    ) -> tuple[str, CompileResult, bool]:
        issue = self.runtime.ledger.get(issue_id)
        issue = self.runtime.ledger.transition(
            issue_id,
            IssueStatus.FIXING,
            round_index=round_index,
            candidate_hash=sha256_text(tex),
        )
        page_id = issue.source_page_ids[0]
        materials = self._materials(page_id, tex, compiled)
        scope = self.callbacks.patch_scope(issue, tex)
        if (
            scope.issue_id != issue.issue_id
            or scope.candidate_hash != sha256_text(tex)
            or not set(issue.source_page_ids).issubset(scope.source_page_ids)
        ):
            raise CallbackContractError("host patch scope is stale or belongs to another issue")
        binding = self._binding(
            role="AI-4",
            operation="local-patch",
            issue_id=issue.issue_id,
            materials=materials,
        )
        plan = self._invoke(
            "local-patch",
            binding,
            self.callbacks.ai4_patch,
            PatchRequest(binding, materials, issue, scope),
        )
        fingerprint = sha256_text(
            binding.candidate_hash
            + binding.issue_id
            + "".join(asdict(binding.material_hashes).values())
        )
        if plan is None:
            self.runtime.ledger.transition(
                issue_id,
                IssueStatus.OPEN,
                round_index=round_index,
                candidate_hash=sha256_text(tex),
            )
            decision = self.runtime.progress.record_issue_attempt(
                issue_id,
                prompt_and_evidence_fingerprint=fingerprint,
                resolved=False,
            )
            if decision.stop_current_strategy:
                self._adjudicate(
                    issues=(self.runtime.ledger.get(issue_id),),
                    reason="STALL",
                    tex=tex,
                    compiled=compiled,
                )
            return tex, compiled, False
        if not isinstance(plan, PatchPlan):
            raise CallbackContractError("AI-4 must return PatchPlan or None")
        if plan.candidate_hash != binding.candidate_hash:
            raise StaleEvidenceError("AI-4 patch belongs to a stale candidate")
        if plan.issue_ids != (issue.issue_id,):
            raise CallbackContractError("AI-4 patch must be bound to exactly one host issue")
        try:
            application = apply_patch_plan(tex, plan, scopes={issue.issue_id: scope})
        except PatchRejected as exc:
            if "candidate_hash" in str(exc) or "stale" in str(exc):
                raise StaleEvidenceError(str(exc)) from exc
            raise CallbackContractError(str(exc)) from exc
        if application.candidate_hash in self._attempted_candidate_hashes:
            self.runtime.ledger.transition(
                issue_id,
                IssueStatus.OPEN,
                round_index=round_index,
                candidate_hash=sha256_text(tex),
            )
            decision = self.runtime.progress.record_issue_attempt(
                issue_id,
                prompt_and_evidence_fingerprint=fingerprint,
                resolved=False,
            )
            if decision.stop_current_strategy:
                self._adjudicate(
                    issues=(self.runtime.ledger.get(issue_id),),
                    reason="STALL",
                    tex=tex,
                    compiled=compiled,
                )
            return tex, compiled, False
        self._attempted_candidate_hashes.add(application.candidate_hash)
        candidate_compile = self._compile(
            application.candidate_tex,
            round_index=round_index,
            reason=f"AI-4 patch {application.patch_id}",
        )
        review = self._review_issue(
            issue=issue,
            application_patch_id=application.patch_id,
            candidate_tex=application.candidate_tex,
            compiled=candidate_compile,
        )
        review_would_close = (
            review[0] == ReviewResult.PASS
            and candidate_compile.compiled_ok
            and review[1]
            and review[2]
            and review[3]
            and review[4] == 0
        )
        selection_quality = self._selection_quality(
            candidate_compile.quality,
            provisionally_closed_issue_ids=(issue.issue_id,) if review_would_close else (),
        )
        # Persist the ledger state that belongs to the candidate, not the
        # pre-review in-memory state.  The repository is immutable, so writing
        # FIXING here would make an accepted recovery checkpoint permanently
        # contradict the host ledger after this method closes the issue.
        candidate_ledger = IssueLedger(self.runtime.ledger.records)
        candidate_ledger.transition(
            issue_id,
            IssueStatus.FIXED_PENDING_REVIEW,
            round_index=round_index,
            candidate_hash=application.candidate_hash,
            patch_id=application.patch_id,
        )
        candidate_ledger.close_after_review(
            issue_id,
            round_index=round_index,
            candidate_hash=application.candidate_hash,
            review_result=review[0],
            compile_ok=candidate_compile.compiled_ok,
            content_conservation_ok=review[1],
            math_conservation_ok=review[2],
            visual_review_ok=review[3],
            new_high_priority_issues=review[4],
        )
        record = self.runtime.candidates.evaluate(
            application=application,
            round_index=round_index,
            pdf=candidate_compile.pdf,
            compile_log=candidate_compile.compile_log,
            quality=selection_quality,
            issue_ledger=candidate_ledger.to_dict(),
            review={
                "result": review[0].value,
                "content_conservation_ok": review[1],
                "math_conservation_ok": review[2],
                "visual_review_ok": review[3],
                "new_high_priority_issues": review[4],
                "page_reviews": review[5],
                "machine_compile_ok": candidate_compile.compiled_ok,
                "machine_quality": asdict(candidate_compile.quality),
                "host_selection_quality": asdict(selection_quality),
            },
        )
        if record.disposition.value == "ACCEPTED":
            self._modified_pages.update(application.affected_page_ids)
            self.runtime.ledger.transition(
                issue_id,
                IssueStatus.FIXED_PENDING_REVIEW,
                round_index=round_index,
                candidate_hash=application.candidate_hash,
                patch_id=application.patch_id,
            )
            closed = self.runtime.ledger.close_after_review(
                issue_id,
                round_index=round_index,
                candidate_hash=application.candidate_hash,
                review_result=review[0],
                compile_ok=candidate_compile.compiled_ok,
                content_conservation_ok=review[1],
                math_conservation_ok=review[2],
                visual_review_ok=review[3],
                new_high_priority_issues=review[4],
            )
            resolved = closed.current_status == IssueStatus.VERIFIED_CLOSED
            self.runtime.progress.record_issue_attempt(
                issue_id,
                prompt_and_evidence_fingerprint=fingerprint,
                resolved=resolved,
            )
            return application.candidate_tex, candidate_compile, True
        self.runtime.ledger.transition(
            issue_id,
            IssueStatus.OPEN,
            round_index=round_index,
            candidate_hash=sha256_text(tex),
        )
        decision = self.runtime.progress.record_issue_attempt(
            issue_id,
            prompt_and_evidence_fingerprint=fingerprint,
            resolved=False,
        )
        if decision.stop_current_strategy:
            self._adjudicate(
                issues=(self.runtime.ledger.get(issue_id),),
                reason="STALL",
                tex=tex,
                compiled=compiled,
            )
        return tex, compiled, False

    def _attempt_issue_batch(
        self,
        *,
        issue_ids: Sequence[str],
        round_index: int,
        tex: str,
        compiled: CompileResult,
    ) -> tuple[str, CompileResult, bool]:
        """Micro-check local plans, then compile one non-overlapping macro batch."""

        plans: list[PatchPlan] = []
        scopes: dict[str, PatchScope] = {}
        issues: dict[str, IssueRecord] = {}
        fingerprints: dict[str, str] = {}
        base_hash = sha256_text(tex)

        for issue_id in issue_ids:
            issue = self.runtime.ledger.transition(
                issue_id,
                IssueStatus.FIXING,
                round_index=round_index,
                candidate_hash=base_hash,
            )
            issues[issue_id] = issue
            page_id = issue.source_page_ids[0]
            materials = self._materials(page_id, tex, compiled)
            scope = self.callbacks.patch_scope(issue, tex)
            if (
                scope.issue_id != issue.issue_id
                or scope.candidate_hash != base_hash
                or not set(issue.source_page_ids).issubset(scope.source_page_ids)
            ):
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.BLOCKED,
                    round_index=round_index,
                    candidate_hash=base_hash,
                    blocker_reason="host patch scope is stale or incomplete",
                )
                self._stop_reasons.append(f"patch_scope_blocked:{issue_id}")
                continue
            binding = self._binding(
                role="AI-4",
                operation="local-patch",
                issue_id=issue.issue_id,
                materials=materials,
            )
            fingerprint = sha256_text(
                binding.candidate_hash
                + binding.issue_id
                + "".join(asdict(binding.material_hashes).values())
            )
            fingerprints[issue_id] = fingerprint
            try:
                plan = self._invoke(
                    "local-patch",
                    binding,
                    self.callbacks.ai4_patch,
                    PatchRequest(binding, materials, issue, scope),
                )
            except BaseException as exc:
                if bool(getattr(exc, "fatal_analysis", False)):
                    raise
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.BLOCKED,
                    round_index=round_index,
                    candidate_hash=base_hash,
                    blocker_reason=f"{type(exc).__name__}: {exc}"[:1000],
                )
                self._stop_reasons.append(f"patch_task_blocked:{issue_id}")
                continue
            if plan is None:
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.OPEN,
                    round_index=round_index,
                    candidate_hash=base_hash,
                )
                self.runtime.progress.record_issue_attempt(
                    issue_id,
                    prompt_and_evidence_fingerprint=fingerprint,
                    resolved=False,
                )
                continue
            if (
                not isinstance(plan, PatchPlan)
                or plan.candidate_hash != base_hash
                or plan.issue_ids != (issue_id,)
            ):
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.BLOCKED,
                    round_index=round_index,
                    candidate_hash=base_hash,
                    blocker_reason="AI-4 returned an invalid or stale patch contract",
                )
                self._stop_reasons.append(f"patch_contract_blocked:{issue_id}")
                continue
            plans.append(plan)
            scopes[issue_id] = scope

        if not plans:
            return tex, compiled, False

        batch = PatchPlan(
            candidate_hash=base_hash,
            issue_ids=tuple(plan.issue_ids[0] for plan in plans),
            operations=tuple(
                operation for plan in plans for operation in plan.operations
            ),
        )
        try:
            application = apply_patch_plan(tex, batch, scopes=scopes)
        except PatchRejected as exc:
            for plan in plans:
                issue_id = plan.issue_ids[0]
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.BLOCKED,
                    round_index=round_index,
                    candidate_hash=base_hash,
                    blocker_reason=f"macro batch micro-check rejected: {exc}"[:1000],
                )
                self._stop_reasons.append(f"micro_patch_rejected:{issue_id}")
            return tex, compiled, False

        self._incremental_check_count += len(plans)
        if application.candidate_hash in self._attempted_candidate_hashes:
            for plan in plans:
                issue_id = plan.issue_ids[0]
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.OPEN,
                    round_index=round_index,
                    candidate_hash=base_hash,
                )
                self.runtime.progress.record_issue_attempt(
                    issue_id,
                    prompt_and_evidence_fingerprint=fingerprints[issue_id],
                    resolved=False,
                )
            return tex, compiled, False
        self._attempted_candidate_hashes.add(application.candidate_hash)

        try:
            candidate_compile = self._compile(
                application.candidate_tex,
                round_index=round_index,
                reason=f"macro patch batch {application.patch_id}",
            )
        except BaseException as exc:
            for plan in plans:
                issue_id = plan.issue_ids[0]
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.BLOCKED,
                    round_index=round_index,
                    candidate_hash=base_hash,
                    blocker_reason=f"macro compile failed: {exc}"[:1000],
                )
            self._stop_reasons.append(f"macro_compile_failed:round-{round_index}")
            return tex, compiled, False

        reviews: dict[
            str,
            tuple[ReviewResult, bool, bool, bool, int, list[dict[str, object]]],
        ] = {}
        review_errors: dict[str, str] = {}
        for plan in plans:
            issue_id = plan.issue_ids[0]
            try:
                reviews[issue_id] = self._review_issue(
                    issue=issues[issue_id],
                    application_patch_id=application.patch_id,
                    candidate_tex=application.candidate_tex,
                    compiled=candidate_compile,
                )
            except BaseException as exc:
                if bool(getattr(exc, "fatal_analysis", False)):
                    raise
                review_errors[issue_id] = f"{type(exc).__name__}: {exc}"[:1000]
                self._stop_reasons.append(f"issue_review_blocked:{issue_id}")

        provisionally_closed = tuple(
            issue_id
            for issue_id, review in reviews.items()
            if (
                review[0] == ReviewResult.PASS
                and candidate_compile.compiled_ok
                and review[1]
                and review[2]
                and review[3]
                and review[4] == 0
            )
        )
        selection_quality = self._selection_quality(
            candidate_compile.quality,
            provisionally_closed_issue_ids=provisionally_closed,
        )

        candidate_ledger = IssueLedger(self.runtime.ledger.records)
        for plan in plans:
            issue_id = plan.issue_ids[0]
            review = reviews.get(issue_id)
            if review is None:
                candidate_ledger.transition(
                    issue_id,
                    IssueStatus.BLOCKED,
                    round_index=round_index,
                    candidate_hash=application.candidate_hash,
                    blocker_reason=review_errors[issue_id],
                )
                continue
            candidate_ledger.transition(
                issue_id,
                IssueStatus.FIXED_PENDING_REVIEW,
                round_index=round_index,
                candidate_hash=application.candidate_hash,
                patch_id=application.patch_id,
            )
            candidate_ledger.close_after_review(
                issue_id,
                round_index=round_index,
                candidate_hash=application.candidate_hash,
                review_result=review[0],
                compile_ok=candidate_compile.compiled_ok,
                content_conservation_ok=review[1],
                math_conservation_ok=review[2],
                visual_review_ok=review[3],
                new_high_priority_issues=review[4],
            )

        record = self.runtime.candidates.evaluate(
            application=application,
            round_index=round_index,
            pdf=candidate_compile.pdf,
            compile_log=candidate_compile.compile_log,
            quality=selection_quality,
            issue_ledger=candidate_ledger.to_dict(),
            review={
                "batch_patch_id": application.patch_id,
                "issue_reviews": {
                    issue_id: {
                        "result": review[0].value,
                        "content_conservation_ok": review[1],
                        "math_conservation_ok": review[2],
                        "visual_review_ok": review[3],
                        "new_high_priority_issues": review[4],
                        "page_reviews": review[5],
                    }
                    for issue_id, review in sorted(reviews.items())
                },
                "review_errors": dict(sorted(review_errors.items())),
                "machine_compile_ok": candidate_compile.compiled_ok,
                "machine_quality": asdict(candidate_compile.quality),
                "host_selection_quality": asdict(selection_quality),
            },
        )
        if record.disposition.value == "ACCEPTED":
            self._modified_pages.update(application.affected_page_ids)
            for plan in plans:
                issue_id = plan.issue_ids[0]
                review = reviews.get(issue_id)
                if review is None:
                    self.runtime.ledger.transition(
                        issue_id,
                        IssueStatus.BLOCKED,
                        round_index=round_index,
                        candidate_hash=application.candidate_hash,
                        blocker_reason=review_errors[issue_id],
                    )
                    continue
                self.runtime.ledger.transition(
                    issue_id,
                    IssueStatus.FIXED_PENDING_REVIEW,
                    round_index=round_index,
                    candidate_hash=application.candidate_hash,
                    patch_id=application.patch_id,
                )
                closed = self.runtime.ledger.close_after_review(
                    issue_id,
                    round_index=round_index,
                    candidate_hash=application.candidate_hash,
                    review_result=review[0],
                    compile_ok=candidate_compile.compiled_ok,
                    content_conservation_ok=review[1],
                    math_conservation_ok=review[2],
                    visual_review_ok=review[3],
                    new_high_priority_issues=review[4],
                )
                self.runtime.progress.record_issue_attempt(
                    issue_id,
                    prompt_and_evidence_fingerprint=fingerprints[issue_id],
                    resolved=closed.current_status == IssueStatus.VERIFIED_CLOSED,
                )
            return application.candidate_tex, candidate_compile, True

        for plan in plans:
            issue_id = plan.issue_ids[0]
            self.runtime.ledger.transition(
                issue_id,
                IssueStatus.OPEN,
                round_index=round_index,
                candidate_hash=base_hash,
            )
            self.runtime.progress.record_issue_attempt(
                issue_id,
                prompt_and_evidence_fingerprint=fingerprints[issue_id],
                resolved=False,
            )
        return tex, compiled, False

    def _final_reviews(
        self,
        tex: str,
        compiled: CompileResult,
    ) -> tuple[IndependentReviewPass, ...]:
        output: list[IndependentReviewPass] = []
        for pass_number, context_id in enumerate(self.final_review_context_ids, start=1):
            plans: list[
                tuple[str, CallBinding, FinalPageReviewRequest]
            ] = []
            for page in self.page_inputs:
                page_id = page.page_unit.source_page_id
                materials = self._materials(page_id, tex, compiled)
                review_scope_id = (
                    f"FINAL-REVIEW-{pass_number}-"
                    f"{sha256_text(self.snapshot.run_id + page_id + context_id)[:12]}"
                )
                binding = self._binding(
                    role="AI-5",
                    operation=f"final-review-{pass_number}",
                    issue_id=review_scope_id,
                    materials=materials,
                )
                plans.append((
                    page_id,
                    binding,
                    FinalPageReviewRequest(binding, materials, pass_number, context_id),
                ))
            calls = tuple(
                lambda ordinal, binding=binding, request=request: self._invoke(
                    f"final-review-{pass_number}",
                    binding,
                    self.callbacks.ai5_final_review,
                    request,
                    invocation_ordinal=ordinal,
                )
                for _page_id, binding, request in plans
            )
            page_results: list[FinalPageReviewResult] = []
            if self.resilient_execution:
                ordinals = self._reserve_invocation_ordinals(len(calls))
                with ThreadPoolExecutor(
                    max_workers=min(self.concurrency_limit, len(calls)),
                    thread_name_prefix="latexstruct-final-review",
                ) as pool:
                    futures = [
                        pool.submit(call, ordinal)
                        for call, ordinal in zip(calls, ordinals, strict=True)
                    ]
                    for (page_id, binding, _request), future in zip(
                        plans, futures, strict=True
                    ):
                        try:
                            result = future.result()
                            if not isinstance(result, FinalPageReviewResult):
                                raise CallbackContractError(
                                    "AI-5 must return FinalPageReviewResult"
                                )
                            if result.candidate_hash != binding.candidate_hash:
                                raise StaleEvidenceError(
                                    "AI-5 final review belongs to a stale candidate"
                                )
                            if (
                                result.source_page_id != page_id
                                or result.pass_number != pass_number
                                or result.context_id != context_id
                            ):
                                raise CallbackContractError(
                                    "AI-5 final review changed its host binding"
                                )
                        except BaseException as exc:
                            if bool(getattr(exc, "fatal_analysis", False)):
                                for pending_future in futures:
                                    pending_future.cancel()
                                raise
                            self._stop_reasons.append(
                                f"final_review_blocked:{pass_number}:{page_id}"
                            )
                            continue
                        page_results.append(result)
            else:
                raw_results = self._parallel_invocations(calls)
                for (page_id, binding, _request), result in zip(
                    plans, raw_results, strict=True
                ):
                    if not isinstance(result, FinalPageReviewResult):
                        raise CallbackContractError(
                            "AI-5 must return FinalPageReviewResult"
                        )
                    if result.candidate_hash != binding.candidate_hash:
                        raise StaleEvidenceError(
                            "AI-5 final review belongs to a stale candidate"
                        )
                    if (
                        result.source_page_id != page_id
                        or result.pass_number != pass_number
                        or result.context_id != context_id
                    ):
                        raise CallbackContractError(
                            "AI-5 final review changed its host binding"
                        )
                    page_results.append(result)
            if not page_results:
                # The schema deliberately forbids an empty review pass.  Its
                # absence is machine-detectable and cannot masquerade as an
                # all(empty) success; a later independent context still runs.
                continue
            complete = len(page_results) == len(plans)
            output.append(IndependentReviewPass(
                pass_number=pass_number,
                context_id=context_id,
                candidate_hash=sha256_text(tex),
                checked_page_ids=tuple(item.source_page_id for item in page_results),
                compile_passes=compiled.compile_passes,
                content_conservation_ok=complete and all(
                    item.content_conservation_ok for item in page_results
                ),
                math_conservation_ok=complete and all(
                    item.math_conservation_ok for item in page_results
                ),
                formal_inventory_ok=complete and all(
                    item.formal_inventory_ok for item in page_results
                ),
                visual_review_ok=complete and all(
                    item.visual_review_ok for item in page_results
                ),
                new_high_risk_issues=sum(
                    item.new_high_risk_issues for item in page_results
                ),
                prior_pass_conclusion_visible=any(
                    item.prior_pass_conclusion_visible for item in page_results
                ),
            ))
        return tuple(output)

    def _verification(
        self,
        *,
        tex: str,
        compiled: CompileResult,
        baseline_compile: CompileResult,
        final_reviews: tuple[IndependentReviewPass, ...],
    ) -> tuple[VerificationEvidence, VerificationDecision]:
        candidate_hash = sha256_text(tex)
        facts = self.callbacks.machine_verify(MachineVerificationRequest(
            run_id=self.snapshot.run_id,
            candidate_hash=candidate_hash,
            tex=tex,
            pdf=compiled.pdf,
            compile_result=compiled,
            issue_ledger=self.runtime.ledger.to_dict(),
            final_reviews=final_reviews,
        ))
        if not isinstance(facts, MachineVerificationFacts):
            raise CallbackContractError("machine_verify must return MachineVerificationFacts")
        if facts.candidate_hash != candidate_hash:
            raise StaleEvidenceError("machine verification belongs to a stale candidate")
        unresolved = self.runtime.ledger.unresolved()
        evidence = VerificationEvidence(
            raw_ocr_frozen=self.raw_ocr_frozen,
            baseline_compile_passes=baseline_compile.compile_passes,
            best_compile_passes=compiled.compile_passes,
            best_pdf_openable=compiled.pdf_openable,
            expected_page_ids=tuple(self._by_page),
            checked_page_ids=facts.checked_page_ids,
            silent_page_omissions=facts.silent_page_omissions,
            silent_text_losses=facts.silent_text_losses,
            unauthorized_math_changes=facts.unauthorized_math_changes,
            formal_errors=facts.formal_errors,
            toc_complete_and_ordered=facts.toc_complete_and_ordered,
            severe_equation_number_errors=facts.severe_equation_number_errors,
            silent_footnote_losses=facts.silent_footnote_losses,
            silent_figure_caption_losses=facts.silent_figure_caption_losses,
            silent_bibliography_losses=facts.silent_bibliography_losses,
            open_critical=sum(item.severity == Severity.CRITICAL for item in unresolved),
            open_high=sum(item.severity == Severity.HIGH for item in unresolved),
            regressions=sum(
                item.current_status == IssueStatus.REGRESSION for item in unresolved
            ),
            candidate_hash=candidate_hash,
            current_candidate_hash=candidate_hash,
            final_reviews=final_reviews,
        )
        decision = self.runtime.final_decision(evidence)
        # ``VerificationEvidence`` historically exposed only CRITICAL/HIGH
        # counters.  The issue ledger is the host authority, however, and a
        # MEDIUM/LOW issue that remains OPEN/BLOCKED/REGRESSION is still an
        # unresolved finding.  Never let clean machine counters promote such a
        # candidate to VERIFIED.
        unresolved_gate = tuple(
            item for item in unresolved
            if item.current_status in {
                IssueStatus.OPEN,
                IssueStatus.BLOCKED,
                IssueStatus.REGRESSION,
            }
        )
        if unresolved_gate:
            status_failures = tuple(
                f"unresolved_ledger_{status.value.lower()}"
                for status in sorted(
                    {item.current_status for item in unresolved_gate},
                    key=lambda item: item.value,
                )
            )
            decision = VerificationDecision(
                status=(
                    AnalysisFinalStatus.COMPLETED_WITH_ISSUES
                    if decision.status == AnalysisFinalStatus.VERIFIED
                    else decision.status
                ),
                verified=False,
                failures=tuple(dict.fromkeys((
                    *decision.failures,
                    "unresolved_ledger_issue",
                    *status_failures,
                ))),
            )
        if self._stop_reasons:
            decision = VerificationDecision(
                status=(
                    AnalysisFinalStatus.COMPLETED_WITH_ISSUES
                    if decision.status == AnalysisFinalStatus.VERIFIED
                    else decision.status
                ),
                verified=False,
                failures=tuple(dict.fromkeys((
                    *decision.failures,
                    "analysis_work_incomplete",
                    *self._stop_reasons,
                ))),
            )
        return evidence, decision

    def _commit_checkpoint(
        self,
        *,
        round_index: int,
        current_tex: str,
        current_compile: CompileResult,
    ) -> None:
        callback = self.checkpoint_callback
        if callback is None:
            return
        current = self.runtime.candidates.current
        best = self.runtime.candidates.best
        if current is None or best is None:
            raise AnalysisOrchestrationError(
                "cannot checkpoint before candidate authority is initialized"
            )
        rollback_ids = tuple(dict.fromkeys((
            *self._prior_rollback_candidate_ids,
            *(
                item.rejected_candidate_id
                for item in self.runtime.candidates.rollback_history
            ),
        )))
        callback(AnalysisCheckpointState(
            round_index=round_index,
            current_tex=current_tex,
            current_compile=current_compile,
            current_candidate=current,
            best_candidate=best,
            issue_ledger=self.runtime.ledger.to_dict(),
            task_ledger=(
                self._task_store.to_dict()
                if self._task_store is not None
                else {
                    "schema": "latexstruct-analysis-task-ledger-v2",
                    "records": {},
                }
            ),
            invocations=tuple(sorted(self._invocations, key=lambda item: item.ordinal)),
            full_compile_count=self._prior_full_compile_count + len(self._compile_history),
            incremental_check_count=self._incremental_check_count,
            rollback_candidate_ids=rollback_ids,
            modified_page_ids=tuple(sorted(self._modified_pages)),
            stop_reasons=tuple(dict.fromkeys(self._stop_reasons)),
        ))

    def run(
        self,
        *,
        baseline_tex: str,
        max_macro_rounds: int = 2,
    ) -> AnalysisOrchestrationResult:
        """Execute all roles, candidate gates, two reviews, and final status."""

        if sha256_text(baseline_tex) != self.snapshot.baseline_tex_hash:
            raise StaleEvidenceError("baseline TeX does not match the immutable snapshot")
        if any(
            item.baseline_tex_region not in baseline_tex
            for item in self.page_inputs
        ):
            raise StaleEvidenceError(
                "a baseline TeX page region does not belong to the immutable baseline"
            )
        if max_macro_rounds < 1:
            raise ValueError("max_macro_rounds must be positive")
        started = self.clock()
        self._run_started = started
        baseline_compile = self._compile(
            baseline_tex, round_index=0, reason="frozen OCR baseline"
        )
        if not baseline_compile.compiled_ok:
            raise AnalysisOrchestrationError(
                "baseline compilation did not produce an openable two-pass PDF"
            )
        if baseline_compile.pdf_hash != self.snapshot.baseline_pdf_hash:
            raise StaleEvidenceError("baseline PDF does not match the immutable snapshot")
        current_tex = baseline_tex
        current_compile = baseline_compile
        # Preserve the verified input before any fallible discovery call, but
        # keep it separate from CandidateController: the real selection
        # baseline must be initialized only after discovery has populated the
        # host ledger and its quality counts are known.
        self.runtime.candidates.repository.save_baseline_input_checkpoint(
            run_id=self.snapshot.run_id,
            tex=baseline_tex,
            pdf=baseline_compile.pdf,
            compile_log=baseline_compile.compile_log,
            compile_passes=baseline_compile.compile_passes,
            pdf_openable=baseline_compile.pdf_openable,
        )
        if self.baseline_frozen_callback is not None:
            self.baseline_frozen_callback(baseline_compile)

        if self.resume_state is not None:
            state = self.resume_state
            self.runtime.ledger = IssueLedger.from_dict(state.issue_ledger)
            record = self.runtime.candidates.resume_from_committed_best(
                state.best_candidate_id
            )
            if (
                record.candidate_id != state.current_candidate_id
                or record.tex_sha256 != state.current_candidate_hash
            ):
                raise StaleEvidenceError(
                    "resume candidate differs from the committed checkpoint"
                )
            current_tex = state.current_tex
            current_compile = (
                baseline_compile
                if state.current_candidate_hash == self.snapshot.baseline_tex_hash
                else self._compile(
                    current_tex,
                    round_index=state.round_index,
                    reason="resume committed history best",
                )
            )
            self._attempted_candidate_hashes.add(state.current_candidate_hash)
            first_round = state.round_index + 1
        else:
            self._discover(current_tex, current_compile)
            for group in self._conflict_groups():
                self._adjudicate(
                    issues=group,
                    reason="CONFLICT",
                    tex=current_tex,
                    compiled=current_compile,
                )
            self.runtime.candidates.save_baseline(
                tex=baseline_tex,
                pdf=baseline_compile.pdf,
                compile_log=baseline_compile.compile_log,
                quality=self._selection_quality(baseline_compile.quality),
                issue_ledger=self.runtime.ledger.to_dict(),
            )
            self._commit_checkpoint(
                round_index=0,
                current_tex=current_tex,
                current_compile=current_compile,
            )
            first_round = 1

        last_committed_round = first_round - 1
        for round_index in range(first_round, max_macro_rounds + 1):
            eligible = [
                item for item in self.runtime.ledger.unresolved()
                if item.current_status in {
                    IssueStatus.OPEN,
                    IssueStatus.BLOCKED,
                    IssueStatus.REGRESSION,
                }
            ]
            if not eligible:
                break
            eligible.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.issue_id))
            if self.macro_batching_enabled:
                current_tex, current_compile, _accepted = self._attempt_issue_batch(
                    issue_ids=tuple(item.issue_id for item in eligible),
                    round_index=round_index,
                    tex=current_tex,
                    compiled=current_compile,
                )
            else:
                for issue in eligible:
                    # AI-6 may have rejected another item while this round was running.
                    live = self.runtime.ledger.get(issue.issue_id)
                    if live.current_status not in {
                        IssueStatus.OPEN,
                        IssueStatus.BLOCKED,
                        IssueStatus.REGRESSION,
                    }:
                        continue
                    current_tex, current_compile, _accepted = self._attempt_issue(
                        issue_id=issue.issue_id,
                        round_index=round_index,
                        tex=current_tex,
                        compiled=current_compile,
                    )
            self._commit_checkpoint(
                round_index=round_index,
                current_tex=current_tex,
                current_compile=current_compile,
            )
            last_committed_round = round_index

        self._recheck_modified_pages(
            current_tex,
            current_compile,
            round_index=last_committed_round + 1,
        )
        if self._modified_pages:
            self._commit_checkpoint(
                round_index=last_committed_round,
                current_tex=current_tex,
                current_compile=current_compile,
            )
        best = self.runtime.candidates.best
        if best is None or best.tex_sha256 != sha256_text(current_tex):
            raise AnalysisOrchestrationError("candidate controller lost the history best")
        final_reviews = self._final_reviews(current_tex, current_compile)
        page_route_closure = self._build_page_route_closure(
            final_candidate_hash=sha256_text(current_tex),
        )
        evidence, decision = self._verification(
            tex=current_tex,
            compiled=current_compile,
            baseline_compile=baseline_compile,
            final_reviews=final_reviews,
        )
        # Capture final-review and machine-verification invocations as a later
        # immutable sequence even when they do not advance the macro round.
        self._commit_checkpoint(
            round_index=last_committed_round,
            current_tex=current_tex,
            current_compile=current_compile,
        )
        elapsed = max(0.0, self.clock() - started)
        closed = sum(
            item.current_status == IssueStatus.VERIFIED_CLOSED
            for item in self.runtime.ledger.records
        )
        blocked = sum(
            item.current_status == IssueStatus.BLOCKED
            for item in self.runtime.ledger.records
        )
        performance = self.runtime.performance.snapshot(
            elapsed_seconds=elapsed,
            machine_preflight_seconds=0.0,
            whole_book_scan_seconds=elapsed,
            role_call_counts=self._role_counts,
            model_elapsed_seconds=self._role_elapsed,
            # Transport usage is owned by the production bridge.  A bare
            # orchestrator cannot know whether a completed or failed request
            # consumed billable tokens, so it must not manufacture zeroes.
            input_tokens=None,
            output_tokens=None,
            usage_complete=False,
            cache_hits=0,
            cache_misses=0,
            cache_status="DISABLED",
            high_risk_pages=sum(
                item.page_unit.risk_level in {PageRisk.R2, PageRisk.R3}
                for item in self.page_inputs
            ),
            modified_pages=len(self._modified_pages),
            full_compile_count=self._prior_full_compile_count + len(self._compile_history),
            incremental_check_count=self._incremental_check_count,
            rollback_count=(
                len(self._prior_rollback_candidate_ids)
                + len(self.runtime.candidates.rollback_history)
            ),
            auto_closed_issues=closed,
            blocked_issues=blocked,
            final_status=decision.status,
        )
        return AnalysisOrchestrationResult(
            decision=decision,
            evidence=evidence,
            best_candidate=best,
            current_tex=current_tex,
            current_pdf=current_compile.pdf,
            final_reviews=final_reviews,
            ledger=self.runtime.ledger.records,
            invocations=tuple(sorted(self._invocations, key=lambda item: item.ordinal)),
            performance=performance,
            rollback_candidate_ids=tuple(dict.fromkeys((
                *self._prior_rollback_candidate_ids,
                *(
                    item.rejected_candidate_id
                    for item in self.runtime.candidates.rollback_history
                ),
            ))),
            stop_reasons=tuple(dict.fromkeys(self._stop_reasons)),
            task_summary=(
                tuple(sorted(self._task_store.summary().items()))
                if self._task_store is not None
                else ()
            ),
            page_route_closure=page_route_closure,
        )


__all__ = [
    "AdjudicationRequest",
    "AdjudicationResult",
    "AnalysisCallbacks",
    "AnalysisCheckpointState",
    "AnalysisOrchestrationError",
    "AnalysisOrchestrationResult",
    "AnalysisOrchestrator",
    "AnalysisResumeState",
    "CallbackContractError",
    "CallBinding",
    "CompileRequest",
    "CompileResult",
    "FinalPageReviewRequest",
    "FinalPageReviewResult",
    "FindingRequest",
    "FourMaterialHashes",
    "InvocationRecord",
    "IssuePageReviewResult",
    "IssueReviewRequest",
    "MachineVerificationFacts",
    "MachineVerificationRequest",
    "PageAnalysisInput",
    "PageMaterials",
    "PatchRequest",
    "StaleEvidenceError",
]

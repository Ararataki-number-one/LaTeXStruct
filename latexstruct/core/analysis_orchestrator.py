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
    PatchPlan,
    PatchRejected,
    PatchScope,
    PerformanceMetrics,
    apply_patch_plan,
)
from .analysis_schema import (
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CompileState,
    IndependentReviewPass,
    IssueProposal,
    IssueRecord,
    IssueStatus,
    PageRisk,
    PageUnit,
    QualityVector,
    ReviewResult,
    SEVERITY_ORDER,
    Severity,
    VerificationDecision,
    VerificationEvidence,
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

    def __post_init__(self) -> None:
        if not self.run_id.strip() or not self.role.strip():
            raise ValueError("run_id and role are required")
        if not self.source_page_id.strip() or not self.issue_id.strip():
            raise ValueError("source_page_id and issue_id are required")
        object.__setattr__(self, "candidate_hash", _require_digest(
            self.candidate_hash, "candidate_hash"
        ))


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
        self._invocations: list[InvocationRecord] = []
        self._role_counts: dict[str, int] = {}
        self._role_elapsed: dict[str, float] = {}
        self._invocation_lock = threading.Lock()
        self._next_invocation_ordinal = 1
        self._compile_history: list[CompileResult] = []
        self._attempted_candidate_hashes: set[str] = set()
        self._modified_pages: set[str] = set()
        self._run_started = 0.0

    def _binding(
        self,
        *,
        role: str,
        issue_id: str,
        materials: PageMaterials,
    ) -> CallBinding:
        return CallBinding(
            run_id=self.snapshot.run_id,
            role=role,
            candidate_hash=materials.candidate_hash,
            source_page_id=materials.source_page_id,
            issue_id=issue_id,
            material_hashes=materials.hashes,
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

    def _discover(self, tex: str, compiled: CompileResult) -> None:
        roles = (
            ("AI-1", "structure-findings", self.callbacks.ai1_structure),
            ("AI-2", "content-math-findings", self.callbacks.ai2_content_math),
            ("AI-3", "visual-findings", self.callbacks.ai3_visual),
        )
        plans: list[tuple[str, CallBinding, Callable[[object], object], FindingRequest]] = []
        for page in self.page_inputs:
            materials = self._materials(page.page_unit.source_page_id, tex, compiled)
            for role, operation, callback in roles:
                discovery_id = (
                    f"DISCOVERY-{role}-{sha256_text(self.snapshot.run_id + materials.source_page_id)[:12]}"
                )
                binding = self._binding(
                    role=role, issue_id=discovery_id, materials=materials
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
        for (_operation, binding, _callback, _request), raw in zip(
            plans, raw_results, strict=True
        ):
            role = binding.role
            if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
                raise CallbackContractError(f"{role} must return a sequence of findings")
            for proposal in raw:
                self._validate_finding(proposal, role=role, binding=binding)
                validated.append(proposal)
        # The only ledger mutation happens here, in immutable page/role order.
        for proposal in validated:
            self.runtime.ledger.upsert(proposal, round_index=0)
        for page in self.page_inputs:
            self.runtime.performance.record_page_completion(
                page.page_unit.source_page_id,
                max(0.0, self.clock() - self._run_started),
            )

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
        binding = self._binding(role="AI-6", issue_id=primary.issue_id, materials=materials)
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
            binding = self._binding(role="AI-5", issue_id=issue.issue_id, materials=materials)
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
        binding = self._binding(role="AI-4", issue_id=issue.issue_id, materials=materials)
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
        record = self.runtime.candidates.evaluate(
            application=application,
            round_index=round_index,
            pdf=candidate_compile.pdf,
            compile_log=candidate_compile.compile_log,
            quality=selection_quality,
            issue_ledger=self.runtime.ledger.to_dict(),
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
                    role="AI-5", issue_id=review_scope_id, materials=materials
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
            raw_results = self._parallel_invocations(calls)
            page_results: list[FinalPageReviewResult] = []
            for (page_id, binding, _request), result in zip(
                plans, raw_results, strict=True
            ):
                if not isinstance(result, FinalPageReviewResult):
                    raise CallbackContractError("AI-5 must return FinalPageReviewResult")
                if result.candidate_hash != binding.candidate_hash:
                    raise StaleEvidenceError("AI-5 final review belongs to a stale candidate")
                if (
                    result.source_page_id != page_id
                    or result.pass_number != pass_number
                    or result.context_id != context_id
                ):
                    raise CallbackContractError("AI-5 final review changed its host binding")
                page_results.append(result)
            output.append(IndependentReviewPass(
                pass_number=pass_number,
                context_id=context_id,
                candidate_hash=sha256_text(tex),
                checked_page_ids=tuple(item.source_page_id for item in page_results),
                compile_passes=compiled.compile_passes,
                content_conservation_ok=all(
                    item.content_conservation_ok for item in page_results
                ),
                math_conservation_ok=all(
                    item.math_conservation_ok for item in page_results
                ),
                formal_inventory_ok=all(
                    item.formal_inventory_ok for item in page_results
                ),
                visual_review_ok=all(item.visual_review_ok for item in page_results),
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
        return evidence, decision

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
        if baseline_compile.pdf_hash != self.snapshot.baseline_pdf_hash:
            raise StaleEvidenceError("baseline PDF does not match the immutable snapshot")
        current_tex = baseline_tex
        current_compile = baseline_compile
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

        for round_index in range(1, max_macro_rounds + 1):
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

        best = self.runtime.candidates.best
        if best is None or best.tex_sha256 != sha256_text(current_tex):
            raise AnalysisOrchestrationError("candidate controller lost the history best")
        final_reviews = self._final_reviews(current_tex, current_compile)
        evidence, decision = self._verification(
            tex=current_tex,
            compiled=current_compile,
            baseline_compile=baseline_compile,
            final_reviews=final_reviews,
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
            input_tokens=0,
            output_tokens=0,
            cache_hits=0,
            cache_misses=sum(self._role_counts.values()),
            high_risk_pages=sum(
                item.page_unit.risk_level in {PageRisk.R2, PageRisk.R3}
                for item in self.page_inputs
            ),
            modified_pages=len(self._modified_pages),
            full_compile_count=len(self._compile_history),
            incremental_check_count=0,
            rollback_count=len(self.runtime.candidates.rollback_history),
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
            rollback_candidate_ids=tuple(
                item.rejected_candidate_id
                for item in self.runtime.candidates.rollback_history
            ),
        )


__all__ = [
    "AdjudicationRequest",
    "AdjudicationResult",
    "AnalysisCallbacks",
    "AnalysisOrchestrationError",
    "AnalysisOrchestrationResult",
    "AnalysisOrchestrator",
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

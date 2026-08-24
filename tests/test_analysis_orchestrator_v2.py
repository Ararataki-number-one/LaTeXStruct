# -*- coding: utf-8 -*-
"""Execution-contract tests for the real v2 multi-role orchestrator."""

from __future__ import annotations

from dataclasses import replace
import threading
import time

import pytest

from latexstruct.core.analysis_orchestrator import (
    AdjudicationResult,
    AnalysisCallbacks,
    AnalysisOrchestrator,
    CompileResult,
    FinalPageReviewResult,
    IssuePageReviewResult,
    MachineVerificationFacts,
    PageAnalysisInput,
    StaleEvidenceError,
)
from latexstruct.core.analysis_runtime import (
    PatchOperation,
    PatchPlan,
    PatchScope,
)
from latexstruct.core.analysis_schema import (
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CompileState,
    IssueProposal,
    IssueStatus,
    ModelBinding,
    PageMapEntry,
    PageUnit,
    PatchOperationKind,
    PdfRegion,
    QualityVector,
    ReviewResult,
    Severity,
    TexAnchor,
    sha256_bytes,
    sha256_text,
)


PAGE_ID = "source-page-000001"
TARGET = "Every graph has a vertex."
BASELINE_TEX = (
    "\\documentclass{article}\n"
    "\\begin{document}\n"
    f"{TARGET}\n"
    "\\end{document}\n"
)
BASELINE_PDF = b"%PDF-baseline-two-pass"
SOURCE_PAGE = b"%PDF-source-page-one"


def _quality(*, open_high: int) -> QualityVector:
    return QualityVector(
        fully_compiled=True,
        open_high=open_high,
        ordinary_layout_errors=open_high,
    )


def _snapshot() -> AnalysisRunSnapshot:
    return AnalysisRunSnapshot(
        run_id="analysis-orchestration-run-1",
        project_id="project-1",
        workflow_version="analysis-loop-v2",
        prompt_version="analysis-prompts-v2",
        application_version="2.0.0",
        source_pdf_hash=sha256_text("whole source pdf"),
        raw_ocr_tex_hash=sha256_text("raw ocr tex"),
        baseline_tex_hash=sha256_text(BASELINE_TEX),
        baseline_pdf_hash=sha256_bytes(BASELINE_PDF),
        page_count=1,
        page_range=(1,),
        latex_engine="xelatex",
        models=tuple(
            ModelBinding(role, f"model-{role.lower()}", ("json",))
            for role in ("AI-1", "AI-2", "AI-3", "AI-4", "AI-5", "AI-6")
        ),
        concurrency_limit=1,
        started_at="2026-08-24T01:00:00+08:00",
        page_map=(PageMapEntry(PAGE_ID, 1, "% Page 1", ("candidate-page-1",)),),
        initial_compile_state=CompileState.COMPILED,
        config_hash=sha256_text("orchestration config"),
    )


def _page_input() -> PageAnalysisInput:
    unit = PageUnit(
        source_page_id=PAGE_ID,
        source_page_number=1,
        source_page_hash=sha256_bytes(SOURCE_PAGE),
        baseline_tex_start_anchor="\\begin{document}",
        baseline_tex_end_anchor="\\end{document}",
        current_tex_start_anchor="\\begin{document}",
        current_tex_end_anchor="\\end{document}",
        candidate_pdf_page_ids=("candidate-page-1",),
    )
    return PageAnalysisInput(unit, SOURCE_PAGE, BASELINE_TEX)


def _proposal(request, *, issue_type="FORMAL_BOUNDARY", severity=Severity.HIGH):
    start = request.materials.current_tex_region.index(TARGET)
    return IssueProposal(
        issue_type=issue_type,
        severity=severity,
        source_page_ids=(PAGE_ID,),
        tex_anchors=(
            TexAnchor("statement-1", start, start + len(TARGET), sha256_text(TARGET)),
        ),
        source_pdf_regions=(PdfRegion(PAGE_ID, 10, 10, 90, 40),),
        detector_role=request.binding.role,
        evidence_hashes=(request.binding.material_hashes.source_pdf_page_hash,),
        baseline_hash=_snapshot().baseline_tex_hash,
        candidate_hash=request.binding.candidate_hash,
        description="The theorem wrapper is missing.",
    )


def _callbacks(
    events: list[str],
    *,
    accept_patch: bool = True,
    final_pass_two_sees_prior: bool = False,
    ai6_events: list[str] | None = None,
) -> AnalysisCallbacks:
    def compile_candidate(request):
        patched = "\\begin{theorem}" in request.tex
        events.append("compile-candidate" if patched else "compile-baseline")
        if patched:
            pdf = b"%PDF-patched-two-pass"
            # High-risk issue counts are host-owned and merged from IssueLedger.
            quality = _quality(open_high=1)
            page_pdf = b"rendered-patched-page"
        else:
            pdf = BASELINE_PDF
            quality = _quality(open_high=1)
            page_pdf = b"rendered-baseline-page"
        return CompileResult(
            candidate_hash=request.candidate_hash,
            pdf=pdf,
            compile_log="xelatex pass 1 ok\nxelatex pass 2 ok",
            compile_passes=2,
            state=CompileState.COMPILED,
            pdf_openable=True,
            page_pdf_bytes=((PAGE_ID, page_pdf),),
            quality=quality,
        )

    def detector(role):
        def call(request):
            events.append(role)
            return (_proposal(request),)

        return call

    def patch(request):
        events.append("AI-4")
        operation = PatchOperation(
            operation=PatchOperationKind.WRAP_ENVIRONMENT,
            issue_ids=(request.issue.issue_id,),
            start_anchor=TARGET,
            end_anchor=TARGET,
            expected_old_hash=sha256_text(TARGET),
            replacement=f"\\begin{{theorem}}\n{TARGET}\n\\end{{theorem}}",
            source_page_ids=(PAGE_ID,),
            reason="repair the host-confirmed formal boundary",
        )
        return PatchPlan(
            candidate_hash=request.binding.candidate_hash,
            issue_ids=(request.issue.issue_id,),
            operations=(operation,),
        )

    def issue_review(request):
        events.append("AI-5-issue")
        return IssuePageReviewResult(
            candidate_hash=request.binding.candidate_hash,
            issue_id=request.issue.issue_id,
            source_page_id=request.binding.source_page_id,
            result=ReviewResult.PASS if accept_patch else ReviewResult.FAIL,
            content_conservation_ok=True,
            math_conservation_ok=True,
            visual_review_ok=True,
        )

    def final_review(request):
        events.append(f"AI-5-final-{request.pass_number}")
        return FinalPageReviewResult(
            candidate_hash=request.binding.candidate_hash,
            source_page_id=request.binding.source_page_id,
            pass_number=request.pass_number,
            context_id=request.context_id,
            content_conservation_ok=True,
            math_conservation_ok=True,
            formal_inventory_ok=True,
            visual_review_ok=True,
            prior_pass_conclusion_visible=(
                final_pass_two_sees_prior and request.pass_number == 2
            ),
        )

    def verify(request):
        events.append("machine-verify")
        return MachineVerificationFacts(
            candidate_hash=request.candidate_hash,
            checked_page_ids=(PAGE_ID,),
            silent_page_omissions=0,
            silent_text_losses=0,
            unauthorized_math_changes=0,
            formal_errors=0,
            toc_complete_and_ordered=True,
            severe_equation_number_errors=0,
            silent_footnote_losses=0,
            silent_figure_caption_losses=0,
            silent_bibliography_losses=0,
        )

    def scope(issue, tex):
        return PatchScope(
            issue_id=issue.issue_id,
            candidate_hash=sha256_text(tex),
            start_offset=0,
            end_offset=len(tex),
            source_page_ids=(PAGE_ID,),
        )

    def ai6(request):
        if ai6_events is not None:
            ai6_events.append(request.reason)
        issue_ids = tuple(sorted(item.issue_id for item in request.issues))
        return AdjudicationResult(
            candidate_hash=request.binding.candidate_hash,
            issue_ids=issue_ids,
            keep_issue_ids=issue_ids[:1],
            resolved=True,
            explanation="retain the first host candidate",
        )

    return AnalysisCallbacks(
        ai1_structure=detector("AI-1"),
        ai2_content_math=detector("AI-2"),
        ai3_visual=detector("AI-3"),
        ai4_patch=patch,
        ai5_issue_review=issue_review,
        ai5_final_review=final_review,
        compile_candidate=compile_candidate,
        machine_verify=verify,
        tex_region=lambda _page, tex: tex,
        patch_scope=scope,
        ai6_adjudicate=ai6,
    )


def _orchestrator(tmp_path, callbacks):
    return AnalysisOrchestrator(
        snapshot=_snapshot(),
        page_inputs=(_page_input(),),
        candidate_root=tmp_path / "candidates",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("independent-context-a", "independent-context-b"),
    )


def test_real_role_order_hash_bindings_two_independent_reviews_and_verified(tmp_path):
    events: list[str] = []
    ai6_events: list[str] = []
    result = _orchestrator(
        tmp_path, _callbacks(events, ai6_events=ai6_events)
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert events == [
        "compile-baseline",
        "AI-1",
        "AI-2",
        "AI-3",
        "AI-4",
        "compile-candidate",
        "AI-5-issue",
        "AI-5-final-1",
        "AI-5-final-2",
        "machine-verify",
    ]
    assert ai6_events == []
    assert result.decision.status == AnalysisFinalStatus.VERIFIED
    assert result.decision.verified is True
    assert len(result.ledger) == 1
    assert result.ledger[0].detector_roles == ("AI-1", "AI-2", "AI-3")
    assert result.ledger[0].current_status == IssueStatus.VERIFIED_CLOSED
    assert [item.context_id for item in result.final_reviews] == [
        "independent-context-a",
        "independent-context-b",
    ]
    assert all(not item.prior_pass_conclusion_visible for item in result.final_reviews)
    assert result.best_candidate.tex_sha256 == sha256_text(result.current_tex)
    assert result.rollback_candidate_ids == ()
    assert result.performance.full_compile_count == 2
    assert dict(result.performance.role_call_counts) == {
        "AI-1": 1,
        "AI-2": 1,
        "AI-3": 1,
        "AI-4": 1,
        "AI-5": 3,
    }

    expected_baseline_hashes = {
        "source_pdf_page_hash": sha256_bytes(SOURCE_PAGE),
        "baseline_tex_region_hash": sha256_text(BASELINE_TEX),
        "current_tex_region_hash": sha256_text(BASELINE_TEX),
        "current_pdf_page_hash": sha256_bytes(b"rendered-baseline-page"),
    }
    first = result.invocations[0]
    assert first.binding.run_id == _snapshot().run_id
    assert first.binding.candidate_hash == sha256_text(BASELINE_TEX)
    assert first.binding.source_page_id == PAGE_ID
    assert first.binding.issue_id.startswith("DISCOVERY-AI-1-")
    assert {
        name: getattr(first.binding.material_hashes, name)
        for name in expected_baseline_hashes
    } == expected_baseline_hashes
    patch_call = next(item for item in result.invocations if item.operation == "local-patch")
    assert patch_call.binding.issue_id == result.ledger[0].issue_id


def test_stale_model_candidate_hash_is_rejected_before_next_role(tmp_path):
    events: list[str] = []
    callbacks = _callbacks(events)

    def stale_ai1(request):
        events.append("AI-1-stale")
        return (replace(_proposal(request), candidate_hash=sha256_text("stale")),)

    callbacks = replace(callbacks, ai1_structure=stale_ai1)
    with pytest.raises(StaleEvidenceError, match="stale candidate"):
        _orchestrator(tmp_path, callbacks).run(
            baseline_tex=BASELINE_TEX, max_macro_rounds=1
        )
    # Discovery is one bounded wave.  Other calls that were already planned
    # may finish, but no finding is merged after host validation fails closed.
    assert events == ["compile-baseline", "AI-1-stale", "AI-2", "AI-3"]


def test_second_review_cannot_see_first_conclusion_and_status_fails_closed(tmp_path):
    events: list[str] = []
    result = _orchestrator(
        tmp_path,
        _callbacks(events, final_pass_two_sees_prior=True),
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert len([item for item in result.invocations if item.operation.startswith("final-review")]) == 2
    assert result.decision.verified is False
    assert result.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "reviews_not_independent" in result.decision.failures


@pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.LOW])
def test_verified_is_blocked_by_any_open_ledger_issue_regardless_of_severity(
    tmp_path,
    severity,
):
    events: list[str] = []
    callbacks = _callbacks(events)

    def only_ai1(request):
        events.append("AI-1")
        return (_proposal(request, severity=severity),)

    callbacks = replace(
        callbacks,
        ai1_structure=only_ai1,
        ai2_content_math=lambda _request: (),
        ai3_visual=lambda _request: (),
        ai4_patch=lambda _request: None,
        ai6_adjudicate=None,
    )
    result = _orchestrator(tmp_path, callbacks).run(
        baseline_tex=BASELINE_TEX,
        max_macro_rounds=1,
    )

    assert result.ledger[0].severity == severity
    assert result.ledger[0].current_status == IssueStatus.OPEN
    assert result.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert result.decision.verified is False
    assert "unresolved_ledger_issue" in result.decision.failures
    assert "unresolved_ledger_open" in result.decision.failures


def test_ai6_runs_for_conflict_but_not_for_normal_findings(tmp_path):
    normal_events: list[str] = []
    normal_ai6: list[str] = []
    _orchestrator(
        tmp_path / "normal",
        _callbacks(normal_events, ai6_events=normal_ai6),
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)
    assert normal_ai6 == []

    conflict_events: list[str] = []
    conflict_ai6: list[str] = []
    callbacks = _callbacks(conflict_events, ai6_events=conflict_ai6)

    def ai1(request):
        conflict_events.append("AI-1")
        return (_proposal(request, issue_type="FORMAL_BOUNDARY"),)

    def ai2(request):
        conflict_events.append("AI-2")
        return (_proposal(request, issue_type="PROSE_ONLY"),)

    def ai3(request):
        conflict_events.append("AI-3")
        return ()

    callbacks = replace(
        callbacks,
        ai1_structure=ai1,
        ai2_content_math=ai2,
        ai3_visual=ai3,
        ai4_patch=lambda request: None,
    )
    result = _orchestrator(tmp_path / "conflict", callbacks).run(
        baseline_tex=BASELINE_TEX, max_macro_rounds=1
    )
    assert conflict_ai6 == ["CONFLICT"]
    assert sum(
        item.current_status == IssueStatus.REJECTED_FALSE_POSITIVE
        for item in result.ledger
    ) == 1
    assert result.decision.verified is False


def test_repeated_stall_invokes_ai6_only_after_second_identical_attempt(tmp_path):
    events: list[str] = []
    ai6_events: list[str] = []
    callbacks = _callbacks(events, ai6_events=ai6_events)

    def only_ai1(request):
        events.append("AI-1")
        return (_proposal(request),)

    callbacks = replace(
        callbacks,
        ai1_structure=only_ai1,
        ai2_content_math=lambda request: (),
        ai3_visual=lambda request: (),
        ai4_patch=lambda request: None,
    )
    _orchestrator(tmp_path, callbacks).run(
        baseline_tex=BASELINE_TEX, max_macro_rounds=2
    )
    assert ai6_events == ["STALL"]


def test_non_improving_compiled_candidate_is_persisted_then_rolled_back(tmp_path):
    events: list[str] = []
    result = _orchestrator(
        tmp_path, _callbacks(events, accept_patch=False)
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert events.index("compile-candidate") < events.index("AI-5-issue")
    assert result.current_tex == BASELINE_TEX
    assert result.best_candidate.tex_sha256 == sha256_text(BASELINE_TEX)
    assert len(result.rollback_candidate_ids) == 1
    assert result.performance.rollback_count == 1
    assert result.decision.verified is False


def test_discovery_and_each_final_review_overlap_but_merge_in_host_order(tmp_path):
    page_ids = tuple(f"source-page-{number:06d}" for number in range(1, 4))
    page_inputs = tuple(
        PageAnalysisInput(
            PageUnit(
                source_page_id=page_id,
                source_page_number=number,
                source_page_hash=sha256_bytes(f"source-{number}".encode()),
                baseline_tex_start_anchor="\\begin{document}",
                baseline_tex_end_anchor="\\end{document}",
                current_tex_start_anchor="\\begin{document}",
                current_tex_end_anchor="\\end{document}",
                candidate_pdf_page_ids=(f"candidate-page-{number}",),
            ),
            f"source-{number}".encode(),
            BASELINE_TEX,
        )
        for number, page_id in enumerate(page_ids, start=1)
    )
    snapshot = replace(
        _snapshot(),
        page_count=3,
        page_range=(1, 2, 3),
        concurrency_limit=3,
        page_map=tuple(
            PageMapEntry(page_id, number, f"% Page {number}", (f"candidate-page-{number}",))
            for number, page_id in enumerate(page_ids, start=1)
        ),
    )
    active = 0
    maximum_active = 0
    lock = threading.Lock()
    final_completed = {1: 0, 2: 0}
    pass_two_started_early = False

    def overlap():
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.025)
        with lock:
            active -= 1

    def finding(role):
        def call(request):
            overlap()
            if role != "AI-1":
                return ()
            start = request.materials.current_tex_region.index(TARGET)
            return (IssueProposal(
                issue_type="FORMAL_BOUNDARY",
                severity=Severity.HIGH,
                source_page_ids=(request.binding.source_page_id,),
                tex_anchors=(TexAnchor(
                    f"statement-{request.binding.source_page_id}",
                    start,
                    start + len(TARGET),
                    sha256_text(TARGET),
                ),),
                source_pdf_regions=(PdfRegion(
                    request.binding.source_page_id, 10, 10, 90, 40
                ),),
                detector_role=role,
                evidence_hashes=(request.binding.material_hashes.source_pdf_page_hash,),
                baseline_hash=snapshot.baseline_tex_hash,
                candidate_hash=request.binding.candidate_hash,
            ),)

        return call

    def final_review(request):
        nonlocal pass_two_started_early
        with lock:
            if request.pass_number == 2 and final_completed[1] != len(page_ids):
                pass_two_started_early = True
        overlap()
        with lock:
            final_completed[request.pass_number] += 1
        return FinalPageReviewResult(
            candidate_hash=request.binding.candidate_hash,
            source_page_id=request.binding.source_page_id,
            pass_number=request.pass_number,
            context_id=request.context_id,
            content_conservation_ok=True,
            math_conservation_ok=True,
            formal_inventory_ok=True,
            visual_review_ok=True,
        )

    callbacks = _callbacks([])
    callbacks = replace(
        callbacks,
        ai1_structure=finding("AI-1"),
        ai2_content_math=finding("AI-2"),
        ai3_visual=finding("AI-3"),
        ai4_patch=lambda _request: None,
        ai5_final_review=final_review,
        compile_candidate=lambda request: CompileResult(
            candidate_hash=request.candidate_hash,
            pdf=BASELINE_PDF,
            compile_log="two passes",
            compile_passes=2,
            state=CompileState.COMPILED,
            pdf_openable=True,
            page_pdf_bytes=tuple(
                (page_id, f"rendered-{page_id}".encode()) for page_id in page_ids
            ),
            quality=_quality(open_high=3),
        ),
        machine_verify=lambda request: MachineVerificationFacts(
            candidate_hash=request.candidate_hash,
            checked_page_ids=page_ids,
            silent_page_omissions=0,
            silent_text_losses=0,
            unauthorized_math_changes=0,
            formal_errors=0,
            toc_complete_and_ordered=True,
            severe_equation_number_errors=0,
            silent_footnote_losses=0,
            silent_figure_caption_losses=0,
            silent_bibliography_losses=0,
        ),
        patch_scope=lambda issue, tex: PatchScope(
            issue_id=issue.issue_id,
            candidate_hash=sha256_text(tex),
            start_offset=0,
            end_offset=len(tex),
            source_page_ids=issue.source_page_ids,
        ),
    )
    result = AnalysisOrchestrator(
        snapshot=snapshot,
        page_inputs=page_inputs,
        candidate_root=tmp_path / "parallel-candidates",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert 2 <= maximum_active <= 3
    discovery = [
        (item.binding.source_page_id, item.binding.role)
        for item in result.invocations
        if item.operation.endswith("findings")
    ]
    assert discovery == [
        (page_id, role)
        for page_id in page_ids
        for role in ("AI-1", "AI-2", "AI-3")
    ]
    assert tuple(item.issue_id for item in result.ledger) == tuple(
        sorted(item.issue_id for item in result.ledger)
    )
    assert [review.checked_page_ids for review in result.final_reviews] == [
        page_ids,
        page_ids,
    ]
    assert final_completed == {1: 3, 2: 3}
    assert pass_two_started_early is False

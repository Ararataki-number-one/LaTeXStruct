# -*- coding: utf-8 -*-
"""Execution-contract tests for the real v2 multi-role orchestrator."""

from __future__ import annotations

from dataclasses import replace
import json
import threading
import time

import pytest

from latexstruct.core.analysis_orchestrator import (
    AdjudicationResult,
    AnalysisCallbacks,
    AnalysisOrchestrator,
    AnalysisResumeState,
    CompileResult,
    FinalPageReviewResult,
    IssuePageReviewResult,
    MachineVerificationFacts,
    PageAnalysisInput,
    StaleEvidenceError,
)
from latexstruct.core.analysis_runtime import (
    CandidateRepository,
    CandidateStoreError,
    PatchOperation,
    PatchPlan,
    PatchScope,
)
from latexstruct.core.analysis_risk import (
    PageRiskPreflightInput,
    build_page_risk_admission,
)
from latexstruct.core.analysis_schema import (
    AnalysisEvidenceHashes,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    AnalysisTransportContract,
    CompileState,
    IssueProposal,
    IssueStatus,
    ModelBinding,
    PageMapEntry,
    PageRisk,
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


def test_snapshot_hash_is_canonical_and_binds_optional_production_evidence():
    legacy = _snapshot()
    assert legacy.snapshot_hash == _snapshot().snapshot_hash

    evidence = AnalysisEvidenceHashes(
        ocr_baseline_manifest_hash=sha256_text("manifest"),
        ocr_page_records_hash=sha256_text("page records"),
        ocr_runtime_page_records_hash=sha256_text("runtime page records"),
        ocr_page_map_hash=sha256_text("page map"),
        ocr_baseline_compile_inputs_hash=sha256_text("ocr compile inputs"),
        baseline_compile_inputs_hash=sha256_text("analysis compile inputs"),
        build_identity_hash=sha256_text("build identity"),
        page_risk_admission_hash=sha256_text("page risk admission"),
        response_schema_hash=sha256_text("response schemas"),
        analysis_config_hash=legacy.config_hash,
        budget_summary_hash=sha256_text("budget summary"),
    )
    operations = {
        "AI-1": ("structure-findings",),
        "AI-2": ("content-math-findings",),
        "AI-3": ("visual-findings",),
        "AI-4": ("local-patch",),
        "AI-5": ("final-review-1", "final-review-2", "issue-review"),
        "AI-6": ("adjudication",),
    }
    contracts = tuple(
        AnalysisTransportContract(
            role=model.role,
            model_id=model.model_id,
            reasoning_effort=model.reasoning_effort,
            operations=operations[model.role],
            client_type="tests.OrchestratorClient",
            method="chat_json_schema",
            max_retries=0,
            max_tokens=0,
            backend_authority_sha256=sha256_text("authority"),
            backend_configuration_sha256=sha256_text("configuration"),
        )
        for model in legacy.models
    )
    bound = replace(
        legacy,
        evidence_hashes=evidence,
        transport_contracts=contracts,
    )
    assert bound.require_production_evidence() == evidence
    assert bound.snapshot_hash != legacy.snapshot_hash
    assert replace(bound, prompt_version="analysis-prompts-v3").snapshot_hash != (
        bound.snapshot_hash
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
        ai3_triage=lambda _request: (),
        ai1_recheck=lambda _request: (),
        ai2_recheck=lambda _request: (),
        ai3_recheck=lambda _request: (),
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


def test_first_discovery_wave_failure_retains_recomputable_baseline_checkpoint(
    tmp_path,
):
    events: list[str] = []
    callbacks = _callbacks(events)

    def unavailable_ai1(_request):
        events.append("AI-1-unavailable")
        raise RuntimeError("discovery transport unavailable")

    callbacks = replace(callbacks, ai1_structure=unavailable_ai1)
    with pytest.raises(RuntimeError, match="discovery transport unavailable"):
        _orchestrator(tmp_path, callbacks).run(
            baseline_tex=BASELINE_TEX,
            max_macro_rounds=1,
        )

    repository = CandidateRepository(tmp_path / "candidates")
    assert repository.verify_baseline_input_checkpoint()
    checkpoint = repository.root / "baseline-input"
    assert (checkpoint / "baseline.tex").read_text(encoding="utf-8") == BASELINE_TEX
    assert (checkpoint / "baseline.pdf").read_bytes() == BASELINE_PDF
    assert "pass 1 ok" in (checkpoint / "compile.log").read_text(
        encoding="utf-8"
    )
    assert not tuple(repository.root.glob("cand-r*"))


def test_baseline_input_checkpoint_is_write_once_and_tamper_evident(tmp_path):
    repository = CandidateRepository(tmp_path / "checkpoint")
    arguments = {
        "run_id": "checkpoint-run",
        "tex": BASELINE_TEX,
        "pdf": BASELINE_PDF,
        "compile_log": "pass 1 ok\npass 2 ok",
        "compile_passes": 2,
        "pdf_openable": True,
    }

    first = repository.save_baseline_input_checkpoint(**arguments)
    second = repository.save_baseline_input_checkpoint(**arguments)
    assert second == first
    resumed = repository.save_baseline_input_checkpoint(
        **{**arguments, "compile_log": "same compile, different private workdir"}
    )
    assert resumed == first
    assert (repository.root / "baseline-input" / "compile.log").read_text(
        encoding="utf-8"
    ) == arguments["compile_log"]
    assert repository.verify_baseline_input_checkpoint()
    with pytest.raises(CandidateStoreError, match="different evidence"):
        repository.save_baseline_input_checkpoint(
            **{**arguments, "tex": BASELINE_TEX + "% changed\n"}
        )

    checkpoint = repository.root / "baseline-input"
    (checkpoint / "compile.log").write_text("tampered", encoding="utf-8")
    assert repository.verify_baseline_input_checkpoint() is False


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


def test_production_risk_router_blocks_r3_and_routes_lower_risks(tmp_path):
    expected = {
        PageRisk.R0: ("AI-3-triage",),
        PageRisk.R1: ("AI-3-triage", "AI-1"),
        PageRisk.R2: ("AI-3-triage", "AI-1", "AI-2", "AI-3"),
        PageRisk.R3: ("AI-3-triage",),
    }
    for risk, expected_roles in expected.items():
        calls: list[str] = []

        def detector(role):
            def run(_request):
                calls.append(role)
                return ()

            return run

        callbacks = replace(
            _callbacks([]),
            ai1_structure=detector("AI-1"),
            ai2_content_math=detector("AI-2"),
            ai3_visual=detector("AI-3"),
            ai3_triage=detector("AI-3-triage"),
        )
        page = _page_input()
        page = replace(page, page_unit=replace(page.page_unit, risk_level=risk))
        result = AnalysisOrchestrator(
            snapshot=_snapshot(),
            page_inputs=(page,),
            candidate_root=tmp_path / risk.value,
            callbacks=callbacks,
            raw_ocr_frozen=True,
            final_review_context_ids=("context-a", "context-b"),
            risk_routing_enabled=True,
        ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

        assert tuple(calls) == expected_roles
        if risk == PageRisk.R3:
            reason = (
                "risk_r3_requires_adjudication:"
                f"{page.page_unit.source_page_id}"
            )
            assert result.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
            assert result.decision.verified is False
            assert reason in result.stop_reasons
            assert reason in result.decision.failures
        else:
            assert result.decision.status == AnalysisFinalStatus.VERIFIED
        assert result.performance.checked_pages == 1


def test_typed_risk_admission_closes_triage_deep_recheck_and_two_final_passes(
    tmp_path,
):
    snapshot = _snapshot()
    admission = build_page_risk_admission(
        source_pdf_sha256=snapshot.source_pdf_hash,
        ocr_page_records_sha256=sha256_text("ocr-page-records"),
        ocr_runtime_page_records_sha256=sha256_text("ocr-runtime-page-records"),
        baseline_tex_sha256=snapshot.baseline_tex_hash,
        baseline_pdf_sha256=snapshot.baseline_pdf_hash,
        page_inputs=(PageRiskPreflightInput(
            source_page_id=PAGE_ID,
            source_page_number=1,
            source_page_object_hash=sha256_text("source-page-object"),
            ocr_coverage_checks={"persisted": "PASS", "syntax_checked": "PASS"},
            unresolved_region_hashes=(),
            baseline_tex_region=BASELINE_TEX,
            candidate_pdf_page_ids=("candidate-page-1",),
            source_pdf_text=TARGET,
            ocr_final_status="SUCCESS",
            ocr_retry_count=1,
            ocr_quality_issues=(),
            host_quality_flags=(),
            machine_visual_anomalies=(),
            double_column=False,
            complex_layout=False,
            compile_map_mismatch=False,
            layout_evidence={"algorithm": "fixture-layout-v1", "executed": True},
            compile_map_evidence={"algorithm": "fixture-map-v1", "matched": True},
        ),),
    )
    admitted_page = admission.pages[0]
    assert admitted_page.risk_level is PageRisk.R2
    page = _page_input()
    page = replace(
        page,
        page_unit=replace(
            page.page_unit,
            risk_level=admitted_page.risk_level,
            risk_reasons=admitted_page.risk_reasons,
        ),
    )

    result = AnalysisOrchestrator(
        snapshot=snapshot,
        page_inputs=(page,),
        candidate_root=tmp_path / "typed-route-closure",
        callbacks=_callbacks([]),
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
        page_risk_admission=admission,
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    closure = result.page_route_closure
    assert closure is not None
    assert closure.admission_sha256 == admission.digest
    assert closure.risk_counts["admitted"] == {
        "R0": 0,
        "R1": 0,
        "R2": 1,
        "R3": 0,
    }
    assert closure.pages[0].modified is True
    successful = {
        (call.role, call.operation, call.source_page_id)
        for call in closure.route_call_keys
        if call.succeeded
    }
    for expected in (
        ("AI-3", "visual-triage", PAGE_ID),
        ("AI-1", "structure-findings", PAGE_ID),
        ("AI-2", "content-math-findings", PAGE_ID),
        ("AI-3", "visual-findings", PAGE_ID),
        ("AI-1", "structure-recheck", PAGE_ID),
        ("AI-2", "content-math-recheck", PAGE_ID),
        ("AI-3", "visual-recheck", PAGE_ID),
        ("AI-5", "final-review-1", PAGE_ID),
        ("AI-5", "final-review-2", PAGE_ID),
    ):
        assert expected in successful
    assert not any(
        reason.startswith("route_") for reason in result.stop_reasons
    )


def test_failed_discovery_batch_retries_only_failed_atomic_task(tmp_path):
    counts = {"AI-1": 0, "AI-2": 0, "AI-3": 0}

    def detector(role):
        def run(_request):
            counts[role] += 1
            if role == "AI-2" and counts[role] == 1:
                raise RuntimeError("transient content auditor failure")
            return ()

        return run

    callbacks = replace(
        _callbacks([]),
        ai1_structure=detector("AI-1"),
        ai2_content_math=detector("AI-2"),
        ai3_visual=detector("AI-3"),
    )
    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R2))
    result = AnalysisOrchestrator(
        snapshot=replace(_snapshot(), concurrency_limit=3),
        page_inputs=(page,),
        candidate_root=tmp_path / "split-retry",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert counts == {"AI-1": 1, "AI-2": 2, "AI-3": 1}
    assert result.task_summary == (
        ("BLOCKED", 0),
        ("COMPLETED", 4),
        ("PENDING", 0),
        ("RUNNING", 0),
    )
    assert result.decision.status == AnalysisFinalStatus.VERIFIED


def test_fatal_analysis_discovery_fault_aborts_run_and_cancels_queued_calls(tmp_path):
    class FatalAnalysisFault(RuntimeError):
        retryable = False
        fatal_analysis = True

    calls: list[str] = []

    def detector(role):
        def run(_request):
            calls.append(role)
            if role == "AI-1":
                raise FatalAnalysisFault("durable budget authority is poisoned")
            return ()

        return run

    callbacks = replace(
        _callbacks([]),
        ai1_structure=detector("AI-1"),
        ai2_content_math=detector("AI-2"),
        ai3_visual=detector("AI-3"),
    )
    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R2))
    orchestrator = AnalysisOrchestrator(
        snapshot=replace(_snapshot(), concurrency_limit=1),
        page_inputs=(page,),
        candidate_root=tmp_path / "fatal-discovery",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
    )

    with pytest.raises(FatalAnalysisFault, match="poisoned"):
        orchestrator.run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)
    assert calls == ["AI-1"]


def test_contract_invalid_discovery_is_blocked_without_retry(tmp_path):
    attempts = 0

    def invalid(_request):
        nonlocal attempts
        attempts += 1
        return "not a finding sequence"

    callbacks = replace(
        _callbacks([]),
        ai1_structure=lambda _request: (),
        ai2_content_math=invalid,
        ai3_visual=lambda _request: (),
    )
    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R2))
    result = AnalysisOrchestrator(
        snapshot=replace(_snapshot(), concurrency_limit=3),
        page_inputs=(page,),
        candidate_root=tmp_path / "contract-block",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert attempts == 1
    assert result.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert result.decision.verified is False
    assert result.task_summary[0] == ("BLOCKED", 1)
    assert result.performance.checked_pages == 0


def test_resilient_final_review_retains_partial_pass_and_runs_second_context(tmp_path):
    base = _callbacks([])
    seen: list[int] = []

    def final_review(request):
        seen.append(request.pass_number)
        if request.pass_number == 1:
            raise RuntimeError("first independent context unavailable")
        return base.ai5_final_review(request)

    callbacks = replace(
        base,
        ai1_structure=lambda _request: (),
        ai2_content_math=lambda _request: (),
        ai3_visual=lambda _request: (),
        ai5_final_review=final_review,
    )
    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R0))
    result = AnalysisOrchestrator(
        snapshot=_snapshot(),
        page_inputs=(page,),
        candidate_root=tmp_path / "partial-final-review",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert seen == [1, 2]
    assert len(result.final_reviews) == 1
    assert result.final_reviews[0].pass_number == 2
    assert result.final_reviews[0].checked_page_ids == (PAGE_ID,)
    assert result.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "final_review_blocked:1:source-page-000001" in result.stop_reasons


def test_fatal_analysis_final_review_fault_cannot_be_downgraded_to_partial(tmp_path):
    class FatalAnalysisFault(RuntimeError):
        retryable = False
        fatal_analysis = True

    seen: list[int] = []

    def final_review(request):
        seen.append(request.pass_number)
        raise FatalAnalysisFault("budget commit could not be persisted")

    callbacks = replace(
        _callbacks([]),
        ai1_structure=lambda _request: (),
        ai2_content_math=lambda _request: (),
        ai3_visual=lambda _request: (),
        ai5_final_review=final_review,
    )
    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R0))
    orchestrator = AnalysisOrchestrator(
        snapshot=_snapshot(),
        page_inputs=(page,),
        candidate_root=tmp_path / "fatal-final-review",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
    )

    with pytest.raises(FatalAnalysisFault, match="could not be persisted"):
        orchestrator.run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)
    assert seen == [1]


def _macro_batch_case(tmp_path, *, overlapping_operations: bool):
    targets = (
        "Every graph has a vertex.",
        "Every tree has a leaf.",
    )
    baseline_tex = (
        "\\documentclass{article}\n"
        "\\begin{document}\n"
        f"{targets[0]}\n"
        f"{targets[1]}\n"
        "\\end{document}\n"
    )
    snapshot = replace(
        _snapshot(),
        baseline_tex_hash=sha256_text(baseline_tex),
    )
    page = _page_input()
    page = replace(
        page,
        page_unit=replace(page.page_unit, risk_level=PageRisk.R2),
        baseline_tex_region=baseline_tex,
    )
    compile_inputs: list[str] = []

    def finding(request):
        proposals = []
        for index, target in enumerate(targets, start=1):
            start = request.materials.current_tex_region.index(target)
            proposals.append(IssueProposal(
                issue_type=f"FORMAL_BOUNDARY_{index}",
                severity=Severity.HIGH,
                source_page_ids=(PAGE_ID,),
                tex_anchors=(TexAnchor(
                    f"statement-{index}",
                    start,
                    start + len(target),
                    sha256_text(target),
                ),),
                source_pdf_regions=(PdfRegion(
                    PAGE_ID,
                    10,
                    index * 50,
                    100,
                    index * 50 + 30,
                ),),
                detector_role="AI-1",
                evidence_hashes=(
                    request.binding.material_hashes.source_pdf_page_hash,
                ),
                baseline_hash=snapshot.baseline_tex_hash,
                candidate_hash=request.binding.candidate_hash,
                description=f"Missing theorem wrapper around statement {index}.",
            ))
        return tuple(proposals)

    def patch(request):
        index = int(request.issue.tex_anchors[0].anchor_id.rsplit("-", 1)[1]) - 1
        target = targets[0] if overlapping_operations else targets[index]
        operation = PatchOperation(
            operation=PatchOperationKind.WRAP_ENVIRONMENT,
            issue_ids=(request.issue.issue_id,),
            start_anchor=target,
            end_anchor=target,
            expected_old_hash=sha256_text(target),
            replacement=f"\\begin{{theorem}}\n{target}\n\\end{{theorem}}",
            source_page_ids=(PAGE_ID,),
            reason="repair one host-confirmed boundary",
        )
        return PatchPlan(
            candidate_hash=request.binding.candidate_hash,
            issue_ids=(request.issue.issue_id,),
            operations=(operation,),
        )

    def compile_candidate(request):
        compile_inputs.append(request.tex)
        baseline = request.tex == baseline_tex
        return CompileResult(
            candidate_hash=request.candidate_hash,
            pdf=BASELINE_PDF if baseline else b"%PDF-macro-batch-two-pass",
            compile_log="xelatex pass 1 ok\nxelatex pass 2 ok",
            compile_passes=2,
            state=CompileState.COMPILED,
            pdf_openable=True,
            page_pdf_bytes=((
                PAGE_ID,
                b"rendered-baseline-page" if baseline else b"rendered-macro-page",
            ),),
            quality=_quality(open_high=2),
        )

    callbacks = replace(
        _callbacks([]),
        ai1_structure=finding,
        ai2_content_math=lambda _request: (),
        ai3_visual=lambda _request: (),
        ai4_patch=patch,
        compile_candidate=compile_candidate,
        patch_scope=lambda issue, tex: PatchScope(
            issue_id=issue.issue_id,
            candidate_hash=sha256_text(tex),
            start_offset=0,
            end_offset=len(tex),
            source_page_ids=(PAGE_ID,),
        ),
        ai6_adjudicate=None,
    )
    candidate_root = tmp_path / (
        "overlap-candidates" if overlapping_operations else "macro-candidates"
    )
    result = AnalysisOrchestrator(
        snapshot=snapshot,
        page_inputs=(page,),
        candidate_root=candidate_root,
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
    ).run(baseline_tex=baseline_tex, max_macro_rounds=1)
    return result, candidate_root, baseline_tex, compile_inputs


def test_macro_batch_micro_checks_two_patches_then_compiles_one_accepted_candidate(
    tmp_path,
):
    result, candidate_root, baseline_tex, compile_inputs = _macro_batch_case(
        tmp_path,
        overlapping_operations=False,
    )

    assert result.performance.incremental_check_count == 2
    assert result.performance.full_compile_count == 2
    assert compile_inputs[0] == baseline_tex
    assert len(compile_inputs) == 2
    assert result.current_tex.count("\\begin{theorem}") == 2
    assert len(result.ledger) == 2
    assert all(
        issue.current_status == IssueStatus.VERIFIED_CLOSED
        for issue in result.ledger
    )

    ledger_path = (
        candidate_root
        / result.best_candidate.artifact_directory
        / "issue_ledger.json"
    )
    persisted = json.loads(ledger_path.read_text(encoding="utf-8"))
    persisted_statuses = {
        issue["issue_id"]: issue["current_status"]
        for issue in persisted["issues"]
    }
    assert set(persisted_statuses) == {
        issue.issue_id for issue in result.ledger
    }
    assert set(persisted_statuses.values()) == {IssueStatus.VERIFIED_CLOSED.value}
    assert IssueStatus.FIXING.value not in persisted_statuses.values()


def test_overlapping_macro_patch_rejects_entire_batch_without_candidate_compile(
    tmp_path,
):
    result, candidate_root, baseline_tex, compile_inputs = _macro_batch_case(
        tmp_path,
        overlapping_operations=True,
    )

    assert compile_inputs == [baseline_tex]
    assert result.performance.full_compile_count == 1
    assert result.performance.incremental_check_count == 0
    assert result.current_tex == baseline_tex
    assert len(result.ledger) == 2
    assert all(issue.current_status == IssueStatus.BLOCKED for issue in result.ledger)
    assert all(
        "macro batch micro-check rejected" in issue.blocker_reason
        for issue in result.ledger
    )
    assert sum(
        reason.startswith("micro_patch_rejected:")
        for reason in result.stop_reasons
    ) == 2
    assert not tuple(candidate_root.glob("cand-r0001-*"))


class _RoundZeroCommitted(RuntimeError):
    pass


def _resume_state_from_checkpoint(checkpoint):
    return AnalysisResumeState(
        snapshot_hash=_snapshot().snapshot_hash,
        round_index=checkpoint.round_index,
        current_tex=checkpoint.current_tex,
        current_candidate_id=checkpoint.current_candidate.candidate_id,
        current_candidate_hash=checkpoint.current_candidate.tex_sha256,
        best_candidate_id=checkpoint.best_candidate.candidate_id,
        best_candidate_hash=checkpoint.best_candidate.tex_sha256,
        issue_ledger=checkpoint.issue_ledger,
        prior_invocations=checkpoint.invocations,
        prior_full_compile_count=checkpoint.full_compile_count,
        prior_incremental_check_count=checkpoint.incremental_check_count,
        prior_rollback_candidate_ids=checkpoint.rollback_candidate_ids,
        prior_modified_page_ids=checkpoint.modified_page_ids,
        prior_stop_reasons=checkpoint.stop_reasons,
    )


def _capture_round_zero_checkpoint(tmp_path):
    snapshot = _snapshot()
    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R2))
    candidate_root = tmp_path / "resume-candidates"
    captured = []

    def stop_after_round_zero(checkpoint):
        captured.append(checkpoint)
        raise _RoundZeroCommitted("simulate restart after durable round zero")

    with pytest.raises(_RoundZeroCommitted, match="durable round zero"):
        AnalysisOrchestrator(
            snapshot=snapshot,
            page_inputs=(page,),
            candidate_root=candidate_root,
            callbacks=_callbacks([]),
            raw_ocr_frozen=True,
            final_review_context_ids=("context-a", "context-b"),
            risk_routing_enabled=True,
            checkpoint_callback=stop_after_round_zero,
        ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert len(captured) == 1
    assert captured[0].round_index == 0
    return snapshot, page, candidate_root, captured[0]


def test_baseline_freeze_and_checkpoint_callbacks_observe_committed_boundaries(
    tmp_path,
):
    events: list[str] = []
    checkpoints = []
    baseline_seen = False
    callbacks = _callbacks(events)

    def require_frozen(callback):
        def checked(request):
            assert baseline_seen is True
            return callback(request)

        return checked

    callbacks = replace(
        callbacks,
        ai1_structure=require_frozen(callbacks.ai1_structure),
        ai2_content_math=require_frozen(callbacks.ai2_content_math),
        ai3_visual=require_frozen(callbacks.ai3_visual),
    )

    def baseline_frozen(compiled):
        nonlocal baseline_seen
        assert compiled.candidate_hash == sha256_text(BASELINE_TEX)
        assert not any(event.startswith("AI-") for event in events)
        baseline_seen = True
        events.append("baseline-frozen")

    def checkpoint_committed(checkpoint):
        checkpoints.append(checkpoint)
        events.append(f"checkpoint-{checkpoint.round_index}")

    page = _page_input()
    page = replace(page, page_unit=replace(page.page_unit, risk_level=PageRisk.R2))
    result = AnalysisOrchestrator(
        snapshot=_snapshot(),
        page_inputs=(page,),
        candidate_root=tmp_path / "checkpoint-candidates",
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
        baseline_frozen_callback=baseline_frozen,
        checkpoint_callback=checkpoint_committed,
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert events[:6] == [
        "compile-baseline",
        "baseline-frozen",
        "AI-1",
        "AI-2",
        "AI-3",
        "checkpoint-0",
    ]
    assert events.index("checkpoint-1") > events.index("AI-5-issue")
    assert events.index("AI-5-final-1") > events.index("checkpoint-1")
    assert events[-2:] == ["machine-verify", "checkpoint-1"]
    assert checkpoints[0].round_index == 0
    assert checkpoints[1].round_index == 1
    assert all(checkpoint.round_index == 1 for checkpoint in checkpoints[1:])
    round_zero = checkpoints[0]
    round_one = checkpoints[1]
    final_checkpoint = checkpoints[-1]

    assert round_zero.current_candidate == round_zero.best_candidate
    assert round_zero.current_candidate.tex_sha256 == sha256_text(BASELINE_TEX)
    assert round_zero.current_compile.candidate_hash == sha256_text(BASELINE_TEX)
    assert round_zero.issue_ledger["issues"][0]["current_status"] == IssueStatus.OPEN.value
    assert round_zero.issue_ledger["issues"][0]["detector_roles"] == (
        "AI-1",
        "AI-2",
        "AI-3",
    )
    assert round_zero.task_ledger["schema"] == "latexstruct-analysis-task-ledger-v2"
    round_zero_tasks = round_zero.task_ledger["records"]
    assert len(round_zero_tasks) == 4
    assert {record["state"] for record in round_zero_tasks.values()} == {"COMPLETED"}
    assert [invocation.binding.role for invocation in round_zero.invocations] == [
        "AI-3",
        "AI-1",
        "AI-2",
        "AI-3",
    ]
    assert round_zero.full_compile_count == 1
    assert round_zero.incremental_check_count == 0

    assert round_one.current_candidate == round_one.best_candidate
    assert round_one.current_candidate.candidate_id == result.best_candidate.candidate_id
    assert round_one.current_candidate.tex_sha256 == sha256_text(round_one.current_tex)
    assert round_one.current_compile.candidate_hash == round_one.current_candidate.tex_sha256
    assert round_one.issue_ledger["issues"][0]["current_status"] == (
        IssueStatus.VERIFIED_CLOSED.value
    )
    assert round_one.task_ledger == round_zero.task_ledger
    assert [invocation.operation for invocation in round_one.invocations] == [
        "visual-triage",
        "structure-findings",
        "content-math-findings",
        "visual-findings",
        "local-patch",
        "issue-review",
    ]
    assert round_one.full_compile_count == 2
    assert round_one.incremental_check_count == 1
    assert round_one.modified_page_ids == (PAGE_ID,)
    assert final_checkpoint.current_candidate == round_one.current_candidate
    assert final_checkpoint.best_candidate == round_one.best_candidate
    assert final_checkpoint.issue_ledger == round_one.issue_ledger
    round_one_records = round_one.task_ledger["records"]
    final_records = final_checkpoint.task_ledger["records"]
    assert {
        task_id: final_records[task_id] for task_id in round_one_records
    } == round_one_records
    assert len(final_records) == len(round_one_records) + 3
    assert {
        record["identity"]["operation"]
        for task_id, record in final_records.items()
        if task_id not in round_one_records
    } == {
        "structure-recheck",
        "content-math-recheck",
        "visual-recheck",
    }
    assert [invocation.operation for invocation in final_checkpoint.invocations] == [
        "visual-triage",
        "structure-findings",
        "content-math-findings",
        "visual-findings",
        "local-patch",
        "issue-review",
        "structure-recheck",
        "content-math-recheck",
        "visual-recheck",
        "final-review-1",
        "final-review-2",
    ]
    assert final_checkpoint.full_compile_count == round_one.full_compile_count
    assert final_checkpoint.incremental_check_count == (
        round_one.incremental_check_count
    )


def test_round_zero_resume_skips_discovery_and_continues_committed_best_and_ledger(
    tmp_path,
):
    snapshot, page, candidate_root, round_zero = _capture_round_zero_checkpoint(
        tmp_path
    )
    resume_state = _resume_state_from_checkpoint(round_zero)
    discovery_calls: list[str] = []
    resume_events: list[str] = []
    resumed_checkpoints = []
    callbacks = _callbacks(resume_events)

    def forbidden_discovery(request):
        discovery_calls.append(request.binding.role)
        raise AssertionError("resume must not replay committed discovery")

    callbacks = replace(
        callbacks,
        ai1_structure=forbidden_discovery,
        ai2_content_math=forbidden_discovery,
        ai3_visual=forbidden_discovery,
    )
    result = AnalysisOrchestrator(
        snapshot=snapshot,
        page_inputs=(page,),
        candidate_root=candidate_root,
        callbacks=callbacks,
        raw_ocr_frozen=True,
        final_review_context_ids=("context-a", "context-b"),
        risk_routing_enabled=True,
        baseline_frozen_callback=lambda _compiled: resume_events.append(
            "resume-baseline-frozen"
        ),
        checkpoint_callback=resumed_checkpoints.append,
        resume_state=resume_state,
    ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    assert discovery_calls == []
    assert resume_events == [
        "compile-baseline",
        "resume-baseline-frozen",
        "AI-4",
        "compile-candidate",
        "AI-5-issue",
        "AI-5-final-1",
        "AI-5-final-2",
        "machine-verify",
    ]
    assert result.invocations[: len(round_zero.invocations)] == round_zero.invocations
    assert not {
        invocation.operation
        for invocation in result.invocations[len(round_zero.invocations) :]
    }.intersection(
        {"structure-findings", "content-math-findings", "visual-findings"}
    )
    assert result.best_candidate.parent_candidate_id == (
        round_zero.best_candidate.candidate_id
    )
    assert result.ledger[0].issue_id == round_zero.issue_ledger["issues"][0]["issue_id"]
    assert result.ledger[0].current_status == IssueStatus.VERIFIED_CLOSED
    assert result.decision.status == AnalysisFinalStatus.VERIFIED
    assert len(resumed_checkpoints) >= 2
    assert all(checkpoint.round_index == 1 for checkpoint in resumed_checkpoints)
    assert resumed_checkpoints[0].best_candidate.candidate_id == (
        result.best_candidate.candidate_id
    )
    assert resumed_checkpoints[0].issue_ledger["issues"][0]["current_status"] == (
        IssueStatus.VERIFIED_CLOSED.value
    )
    assert resumed_checkpoints[-1].best_candidate == (
        resumed_checkpoints[0].best_candidate
    )
    resumed_tail = resumed_checkpoints[-1].invocations[
        len(resumed_checkpoints[0].invocations) :
    ]
    assert [item.operation for item in resumed_tail] == [
        "structure-recheck",
        "content-math-recheck",
        "visual-recheck",
        "final-review-1",
        "final-review-2",
    ]

    repository = CandidateRepository(candidate_root)
    assert repository.verify_baseline_input_checkpoint()
    assert len(tuple(candidate_root.glob("cand-r0000-*"))) == 1
    assert len(tuple(candidate_root.glob("cand-r0001-*"))) == 1


def test_resume_snapshot_mismatch_fails_before_candidate_restore(tmp_path):
    snapshot, page, candidate_root, checkpoint = _capture_round_zero_checkpoint(
        tmp_path
    )
    resume_state = replace(
        _resume_state_from_checkpoint(checkpoint),
        snapshot_hash=sha256_text("different immutable snapshot"),
    )

    with pytest.raises(ValueError, match="different immutable snapshot"):
        AnalysisOrchestrator(
            snapshot=snapshot,
            page_inputs=(page,),
            candidate_root=candidate_root,
            callbacks=_callbacks([]),
            raw_ocr_frozen=True,
            final_review_context_ids=("context-a", "context-b"),
            risk_routing_enabled=True,
            resume_state=resume_state,
        )


def test_resume_candidate_hash_mismatch_fails_closed_without_baseline_collision(
    tmp_path,
):
    snapshot, page, candidate_root, checkpoint = _capture_round_zero_checkpoint(
        tmp_path
    )
    divergent_tex = checkpoint.current_tex + "% divergent checkpoint bytes\n"
    divergent_hash = sha256_text(divergent_tex)
    resume_state = replace(
        _resume_state_from_checkpoint(checkpoint),
        current_tex=divergent_tex,
        current_candidate_hash=divergent_hash,
        best_candidate_hash=divergent_hash,
    )

    with pytest.raises(StaleEvidenceError, match="resume candidate differs"):
        AnalysisOrchestrator(
            snapshot=snapshot,
            page_inputs=(page,),
            candidate_root=candidate_root,
            callbacks=_callbacks([]),
            raw_ocr_frozen=True,
            final_review_context_ids=("context-a", "context-b"),
            risk_routing_enabled=True,
            resume_state=resume_state,
        ).run(baseline_tex=BASELINE_TEX, max_macro_rounds=1)

    repository = CandidateRepository(candidate_root)
    assert repository.verify_baseline_input_checkpoint()
    assert len(tuple(candidate_root.glob("cand-r0000-*"))) == 1

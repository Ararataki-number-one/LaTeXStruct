# -*- coding: utf-8 -*-
"""Host authority and rollback guarantees for the v2 analysis quality loop."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from latexstruct.core.analysis_runtime import (
    AnalysisQualityRuntime,
    CandidateController,
    CandidateRepository,
    CandidateStoreError,
    EscalationAction,
    IssueLedger,
    LedgerTransitionError,
    LocalAnalysisCache,
    NoProgressController,
    PatchApplication,
    PatchOperation,
    PatchPlan,
    PatchRejected,
    PatchScope,
    PerformanceTracker,
    RoundObservation,
    apply_patch_plan,
    decide_final_status,
)
from latexstruct.core.analysis_schema import (
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
    PageStatus,
    PageUnit,
    PatchOperationKind,
    PdfRegion,
    PerformanceTargetStatus,
    QualityVector,
    ReviewResult,
    Severity,
    TexAnchor,
    VerificationEvidence,
    sha256_bytes,
    sha256_text,
)


def _digest(label: str) -> str:
    return sha256_text(label)


def _snapshot(*, pages=(1, 2)) -> AnalysisRunSnapshot:
    return AnalysisRunSnapshot(
        run_id="analysis-run-1",
        project_id="项目-甲",
        workflow_version="analysis-loop-v2",
        prompt_version="analysis-prompts-v2",
        application_version="2.0.0",
        source_pdf_hash=_digest("source.pdf"),
        raw_ocr_tex_hash=_digest("raw.tex"),
        baseline_tex_hash=_digest("baseline.tex"),
        baseline_pdf_hash=_digest("baseline.pdf"),
        page_count=max(pages),
        page_range=pages,
        latex_engine="xelatex",
        models=(
            ModelBinding("AI-1", "structure-model", ("json",)),
            ModelBinding("AI-5", "review-model", ("vision", "json")),
        ),
        concurrency_limit=3,
        started_at="2026-08-23T12:00:00+08:00",
        page_map=tuple(
            PageMapEntry(f"source-page-{page:06d}", page, f"% Page {page}", (f"pdf-{page}",))
            for page in pages
        ),
        initial_compile_state=CompileState.COMPILED,
        initial_issue_counts=(("OPEN", 0),),
        config_hash=_digest("config"),
    )


def _page(number: int) -> PageUnit:
    return PageUnit(
        source_page_id=f"source-page-{number:06d}",
        source_page_number=number,
        source_page_hash=_digest(f"page-{number}"),
        baseline_tex_start_anchor=f"baseline-start-{number}",
        baseline_tex_end_anchor=f"baseline-end-{number}",
        current_tex_start_anchor=f"current-start-{number}",
        current_tex_end_anchor=f"current-end-{number}",
        candidate_pdf_page_ids=(f"pdf-{number}",),
        risk_level=PageRisk.R1 if number == 2 else PageRisk.R0,
        risk_reasons=("formal candidate",) if number == 2 else (),
    )


def _proposal(
    *,
    candidate_hash: str,
    role: str = "AI-1",
    evidence: str = "evidence-a",
) -> IssueProposal:
    return IssueProposal(
        issue_type="FORMAL_BOUNDARY",
        severity=Severity.HIGH,
        source_page_ids=("source-page-000002",),
        tex_anchors=(TexAnchor("theorem-2", 20, 70, _digest("statement")),),
        source_pdf_regions=(PdfRegion("source-page-000002", 10, 10, 100, 80),),
        detector_role=role,
        evidence_hashes=(_digest(evidence),),
        baseline_hash=_digest("baseline.tex"),
        candidate_hash=candidate_hash,
        description="Theorem 2 body ends after the displayed equation.",
    )


def _quality(**changes) -> QualityVector:
    values = {
        "fully_compiled": True,
        "silent_page_omissions": 0,
        "silent_text_losses": 0,
        "unauthorized_math_changes": 0,
        "open_critical": 0,
        "open_high": 0,
        "formal_errors": 0,
        "structure_reference_errors": 0,
        "footnote_figure_equation_errors": 0,
        "severe_visual_errors": 0,
        "ordinary_layout_errors": 0,
    }
    values.update(changes)
    return QualityVector(**values)


def _reviews(candidate_hash: str, pages=("p1", "p2")):
    common = dict(
        candidate_hash=candidate_hash,
        checked_page_ids=pages,
        compile_passes=2,
        content_conservation_ok=True,
        math_conservation_ok=True,
        formal_inventory_ok=True,
        visual_review_ok=True,
        new_high_risk_issues=0,
        prior_pass_conclusion_visible=False,
    )
    return (
        IndependentReviewPass(pass_number=1, context_id="review-context-a", **common),
        IndependentReviewPass(pass_number=2, context_id="review-context-b", **common),
    )


def _verification(candidate_hash: str, **changes) -> VerificationEvidence:
    values = dict(
        raw_ocr_frozen=True,
        baseline_compile_passes=2,
        best_compile_passes=2,
        best_pdf_openable=True,
        expected_page_ids=("p1", "p2"),
        checked_page_ids=("p1", "p2"),
        silent_page_omissions=0,
        silent_text_losses=0,
        unauthorized_math_changes=0,
        formal_errors=0,
        toc_complete_and_ordered=True,
        severe_equation_number_errors=0,
        silent_footnote_losses=0,
        silent_figure_caption_losses=0,
        silent_bibliography_losses=0,
        open_critical=0,
        open_high=0,
        regressions=0,
        candidate_hash=candidate_hash,
        current_candidate_hash=candidate_hash,
        final_reviews=_reviews(candidate_hash),
    )
    values.update(changes)
    return VerificationEvidence(**values)


def test_snapshot_and_page_units_are_immutable_and_stale_is_host_derived():
    snapshot = _snapshot()
    with pytest.raises(FrozenInstanceError):
        snapshot.page_count = 99
    assert snapshot.page_range == (1, 2)
    assert snapshot.stale_reasons(
        source_pdf_hash=snapshot.source_pdf_hash,
        raw_ocr_tex_hash=snapshot.raw_ocr_tex_hash,
        baseline_tex_hash=_digest("changed baseline"),
        page_range=(1, 2),
    ) == ("baseline_tex_hash",)

    page = _page(1)
    checked = page.checked(_digest("candidate"), verified=True)
    assert page.current_status == PageStatus.PENDING
    assert page.last_checked_candidate_hash == ""
    assert checked.current_status == PageStatus.VERIFIED


def test_snapshot_rejects_incomplete_or_duplicate_page_mapping():
    snapshot = _snapshot()
    with pytest.raises(ValueError, match="exactly once"):
        replace(snapshot, page_map=snapshot.page_map[:1])
    with pytest.raises(ValueError, match="unique"):
        replace(snapshot, page_range=(1, 1))


def test_issue_ledger_deduplicates_roles_and_reappearance_is_regression():
    candidate_hash = _digest("candidate-a")
    ledger = IssueLedger()
    original = ledger.upsert(_proposal(candidate_hash=candidate_hash), round_index=1)
    duplicate = ledger.upsert(
        _proposal(candidate_hash=candidate_hash, role="AI-3", evidence="evidence-b"),
        round_index=1,
    )
    assert duplicate.issue_id == original.issue_id
    assert duplicate.detector_roles == ("AI-1", "AI-3")
    assert len(ledger.records) == 1

    fixing = ledger.transition(
        original.issue_id,
        IssueStatus.FIXING,
        round_index=2,
        patch_id="PATCH-host",
    )
    pending = ledger.transition(
        original.issue_id,
        IssueStatus.FIXED_PENDING_REVIEW,
        round_index=2,
        candidate_hash=candidate_hash,
    )
    assert fixing.retry_count == 1
    assert pending.current_status == IssueStatus.FIXED_PENDING_REVIEW
    closed = ledger.close_after_review(
        original.issue_id,
        round_index=2,
        candidate_hash=candidate_hash,
        review_result=ReviewResult.PASS,
        compile_ok=True,
        content_conservation_ok=True,
        math_conservation_ok=True,
        visual_review_ok=True,
        new_high_priority_issues=0,
    )
    assert closed.current_status == IssueStatus.VERIFIED_CLOSED

    regression = ledger.upsert(
        _proposal(candidate_hash=_digest("candidate-b"), role="AI-5"),
        round_index=3,
    )
    assert regression.issue_id == original.issue_id
    assert regression.current_status == IssueStatus.REGRESSION
    assert regression.regression_count == 1
    assert len(ledger.records) == 1


def test_issue_closure_is_fail_closed_and_ledger_recovers_exactly():
    candidate_hash = _digest("candidate")
    ledger = IssueLedger()
    issue = ledger.upsert(_proposal(candidate_hash=candidate_hash), round_index=0)
    with pytest.raises(LedgerTransitionError, match="independent review"):
        ledger.transition(issue.issue_id, IssueStatus.VERIFIED_CLOSED, round_index=1)
    ledger.transition(issue.issue_id, IssueStatus.FIXING, round_index=1)
    ledger.transition(
        issue.issue_id,
        IssueStatus.FIXED_PENDING_REVIEW,
        round_index=1,
        candidate_hash=candidate_hash,
    )
    reopened = ledger.close_after_review(
        issue.issue_id,
        round_index=1,
        candidate_hash=candidate_hash,
        review_result=ReviewResult.PASS,
        compile_ok=True,
        content_conservation_ok=False,
        math_conservation_ok=True,
        visual_review_ok=True,
        new_high_priority_issues=0,
    )
    assert reopened.current_status == IssueStatus.OPEN
    recovered = IssueLedger.from_dict(ledger.to_dict())
    assert recovered.to_dict() == ledger.to_dict()


def _wrap_patch(source: str, issue_id: str, *, scope=(0, None)):
    target = "Every graph has a vertex."
    start = source.index(target)
    end = start + len(target)
    scope_end = len(source) if scope[1] is None else scope[1]
    operation = PatchOperation(
        operation=PatchOperationKind.WRAP_ENVIRONMENT,
        issue_ids=(issue_id,),
        start_anchor=target,
        end_anchor=target,
        expected_old_hash=sha256_text(target),
        replacement="\\begin{theorem}\n" + target + "\n\\end{theorem}",
        source_page_ids=("source-page-000001",),
        reason="host-confirmed missing theorem wrapper",
    )
    plan = PatchPlan(
        candidate_hash=sha256_text(source), issue_ids=(issue_id,), operations=(operation,)
    )
    patch_scope = PatchScope(
        issue_id=issue_id,
        candidate_hash=sha256_text(source),
        start_offset=scope[0],
        end_offset=scope_end,
        source_page_ids=("source-page-000001",),
    )
    return plan, {issue_id: patch_scope}, start, end


def test_patch_is_local_hash_bound_and_preserves_body_and_math_tokens():
    source = "\\begin{document}\nEvery graph has a vertex.\n$x+y=z$.\n\\end{document}\n"
    issue_id = "ISS-0123456789ab"
    plan, scopes, _start, _end = _wrap_patch(source, issue_id)
    applied = apply_patch_plan(source, plan, scopes=scopes)
    assert applied.parent_hash == sha256_text(source)
    assert applied.candidate_hash == sha256_text(applied.candidate_tex)
    assert "\\begin{theorem}" in applied.candidate_tex
    assert applied.conservation.ok is True
    assert applied.conservation.unauthorized_changes == ()
    assert applied.affected_page_ids == ("source-page-000001",)

    stale = replace(plan, candidate_hash=_digest("stale"))
    with pytest.raises(PatchRejected, match="candidate_hash"):
        apply_patch_plan(source, stale, scopes=scopes)


def test_patch_rejects_out_of_scope_whole_document_and_unauthorized_math_change():
    source = "prefix\nEvery graph has a vertex.\n$x$.\nsuffix"
    issue_id = "ISS-0123456789ab"
    plan, scopes, start, _end = _wrap_patch(source, issue_id, scope=(0, 7))
    with pytest.raises(PatchRejected, match="boundary"):
        apply_patch_plan(source, plan, scopes=scopes)

    whole = PatchOperation(
        PatchOperationKind.REPLACE,
        (issue_id,),
        source,
        source,
        sha256_text(source),
        "replacement",
        ("source-page-000001",),
    )
    whole_plan = PatchPlan(sha256_text(source), (issue_id,), (whole,))
    broad_scope = PatchScope(
        issue_id, sha256_text(source), 0, len(source), ("source-page-000001",)
    )
    with pytest.raises(PatchRejected, match="whole-document"):
        apply_patch_plan(source, whole_plan, scopes={issue_id: broad_scope})

    target = "$x$"
    math_op = PatchOperation(
        PatchOperationKind.REPLACE,
        (issue_id,),
        target,
        target,
        sha256_text(target),
        "$y$",
        ("source-page-000001",),
    )
    math_plan = PatchPlan(sha256_text(source), (issue_id,), (math_op,))
    math_start = source.index(target)
    strict = PatchScope(
        issue_id,
        sha256_text(source),
        math_start,
        math_start + len(target),
        ("source-page-000001",),
    )
    with pytest.raises(PatchRejected, match="math"):
        apply_patch_plan(source, math_plan, scopes={issue_id: strict})
    authorized = replace(strict, allowed_invariant_changes=("math",))
    changed = apply_patch_plan(source, math_plan, scopes={issue_id: authorized})
    assert changed.conservation.authorized_changes == ("math",)
    assert start < math_start


def test_patch_rejects_nonunique_anchor_and_document_shell_injection():
    issue_id = "ISS-0123456789ab"
    source = "same\nsame\n"
    operation = PatchOperation(
        PatchOperationKind.REPLACE,
        (issue_id,),
        "same",
        "same",
        sha256_text("same"),
        "changed",
        ("source-page-000001",),
    )
    plan = PatchPlan(sha256_text(source), (issue_id,), (operation,))
    scope = PatchScope(issue_id, sha256_text(source), 0, len(source), ("source-page-000001",))
    with pytest.raises(PatchRejected, match="exactly one"):
        apply_patch_plan(source, plan, scopes={issue_id: scope})

    unique = "only target"
    shell = replace(
        operation,
        start_anchor=unique,
        end_anchor=unique,
        expected_old_hash=sha256_text(unique),
        replacement="\\documentclass{book}",
    )
    shell_plan = PatchPlan(sha256_text(unique), (issue_id,), (shell,))
    shell_scope = PatchScope(
        issue_id, sha256_text(unique), 0, len(unique), ("source-page-000001",)
    )
    with pytest.raises(PatchRejected, match="shell"):
        apply_patch_plan(unique, shell_plan, scopes={issue_id: shell_scope})


def test_quality_vector_is_lexicographic_not_an_average():
    best = _quality(open_high=0, ordinary_layout_errors=100)
    prettier_but_unsafe = _quality(open_high=1, ordinary_layout_errors=0)
    assert best.better_than(prettier_but_unsafe)
    compile_failed = _quality(fully_compiled=False)
    assert best.better_than(compile_failed)
    assert not best.better_than(best)
    assert best.no_worse_than(best)


def _application(parent: str, candidate: str, patch_id: str) -> PatchApplication:
    return PatchApplication(
        patch_id=patch_id,
        parent_hash=sha256_text(parent),
        candidate_hash=sha256_text(candidate),
        candidate_tex=candidate,
        diff="candidate diff",
        affected_page_ids=("p1",),
        conservation=None,  # repository only persists the already-gated application
    )


def test_candidates_are_write_once_and_regression_rolls_back_to_history_best(tmp_path):
    repository = CandidateRepository(tmp_path / "中文候选")
    controller = CandidateController(repository)
    baseline_tex = "baseline"
    baseline = controller.save_baseline(
        tex=baseline_tex,
        pdf=b"baseline-pdf",
        compile_log="two passes ok",
        quality=_quality(open_high=1),
        issue_ledger={"issues": []},
    )
    assert repository.verify(baseline.candidate_id)

    improved_tex = "improved"
    accepted = controller.evaluate(
        application=_application(baseline_tex, improved_tex, "PATCH-good"),
        round_index=1,
        pdf=b"improved-pdf",
        compile_log="two passes ok",
        quality=_quality(open_high=0),
        issue_ledger={"issues": []},
        review={"result": "PASS"},
    )
    assert controller.best == accepted

    unsafe_tex = "prettier but does not compile"
    rejected = controller.evaluate(
        application=_application(improved_tex, unsafe_tex, "PATCH-bad"),
        round_index=2,
        pdf=b"partial-pdf",
        compile_log="compile failed",
        quality=_quality(fully_compiled=False, ordinary_layout_errors=0),
        issue_ledger={"issues": []},
        review={"result": "FAIL"},
    )
    assert rejected.disposition.value == "REJECTED_ROLLED_BACK"
    assert controller.current == accepted
    assert controller.best == accepted
    assert controller.rollback_history[0].retained_candidate_id == accepted.candidate_id
    assert repository.verify(rejected.candidate_id)

    with pytest.raises(CandidateStoreError, match="already exists"):
        controller.repository.persist(
            candidate_id=baseline.candidate_id,
            parent_candidate_id="",
            round_index=0,
            tex=baseline_tex,
            pdf=b"baseline-pdf",
            compile_log="",
            patch={},
            diff="",
            issue_ledger={},
            quality=_quality(open_high=1),
            review={},
            disposition=baseline.disposition,
            reason="duplicate",
        )


def test_candidate_sha256s_are_recomputable_and_tampering_is_detected(tmp_path):
    repository = CandidateRepository(tmp_path)
    controller = CandidateController(repository)
    record = controller.save_baseline(
        tex="基线正文",
        pdf=b"pdf",
        compile_log="ok",
        quality=_quality(),
        issue_ledger={},
    )
    directory = repository.root / record.artifact_directory
    assert record.tex_sha256 == sha256_bytes((directory / "candidate.tex").read_bytes())
    assert repository.verify(record.candidate_id)
    resumed = CandidateController(repository).resume_from_committed_best(record.candidate_id)
    assert resumed == record
    assert not Path(record.artifact_directory).is_absolute()
    (directory / "compile.log").write_text("tampered", encoding="utf-8")
    assert repository.verify(record.candidate_id) is False
    with pytest.raises(CandidateStoreError, match="manifest"):
        CandidateController(repository).resume_from_committed_best(record.candidate_id)


def _cache_key(page: str, *, current="current", role="AI-1") -> AnalysisCacheKey:
    return AnalysisCacheKey(
        snapshot_hash=_digest("analysis-snapshot"),
        source_page_id=page,
        source_page_hash=_digest(f"source-{page}"),
        baseline_tex_region_hash=_digest(f"baseline-{page}"),
        current_tex_region_hash=_digest(current),
        current_render_hash=_digest(f"render-{page}"),
        prompt_version="prompt-v2",
        response_schema_version="analysis-response-v2",
        model_id="model-a",
        tool_version="latexstruct-2.0.0",
        audit_role=role,
    )


def test_cache_change_invalidates_only_matching_page_and_role():
    cache = LocalAnalysisCache()
    p1 = _cache_key("p1")
    p2 = _cache_key("p2")
    p1_visual = _cache_key("p1", role="AI-3")
    assert len({
        p1.digest,
        replace(p1, snapshot_hash=_digest("other-snapshot")).digest,
        replace(p1, response_schema_version="analysis-response-v3").digest,
        replace(p1, tool_version="latexstruct-2.0.1").digest,
    }) == 4
    cache.put(p1, {"answer": [1]})
    cache.put(p2, {"answer": [2]})
    cache.put(p1_visual, {"answer": [3]})
    changed = _cache_key("p1", current="changed")
    removed = cache.invalidate_changed(changed)
    assert removed == (p1.digest,)
    assert cache.get(p1) is None
    assert cache.get(p2) == {"answer": [2]}
    assert cache.get(p1_visual) == {"answer": [3]}
    cached = cache.get(p2)
    cached["answer"].append(9)
    assert cache.get(p2) == {"answer": [2]}


def test_two_stagnant_macro_rounds_and_repeated_issue_force_escalation():
    controller = NoProgressController()
    base = RoundObservation(1, 3, 1, 0, 0, _quality(open_high=1))
    assert controller.observe_round(base).stop_current_strategy is False
    assert controller.observe_round(replace(base, round_index=2)).stop_current_strategy is False
    stopped = controller.observe_round(replace(base, round_index=3))
    assert stopped.stop_current_strategy is True
    assert stopped.action == EscalationAction.RELOAD_CURRENT

    first = controller.record_issue_attempt(
        "ISS-0123456789ab", prompt_and_evidence_fingerprint="same", resolved=False
    )
    second = controller.record_issue_attempt(
        "ISS-0123456789ab", prompt_and_evidence_fingerprint="same", resolved=False
    )
    assert first.stop_current_strategy is False
    assert second.stop_current_strategy is True
    assert second.action == EscalationAction.REDUCE_TO_SINGLE_ISSUE
    changed = controller.record_issue_attempt(
        "ISS-0123456789ab", prompt_and_evidence_fingerprint="new evidence", resolved=False
    )
    assert changed.no_progress_rounds == 1


def test_verified_is_derived_only_from_complete_host_evidence():
    candidate_hash = _digest("best")
    clean = decide_final_status(_verification(candidate_hash))
    assert clean.status == AnalysisFinalStatus.VERIFIED
    assert clean.verified is True

    incomplete = decide_final_status(_verification(
        candidate_hash,
        checked_page_ids=("p1",),
        final_reviews=_reviews(candidate_hash)[:1],
    ))
    assert incomplete.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "page_coverage_incomplete" in incomplete.failures
    assert "two_independent_reviews_missing" in incomplete.failures

    same_context = _reviews(candidate_hash)
    same_context = (same_context[0], replace(same_context[1], context_id="review-context-a"))
    not_independent = decide_final_status(_verification(candidate_hash, final_reviews=same_context))
    assert "reviews_not_independent" in not_independent.failures

    failed = decide_final_status(
        _verification(candidate_hash, unauthorized_math_changes=1),
        processing_failed=True,
    )
    assert failed.status == AnalysisFinalStatus.FAILED_BEST_RETAINED
    assert failed.verified is False


def test_review_candidate_hash_and_second_context_fail_closed():
    candidate_hash = _digest("best")
    stale_review = replace(_reviews(candidate_hash)[1], candidate_hash=_digest("old"))
    decision = decide_final_status(_verification(
        candidate_hash,
        final_reviews=(_reviews(candidate_hash)[0], stale_review),
    ))
    assert "review_2_candidate_hash_stale" in decision.failures

    visible = replace(_reviews(candidate_hash)[1], prior_pass_conclusion_visible=True)
    decision = decide_final_status(_verification(
        candidate_hash,
        final_reviews=(_reviews(candidate_hash)[0], visible),
    ))
    assert "reviews_not_independent" in decision.failures


def test_performance_metrics_use_real_coverage_and_recent_throughput():
    tracker = PerformanceTracker(total_pages=20, target_seconds=180)
    for index in range(1, 11):
        tracker.record_page_completion(f"p{index}", float(index))
    with pytest.raises(ValueError, match="inflate"):
        tracker.record_page_completion("p1", 11)
    metrics = tracker.snapshot(
        elapsed_seconds=10,
        machine_preflight_seconds=1,
        whole_book_scan_seconds=2,
        role_call_counts={"AI-1": 2, "AI-5": 1},
        model_elapsed_seconds={"model-a": 4.5},
        input_tokens=100,
        output_tokens=20,
        cache_hits=5,
        cache_misses=5,
        high_risk_pages=2,
        modified_pages=1,
        full_compile_count=2,
        incremental_check_count=3,
        rollback_count=0,
        auto_closed_issues=1,
        blocked_issues=0,
        final_status=AnalysisFinalStatus.COMPLETED_WITH_ISSUES,
    )
    assert metrics.checked_pages == 10
    assert metrics.estimated_remaining_seconds == pytest.approx(10.0)
    assert metrics.cache_hit_rate == 0.5
    assert metrics.benchmark_eligible is False
    assert metrics.target_evaluated is False
    assert metrics.target_status == PerformanceTargetStatus.NOT_EVALUATED
    assert metrics.target_met is None

    for index in range(11, 21):
        tracker.record_page_completion(f"p{index}", float(index))
    complete = tracker.snapshot(
        elapsed_seconds=20,
        machine_preflight_seconds=1,
        whole_book_scan_seconds=2,
        role_call_counts={},
        model_elapsed_seconds={},
        input_tokens=0,
        output_tokens=0,
        cache_hits=0,
        cache_misses=0,
        high_risk_pages=0,
        modified_pages=0,
        full_compile_count=2,
        incremental_check_count=1,
        rollback_count=0,
        auto_closed_issues=0,
        blocked_issues=0,
        final_status=AnalysisFinalStatus.VERIFIED,
    )
    assert complete.checked_pages == 20
    assert complete.estimated_remaining_seconds == 0
    assert complete.benchmark_eligible is False
    assert complete.target_evaluated is False
    assert complete.target_status == PerformanceTargetStatus.NOT_EVALUATED
    assert complete.target_met is None


def test_runtime_requires_exact_page_units_and_rejects_stale_best_evidence(tmp_path):
    snapshot = _snapshot()
    with pytest.raises(ValueError, match="exactly once"):
        AnalysisQualityRuntime(
            snapshot=snapshot,
            page_units=(_page(1),),
            candidate_root=tmp_path / "bad",
        )
    runtime = AnalysisQualityRuntime(
        snapshot=snapshot,
        page_units=(_page(1), _page(2)),
        candidate_root=tmp_path / "good",
    )
    baseline = runtime.candidates.save_baseline(
        tex="best",
        pdf=b"pdf",
        compile_log="ok twice",
        quality=_quality(),
        issue_ledger=runtime.ledger.to_dict(),
    )
    stale = _verification(_digest("rejected"))
    decision = runtime.final_decision(stale)
    assert decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "candidate_hash_stale" in decision.failures
    assert baseline.tex_sha256 != stale.candidate_hash

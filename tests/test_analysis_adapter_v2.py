# -*- coding: utf-8 -*-
"""Portable, fail-closed archives for existing v2 pipeline runs."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path, PurePosixPath

import pytest

import latexstruct.core.analysis_adapter as analysis_adapter
from latexstruct.core.analysis_adapter import (
    AnalysisArchiveError,
    AnalysisRunArtifacts,
    ProductionAnalysisArchiveEvidence,
    freeze_pipeline_analysis_run,
    stable_source_page_id,
    verify_frozen_analysis_run,
)
from latexstruct.core.analysis_budget import (
    ActualUsage,
    AnalysisBudget,
    BudgetClaim,
    BudgetLimits,
    BudgetUsage,
)
from latexstruct.core.analysis_inventory import (
    AnalysisNativeSourceBlock,
    build_analysis_inventory_bundle,
    build_host_inventory_authorizations,
)
from latexstruct.core.analysis_orchestrator import PageAnalysisInput
from latexstruct.core.analysis_risk import (
    PageRiskPreflightInput,
    build_page_risk_admission,
)
from latexstruct.core.analysis_schema import (
    ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
    AnalysisCacheKey,
    AnalysisEvidenceHashes,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    AnalysisTransportContract,
    CompileState,
    IndependentReviewPass,
    ModelBinding,
    PageMapEntry,
    PageRisk,
    PageRiskRouteClosure,
    PageRouteRecord,
    PageTriageOutcome,
    PageUnit,
    VerificationEvidence,
    canonical_json_bytes,
    sha256_bytes,
    sha256_text,
)


SOURCE_PDF = b"%PDF-1.7\nsource-pages\n%%EOF\n"
BASELINE_PDF = b"%PDF-1.7\nbaseline\n%%EOF\n"
CURRENT_PDF = b"%PDF-1.7\ncurrent\n%%EOF\n"
RAW_TEX = (
    "\\documentclass{article}\n\\begin{document}\n"
    "% Page 1\nTheorem 1. Raw OCR.\n"
    "% Page 2\nSecond page.\n\\end{document}\n"
)
BASELINE_TEX = RAW_TEX
CURRENT_TEX = (
    "\\documentclass{article}\n\\begin{document}\n% Page 1\n"
    "\\begin{theorem}Theorem 1. Raw OCR.\\end{theorem}\n"
    "% Page 2\nSecond page.\n\\end{document}\n"
)
NATIVE_FORMAL_BLOCKS = (
    AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="formal-source-0001",
        block_type="HEADING_TEXT",
        plain_text="Theorem 1. Raw OCR.",
        source_sha256=sha256_text("Theorem 1. Raw OCR."),
    ),
)


def _models():
    return (
        ModelBinding("AI-1", "structure-model", ("json",)),
        ModelBinding("AI-5", "review-model", ("vision", "json")),
    )


def _transport_contracts():
    operations = {
        "AI-1": ("structure-findings",),
        "AI-5": ("final-review-1", "final-review-2", "issue-review"),
    }
    return tuple(
        AnalysisTransportContract(
            role=model.role,
            model_id=model.model_id,
            reasoning_effort=model.reasoning_effort,
            operations=operations[model.role],
            client_type="tests.AuthoritativeClient",
            method=(
                "chat_vision_json_images_bytes"
                if model.role == "AI-5"
                else "chat_json_schema"
            ),
            max_retries=0,
            max_tokens=0,
            backend_authority_sha256=sha256_text("authority"),
            backend_configuration_sha256=sha256_text("configuration"),
        )
        for model in _models()
    )


def _artifacts(**changes) -> AnalysisRunArtifacts:
    values = dict(
        source_pdf=SOURCE_PDF,
        source_tex=RAW_TEX,
        raw_ocr_tex=RAW_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=BASELINE_PDF,
        baseline_compile_log="baseline pass 1; baseline pass 2",
        current_tex=CURRENT_TEX,
        current_pdf=CURRENT_PDF,
        current_compile_log="current pass 1; current pass 2",
        verification={
            "safe_to_export": True,
            "compile_before": {"available": True, "ok": True},
            "compile_after": {"available": True, "ok": True},
            "invariants": {
                "body_text": {"checked": True, "equal": True},
                "math": {"checked": True, "equal": True},
            },
            "final_formal_inventory": {"findings": []},
        },
        decision_items=(),
        report_md="# real pipeline report\n",
    )
    values.update(changes)
    return AnalysisRunArtifacts(**values)


def _freeze(tmp_path: Path, run_id: str, **changes):
    values = dict(
        project_dir=tmp_path / "中文项目",
        run_id=run_id,
        project_id="项目-甲",
        artifacts=_artifacts(),
        page_range=(1, 2),
        page_count=2,
        models=_models(),
        application_version="2.0.0",
        started_at="2026-08-23T12:00:00+08:00",
    )
    values.update(changes)
    snapshot = values.get("authoritative_snapshot")
    if snapshot is not None and "production_evidence" not in changes:
        values["production_evidence"] = _production_archive_evidence(
            snapshot,
            current_tex=values["artifacts"].current_tex,
        )
    return freeze_pipeline_analysis_run(**values)


def _verified_evidence() -> VerificationEvidence:
    source_hash = sha256_bytes(SOURCE_PDF)
    pages = tuple(stable_source_page_id(source_hash, page) for page in (1, 2))
    candidate_hash = sha256_text(CURRENT_TEX)
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
    reviews = (
        IndependentReviewPass(pass_number=1, context_id="fresh-review-a", **common),
        IndependentReviewPass(pass_number=2, context_id="fresh-review-b", **common),
    )
    return VerificationEvidence(
        raw_ocr_frozen=True,
        baseline_compile_passes=2,
        best_compile_passes=2,
        best_pdf_openable=True,
        expected_page_ids=pages,
        checked_page_ids=pages,
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
        final_reviews=reviews,
    )


def _analysis_configuration() -> dict:
    authorizations = build_host_inventory_authorizations(
        NATIVE_FORMAL_BLOCKS,
        ocr_manifest_sha256=sha256_text("ocr-manifest"),
    )
    baseline_inventory = build_analysis_inventory_bundle(
        BASELINE_TEX,
        BASELINE_TEX,
        {1: (1,), 2: (2,)},
        native_source_blocks=NATIVE_FORMAL_BLOCKS,
        authorizations=authorizations,
        require_native_heading_inventory=True,
    )
    return {
        "application_version": "2.0.0",
        "baseline_inventory_digest": baseline_inventory.digest,
        "baseline_inventory_json_sha256": sha256_bytes(
            canonical_json_bytes(baseline_inventory.as_dict())
        ),
        "candidate_page_map": [[1, [1]], [2, [2]]],
        "concurrency_limit": 3,
        "inventory_authorization_source": "HOST_REQUIRED_POLICY",
        "inventory_authorizations": [
            item.as_dict() for item in authorizations
        ],
        "inventory_policy_ocr_manifest_sha256": sha256_text("ocr-manifest"),
        "inventory_policy_schema": "latexstruct-host-inventory-policy-v1",
        "latex_engine": "xelatex",
        "models": [asdict(item) for item in _models()],
        "native_heading_inventory_required": True,
        "native_source_blocks": [
            item.as_dict() for item in NATIVE_FORMAL_BLOCKS
        ],
        "native_source_blocks_supplied": True,
        "prompt_version": "analysis-prompts-v2",
        "workflow_version": "analysis-loop-v2",
    }


def _risk_preflight() -> tuple[PageRiskPreflightInput, ...]:
    source_hash = sha256_bytes(SOURCE_PDF)
    return tuple(
        PageRiskPreflightInput(
            source_page_id=stable_source_page_id(source_hash, page),
            source_page_number=page,
            source_page_object_hash=sha256_text(f"source-object-{page}"),
            ocr_coverage_checks={
                "content": "PASS",
                "math": "PASS",
                "structure": "PASS",
            },
            unresolved_region_hashes=(),
            baseline_tex_region="Raw OCR.",
            candidate_pdf_page_ids=(f"candidate-page-{page}",),
            source_pdf_text="Raw OCR.",
            ocr_final_status="SUCCESS",
            ocr_retry_count=0,
            ocr_quality_issues=(),
            host_quality_flags=(),
            machine_visual_anomalies=(),
            double_column=False,
            complex_layout=False,
            compile_map_mismatch=False,
            layout_evidence={"algorithm": "test-layout-v1", "status": "CLEAR"},
            compile_map_evidence={"algorithm": "test-map-v1", "status": "MATCH"},
        )
        for page in (1, 2)
    )


def _risk_admission():
    return build_page_risk_admission(
        source_pdf_sha256=sha256_bytes(SOURCE_PDF),
        ocr_page_records_sha256=sha256_text("ocr-page-records"),
        ocr_runtime_page_records_sha256=sha256_text("ocr-runtime-page-records"),
        baseline_tex_sha256=sha256_text(BASELINE_TEX),
        baseline_pdf_sha256=sha256_bytes(BASELINE_PDF),
        page_inputs=_risk_preflight(),
    )


def _authoritative_snapshot(run_id: str) -> AnalysisRunSnapshot:
    source_hash = sha256_bytes(SOURCE_PDF)
    admission = _risk_admission()
    config_hash = sha256_bytes(canonical_json_bytes(_analysis_configuration()))
    page_map = tuple(
        PageMapEntry(
            source_page_id=stable_source_page_id(source_hash, page),
            source_page_number=page,
            tex_page_marker=f"% Page {page}",
            candidate_pdf_page_ids=(f"candidate-page-{page}",),
        )
        for page in (1, 2)
    )
    evidence_hashes = AnalysisEvidenceHashes(
        ocr_baseline_manifest_hash=sha256_text("ocr-manifest"),
        ocr_page_records_hash=admission.ocr_page_records_sha256,
        ocr_runtime_page_records_hash=(
            admission.ocr_runtime_page_records_sha256
        ),
        ocr_page_map_hash=sha256_text("ocr-page-map"),
        ocr_baseline_compile_inputs_hash=sha256_text("ocr-compile-inputs"),
        baseline_compile_inputs_hash=sha256_text("analysis-compile-inputs"),
        build_identity_hash=sha256_text("build-identity"),
        page_risk_admission_hash=admission.digest,
        response_schema_hash=sha256_text("response-schema"),
        analysis_config_hash=config_hash,
        budget_summary_hash=sha256_text("budget-summary"),
    )
    return AnalysisRunSnapshot(
        run_id=run_id,
        project_id="项目-甲",
        workflow_version="analysis-loop-v2",
        prompt_version="analysis-prompts-v2",
        application_version="2.0.0",
        source_pdf_hash=source_hash,
        raw_ocr_tex_hash=sha256_text(RAW_TEX),
        baseline_tex_hash=sha256_text(BASELINE_TEX),
        baseline_pdf_hash=sha256_bytes(BASELINE_PDF),
        page_count=2,
        page_range=(1, 2),
        latex_engine="xelatex",
        models=_models(),
        transport_contracts=_transport_contracts(),
        concurrency_limit=3,
        started_at="2026-08-23T12:00:00+08:00",
        page_map=page_map,
        initial_compile_state=CompileState.COMPILED,
        config_hash=config_hash,
        evidence_hashes=evidence_hashes,
    )


def _production_archive_evidence(
    snapshot: AnalysisRunSnapshot,
    *,
    current_tex: str = CURRENT_TEX,
) -> ProductionAnalysisArchiveEvidence:
    admission = _risk_admission()
    preflight = _risk_preflight()
    admitted_by_id = {
        item.summary.source_page_id: item for item in admission.pages
    }
    page_inputs = []
    for index, entry in enumerate(snapshot.page_map):
        admitted = admitted_by_id[entry.source_page_id]
        end_anchor = (
            snapshot.page_map[index + 1].tex_page_marker
            if index + 1 < len(snapshot.page_map)
            else "\\end{document}"
        )
        source_page = f"%PDF-test-page-{entry.source_page_number}".encode("utf-8")
        unit = PageUnit(
            source_page_id=entry.source_page_id,
            source_page_number=entry.source_page_number,
            source_page_hash=sha256_bytes(source_page),
            baseline_tex_start_anchor=entry.tex_page_marker,
            baseline_tex_end_anchor=end_anchor,
            current_tex_start_anchor=entry.tex_page_marker,
            current_tex_end_anchor=end_anchor,
            candidate_pdf_page_ids=entry.candidate_pdf_page_ids,
            source_text_layer="Raw OCR.",
            risk_level=admitted.risk_level,
            risk_reasons=admitted.risk_reasons,
        )
        page_inputs.append(PageAnalysisInput(unit, source_page, "Raw OCR."))
    final_hash = sha256_text(current_tex)
    sampled = set(admission.low_risk_sampling.selected_page_ids)
    route_pages = tuple(
        PageRouteRecord(
            source_page_id=item.summary.source_page_id,
            source_page_number=item.summary.source_page_number,
            admitted_risk=item.risk_level,
            triage_outcome=PageTriageOutcome.CLEAR,
            triage_response_sha256=sha256_bytes(canonical_json_bytes([])),
            effective_risk=item.risk_level,
            modified=False,
            anomaly_reasons=(),
            sampled_low_risk=item.summary.source_page_id in sampled,
            deep_review_required=(
                item.risk_level in {PageRisk.R2, PageRisk.R3}
                or item.summary.source_page_id in sampled
            ),
            final_candidate_hash=final_hash,
        )
        for item in admission.pages
    )
    closure = PageRiskRouteClosure(
        admission_sha256=admission.digest,
        final_candidate_hash=final_hash,
        pages=route_pages,
        route_call_keys=(),
    )
    configuration = _analysis_configuration()
    return ProductionAnalysisArchiveEvidence(
        snapshot=snapshot,
        page_risk_admission=admission,
        page_inputs=tuple(page_inputs),
        page_route_closure=closure,
        analysis_configuration=configuration,
        analysis_configuration_sha256=sha256_bytes(
            canonical_json_bytes(configuration)
        ),
        risk_preflight=preflight,
    )


def _production_call_evidence(snapshot: AnalysisRunSnapshot) -> tuple[dict, dict]:
    operation = "structure-findings"
    response_schema_version = ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation]
    material_hashes = {
        "source_pdf_page_hash": sha256_text("source-page"),
        "baseline_tex_region_hash": sha256_text("baseline-region"),
        "current_tex_region_hash": sha256_text("current-region"),
        "current_pdf_page_hash": sha256_text("candidate-page"),
    }
    binding = {
        "run_id": snapshot.run_id,
        "role": "AI-1",
        "candidate_hash": snapshot.baseline_tex_hash,
        "source_page_id": snapshot.page_map[0].source_page_id,
        "issue_id": "DISCOVERY",
        "material_hashes": material_hashes,
        "snapshot_hash": snapshot.snapshot_hash,
        "prompt_version": snapshot.prompt_version,
        "response_schema_version": response_schema_version,
    }
    invocation = {
        "ordinal": 1,
        "operation": operation,
        "binding": binding,
        "elapsed_seconds": 1.0,
        "succeeded": True,
    }
    transport = {
        "role": binding["role"],
        "operation": operation,
        "candidate_hash": binding["candidate_hash"],
        "source_page_id": binding["source_page_id"],
        "issue_id": binding["issue_id"],
        "material_hashes": sorted(material_hashes.items()),
        "snapshot_hash": binding["snapshot_hash"],
        "prompt_version": binding["prompt_version"],
        "response_schema_version": response_schema_version,
        "usage": [],
        "attempts": [],
        "attempt_evidence_complete": False,
    }
    return invocation, transport


def _complete_production_transport(transport: dict) -> dict:
    usage = [
        ["billing_mode", "chatgpt_subscription"],
        ["cached_input_tokens", 1],
        ["input_tokens", 10],
        ["output_tokens", 2],
        ["total_tokens", 12],
    ]
    return {
        **transport,
        "usage": usage,
        "attempts": [
            {
                "attempt_number": 1,
                "succeeded": True,
                "usage_complete": True,
                "failure_stage": "",
                "usage": usage,
            }
        ],
        "attempt_evidence_complete": True,
        "budget_claim": {
            "input_tokens": 100,
            "output_tokens": 20,
            "cost": 0.0,
            "requests": 1,
            "strong_model_calls": 0,
        },
        "budget_actual_usage": {
            "input_tokens": 10,
            "output_tokens": 2,
            "cost": None,
        },
    }


def _production_budget_evidence(*transports: dict) -> dict:
    totals: dict[str, int | float] = {
        "observed_input_tokens": 0,
        "observed_output_tokens": 0,
        "observed_cost": 0.0,
        "accounted_input_tokens": 0,
        "accounted_output_tokens": 0,
        "accounted_cost": 0.0,
        "requests": 0,
        "strong_model_calls": 0,
        "unknown_input_token_requests": 0,
        "unknown_output_token_requests": 0,
        "unknown_cost_requests": 0,
        "committed_reservations": 0,
    }
    for transport in transports:
        claim = BudgetClaim.from_dict(transport["budget_claim"])
        actual = ActualUsage.from_dict(transport["budget_actual_usage"])
        totals["requests"] += claim.requests
        totals["strong_model_calls"] += claim.strong_model_calls
        totals["committed_reservations"] += 1
        for dimension, observed, accounted, unknown in (
            (
                "input_tokens",
                "observed_input_tokens",
                "accounted_input_tokens",
                "unknown_input_token_requests",
            ),
            (
                "output_tokens",
                "observed_output_tokens",
                "accounted_output_tokens",
                "unknown_output_token_requests",
            ),
            ("cost", "observed_cost", "accounted_cost", "unknown_cost_requests"),
        ):
            actual_value = getattr(actual, dimension)
            if actual_value is None:
                totals[accounted] += getattr(claim, dimension)
                totals[unknown] += claim.requests
            else:
                totals[observed] += actual_value
                totals[accounted] += actual_value
    usage = BudgetUsage(
        **totals,
        cancelled_reservations=0,
        wall_time_minutes=1.0,
    )
    limits = BudgetLimits(
        max_input_tokens=1000,
        max_output_tokens=1000,
        max_cost=0.0,
        max_requests=10,
        max_strong_model_calls=10,
        max_wall_time_minutes=30.0,
    )
    state = AnalysisBudget.from_usage(
        limits,
        usage,
        clock=lambda: 0.0,
    ).to_dict()
    return {"budget_state": state, "budget_usage": usage.to_dict()}


def _production_performance(
    snapshot: AnalysisRunSnapshot,
    invocation: dict,
    transport: dict,
) -> dict:
    return {
        **analysis_adapter._recompute_transport_accounting(
            transports=[transport],
            invocations=[invocation],
            snapshot=snapshot.to_dict(),
        ),
        "available": True,
        "elapsed_seconds": 1.0,
        "total_pages": 2,
    }


def _production_cache_hit(snapshot: AnalysisRunSnapshot, invocation: dict) -> dict:
    binding = invocation["binding"]
    hashes = binding["material_hashes"]
    key = AnalysisCacheKey(
        snapshot_hash=binding["snapshot_hash"],
        source_page_id=binding["source_page_id"],
        source_page_hash=hashes["source_pdf_page_hash"],
        baseline_tex_region_hash=hashes["baseline_tex_region_hash"],
        current_tex_region_hash=hashes["current_tex_region_hash"],
        current_render_hash=hashes["current_pdf_page_hash"],
        prompt_version=binding["prompt_version"],
        response_schema_version=binding["response_schema_version"],
        model_id="structure-model",
        tool_version=snapshot.application_version,
        audit_role=f"AI-1:{invocation['operation']}",
    )
    response = {"binding": binding, "findings": []}
    return {
        "role": "AI-1",
        "operation": invocation["operation"],
        "candidate_hash": binding["candidate_hash"],
        "source_page_id": binding["source_page_id"],
        "issue_id": binding["issue_id"],
        "material_hashes": sorted(hashes.items()),
        "snapshot_hash": binding["snapshot_hash"],
        "prompt_version": binding["prompt_version"],
        "response_schema_version": binding["response_schema_version"],
        "model_id": "structure-model",
        "tool_version": snapshot.application_version,
        "cache_key_sha256": key.digest,
        "response_sha256": sha256_bytes(canonical_json_bytes(response)),
        "binding_echo_validated": True,
    }


def _unknown_production_performance() -> dict:
    return {
        "available": True,
        "total_pages": 2,
        "elapsed_seconds": 1.0,
        "usage_complete": False,
        "input_tokens": None,
        "output_tokens": None,
        "cached_tokens": None,
        "total_tokens": None,
        "observed_input_tokens": 0,
        "observed_output_tokens": 0,
        "observed_cached_tokens": 0,
        "observed_total_tokens": 0,
        "transport_call_count": 1,
        "usage_observed_call_count": 0,
        "usage_missing_call_count": 1,
        "transport_attempt_count": None,
        "observed_transport_attempt_count": 0,
        "usage_observed_attempt_count": 0,
        "usage_missing_attempt_count": None,
        "attempt_evidence_complete": False,
        "cache_hits": 0,
        "cache_misses": 0,
        "cache_status": "DISABLED",
        "estimated_cost_cny": None,
        "cost_status": "UNKNOWN",
        "pricing_sources": [],
        "billing_mode": None,
        "role_call_counts": [["AI-1", 1]],
    }


def _rewrite_run_sums(root: Path) -> None:
    manifest = root / "audit" / "SHA256SUMS"
    lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path == manifest:
            continue
        relative = path.relative_to(root).as_posix()
        lines.append(f"{sha256_bytes(path.read_bytes())}  {relative}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _rehash_page_inputs_archive(value: dict) -> None:
    for page in value["pages"]:
        core = {
            key: item for key, item in page.items() if key != "page_input_sha256"
        }
        page["page_input_sha256"] = sha256_bytes(canonical_json_bytes(core))
    value["page_inputs_sha256"] = sha256_bytes(
        canonical_json_bytes(value["pages"])
    )


def _rehash_route_closure(value: dict) -> None:
    value["pages_sha256"] = sha256_bytes(canonical_json_bytes(value["pages"]))
    admitted = {risk.value: 0 for risk in PageRisk}
    effective = {risk.value: 0 for risk in PageRisk}
    for page in value["pages"]:
        admitted[page["admitted_risk"]] += 1
        effective[page["effective_risk"]] += 1
    value["risk_counts"] = {"admitted": admitted, "effective": effective}
    value["route_call_keys_sha256"] = sha256_bytes(
        canonical_json_bytes(value["route_call_keys"])
    )
    core = {key: item for key, item in value.items() if key != "closure_sha256"}
    value["closure_sha256"] = sha256_bytes(canonical_json_bytes(core))


def test_archive_has_standard_tree_exact_artifacts_and_recomputable_sums(tmp_path):
    result = _freeze(tmp_path, "analysis-real-001")
    root = result.run_directory
    assert result.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert result.verified is False
    assert "two_independent_reviews_missing" in result.failures
    assert result.runtime_executed is True
    assert result.candidate_count == 2
    assert verify_frozen_analysis_run(root)

    required = {
        "inputs/source.pdf",
        "baseline/raw_ocr.tex",
        "baseline/baseline.tex",
        "baseline/baseline.pdf",
        "baseline/baseline_compile.log",
        "baseline/page_map.json",
        "candidates/round_000/candidate.tex",
        "candidates/round_001/candidate.tex",
        "candidates/best/candidate.tex",
        "audit/analysis_run_snapshot.json",
        "audit/page_units.json",
        "audit/issue_ledger.json",
        "audit/formal_inventory.json",
        "audit/content_conservation.json",
        "audit/math_token_report.json",
        "audit/visual_review.json",
        "audit/compile_history.json",
        "audit/rollback_history.json",
        "audit/quality_runtime.json",
        "audit/v2_verification_evidence.json",
        "audit/performance_metrics.json",
        "audit/final_report.md",
        "audit/final_decision.json",
        "audit/SHA256SUMS",
    }
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    assert required <= actual
    assert (root / "inputs" / "source.pdf").read_bytes() == SOURCE_PDF
    assert (root / "baseline" / "raw_ocr.tex").read_text(encoding="utf-8") == RAW_TEX
    assert (root / "candidates" / "best" / "candidate.tex").read_text(
        encoding="utf-8"
    ) == CURRENT_TEX

    snapshot = json.loads(
        (root / "audit" / "analysis_run_snapshot.json").read_text(encoding="utf-8")
    )
    assert snapshot["raw_ocr_tex_hash"] == sha256_text(RAW_TEX)
    assert snapshot["baseline_tex_hash"] == sha256_text(BASELINE_TEX)
    assert snapshot["performance_target_seconds"] == 7200.0
    performance = json.loads(
        (root / "audit" / "performance_metrics.json").read_text(encoding="utf-8")
    )
    assert performance["available"] is False
    assert performance["target_seconds"] == 7200.0
    assert performance["benchmark_eligible"] is False
    assert performance["target_status"] == "NOT_EVALUATED"
    assert performance["target_evaluated"] is False
    assert performance["target_met"] is None
    manifest = json.loads(
        (root / "audit" / "artifact_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["paths_are_relative"] is True
    for artifact in manifest["artifacts"]:
        path = PurePosixPath(artifact["path"])
        assert not path.is_absolute()
        assert ".." not in path.parts
        payload = root.joinpath(*path.parts).read_bytes()
        assert artifact["sha256"] == sha256_bytes(payload)


def test_archive_missing_page_risk_fails_closed_to_r3_with_real_reason(tmp_path):
    result = _freeze(tmp_path, "analysis-missing-risk")
    page_units = json.loads(
        (result.run_directory / "audit" / "page_units.json").read_text(
            encoding="utf-8"
        )
    )

    assert {item["risk_level"] for item in page_units} == {"R3"}
    assert all(
        item["risk_reasons"] == [
            "page risk classifier unavailable",
            "full page review required",
        ]
        for item in page_units
    )


def test_archive_preserves_the_exact_authoritative_production_snapshot(tmp_path):
    run_id = "analysis-authoritative-snapshot"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": _unknown_production_performance(),
    }

    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=_unknown_production_performance(),
    )

    archived = json.loads(
        (result.run_directory / "audit" / "analysis_run_snapshot.json").read_text(
            encoding="utf-8"
        )
    )
    assert archived["snapshot_hash"] == snapshot.snapshot_hash
    assert archived["config_hash"] == snapshot.config_hash
    assert archived["evidence_hashes"] == asdict(snapshot.evidence_hashes)
    production_audit_files = {
        "page_risk_admission.json",
        "page_inputs.json",
        "page_route_closure.json",
        "analysis_configuration.json",
        "risk_preflight.json",
    }
    assert production_audit_files <= {
        item.name for item in (result.run_directory / "audit").iterdir()
    }
    archived_configuration = json.loads(
        (result.run_directory / "audit" / "analysis_configuration.json").read_text(
            encoding="utf-8"
        )
    )
    assert archived_configuration["analysis_configuration"] == (
        json.loads(canonical_json_bytes(_analysis_configuration()))
    )
    assert archived_configuration["analysis_configuration_sha256"] == (
        snapshot.config_hash
    )
    archived_admission = json.loads(
        (result.run_directory / "audit" / "page_risk_admission.json").read_text(
            encoding="utf-8"
        )
    )
    assert archived_admission["admission_sha256"] == _risk_admission().digest
    verification_archive = json.loads(
        (result.run_directory / "audit" / "verification.json").read_text(
            encoding="utf-8"
        )
    )
    assert verification_archive["analysis_v2"]["snapshot"]["snapshot_hash"] == (
        snapshot.snapshot_hash
    )
    assert verification_archive["analysis_v2"]["transport_invocations"][0][
        "snapshot_hash"
    ] == snapshot.snapshot_hash
    assert verify_frozen_analysis_run(result.run_directory)

    stale_snapshot = replace(snapshot, run_id="analysis-stale-transport")
    stale_verification = dict(verification)
    stale_verification["analysis_v2"] = {
        **verification["analysis_v2"],
        "snapshot": stale_snapshot.to_dict(),
    }
    stale_verification["analysis_v2"]["transport_invocations"] = [
        {**transport, "snapshot_hash": sha256_text("stale-snapshot")}
    ]
    with pytest.raises(AnalysisArchiveError, match="snapshot, prompt, or response schema"):
        _freeze(
            tmp_path,
            "analysis-stale-transport",
            artifacts=replace(base, verification=stale_verification),
            authoritative_snapshot=stale_snapshot,
            performance_metrics=_unknown_production_performance(),
        )


def test_authoritative_snapshot_requires_typed_production_archive_evidence(tmp_path):
    run_id = "analysis-missing-production-archive-evidence"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": _unknown_production_performance(),
    }
    with pytest.raises(
        AnalysisArchiveError,
        match="requires typed production_evidence",
    ):
        _freeze(
            tmp_path,
            run_id,
            artifacts=replace(base, verification=verification),
            authoritative_snapshot=snapshot,
            production_evidence=None,
            performance_metrics=_unknown_production_performance(),
        )


@pytest.mark.parametrize(
    "artifact_name,mutation",
    (
        ("analysis_configuration.json", "configuration"),
        ("risk_preflight.json", "risk_preflight"),
        ("page_risk_admission.json", "admission"),
        ("page_inputs.json", "page_inputs"),
        ("page_route_closure.json", "route_sample"),
        ("page_route_closure.json", "route_final_candidate"),
    ),
)
def test_frozen_verifier_rederives_every_production_archive_binding_after_rehash(
    tmp_path,
    artifact_name,
    mutation,
):
    run_id = f"analysis-production-tamper-{mutation}"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": _unknown_production_performance(),
    }
    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=_unknown_production_performance(),
    )
    assert verify_frozen_analysis_run(result.run_directory)

    path = result.run_directory / "audit" / artifact_name
    payload = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "configuration":
        payload["analysis_configuration"]["concurrency_limit"] = 4
        payload["analysis_configuration_sha256"] = sha256_bytes(
            canonical_json_bytes(payload["analysis_configuration"])
        )
    elif mutation == "risk_preflight":
        payload["pages"][0]["source_pdf_text"] = "tampered source text"
        payload["risk_preflight_sha256"] = sha256_bytes(
            canonical_json_bytes(payload["pages"])
        )
    elif mutation == "admission":
        payload["pages"][0]["risk_level"] = "R1"
        payload["pages"][0]["risk_reasons"] = ["sparse_math_present"]
        admission_core = {
            key: item
            for key, item in payload.items()
            if key != "admission_sha256"
        }
        payload["admission_sha256"] = sha256_bytes(
            canonical_json_bytes(admission_core)
        )
    elif mutation == "page_inputs":
        page = payload["pages"][0]
        page["baseline_tex_region"] = "Tampered region."
        page["baseline_tex_region_sha256"] = sha256_text(
            page["baseline_tex_region"]
        )
        _rehash_page_inputs_archive(payload)
    elif mutation == "route_sample":
        page = payload["pages"][0]
        page["sampled_low_risk"] = False
        page["deep_review_required"] = False
        _rehash_route_closure(payload)
    elif mutation == "route_final_candidate":
        forged = sha256_text("forged final candidate")
        payload["final_candidate_hash"] = forged
        for page in payload["pages"]:
            page["final_candidate_hash"] = forged
        _rehash_route_closure(payload)
    else:  # pragma: no cover - parametrization invariant
        raise AssertionError(mutation)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_run_sums(result.run_directory)
    assert verify_frozen_analysis_run(result.run_directory) is False


def test_inventory_json_cannot_self_authorize_after_rehashing_all_local_digests(
    tmp_path,
):
    run_id = "analysis-inventory-self-authorization-tamper"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": _unknown_production_performance(),
    }
    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=_unknown_production_performance(),
    )
    assert verify_frozen_analysis_run(result.run_directory)

    audit = result.run_directory / "audit"
    baseline_path = audit / "analysis_inventory_baseline.json"
    final_path = audit / "analysis_inventory_final.json"
    gate_path = audit / "analysis_inventory_gate.json"
    decision_path = audit / "final_decision.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    final = json.loads(final_path.read_text(encoding="utf-8"))
    forged_authorization = {
        "authorization_id": "forged-host-wrapper:heading",
        "category": "heading",
        "action": "STRUCTURE_WRAPPER",
        "evidence_id": "forged-local-evidence",
    }
    for payload in (baseline, final):
        payload["authorizations"].append(forged_authorization)
        payload["authorizations"].sort(key=lambda item: item["authorization_id"])
        core = {key: value for key, value in payload.items() if key != "digest"}
        payload["digest"] = sha256_bytes(canonical_json_bytes(core))
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["bundle_digest"] = final["digest"]
    gate_core = {key: value for key, value in gate.items() if key != "digest"}
    gate["digest"] = sha256_bytes(canonical_json_bytes(gate_core))
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    decision.update({
        "baseline_inventory_digest": baseline["digest"],
        "final_inventory_digest": final["digest"],
        "inventory_gate_digest": gate["digest"],
        "baseline_inventory_json_sha256": sha256_bytes(
            canonical_json_bytes(baseline)
        ),
        "final_inventory_json_sha256": sha256_bytes(
            canonical_json_bytes(final)
        ),
        "inventory_gate_json_sha256": sha256_bytes(canonical_json_bytes(gate)),
    })
    baseline_path.write_bytes(canonical_json_bytes(baseline))
    final_path.write_bytes(canonical_json_bytes(final))
    gate_path.write_bytes(canonical_json_bytes(gate))
    decision_path.write_bytes(canonical_json_bytes(decision))
    _rewrite_run_sums(result.run_directory)

    # The snapshot-bound configuration remains authoritative; internally
    # consistent forged inventory JSON cannot grant itself new policy.
    assert verify_frozen_analysis_run(result.run_directory) is False


def test_production_archive_transport_closure_gates_verified_decision(tmp_path):
    run_id = "analysis-incomplete-attempt-closure"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    performance = _unknown_production_performance()
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": performance,
        "verification_evidence": asdict(_verified_evidence()),
    }

    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=performance,
    )

    assert result.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert result.verified is False
    assert set(result.failures) >= {
        "analysis_transport_evidence_incomplete",
        "analysis_transport_usage_incomplete",
        "analysis_transport_attempt_evidence_incomplete",
        "analysis_transport_call_closure_incomplete",
        "analysis_transport_attempt_usage_incomplete",
        "analysis_transport_count_closure_incomplete",
    }
    decision_path = result.run_directory / "audit" / "final_decision.json"
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision["status"] == AnalysisFinalStatus.COMPLETED_WITH_ISSUES.value
    assert decision["verified"] is False
    assert verify_frozen_analysis_run(result.run_directory)

    # Rehashing a locally promoted decision must not bypass semantic closure.
    decision.update({"status": "VERIFIED", "verified": True, "failures": []})
    decision_path.write_text(
        json.dumps(decision, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    performance_path = result.run_directory / "audit" / "performance_metrics.json"
    archived_performance = json.loads(performance_path.read_text(encoding="utf-8"))
    archived_performance["final_status"] = "VERIFIED"
    performance_path.write_text(
        json.dumps(archived_performance, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    _rewrite_run_sums(result.run_directory)
    assert verify_frozen_analysis_run(result.run_directory) is False


def test_complete_transport_without_budget_closure_cannot_verify(tmp_path):
    run_id = "analysis-complete-transport-missing-budget"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    transport = _complete_production_transport(transport)
    performance = _production_performance(snapshot, invocation, transport)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": performance,
        "verification_evidence": asdict(_verified_evidence()),
    }

    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=performance,
    )

    assert result.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert result.verified is False
    assert set(result.failures) >= {
        "analysis_transport_evidence_incomplete",
        "analysis_budget_evidence_incomplete",
        "analysis_budget_evidence_missing",
    }
    assert verify_frozen_analysis_run(result.run_directory)

def test_production_archive_accepts_verified_decision_with_complete_transport_closure(
    tmp_path,
):
    run_id = "analysis-complete-attempt-closure"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    transport = _complete_production_transport(transport)
    performance = _production_performance(snapshot, invocation, transport)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": performance,
        "verification_evidence": asdict(_verified_evidence()),
        **_production_budget_evidence(transport),
    }

    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=performance,
    )

    assert result.status == AnalysisFinalStatus.VERIFIED
    assert result.verified is True
    assert not any(item.startswith("analysis_transport_") for item in result.failures)
    assert verify_frozen_analysis_run(result.run_directory)

    verification_path = result.run_directory / "audit" / "verification.json"
    frozen = json.loads(verification_path.read_text(encoding="utf-8"))
    frozen["analysis_v2"]["transport_invocations"][0][
        "budget_actual_usage"
    ]["input_tokens"] = 11
    verification_path.write_text(
        json.dumps(frozen, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    _rewrite_run_sums(result.run_directory)
    assert verify_frozen_analysis_run(result.run_directory) is False


def test_production_transport_attempt_ledger_rejects_forged_closure_semantics():
    snapshot = _authoritative_snapshot("analysis-forged-attempt-ledger")
    invocation, empty_transport = _production_call_evidence(snapshot)
    complete = _complete_production_transport(empty_transport)
    terminal_usage_mismatch = {
        **complete,
        "usage": [
            ["billing_mode", "chatgpt_subscription"],
            ["cached_input_tokens", 1],
            ["input_tokens", 11],
            ["output_tokens", 2],
            ["total_tokens", 13],
        ],
    }
    first_success = dict(complete["attempts"][0])
    terminal_success = {**first_success, "attempt_number": 2}
    prior_success = {
        **complete,
        "attempts": [first_success, terminal_success],
    }
    stale_incomplete_flag = {**complete, "attempt_evidence_complete": False}
    malformed_failure_stage = {
        **empty_transport,
        "attempts": [
            {
                **first_success,
                "succeeded": False,
                "failure_stage": "",
            }
        ],
    }
    bool_attempt_number = {
        **complete,
        "attempts": [{**first_success, "attempt_number": True}],
    }
    incomplete_usage = [["input_tokens", 10]]
    forged_usage_complete = {
        **complete,
        "usage": incomplete_usage,
        "attempts": [
            {
                **first_success,
                "usage": incomplete_usage,
                "usage_complete": True,
            }
        ],
    }

    for forged, error in (
        (
            {**empty_transport, "attempt_evidence_complete": True},
            "closure is stale or forged",
        ),
        (terminal_usage_mismatch, "closure is stale or forged"),
        (prior_success, "closure is stale or forged"),
        (stale_incomplete_flag, "closure is stale or forged"),
        (malformed_failure_stage, "attempt is malformed"),
        (bool_attempt_number, "attempt is malformed"),
        (forged_usage_complete, "usage closure is forged"),
    ):
        with pytest.raises(AnalysisArchiveError, match=error):
            analysis_adapter._recompute_transport_accounting(
                transports=[forged],
                invocations=[invocation],
                snapshot=snapshot.to_dict(),
            )


def test_production_archive_rejects_empty_transport_forged_snapshot_and_wrong_schema(
    tmp_path,
):
    base = _artifacts()
    for suffix, mutate, error in (
        (
            "empty-transport",
            lambda snapshot, invocation, transport: {
                "snapshot": snapshot.to_dict(),
                "invocations": [invocation],
                "transport_invocations": [],
                "performance": _unknown_production_performance(),
            },
            "transport evidence is empty",
        ),
        (
            "forged-snapshot",
            lambda snapshot, invocation, transport: {
                "snapshot": {
                    **snapshot.to_dict(),
                    "application_version": "forged",
                },
                "invocations": [invocation],
                "transport_invocations": [transport],
                "performance": _unknown_production_performance(),
            },
            "differs field-by-field",
        ),
        (
            "wrong-schema",
            lambda snapshot, invocation, transport: {
                "snapshot": snapshot.to_dict(),
                "invocations": [invocation],
                "transport_invocations": [{
                    **transport,
                    "response_schema_version": "forged-schema-v9",
                }],
                "performance": _unknown_production_performance(),
            },
            "snapshot, prompt, or response schema",
        ),
    ):
        run_id = f"analysis-{suffix}"
        snapshot = _authoritative_snapshot(run_id)
        invocation, transport = _production_call_evidence(snapshot)
        verification = dict(base.verification)
        verification["analysis_v2"] = mutate(snapshot, invocation, transport)
        with pytest.raises(AnalysisArchiveError, match=error):
            _freeze(
                tmp_path,
                run_id,
                artifacts=replace(base, verification=verification),
                authoritative_snapshot=snapshot,
                performance_metrics=_unknown_production_performance(),
            )


def test_production_archive_requires_transport_invocation_counter_closure(tmp_path):
    run_id = "analysis-counter-closure"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation, {**invocation, "ordinal": 2}],
        "transport_invocations": [transport],
        "performance": _unknown_production_performance(),
    }

    with pytest.raises(AnalysisArchiveError, match="does not close"):
        _freeze(
            tmp_path,
            run_id,
            artifacts=replace(base, verification=verification),
            authoritative_snapshot=snapshot,
            performance_metrics=_unknown_production_performance(),
        )


def test_production_archive_accepts_separate_validated_cache_hit_closure():
    snapshot = _authoritative_snapshot("analysis-cache-hit-closure")
    invocation, _transport = _production_call_evidence(snapshot)
    hit = _production_cache_hit(snapshot, invocation)
    accounting = analysis_adapter._recompute_transport_accounting(
        transports=[],
        invocations=[invocation],
        snapshot=snapshot.to_dict(),
        cache_hits=[hit],
        cache_enabled=True,
    )
    analysis_v2 = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [],
        "cache_hit_evidence": [hit],
        "performance": accounting,
    }

    validated = analysis_adapter._validate_production_analysis_semantics(
        authoritative_snapshot=snapshot.to_dict(),
        analysis_v2=analysis_v2,
    )

    assert validated["orchestration_invocation_count"] == 1
    assert validated["transport_call_count"] == 0
    assert validated["cache_hit_evidence_count"] == 1
    assert validated["cache_hits"] == 1
    assert validated["cache_misses"] == 0
    assert validated["total_tokens"] == 0

    forged = {
        **analysis_v2,
        "cache_hit_evidence": [
            {**hit, "cache_key_sha256": sha256_text("forged-cache-key")}
        ],
    }
    with pytest.raises(AnalysisArchiveError, match="cache-hit digest"):
        analysis_adapter._validate_production_analysis_semantics(
            authoritative_snapshot=snapshot.to_dict(),
            analysis_v2=forged,
        )


def test_frozen_verifier_rechecks_production_semantics_after_valid_rehash(tmp_path):
    run_id = "analysis-semantic-recheck"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": _unknown_production_performance(),
    }
    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=_unknown_production_performance(),
    )
    verification_path = result.run_directory / "audit" / "verification.json"
    frozen = json.loads(verification_path.read_text(encoding="utf-8"))
    frozen["analysis_v2"]["transport_invocations"][0][
        "response_schema_version"
    ] = "forged-schema-v9"
    verification_path.write_text(
        json.dumps(frozen, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    _rewrite_run_sums(result.run_directory)

    assert verify_frozen_analysis_run(result.run_directory) is False


def test_frozen_verifier_recomputes_attempt_usage_and_rejects_rehashed_fake_totals(
    tmp_path,
):
    run_id = "analysis-performance-recheck"
    snapshot = _authoritative_snapshot(run_id)
    invocation, transport = _production_call_evidence(snapshot)
    performance = _unknown_production_performance()
    base = _artifacts()
    verification = dict(base.verification)
    verification["analysis_v2"] = {
        "snapshot": snapshot.to_dict(),
        "invocations": [invocation],
        "transport_invocations": [transport],
        "performance": performance,
    }
    result = _freeze(
        tmp_path,
        run_id,
        artifacts=replace(base, verification=verification),
        authoritative_snapshot=snapshot,
        performance_metrics=performance,
    )
    forged = {
        "usage_complete": True,
        "input_tokens": 10,
        "output_tokens": 2,
        "cached_tokens": 0,
        "total_tokens": 12,
        "estimated_cost_cny": 0.01,
        "cost_status": "ESTIMATED",
    }
    verification_path = result.run_directory / "audit" / "verification.json"
    frozen_verification = json.loads(verification_path.read_text(encoding="utf-8"))
    frozen_verification["analysis_v2"]["performance"].update(forged)
    verification_path.write_text(
        json.dumps(frozen_verification, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    performance_path = result.run_directory / "audit" / "performance_metrics.json"
    frozen_performance = json.loads(performance_path.read_text(encoding="utf-8"))
    frozen_performance.update(forged)
    performance_path.write_text(
        json.dumps(frozen_performance, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    _rewrite_run_sums(result.run_directory)

    assert verify_frozen_analysis_run(result.run_directory) is False


def test_legacy_success_cannot_promote_verified_and_run_id_is_write_once(tmp_path):
    first = _freeze(tmp_path, "analysis-write-once")
    sums_before = (first.run_directory / "audit" / "SHA256SUMS").read_bytes()
    decision = json.loads(
        (first.run_directory / "audit" / "final_decision.json").read_text(
            encoding="utf-8"
        )
    )
    assert decision["legacy_safe_to_export"] is True
    assert decision["verified"] is False
    with pytest.raises(FileExistsError, match="already exists"):
        _freeze(
            tmp_path,
            "analysis-write-once",
            artifacts=_artifacts(current_tex="malicious overwrite"),
        )
    assert (first.run_directory / "audit" / "SHA256SUMS").read_bytes() == sums_before
    assert verify_frozen_analysis_run(first.run_directory)


def test_complete_machine_evidence_without_production_authority_stays_unverified(
    tmp_path,
):
    unverified = _freeze(
        tmp_path,
        "analysis-verified",
        verification_evidence=_verified_evidence(),
    )
    assert unverified.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert unverified.verified is False
    assert "analysis_production_authority_missing" in unverified.failures
    page_units = json.loads(
        (unverified.run_directory / "audit" / "page_units.json").read_text(
            encoding="utf-8"
        )
    )
    assert {page["current_status"] for page in page_units} == {"CHECKED"}

    decision_path = unverified.run_directory / "audit" / "final_decision.json"
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    decision.update({"status": "VERIFIED", "verified": True, "failures": []})
    decision_path.write_text(
        json.dumps(decision, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    performance_path = unverified.run_directory / "audit" / "performance_metrics.json"
    performance = json.loads(performance_path.read_text(encoding="utf-8"))
    performance["final_status"] = "VERIFIED"
    performance_path.write_text(
        json.dumps(performance, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    _rewrite_run_sums(unverified.run_directory)
    assert verify_frozen_analysis_run(unverified.run_directory) is False

    stale = _verified_evidence()
    stale_artifacts = _artifacts(current_tex=CURRENT_TEX + "% later edit\n")
    rejected = _freeze(
        tmp_path,
        "analysis-stale-evidence",
        artifacts=stale_artifacts,
        verification_evidence=stale,
    )
    assert rejected.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "candidate_hash_not_current_artifact" in rejected.failures


def test_nested_verification_evidence_without_production_authority_stays_unverified(
    tmp_path,
):
    artifacts = _artifacts()
    verification = dict(artifacts.verification)
    verification["analysis_v2"] = {
        "verification_evidence": asdict(_verified_evidence()),
    }

    result = _freeze(
        tmp_path,
        "analysis-nested-v2-evidence",
        artifacts=replace(artifacts, verification=verification),
    )

    assert result.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert result.verified is False
    assert "analysis_production_authority_missing" in result.failures
    assert verify_frozen_analysis_run(result.run_directory)


def test_page_mismatch_and_failed_processing_remain_fail_closed(tmp_path):
    source_hash = sha256_bytes(SOURCE_PDF)
    wrong_page = stable_source_page_id(source_hash, 1)
    evidence = _verified_evidence()
    mismatched = replace(
        evidence,
        expected_page_ids=(wrong_page,),
        checked_page_ids=(wrong_page,),
    )
    result = _freeze(
        tmp_path,
        "analysis-page-mismatch",
        verification_evidence=mismatched,
        processing_failed=True,
    )
    assert result.status == AnalysisFinalStatus.FAILED_BEST_RETAINED
    assert result.verified is False
    assert "processing_failed" in result.failures
    assert "snapshot_page_ids_mismatch" in result.failures


def test_decisions_become_host_issues_only_with_page_and_tex_bindings(tmp_path):
    artifacts = _artifacts(
        decision_items=(
            {
                "candidate_id": "formal-1",
                "kind": "FORMAL_BOUNDARY",
                "source_page_number": 1,
                "line": 3,
                "status": "applied",
                "source": "AI-1",
                "severity": "HIGH",
                "reason": "wrapped theorem candidate",
            },
            {
                "candidate_id": "unbound-2",
                "kind": "FORMAL_BOUNDARY",
                "line": 99,
                "status": "ambiguous",
                "source": "AI-5",
                "reason": "no stable page evidence",
            },
        )
    )
    result = _freeze(tmp_path, "analysis-ledger", artifacts=artifacts)
    ledger = json.loads(
        (result.run_directory / "audit" / "issue_ledger.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(ledger["issues"]) == 1
    assert ledger["issues"][0]["current_status"] == "FIXED_PENDING_REVIEW"
    assert ledger["issues"][0]["issue_id"].startswith("ISS-")
    assert ledger["unbound_decision_items"][0]["candidate_id"] == "unbound-2"
    assert "decision_items_not_page_bound" in result.failures


def test_missing_artifacts_are_recorded_as_absent_not_verified(tmp_path):
    missing = AnalysisRunArtifacts(
        raw_ocr_tex=RAW_TEX,
        baseline_tex=BASELINE_TEX,
        current_tex=CURRENT_TEX,
        verification={"safe_to_export": True},
    )
    result = _freeze(tmp_path, "analysis-missing", artifacts=missing)
    assert result.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "source_pdf_missing" in result.failures
    assert "baseline_pdf_missing" in result.failures
    assert "current_pdf_missing" in result.failures
    assert not (result.run_directory / "inputs" / "source.pdf").exists()
    assert not (result.run_directory / "baseline" / "baseline.pdf").exists()
    assert verify_frozen_analysis_run(result.run_directory)


def test_tampering_is_detected_by_complete_run_manifest(tmp_path):
    result = _freeze(tmp_path, "analysis-tamper")
    report = result.run_directory / "audit" / "final_report.md"
    report.write_text("tampered", encoding="utf-8")
    assert verify_frozen_analysis_run(result.run_directory) is False


def test_atomic_commit_failure_leaves_no_visible_or_partial_run(tmp_path, monkeypatch):
    destination = tmp_path / "中文项目" / "analysis-runs" / "analysis-atomic-fail"

    def fail_rename(_source, _destination):
        raise OSError("simulated final rename failure")

    monkeypatch.setattr(analysis_adapter.os, "replace", fail_rename)
    with pytest.raises(OSError, match="rename failure"):
        _freeze(tmp_path, "analysis-atomic-fail")
    assert not destination.exists()
    runs_root = destination.parent
    assert not list(runs_root.glob(".analysis-atomic-fail-*"))

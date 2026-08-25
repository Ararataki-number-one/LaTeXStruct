# -*- coding: utf-8 -*-
"""Offline integration tests for the server-side v2 production handoff."""

from __future__ import annotations

import hashlib
import io
import json
from types import SimpleNamespace
import zipfile

import pymupdf
import pytest

from latexstruct.config import AppConfig
from latexstruct.core.analysis_adapter import stable_source_page_id
from latexstruct.core.analysis_orchestrator import PageAnalysisInput
from latexstruct.core.analysis_risk import (
    PageRiskPreflightInput,
    build_page_risk_admission,
    coerce_page_risk_admission,
)
from latexstruct.core.analysis_schema import (
    AnalysisFinalStatus,
    PageRisk,
    PageRiskRouteClosure,
    PageRouteRecord,
    PageTriageOutcome,
    PageUnit,
    canonical_json_bytes,
)
from latexstruct.core.compilecheck import build_compile_input_manifest
from latexstruct.core.ocr_recovery import (
    OcrRecoveryEvidenceStore,
    RecoveryImageInput,
    RecoveryImageRole,
    RecoveryPageStatus,
    RecoveryStage,
)
from latexstruct.core.ocr_runtime import (
    AdaptivePageConcurrency,
    OcrBatchAttemptEvidence,
    OcrErrorCategory,
    OcrExecutionResult,
    OcrPageRecord,
    OcrPageRequest,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunStore,
    ValidatedOcrPage,
    make_page_id,
    make_run_snapshot,
    progress_metrics,
)
from latexstruct.core.ocrstruct import encode_ocr_metadata
from latexstruct.core.visual_quality import (
    CANDIDATE_SCOPE_REFLOW,
    GEOMETRY_POLICY_TEMPLATE_REFLOW,
    evaluate_visual_quality,
)
from latexstruct.server import app as server


def _pdf(pages: list[str], *, x: float = 42) -> bytes:
    document = pymupdf.open()
    try:
        for text in pages:
            page = document.new_page(width=360, height=480)
            page.insert_text((x, 70), text)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _tex() -> str:
    metadata = encode_ocr_metadata([], "article", [1, 2], False)
    return (
        "\\documentclass{article}\n"
        f"{metadata}\n"
        "\\begin{document}\n"
        "% Page 1\n"
        "alpha theorem unique complete\n"
        "% Page 2\n"
        "beta proof unique first second complete\n"
        "\\end{document}\n"
    )


def _frozen_inputs():
    source = _pdf([
        "alpha theorem unique complete",
        "beta proof unique first second complete",
    ])
    candidate = _pdf([
        "contents alpha beta",
        "alpha theorem unique complete",
        "beta proof unique first",
        "beta proof unique second complete",
    ], x=74)
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        (1, 2),
        preview_status="COMPILED",
        source_geometry_authoritative=False,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
    ).to_dict()
    assert deterministic["page_alignment"]["mapping_reliable"] is True
    return source, candidate, deterministic


def _pipeline_result(candidate: bytes, deterministic: dict):
    tex = _tex()
    pdf_hash = hashlib.sha256(candidate).hexdigest()
    tex_hash = hashlib.sha256(tex.encode("utf-8")).hexdigest()
    compile_input_hash = build_compile_input_manifest(tex, {})["manifest_sha256"]
    return SimpleNamespace(
        ok=False,
        result="legacy-result",
        export_text="legacy-export",
        newline="\n",
        compiled_tex=tex,
        compiled_snapshot=tex,
        compiled_pdf=candidate,
        compiled_pdf_name="compiled.pdf",
        compiled_extra_files={},
        reviewed_tex="",
        report_md="# Legacy report\n",
        verification={
            "safe_to_export": False,
            "export_blocked": True,
            "checks": [
                {"id": "structure-decisions", "label": "structure", "ok": False},
                {"id": "full-document-review", "label": "review", "ok": False},
                {"id": "final-formal-inventory", "label": "formal", "ok": False},
                {"id": "ai-review", "label": "ai review", "ok": False},
                {
                    "id": "compile-render-visual-repair",
                    "label": "visual",
                    "ok": False,
                },
                {"id": "compile", "label": "compile", "ok": True},
            ],
            "preview_artifact": {
                "status": "COMPILED",
                "sha256": pdf_hash,
                "pdf_sha256": pdf_hash,
                "tex_sha256": tex_hash,
                "compile_input_sha256": compile_input_hash,
            },
            "compile_after": {
                "available": True,
                "ok": True,
                "preview_status": "COMPILED",
                "pdf_sha256": pdf_hash,
                "compile_input_sha256": compile_input_hash,
            },
            "visual_quality_loop": {
                "rounds": [{
                    "compile": {"ok": True, "preview_status": "COMPILED"},
                    "deterministic": deterministic,
                }],
                "checked": True,
                "ok": False,
                "unresolved": [{"reason": "legacy gate failed"}],
            },
        },
    )


def _server_analysis_budget(**overrides):
    limits = {
        "max_input_tokens": 0,
        "max_output_tokens": 0,
        "max_cost": 0.0,
        "max_requests": 0,
        "max_strong_model_calls": 0,
        "max_wall_time_minutes": 120.0,
    }
    limits.update(overrides)
    return limits


def test_server_analysis_budget_defaults_are_explicit_and_complete():
    assert server._analysis_v2_budget_limits({}) == _server_analysis_budget()


@pytest.mark.parametrize(
    "configured",
    [
        None,
        [],
        {"max_requests": 10},
        _server_analysis_budget(unrecognized_limit=1),
        _server_analysis_budget(max_requests=True),
        _server_analysis_budget(max_requests=1.5),
        _server_analysis_budget(max_input_tokens=-1),
        _server_analysis_budget(max_cost=float("nan")),
        _server_analysis_budget(max_wall_time_minutes=0),
    ],
)
def test_server_analysis_budget_rejects_invalid_shapes_types_and_values(
    configured,
):
    with pytest.raises(ValueError, match="analysis_budget"):
        server._analysis_v2_budget_limits({"analysis_budget": configured})


def test_host_frozen_reflow_map_excludes_toc_and_preserves_split_page():
    source, candidate, deterministic = _frozen_inputs()
    result = _pipeline_result(candidate, deterministic)

    mapping, evidence = server._analysis_v2_candidate_page_map(
        result.verification,
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=(1, 2),
    )

    assert mapping == {1: (2,), 2: (3, 4)}
    assert evidence["candidate_only_pages"] == [1]
    assert evidence["mapping_sha256"]


def test_live_candidate_map_excludes_candidate_only_toc(monkeypatch):
    source, candidate, _deterministic = _frozen_inputs()
    monkeypatch.setattr(
        "latexstruct.core.visual_quality.evaluate_visual_quality",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("candidate mapper must not run full visual evaluation")
        ),
    )

    mapping, evidence = server._analysis_v2_live_candidate_page_map(
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=(1, 2),
    )

    assert mapping == {1: (2,), 2: (3, 4)}
    assert evidence["candidate_only_pages"] == [1]


def test_machine_verifier_rejects_map_not_bound_to_current_candidate():
    source, candidate, _deterministic = _frozen_inputs()
    candidate_hash = hashlib.sha256(_tex().encode("utf-8")).hexdigest()
    source_hash = hashlib.sha256(source).hexdigest()
    page_ids = tuple(
        stable_source_page_id(source_hash, page) for page in (1, 2)
    )
    capture = {}
    verifier = server._analysis_v2_machine_verifier(
        raw_ocr_tex=_tex(),
        source_pdf_bytes=source,
        page_range=(1, 2),
        candidate_page_maps={
            candidate_hash: {"map": {1: (1,), 2: (2,)}}
        },
        pack=None,
        capture=capture,
    )

    facts = verifier(SimpleNamespace(
        candidate_hash=candidate_hash,
        tex=_tex(),
        pdf=candidate,
        compile_result=SimpleNamespace(
            page_pdf_bytes=tuple((page_id, b"png") for page_id in page_ids)
        ),
        final_reviews=(),
    ))

    assert facts.silent_page_omissions >= 1
    assert facts.checked_page_ids == ()
    assert capture["mapping_matches_current_candidate"] is False


def test_unreliable_or_missing_alignment_fails_before_any_model_call():
    source, candidate, deterministic = _frozen_inputs()
    deterministic = dict(deterministic)
    deterministic["page_alignment"] = dict(deterministic["page_alignment"])
    deterministic["page_alignment"]["mapping_reliable"] = False
    result = _pipeline_result(candidate, deterministic)

    with pytest.raises(ValueError, match="evidence hash|digest|不可靠"):
        server._analysis_v2_candidate_page_map(
            result.verification,
            source_pdf_bytes=source,
            candidate_pdf_bytes=candidate,
            page_range=(1, 2),
        )


def test_server_stage_calls_production_runner_and_atomically_publishes_verified_result(
    tmp_path, monkeypatch
):
    source, candidate, deterministic = _frozen_inputs()
    result = _pipeline_result(candidate, deterministic)
    calls = {"runner": 0, "compiler": []}
    budget_limits = {
        "max_input_tokens": 120_000,
        "max_output_tokens": 24_000,
        "max_cost": 12.5,
        "max_requests": 80,
        "max_strong_model_calls": 6,
        "max_wall_time_minutes": 45.0,
    }
    budget_usage = {
        "observed_input_tokens": 100,
        "observed_output_tokens": 20,
        "observed_cost": 0.1,
        "accounted_input_tokens": 100,
        "accounted_output_tokens": 20,
        "accounted_cost": 0.1,
        "requests": 1,
        "strong_model_calls": 0,
        "unknown_input_token_requests": 0,
        "unknown_output_token_requests": 0,
        "unknown_cost_requests": 0,
        "committed_reservations": 1,
        "cancelled_reservations": 0,
        "wall_time_minutes": 0.25,
    }
    active_root = tmp_path / "analysis-v2" / "server-production-run"
    (active_root / "inputs").mkdir(parents=True)

    def fake_compile(tex, *, extra_files, include_pdf, minimum_passes):
        calls["compiler"].append(
            (tex, dict(extra_files), include_pdf, minimum_passes)
        )
        compile_inputs = build_compile_input_manifest(tex, extra_files)
        return {
            "available": True,
            "ok": True,
            "preview_status": "COMPILED",
            "pdf_bytes": candidate,
            "page_count": 4,
            "pages": 4,
            "engine": "fake-xelatex",
            "errors": [],
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "compile_workdir": "compile-workdir:sha256:" + "a" * 64,
            "compile_input_sha256": compile_inputs["manifest_sha256"],
        }

    monkeypatch.setattr("latexstruct.core.compilecheck.compile_latex", fake_compile)
    admitted = {
        "ocr_baseline_manifest_hash": "1" * 64,
        "ocr_page_records_hash": "2" * 64,
        "ocr_runtime_page_records_hash": "6" * 64,
        "ocr_page_map_hash": "5" * 64,
        "ocr_baseline_compile_inputs_hash": "3" * 64,
        "baseline_compile_inputs_hash": build_compile_input_manifest(_tex(), {})[
            "manifest_sha256"
        ],
        "build_identity_hash": "4" * 64,
    }

    def fake_snapshot_evidence(**kwargs):
        source_hash = hashlib.sha256(source).hexdigest()
        coverage_checks = {
            name: "PASS"
            for name in (
                "source_hash_bound",
                "candidate_created",
                "visual_authority_checked",
                "reading_order_checked",
                "text_coverage_checked",
                "math_region_coverage_checked",
                "syntax_checked",
                "persisted",
            )
        }
        regions = {
            1: "% Page 1\nalpha theorem unique complete\n",
            2: "% Page 2\nbeta proof unique first second complete\n",
        }
        typed_preflight = tuple(
            PageRiskPreflightInput(
                source_page_id=stable_source_page_id(source_hash, page),
                source_page_number=page,
                source_page_object_hash=f"{index + 5:x}" * 64,
                ocr_coverage_checks=dict(coverage_checks),
                unresolved_region_hashes=(),
                baseline_tex_region=regions[page],
                candidate_pdf_page_ids=tuple(
                    f"candidate-page-{candidate_page:06d}"
                    for candidate_page in kwargs["candidate_page_map"][page]
                ),
                source_pdf_text=(
                    "alpha theorem unique complete"
                    if page == 1
                    else "beta proof unique first second complete"
                ),
                ocr_final_status="SUCCESS",
                ocr_retry_count=0,
                ocr_quality_issues=(),
                host_quality_flags=(),
                machine_visual_anomalies=(),
                double_column=False,
                complex_layout=False,
                compile_map_mismatch=False,
                layout_evidence={"schema": "test-layout-v1", "page": page},
                compile_map_evidence={"schema": "test-map-v1", "page": page},
            )
            for index, page in enumerate((1, 2), 1)
        )
        admission = build_page_risk_admission(
            source_pdf_sha256=source_hash,
            ocr_page_records_sha256=admitted["ocr_page_records_hash"],
            ocr_runtime_page_records_sha256=admitted[
                "ocr_runtime_page_records_hash"
            ],
            baseline_tex_sha256=hashlib.sha256(_tex().encode("utf-8")).hexdigest(),
            baseline_pdf_sha256=hashlib.sha256(candidate).hexdigest(),
            page_inputs=typed_preflight,
        )
        payload = admission.to_dict()
        digest = admission.digest
        admitted["page_risk_admission_hash"] = digest
        kwargs["page_risk_admission_capture"].update({
            "payload": payload,
            "sha256": digest,
            "strategy": admission.strategy,
            "page_count": 2,
            "preflight_inputs": [
                {
                    "source_page_id": item.summary.source_page_id,
                    "source_page_number": item.summary.source_page_number,
                    "source_page_object_hash": item.summary.source_page_object_hash,
                }
                for item in admission.pages
            ],
            "typed_preflight_inputs": typed_preflight,
        })
        return dict(admitted)

    monkeypatch.setattr(
        server,
        "_analysis_v2_snapshot_evidence",
        fake_snapshot_evidence,
    )

    def fake_runner(**kwargs):
        calls["runner"] += 1
        assert kwargs["candidate_page_map"] == {1: (2,), 2: (3, 4)}
        assert kwargs["snapshot_evidence"] == admitted
        admission = coerce_page_risk_admission(kwargs["page_risk_admission"])
        assert admission.digest == admitted["page_risk_admission_hash"]
        assert not any(
            item.summary.required_evidence_missing for item in admission.pages
        )
        assert set(kwargs["text_clients"]) == {"AI-1", "AI-2", "AI-4", "AI-6"}
        assert set(kwargs["vision_clients"]) == {"AI-3", "AI-5"}
        assert {
            key: kwargs[key] for key in budget_limits
        } == budget_limits
        assert kwargs["resume"] is True
        assert kwargs["candidate_root"] == active_root / "candidates"
        # One callback invocation owns both passes in the same private workdir.
        compiled = kwargs["compiler"](kwargs["baseline_tex"], extra_files={})
        assert compiled["ok"] is True
        source_hash = hashlib.sha256(source).hexdigest()
        page_ids = tuple(
            stable_source_page_id(source_hash, page) for page in (1, 2)
        )
        compile_result = SimpleNamespace(
            page_pdf_bytes=tuple((page_id, b"png") for page_id in page_ids)
        )
        facts = kwargs["machine_verifier"](SimpleNamespace(
            candidate_hash=hashlib.sha256(_tex().encode("utf-8")).hexdigest(),
            tex=_tex(),
            pdf=candidate,
            compile_result=compile_result,
            final_reviews=(),
        ))
        assert facts.silent_page_omissions == 0
        orchestration = SimpleNamespace(
            decision=SimpleNamespace(
                verified=True,
                status=AnalysisFinalStatus.VERIFIED,
                failures=(),
            ),
            evidence={"machine": "facts"},
            best_candidate={"candidate_id": "cand-r0000-test"},
            current_tex=_tex(),
            current_pdf=candidate,
            final_reviews=(
                {"pass_number": 1, "ok": True},
                {"pass_number": 2, "ok": True},
            ),
            ledger=(),
            invocations=({"operation": "AI-1", "succeeded": True},),
            performance={"final_status": "VERIFIED"},
            rollback_candidate_ids=(),
        )
        tex_hash = hashlib.sha256(_tex().encode("utf-8")).hexdigest()
        pdf_hash = hashlib.sha256(candidate).hexdigest()
        compile_input_hash = build_compile_input_manifest(_tex(), {})[
            "manifest_sha256"
        ]
        analysis_configuration = {
            "schema": "latexstruct-test-analysis-configuration-v2",
            "model": "gpt-5.4",
            "reasoning_effort": "high",
        }
        analysis_configuration_sha256 = hashlib.sha256(
            canonical_json_bytes(analysis_configuration)
        ).hexdigest()
        regions = {
            1: "% Page 1\nalpha theorem unique complete\n",
            2: "% Page 2\nbeta proof unique first second complete\n",
        }
        page_inputs = []
        for admitted_page in admission.pages:
            page_number = admitted_page.summary.source_page_number
            page_bytes = f"source-page-{page_number}".encode("utf-8")
            marker = f"% Page {page_number}"
            end_anchor = "% Page 2" if page_number == 1 else "\\end{document}"
            page_inputs.append(PageAnalysisInput(
                PageUnit(
                    source_page_id=admitted_page.summary.source_page_id,
                    source_page_number=page_number,
                    source_page_hash=hashlib.sha256(page_bytes).hexdigest(),
                    baseline_tex_start_anchor=marker,
                    baseline_tex_end_anchor=end_anchor,
                    current_tex_start_anchor=marker,
                    current_tex_end_anchor=end_anchor,
                    candidate_pdf_page_ids=tuple(
                        f"candidate-page-{page:06d}"
                        for page in kwargs["candidate_page_map"][page_number]
                    ),
                    source_text_layer=(
                        "alpha theorem unique complete"
                        if page_number == 1
                        else "beta proof unique first second complete"
                    ),
                    risk_level=admitted_page.risk_level,
                    risk_reasons=admitted_page.risk_reasons,
                ),
                page_bytes,
                regions[page_number],
            ))
        sampled_ids = set(admission.low_risk_sampling.selected_page_ids)
        route_closure = PageRiskRouteClosure(
            admission_sha256=admission.digest,
            final_candidate_hash=tex_hash,
            pages=tuple(
                PageRouteRecord(
                    source_page_id=item.summary.source_page_id,
                    source_page_number=item.summary.source_page_number,
                    admitted_risk=item.risk_level,
                    triage_outcome=PageTriageOutcome.CLEAR,
                    triage_response_sha256=hashlib.sha256(b"[]").hexdigest(),
                    effective_risk=item.risk_level,
                    modified=False,
                    anomaly_reasons=(),
                    sampled_low_risk=(
                        item.summary.source_page_id in sampled_ids
                    ),
                    deep_review_required=(
                        item.risk_level in {PageRisk.R2, PageRisk.R3}
                        or item.summary.source_page_id in sampled_ids
                    ),
                    final_candidate_hash=tex_hash,
                )
                for item in admission.pages
            ),
            route_call_keys=(),
        )
        orchestration.page_route_closure = route_closure
        snapshot_evidence_hashes = SimpleNamespace(
            page_risk_admission_hash=admission.digest,
            analysis_config_hash=analysis_configuration_sha256,
        )
        return SimpleNamespace(
            snapshot=SimpleNamespace(
                config_hash=analysis_configuration_sha256,
                evidence_hashes=snapshot_evidence_hashes,
                to_dict=lambda: {
                    "run_id": kwargs["run_id"],
                    "config_hash": analysis_configuration_sha256,
                },
            ),
            page_risk_admission=admission,
            analysis_configuration=analysis_configuration,
            analysis_configuration_sha256=analysis_configuration_sha256,
            page_inputs=tuple(page_inputs),
            orchestration=orchestration,
            compile_invocations=(SimpleNamespace(
                candidate_hash=tex_hash,
                reason="final atomic compile",
                run_number=1,
                ok=True,
                pdf_hash=pdf_hash,
                page_count=4,
                engine="fake-xelatex",
                passes_requested=2,
                passes_attempted=2,
                passes_completed=2,
                compile_workdir="compile-workdir:sha256:" + "a" * 64,
                compile_input_sha256=compile_input_hash,
                same_workdir_verified=True,
            ),),
            transport_invocations=({"role": "AI-1"},),
            cache_hit_evidence=(),
            budget_state={
                "schema_version": "analysis-budget-v1",
                "limits": dict(budget_limits),
                "usage": dict(budget_usage),
                "low_priority_threshold": 0.9,
                "stop_reason": None,
                "stop_details": [],
                "unbounded_unknown_dimensions": [],
                "reservations": [],
            },
            budget_usage=dict(budget_usage),
            current_compile_log="v2 compile pass 1\nv2 compile pass 2",
            resumed=True,
            recovery_checkpoint_id="checkpoint-000004-deadbeefcafe",
            recovery_rejections=(
                {"path": "checkpoints/checkpoint-000005", "reason": "tampered"},
            ),
        )

    server._run_analysis_v2_production_stage(
        result,
        pid="project-ocr",
        project={
            "kind": "ocr",
            "mode": "ai",
            "analysis_budget": budget_limits,
        },
        project_dir=tmp_path,
        cfg=AppConfig(
            analysis_backend="api",
            review_enabled=True,
            decide_base_url="https://decide.invalid/v1",
            decide_model="decision-model",
            review_base_url="https://review.invalid/v1",
            review_model="review-model",
            ocr_base_url="https://vision.invalid/v1",
            ocr_model="vision-model",
        ),
        raw_ocr_tex=_tex(),
        source_pdf_bytes=source,
        source_pdf_page_range=(1, 2),
        compile_extra_files={},
        pack=None,
        run_id="server-production-run",
        analysis_runner=fake_runner,
    )

    assert calls["runner"] == 1
    assert [item[2] for item in calls["compiler"]] == [True]
    assert [item[3] for item in calls["compiler"]] == [2]
    assert result.ok is True
    assert result.result == _tex()
    assert result.compiled_pdf == candidate
    assert result.verification["analysis_v2"]["status"] == "VERIFIED"
    assert result.verification["compile_after"]["log"] == (
        "v2 compile pass 1\nv2 compile pass 2"
    )
    assert result.verification["analysis_v2"]["snapshot"]["run_id"] == (
        "server-production-run"
    )
    assert result.verification["analysis_v2"]["compile_invocations"]
    assert result.verification["analysis_v2"]["transport_invocations"]
    archived_risk = result.verification["analysis_v2"]["page_risk_admission"]
    assert archived_risk["admission_sha256"] == admitted[
        "page_risk_admission_hash"
    ]
    assert len(archived_risk["pages"]) == 2
    assert result.verification["analysis_v2"]["page_route_closure"][
        "admission_sha256"
    ] == archived_risk["admission_sha256"]
    assert result.verification["analysis_v2"]["analysis_configuration"][
        "model"
    ] == "gpt-5.4"
    assert result.verification["analysis_v2"]["budget_state"]["limits"] == (
        budget_limits
    )
    assert result.verification["analysis_v2"]["budget_usage"] == budget_usage
    assert result.verification["analysis_v2"]["recovery"] == {
        "resumed": True,
        "checkpoint_id": "checkpoint-000004-deadbeefcafe",
        "rejections": [
            {"path": "checkpoints/checkpoint-000005", "reason": "tampered"}
        ],
    }
    assert all(
        check["ok"] is True
        for check in result.verification["checks"]
        if check["id"] in {
            "analysis-v2-production",
            "structure-decisions",
            "final-formal-inventory",
            "compile-render-visual-repair",
        }
    )


def test_runner_failure_keeps_legacy_candidate_and_marks_v2_unverified(
    tmp_path, monkeypatch
):
    source, candidate, deterministic = _frozen_inputs()
    result = _pipeline_result(candidate, deterministic)
    original = (
        result.result,
        result.export_text,
        result.compiled_tex,
        result.compiled_pdf,
    )

    def fail_runner(**_kwargs):
        raise RuntimeError(r"failed at C:\Users\Private\candidate.tex")

    monkeypatch.setattr(
        server,
        "_analysis_v2_snapshot_evidence",
        lambda **_kwargs: {
            "ocr_baseline_manifest_hash": "1" * 64,
            "ocr_page_records_hash": "2" * 64,
            "ocr_page_map_hash": "5" * 64,
            "ocr_baseline_compile_inputs_hash": "3" * 64,
            "baseline_compile_inputs_hash": build_compile_input_manifest(_tex(), {})[
                "manifest_sha256"
            ],
            "build_identity_hash": "4" * 64,
        },
    )

    server._run_analysis_v2_production_stage(
        result,
        pid="project-ocr",
        project={"kind": "ocr", "mode": "ai"},
        project_dir=tmp_path,
        cfg=AppConfig(analysis_backend="codex_cli", review_enabled=True),
        raw_ocr_tex=_tex(),
        source_pdf_bytes=source,
        source_pdf_page_range=(1, 2),
        compile_extra_files={},
        pack=None,
        run_id="failed-production-run",
        analysis_runner=fail_runner,
    )

    assert (
        result.result,
        result.export_text,
        result.compiled_tex,
        result.compiled_pdf,
    ) == original
    assert result.ok is False
    assert result.verification["analysis_v2"]["status"] == "FAILED"
    assert "C:\\Users\\Private" not in result.verification["analysis_v2"]["reason"]
    assert result.verification["safe_to_export"] is False


def test_non_ocr_or_non_ai_workflow_is_explicitly_skipped(tmp_path):
    result = SimpleNamespace(verification={}, ok=True)

    server._run_analysis_v2_production_stage(
        result,
        pid="plain",
        project={"kind": "single", "mode": "ai"},
        project_dir=tmp_path,
        cfg=AppConfig(),
        raw_ocr_tex="",
        source_pdf_bytes=b"",
        source_pdf_page_range=None,
        compile_extra_files=None,
        pack=None,
        run_id="skip",
        analysis_runner=lambda **_kwargs: pytest.fail("runner must not be called"),
    )

    assert result.ok is True
    assert result.verification["analysis_v2"]["status"] == "SKIPPED"
    assert result.verification["analysis_v2"]["required"] is False


def _ocr_request(*, dpi=200):
    return OcrPageRequest(
        page_id=make_page_id(1),
        source_page=1,
        task_index=1,
        image_bytes=b"page-pixels",
        dpi=dpi,
        image_size_pixels=(100, 120),
    )


def _ocr_execution(tex: str | None, *, needs_retry=False, dpi=200):
    page = None
    if tex is not None:
        page = ValidatedOcrPage(
            page_id=make_page_id(1),
            latex=tex,
            figures=(),
            unresolved_regions=(),
            issues=(),
            needs_retry=needs_retry,
            needs_review=False,
            raw_object={"page_id": make_page_id(1), "latex": tex},
        )
    return OcrExecutionResult(request=_ocr_request(dpi=dpi), page=page)


def test_host_validation_failure_advances_the_recovery_ladder(tmp_path):
    execution = OcrExecutionResult(
        request=_ocr_request(),
        page=None,
        error="invalid host-checked payload",
        error_category=OcrErrorCategory.UNKNOWN,
        retry_instruction="repair the invalid JSON",
        retry_state={"validation_code": "NON_JSON"},
    )
    outcome = server._ocr_v2_attempt_outcome(execution)
    store = OcrRecoveryEvidenceStore(tmp_path / "recovery")
    run_id = "a" * 32
    stages = (
        (RecoveryStage.INITIAL_READ, 200, True),
        (RecoveryStage.SAME_DPI_RETRY, 200, False),
        (RecoveryStage.BATCH_TO_SINGLE, 200, False),
        (RecoveryStage.DPI_300_RETRY, 300, False),
        (RecoveryStage.INDEPENDENT_SECOND_READ, 300, False),
    )
    observed = []
    for index, (stage, dpi, batched) in enumerate(stages, 1):
        store.record_attempt(
            run_id=run_id,
            page_id=make_page_id(1),
            source_page=1,
            task_index=1,
            stage=stage,
            outcome=outcome,
            base_dpi=200,
            dpi=dpi,
            model="offline-vision",
            backend="api",
            model_context_id=f"context-{index}",
            images=(RecoveryImageInput(
                role=RecoveryImageRole.FULL_PAGE,
                content=b"page-pixels",
                dpi=dpi,
                width_pixels=100,
                height_pixels=120,
            ),),
            raw_response=None,
            duration_ms=1,
            error={"message": "host validation failed"},
            is_batched=batched,
            batch_id="batch-1" if batched else "",
            batch_size=2 if batched else 1,
            crops_available=False,
            independent_second_read=True,
        )
        _, state = store.recover_page(
            run_id,
            make_page_id(1),
            crops_available=False,
        )
        observed.append(state.current_stage)
    assert observed == [item[0] for item in stages]
    assert state.status is RecoveryPageStatus.NEEDS_REVIEW


def test_recovery_attempt_export_redacts_credentials_and_absolute_paths(tmp_path):
    run_id = "e" * 32
    recovery_root = tmp_path / "private-recovery-root"
    store = OcrRecoveryEvidenceStore(recovery_root)
    secret = "super-secret-token-123456"
    private_path = r"C:\Users\ZQY\private\ocr.log"
    unsafe = f"Authorization: Bearer {secret} failed at {private_path}"
    safe_error = server._safe_task_error(RuntimeError(unsafe))
    store.record_attempt(
        run_id=run_id,
        page_id=make_page_id(1),
        source_page=1,
        task_index=1,
        stage=RecoveryStage.INITIAL_READ,
        outcome="RETRYABLE_FAILURE",
        base_dpi=200,
        dpi=200,
        model="offline-vision",
        backend="api",
        model_context_id="privacy-context",
        images=(RecoveryImageInput(
            role=RecoveryImageRole.FULL_PAGE,
            content=b"page-pixels",
            dpi=200,
            width_pixels=100,
            height_pixels=120,
        ),),
        raw_response=json.dumps({"error": safe_error}, ensure_ascii=False),
        duration_ms=1,
        error={"message": safe_error},
        crops_available=False,
        independent_second_read=True,
    )
    source = tmp_path / "source.pdf"
    source.write_bytes(b"%PDF-1.7\nsource\n")
    source_bytes = source.read_bytes()
    bundle, manifest = server._ocr_bundle_bytes({
        "target": str(source),
        "_source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "_recovery_evidence_root": str(recovery_root),
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "pages": {},
        "status": "partial",
    }, "Recovered page.")

    attempt_row = next(
        item for item in manifest["recovery_evidence"]
        if item["kind"] == "attempt"
    )
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        payload = archive.read(attempt_row["path"]).decode("utf-8")
    assert secret not in payload
    assert private_path not in payload
    assert "<REDACTED>" in payload
    assert "<LOCAL_PATH>" in payload


def test_independent_read_conflict_retains_a_and_missing_a_is_not_fake_compared():
    first = _ocr_execution("candidate A", needs_retry=True, dpi=300)
    second = _ocr_execution("candidate B", dpi=300)
    evidence, selected, comparison_hash, conflict = (
        server._ocr_v2_prepare_independent_result(first, second)
    )
    assert evidence.page.latex == "candidate B"
    assert selected.page.latex == "candidate A"
    assert comparison_hash == hashlib.sha256(b"candidate A").hexdigest()
    assert conflict is True
    assert {item.code for item in selected.page.issues} == {
        "INDEPENDENT_READ_CONFLICT"
    }

    evidence, selected, comparison_hash, conflict = (
        server._ocr_v2_prepare_independent_result(None, second)
    )
    assert evidence is selected
    assert comparison_hash == ""
    assert conflict is False
    assert selected.page.needs_review is True
    assert {item.code for item in selected.page.issues} == {
        "INDEPENDENT_READ_NO_COMPARISON"
    }

    matching = _ocr_execution("candidate A", dpi=300)
    _evidence, selected, _hash, conflict = (
        server._ocr_v2_prepare_independent_result(first, matching)
    )
    assert conflict is False
    assert selected.page.latex == "candidate A"
    assert selected.page.needs_review is False


def test_rate_limit_reduces_next_wave_and_recovers_slowly():
    limiter = AdaptivePageConcurrency(maximum=3, recovery_successes=12)
    job = {}
    limited = OcrExecutionResult(
        request=_ocr_request(),
        page=None,
        error="429",
        error_category=OcrErrorCategory.RATE_LIMIT,
    )
    assert server._ocr_adaptive_observe(job, limiter, limited) == 2
    assert job["rate_limited"] is True
    assert job["rate_limit_events"] == 1
    assert server._ocr_adaptive_budgets(
        limiter,
        configured_batch_size=3,
        configured_concurrency_limit=3,
    ) == (2, 2)
    success = _ocr_execution("valid result")
    for _ in range(11):
        server._ocr_adaptive_observe(job, limiter, success)
    assert limiter.current == 2
    server._ocr_adaptive_observe(job, limiter, success)
    assert limiter.current == 3
    assert job["rate_limited"] is False


def test_compiled_progress_requires_merged_and_frozen_raw():
    snapshot = make_run_snapshot(
        source_bytes=b"%PDF-1.7\nsource",
        source_type="pdf",
        original_filename="source.pdf",
        source_total_pages=1,
        selected_pages=(1,),
        ocr_model="offline",
        api_backend="api",
        app_version="test",
        run_id="b" * 32,
    )
    record = OcrPageRecord.pending(1, 1)
    record = record.transition(OcrPageStatus.RENDERING, dpi=200)
    record = record.transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(b"pixels").hexdigest(),
        image_size_pixels=(100, 120),
        dpi=200,
        model="offline",
        call_index=1,
        started_at="2026-08-24T00:00:00Z",
    )
    record = record.transition(OcrPageStatus.VALIDATING)
    record = record.transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=hashlib.sha256(b"response").hexdigest(),
        raw_tex="page text",
        cleaned_tex="page text",
        ended_at="2026-08-24T00:00:01Z",
    )
    incomplete_job = {
        "raw_ready": True,
        "raw_frozen": False,
        "compile_status": OcrPreviewStatus.COMPILED.value,
    }
    status = server._ocr_effective_compile_status(incomplete_job)
    assert status is None
    metrics = progress_metrics(
        snapshot,
        (record,),
        terminal_epoch=1.0,
        merge_complete=True,
        raw_frozen=False,
        compile_status=status,
    )
    assert metrics["overall_progress"] < 1.0
    incomplete_job["raw_frozen"] = True
    assert server._ocr_effective_compile_status(incomplete_job) == "COMPILED"


def test_shared_batch_rate_limit_is_persisted_once_and_aliased_to_fallback_pages(
    tmp_path,
):
    run_id = "c" * 32
    store = OcrRunStore(tmp_path / "ocr-runs")
    snapshot = SimpleNamespace(run_id=run_id)
    job_id = "batch-rate-limit-job"
    limiter = AdaptivePageConcurrency(maximum=3, recovery_successes=12)
    server._ocr_adaptive_limiters[job_id] = limiter
    job = {
        "id": job_id,
        "pages": {
            index: {"task_index": index}
            for index in (1, 2, 3)
        },
    }
    attempt = OcrBatchAttemptEvidence.provider_failure(
        batch_id="ocr-batch-123456abcdef",
        page_ids=tuple(make_page_id(index) for index in (1, 2, 3)),
        error=RuntimeError("429 at C:/private/key.txt Authorization: Bearer secret"),
        category=OcrErrorCategory.RATE_LIMIT,
    )
    try:
        first = server._ocr_record_batch_attempt(job, store, snapshot, attempt)
        second = server._ocr_record_batch_attempt(job, store, snapshot, attempt)
        assert first == second
        assert limiter.current == 2
        assert job["rate_limit_events"] == 1
        assert job["current_concurrency_limit"] == 2
        assert server._ocr_adaptive_budgets(
            limiter,
            configured_batch_size=3,
            configured_concurrency_limit=3,
        ) == (2, 2)
        assert len(job["batch_attempts"]) == 1
        assert {
            page["batch_attempt_aliases"][0]["batch_id"]
            for page in job["pages"].values()
        } == {attempt.batch_id}

        request = OcrPageRequest(
            page_id=make_page_id(1),
            source_page=1,
            task_index=1,
            image_bytes=b"pixels",
            dpi=200,
            image_size_pixels=(10, 10),
        )
        result = OcrExecutionResult(
            request=request,
            page=None,
            error="single fallback still retryable",
            error_category=OcrErrorCategory.TRANSIENT,
            batch_id=attempt.batch_id,
            fell_back_to_single=True,
        )
        attached = server._ocr_attach_batch_attempt_alias(job, result)
        parent = attached.retry_state["batch_parent"]
        assert parent["shared_call"] is True
        assert parent["usage_accounting"] == "GLOBAL_ONCE"
        assert parent["batch_id"] == attempt.batch_id
    finally:
        server._ocr_adaptive_limiters.pop(job_id, None)


def test_ocr_bundle_contains_verified_shared_batch_evidence(tmp_path):
    source = tmp_path / "中文原始输入.pdf"
    source.write_bytes(b"%PDF-1.7\nimmutable source\n")
    run_id = "d" * 32
    store = OcrRunStore(tmp_path / "ocr-runs")
    attempt = OcrBatchAttemptEvidence.validation_failure(
        batch_id="ocr-batch-fedcba654321",
        page_ids=tuple(make_page_id(index) for index in (1, 2, 3)),
        response={"pages": [{"page_id": make_page_id(1)}]},
        validation_code="MISSING_PAGE_ID",
    )
    job = {
        "id": "batch-bundle-job",
        "pages": {index: {"task_index": index} for index in (1, 2, 3)},
    }
    server._ocr_record_batch_attempt(
        job,
        store,
        SimpleNamespace(run_id=run_id),
        attempt,
    )
    recovery_root = store.run_dir(run_id) / "recovery-evidence"
    source_bytes = source.read_bytes()
    bundle, manifest = server._ocr_bundle_bytes({
        "target": str(source),
        "_source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "_recovery_evidence_root": str(recovery_root),
        "source_type": "pdf",
        "source_total": 3,
        "selected_start": 1,
        "selected_end": 3,
        "selected_pages": [1, 2, 3],
        "pages": {},
        "status": "partial",
        "batch_attempts": job["batch_attempts"],
    }, "Recovered pages.")

    rows = [
        row for row in manifest["recovery_evidence"]
        if row["kind"] == "batch_attempt"
    ]
    assert len(rows) == 1
    assert rows[0]["path"].endswith(
        "/batch-attempts/ocr-batch-fedcba654321.json"
    )
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        payload = json.loads(archive.read(rows[0]["path"]))
    assert payload["shared_call"] is True
    assert payload["usage_accounting"] == "GLOBAL_ONCE"
    assert str(tmp_path) not in json.dumps(payload)

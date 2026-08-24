# -*- coding: utf-8 -*-
"""Portable, fail-closed archives for existing v2 pipeline runs."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path, PurePosixPath

import pytest

import latexstruct.core.analysis_adapter as analysis_adapter
from latexstruct.core.analysis_adapter import (
    AnalysisRunArtifacts,
    freeze_pipeline_analysis_run,
    stable_source_page_id,
    verify_frozen_analysis_run,
)
from latexstruct.core.analysis_schema import (
    AnalysisFinalStatus,
    IndependentReviewPass,
    ModelBinding,
    VerificationEvidence,
    sha256_bytes,
    sha256_text,
)


SOURCE_PDF = b"%PDF-1.7\nsource-pages\n%%EOF\n"
BASELINE_PDF = b"%PDF-1.7\nbaseline\n%%EOF\n"
CURRENT_PDF = b"%PDF-1.7\ncurrent\n%%EOF\n"
RAW_TEX = "\\documentclass{article}\n\\begin{document}\nRaw OCR.\n\\end{document}\n"
BASELINE_TEX = RAW_TEX
CURRENT_TEX = (
    "\\documentclass{article}\n\\begin{document}\n"
    "\\begin{theorem}Raw OCR.\\end{theorem}\n\\end{document}\n"
)


def _models():
    return (
        ModelBinding("AI-1", "structure-model", ("json",)),
        ModelBinding("AI-5", "review-model", ("vision", "json")),
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


def test_complete_machine_evidence_can_verify_only_the_exact_current_bytes(tmp_path):
    verified = _freeze(
        tmp_path,
        "analysis-verified",
        verification_evidence=_verified_evidence(),
    )
    assert verified.status == AnalysisFinalStatus.VERIFIED
    assert verified.verified is True
    page_units = json.loads(
        (verified.run_directory / "audit" / "page_units.json").read_text(encoding="utf-8")
    )
    assert {page["current_status"] for page in page_units} == {"VERIFIED"}

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


def test_nested_production_verification_evidence_can_verify_the_exact_current_bytes(
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

    assert result.status == AnalysisFinalStatus.VERIFIED
    assert result.verified is True


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

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import zipfile
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest
import pymupdf


TOOL = Path(__file__).resolve().parents[1] / "tools" / "v2_analysis_acceptance.py"
SPEC = importlib.util.spec_from_file_location("v2_analysis_acceptance", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TEST_COMMIT = "c" * 40
TEST_BUILD_ID = "200"
PROJECT_ID = "d" * 12
RUN_ID = "e" * 12


def _pdf_bytes(page_texts: list[str]) -> bytes:
    document = pymupdf.open()
    try:
        for text in page_texts:
            page = document.new_page()
            page.insert_text((72, 72), text)
        return document.tobytes()
    finally:
        document.close()


def _source_page_texts(page_count: int) -> list[str]:
    return [
        f"Ramsey source page {page:04d} unique-token-{page:04d} theorem proof content"
        for page in range(1, page_count + 1)
    ]


def _config(tmp_path: Path) -> MODULE.AnalysisAcceptanceConfig:
    source = tmp_path / "source.pdf"
    source.write_bytes(_pdf_bytes(_source_page_texts(37)))
    MODULE.RELEASE_INTEGRITY.RAMSEY_37_SOURCE_SHA256 = MODULE._sha256_file(source)
    executable = tmp_path / "LaTeXStruct.exe"
    executable.write_bytes(b"candidate executable")
    return MODULE.AnalysisAcceptanceConfig(
        base_url="http://127.0.0.1:8080",
        source=source,
        profile="analysis-37",
        output_dir=tmp_path / "evidence",
        expected_version="2.0.0",
        expected_commit=TEST_COMMIT,
        expected_build_id=TEST_BUILD_ID,
        executable=executable,
        expected_executable_sha256=MODULE._sha256_file(executable),
        service_pid=os.getpid(),
    )


def _artifact(role: str, path: str, body: bytes, **extra):
    return {
        "artifact_role": role,
        "path": path,
        "bytes_sha256": MODULE._sha256_bytes(body),
        "source_bytes_sha256": MODULE._sha256_bytes(body),
        "byte_count": len(body),
        **extra,
    }


def _verified_bundle(config: MODULE.AnalysisAcceptanceConfig):
    from latexstruct.core.compilecheck import build_compile_input_manifest
    from latexstruct.core.analysis_production import analysis_response_schema_hash
    from latexstruct.core.analysis_risk import (
        PAGE_RISK_CLASSIFIER_POLICY,
        PageRiskPreflightInput,
        build_page_risk_admission,
    )
    from latexstruct.core.analysis_schema import (
        ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
        PageRisk,
        PageRiskRouteClosure,
        PageRouteCallKey,
        PageRouteRecord,
        PageTriageOutcome,
        canonical_json_bytes,
    )
    from latexstruct.core.ocr_page_evidence import (
        FinalPageStatus,
        PageCoverageChecks,
        PageCoverageRecord,
        VisualMode,
        build_page_summaries,
    )
    from latexstruct.core.ocr_manifest import OCR_RUNTIME_PAGE_RECORDS_SCHEMA
    from latexstruct.core.ocr_runtime import OcrPageRecord, OcrPageStatus

    source = config.source.read_bytes()
    source_sha = MODULE._sha256_bytes(source)
    from latexstruct.core.analysis_adapter import stable_source_page_id

    page_ids = [
        stable_source_page_id(source_sha, page)
        for page in range(1, config.expected_pages + 1)
    ]
    source_page_object_hashes = [
        MODULE._sha256_bytes(f"source-page-object-{page}".encode("utf-8"))
        for page in range(1, config.expected_pages + 1)
    ]
    coverage_checks = PageCoverageChecks.from_bools(
        **{name: True for name in MODULE.OCR_COVERAGE_CHECK_NAMES}
    )
    page_records = tuple(
        PageCoverageRecord(
            page_id=f"ocr-page-{page:06d}",
            source_page_number=page,
            source_sha256=source_sha,
            source_page_object_hash=source_page_object_hashes[page - 1],
            checks=coverage_checks,
            visual_mode=VisualMode.FULL_OCR,
            final_status=FinalPageStatus.SUCCESS,
            artifact_hashes={
                name: MODULE._sha256_bytes(
                    f"{page}:{name}".encode("utf-8")
                )
                for name in (
                    "source.json",
                    "candidate.json",
                    "verification.json",
                    "raw-response.json",
                    "page.tex",
                )
            },
        )
        for page in range(1, config.expected_pages + 1)
    )
    page_records_bytes = build_page_summaries(
        page_records,
        run_id=RUN_ID,
        source_sha256=source_sha,
        expected_source_pages=range(1, config.expected_pages + 1),
    ).page_records_bytes
    runtime_records = tuple(
        OcrPageRecord(
            page_id=f"ocr-page-{page:06d}",
            source_page=page,
            task_index=page,
            status=OcrPageStatus.SUCCESS,
            model="gpt-5.4",
            raw_response_sha256=page_records[page - 1].artifact_hashes[
                "raw-response.json"
            ],
            raw_tex=f"OCR page {page}",
            cleaned_tex=f"OCR page {page}",
            retry_count=0,
            quality_issues=(
                ({"code": "fixture-quality", "severity": "warning"},)
                if page == 32
                else ()
            ),
            host_quality_flags=(
                ({"code": "fixture-host-flag", "source": "host"},)
                if page == 32
                else ()
            ),
        )
        for page in range(1, config.expected_pages + 1)
    )
    runtime_page_records_bytes = canonical_json_bytes({
        "schema_version": OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
        "run_id": RUN_ID,
        "pages": [record.to_dict() for record in runtime_records],
    })
    with pymupdf.open(stream=source, filetype="pdf") as source_document:
        extracted_source_texts = [
            str(source_document.load_page(page - 1).get_text("text") or "")
            for page in range(1, config.expected_pages + 1)
        ]
    baseline_parts = [
        "\\documentclass{article}",
        "\\begin{document}",
        "\\tableofcontents",
    ]
    for page, source_text in enumerate(extracted_source_texts, 1):
        suffix = ""
        if 17 <= page <= 31:
            suffix = "\\(x\\)"
        elif page >= 32:
            suffix = " ".join("\\(x\\)" for _ in range(8))
        baseline_parts.extend((f"% Page {page}", source_text.rstrip(), suffix))
    baseline_parts.append("\\end{document}")
    baseline_tex = ("\n".join(baseline_parts).rstrip() + "\n").encode("utf-8")
    baseline_pdf = _pdf_bytes(extracted_source_texts)
    baseline_regions = MODULE.RELEASE_INTEGRITY._tex_page_regions(
        baseline_tex.decode("utf-8"),
        range(1, config.expected_pages + 1),
    )
    current_tex = (
        b"\\documentclass{article}\n\\begin{document}\n"
        b"\\tableofcontents\nx\n\\end{document}\n"
    )
    current_pdf = _pdf_bytes(["Contents"] + _source_page_texts(config.expected_pages))
    compile_log = b"pass 1 ok\npass 2 ok\n"
    tex_sha = MODULE._sha256_bytes(current_tex)
    pdf_sha = MODULE._sha256_bytes(current_pdf)
    compile_input_manifest = build_compile_input_manifest(
        current_tex.decode("utf-8"),
        {},
    )
    compile_workdir = "compile-workdir:sha256:" + "9" * 64
    reviews = [
        {
            "pass_number": pass_number,
            "context_id": f"independent-context-{pass_number}",
            "candidate_hash": tex_sha,
            "checked_page_ids": page_ids,
            "compile_passes": 2,
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "formal_inventory_ok": True,
            "visual_review_ok": True,
            "new_high_risk_issues": 0,
            "prior_pass_conclusion_visible": False,
        }
        for pass_number in (1, 2)
    ]
    evidence_hashes = {
        name: MODULE._sha256_bytes(name.encode("utf-8"))
        for name in MODULE.RELEASE_INTEGRITY.ANALYSIS_EVIDENCE_HASH_FIELDS
    }
    evidence_hashes["response_schema_hash"] = analysis_response_schema_hash()
    evidence_hashes["ocr_page_records_hash"] = MODULE._sha256_bytes(
        page_records_bytes
    )
    evidence_hashes["ocr_runtime_page_records_hash"] = MODULE._sha256_bytes(
        runtime_page_records_bytes
    )
    policy_versions = {
        key: PAGE_RISK_CLASSIFIER_POLICY[key]
        for key in (
            "feature_extractor_version",
            "visual_layout_algorithm_version",
            "machine_visual_algorithm_version",
            "compile_map_algorithm_version",
        )
    }
    preflight_inputs = []
    preflight_rows = []
    for page, page_id in enumerate(page_ids, 1):
        runtime_record = runtime_records[page - 1]
        quality_issues = tuple(dict(item) for item in runtime_record.quality_issues)
        host_quality_flags = tuple(
            dict(item) for item in runtime_record.host_quality_flags
        )
        candidate_ids = (f"candidate-page-{page:06d}",)
        layout_evidence = {
            "schema": "latexstruct-source-layout-preflight-v1",
            **policy_versions,
            "page": page,
            "double_column": False,
            "complex_layout": False,
        }
        compile_map_evidence = {
            "schema": "latexstruct-compile-map-preflight-v1",
            **policy_versions,
            "mapping_sha256": "7" * 64,
            "source_page_number": page,
            "candidate_page_numbers": [page],
            "mapping_complete": True,
            "mapping_in_range": True,
            "mismatch": False,
        }
        machine_visual_evidence = {
            "schema": "latexstruct-machine-visual-preflight-v1",
            **policy_versions,
            "page": page,
            "anomaly_codes": [],
        }
        risk_input = PageRiskPreflightInput(
            source_page_id=page_id,
            source_page_number=page,
            source_page_object_hash=source_page_object_hashes[page - 1],
            ocr_coverage_checks=coverage_checks.to_dict(),
            unresolved_region_hashes=(),
            baseline_tex_region=baseline_regions[page],
            candidate_pdf_page_ids=candidate_ids,
            source_pdf_text=extracted_source_texts[page - 1],
            ocr_final_status="SUCCESS",
            ocr_retry_count=0,
            ocr_quality_issues=quality_issues,
            host_quality_flags=host_quality_flags,
            machine_visual_anomalies=(),
            double_column=False,
            complex_layout=False,
            compile_map_mismatch=False,
            layout_evidence=layout_evidence,
            compile_map_evidence=compile_map_evidence,
        )
        preflight_inputs.append(risk_input)
        preflight_rows.append({
            "source_page_id": page_id,
            "source_page_number": page,
            "source_page_object_hash": source_page_object_hashes[page - 1],
            "ocr_page_id": f"ocr-page-{page:06d}",
            "ocr_coverage_checks": coverage_checks.to_dict(),
            "unresolved_region_hashes": [],
            "ocr_final_status": "SUCCESS",
            "ocr_retry_count": 0,
            "ocr_quality_issues": list(quality_issues),
            "host_quality_flags": list(host_quality_flags),
            "candidate_pdf_page_ids": list(candidate_ids),
            "source_pdf_text_sha256": MODULE._sha256_bytes(
                extracted_source_texts[page - 1].encode("utf-8")
            ),
            "baseline_tex_region_sha256": MODULE._sha256_bytes(
                baseline_regions[page].encode("utf-8")
            ),
            "machine_visual_anomalies": [],
            "machine_visual_evidence": machine_visual_evidence,
            "double_column": False,
            "complex_layout": False,
            "layout_evidence": layout_evidence,
            "compile_map_mismatch": False,
            "compile_map_evidence": compile_map_evidence,
        })
    admission = build_page_risk_admission(
        source_pdf_sha256=source_sha,
        ocr_page_records_sha256=evidence_hashes["ocr_page_records_hash"],
        ocr_runtime_page_records_sha256=evidence_hashes[
            "ocr_runtime_page_records_hash"
        ],
        baseline_tex_sha256=MODULE._sha256_bytes(baseline_tex),
        baseline_pdf_sha256=MODULE._sha256_bytes(baseline_pdf),
        page_inputs=tuple(preflight_inputs),
    )
    page_risk_payload = admission.to_dict()
    page_risk_sha = admission.digest
    evidence_hashes["page_risk_admission_hash"] = page_risk_sha
    risk_preflight = {
        "schema": "latexstruct-analysis-risk-preflight-inputs-v2",
        "source_pdf_sha256": source_sha,
        "baseline_tex_sha256": MODULE._sha256_bytes(baseline_tex),
        "baseline_pdf_sha256": MODULE._sha256_bytes(baseline_pdf),
        "ocr_page_records_sha256": evidence_hashes["ocr_page_records_hash"],
        "ocr_runtime_page_records_sha256": evidence_hashes[
            "ocr_runtime_page_records_hash"
        ],
        "inputs": preflight_rows,
    }
    risk_preflight["preflight_sha256"] = (
        MODULE.RELEASE_INTEGRITY._canonical_json_sha256(risk_preflight)
    )
    budget_limits = {
        "max_input_tokens": 100_000,
        "max_output_tokens": 100_000,
        "max_cost": 0.0,
        "max_requests": 1_000,
        "max_strong_model_calls": 0,
        "max_wall_time_minutes": 120.0,
    }
    model_bindings = [
        {
            "role": f"AI-{index}",
            "model_id": "gpt-5.4-mini",
            "capabilities": [],
            "reasoning_effort": "high",
        }
        for index in range(1, 7)
    ]
    transport_contracts = [
        {
            "role": model["role"],
            "model_id": model["model_id"],
            "reasoning_effort": model["reasoning_effort"],
            "operations": sorted(
                operation
                for operation, role in MODULE.RELEASE_INTEGRITY.ANALYSIS_OPERATION_ROLES.items()
                if role == model["role"]
            ),
            "client_type": "latexstruct.core.codex_cli.CodexCLIClient",
            "method": (
                "chat_vision_json_images_bytes"
                if model["role"] in {"AI-3", "AI-5"}
                else "chat_json_schema"
            ),
            "max_retries": 0,
            "max_tokens": 20,
            "backend_authority_sha256": (
                MODULE.RELEASE_INTEGRITY.ANALYSIS_STABLE_BACKEND_AUTHORITY_SHA256
            ),
            "backend_configuration_sha256": (
                MODULE.RELEASE_INTEGRITY.ANALYSIS_STABLE_BACKEND_CONFIGURATION_SHA256
            ),
        }
        for model in model_bindings
    ]
    analysis_configuration = {
        "workflow_version": "analysis-loop-v2",
        "prompt_version": "analysis-prompts-v2",
        "application_version": "2.0.0",
        "latex_engine": "xelatex",
        "concurrency_limit": 3,
        "models": model_bindings,
        "transport_contracts": transport_contracts,
        "page_range": list(range(1, config.expected_pages + 1)),
        "candidate_page_map": [
            [page, [page]] for page in range(1, config.expected_pages + 1)
        ],
        "candidate_storage_name": "candidate.tex",
        "raw_ocr_frozen": True,
        "page_risks": [
            {
                "source_page_number": page.summary.source_page_number,
                "risk_level": page.risk_level.value,
                "risk_reasons": list(page.risk_reasons),
            }
            for page in admission.pages
        ],
        "page_risk_admission": admission.canonical_payload(),
        "page_risk_admission_hash": admission.digest,
        "page_risk_source_admission_hash": admission.digest,
        "compile_extra_files": [],
        "max_macro_rounds": 3,
        **budget_limits,
    }
    analysis_configuration_sha256 = (
        MODULE.RELEASE_INTEGRITY._canonical_json_sha256(analysis_configuration)
    )
    evidence_hashes["analysis_config_hash"] = analysis_configuration_sha256
    snapshot = {
        "run_id": RUN_ID,
        "project_id": PROJECT_ID,
        "workflow_version": "analysis-loop-v2",
        "prompt_version": "analysis-prompts-v2",
        "application_version": "2.0.0",
        "source_pdf_hash": source_sha,
        "raw_ocr_tex_hash": "a" * 64,
        "baseline_tex_hash": MODULE._sha256_bytes(baseline_tex),
        "baseline_pdf_hash": MODULE._sha256_bytes(baseline_pdf),
        "page_count": config.expected_pages,
        "page_range": list(range(1, config.expected_pages + 1)),
        "latex_engine": "xelatex",
        "models": model_bindings,
        "concurrency_limit": 3,
        "started_at": "2026-08-24T00:00:00Z",
        "performance_target_seconds": 7200.0,
        **budget_limits,
        "transport_contracts": transport_contracts,
        "page_map": [
            {
                "source_page_id": page_id,
                "source_page_number": page,
                "tex_page_marker": f"% page {page}",
                "candidate_pdf_page_ids": [f"candidate-page-{page:06d}"],
            }
            for page, page_id in enumerate(page_ids, 1)
        ],
        "initial_compile_state": "COMPILED",
        "initial_issue_counts": [],
        "config_hash": analysis_configuration_sha256,
        "evidence_hashes": evidence_hashes,
    }
    snapshot["snapshot_hash"] = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
        snapshot
    )

    material_hashes = {
        "source_pdf_page_hash": "1" * 64,
        "baseline_tex_region_hash": "2" * 64,
        "current_tex_region_hash": "3" * 64,
        "current_pdf_page_hash": "4" * 64,
    }

    def transport_row(role: str, operation: str, page_id: str = "document"):
        usage = [
            ["input_tokens", 10],
            ["output_tokens", 5],
            ["cached_input_tokens", 2],
            ["total_tokens", 15],
            ["billing_mode", "chatgpt_subscription"],
        ]
        return {
            "role": role,
            "operation": operation,
            "candidate_hash": tex_sha,
            "source_page_id": page_id,
            "issue_id": "DISCOVERY-fixture",
            "material_hashes": [[key, value] for key, value in material_hashes.items()],
            "snapshot_hash": snapshot["snapshot_hash"],
            "prompt_version": snapshot["prompt_version"],
            "response_schema_version": ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation],
            "budget_claim": {
                "input_tokens": 100,
                "output_tokens": 20,
                "cost": 0.0,
                "requests": 1,
                "strong_model_calls": 0,
            },
            "budget_actual_usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cost": None,
            },
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
        }

    transport = [
        transport_row("AI-3", "visual-triage", page_id)
        for page_id in page_ids
    ]
    sampled_low_risk = set(admission.low_risk_sampling.selected_page_ids)
    for admitted_page in admission.pages:
        page_id = admitted_page.summary.source_page_id
        if (
            admitted_page.risk_level in {PageRisk.R1, PageRisk.R2}
            or page_id in sampled_low_risk
        ):
            transport.append(
                transport_row("AI-1", "structure-findings", page_id)
            )
        if admitted_page.risk_level is PageRisk.R2 or page_id in sampled_low_risk:
            transport.extend((
                transport_row("AI-2", "content-math-findings", page_id),
                transport_row("AI-3", "visual-findings", page_id),
            ))
    for pass_number in (1, 2):
        transport.extend(
            transport_row(
                "AI-5", f"final-review-{pass_number}", page_id
            )
            for page_id in page_ids
        )
    route_calls = tuple(sorted(
        (
            PageRouteCallKey(
                role=row["role"],
                operation=row["operation"],
                source_page_id=row["source_page_id"],
                candidate_hash=row["candidate_hash"],
                issue_id=row["issue_id"],
                snapshot_hash=row["snapshot_hash"],
                response_schema_version=row["response_schema_version"],
                succeeded=True,
            )
            for row in transport
        ),
        key=lambda item: (
            item.role,
            item.operation,
            item.source_page_id,
            item.candidate_hash,
            item.issue_id,
        ),
    ))
    route_closure = PageRiskRouteClosure(
        admission_sha256=admission.digest,
        final_candidate_hash=tex_sha,
        pages=tuple(
            PageRouteRecord(
                source_page_id=page.summary.source_page_id,
                source_page_number=page.summary.source_page_number,
                admitted_risk=page.risk_level,
                triage_outcome=PageTriageOutcome.CLEAR,
                triage_response_sha256=MODULE._sha256_bytes(
                    f"triage:{page.summary.source_page_id}".encode("utf-8")
                ),
                effective_risk=page.risk_level,
                modified=False,
                anomaly_reasons=(),
                sampled_low_risk=(
                    page.summary.source_page_id in sampled_low_risk
                ),
                deep_review_required=(
                    page.risk_level is PageRisk.R2
                    or page.summary.source_page_id in sampled_low_risk
                ),
                final_candidate_hash=tex_sha,
            )
            for page in admission.pages
        ),
        route_call_keys=route_calls,
    )
    invocations = [
        {
            "ordinal": ordinal,
            "operation": row["operation"],
            "binding": {
                "run_id": RUN_ID,
                "role": row["role"],
                "candidate_hash": row["candidate_hash"],
                "source_page_id": row["source_page_id"],
                "issue_id": row["issue_id"],
                "material_hashes": dict(material_hashes),
                "snapshot_hash": row["snapshot_hash"],
                "prompt_version": row["prompt_version"],
                "response_schema_version": row["response_schema_version"],
            },
            "elapsed_seconds": 0.1,
            "succeeded": True,
        }
        for ordinal, row in enumerate(transport, 1)
    ]
    budget_usage = {
        "observed": {
            "input_tokens": len(transport) * 10,
            "output_tokens": len(transport) * 5,
            "cost": 0.0,
        },
        "actual": {
            "input_tokens": len(transport) * 10,
            "output_tokens": len(transport) * 5,
            "cost": None,
        },
        "accounted": {
            "input_tokens": len(transport) * 10,
            "output_tokens": len(transport) * 5,
            "cost": 0.0,
        },
        "requests": len(transport),
        "strong_model_calls": 0,
        "unknown": {
            "input_token_requests": 0,
            "output_token_requests": 0,
            "cost_requests": len(transport),
        },
        "committed_reservations": len(transport),
        "cancelled_reservations": 0,
        "wall_time_minutes": 2.0,
    }
    budget_state = {
        "schema_version": "analysis-budget-v1",
        "limits": budget_limits,
        "usage": budget_usage,
        "low_priority_threshold": 0.9,
        "stop_reason": None,
        "stop_details": [],
        "unbounded_unknown_dimensions": [],
        "reservations": [],
    }
    recomputed_mapping = MODULE._recompute_production_alignment(
        source_pdf=source,
        candidate_pdf=current_pdf,
        selected_source_pages=list(range(1, config.expected_pages + 1)),
    )
    machine_evidence = {
        "final_reviews": reviews,
        "raw_ocr_frozen": True,
        "candidate_hash": tex_sha,
        "current_candidate_hash": tex_sha,
        "expected_page_ids": page_ids,
        "checked_page_ids": page_ids,
        "best_compile_passes": 2,
        "best_pdf_openable": True,
        "silent_page_omissions": 0,
        "silent_text_losses": 0,
        "unauthorized_math_changes": 0,
        "formal_errors": 0,
        "open_critical": 0,
        "open_high": 0,
        "regressions": 0,
        "severe_equation_number_errors": 0,
        "silent_footnote_losses": 0,
        "silent_figure_caption_losses": 0,
        "silent_bibliography_losses": 0,
    }
    verification = {
        "terminal_status": "SUCCESS",
        "verification": {
            "safe_to_export": True,
            "compile_after": {
                "available": True,
                "ok": True,
                "preview_status": "COMPILED",
                "exit_code": 0,
                "timed_out": False,
                "passes_requested": 2,
                "passes_attempted": 2,
                "passes_completed": 2,
                "compile_workdir": compile_workdir,
                "same_workdir_verified": True,
                "page_count": 38,
                "pdf_sha256": pdf_sha,
                "log": compile_log.decode("utf-8"),
                "input_manifest": compile_input_manifest,
                "compile_input_sha256": compile_input_manifest[
                    "manifest_sha256"
                ],
            },
            "analysis_v2": {
                "required": True,
                "executed": True,
                "ok": True,
                "verified": True,
                "status": "VERIFIED",
                "result_tex_sha256": tex_sha,
                "result_pdf_sha256": pdf_sha,
                "decision": {"verified": True, "status": "VERIFIED", "failures": []},
                "snapshot": snapshot,
                "page_risk_admission": page_risk_payload,
                "page_risk_preflight": risk_preflight,
                "page_route_closure": route_closure.to_dict(),
                "analysis_configuration": analysis_configuration,
                "analysis_configuration_sha256": (
                    analysis_configuration_sha256
                ),
                "transport_invocations": transport,
                "cache_hit_evidence": [],
                "budget_state": budget_state,
                "budget_usage": budget_usage,
                "invocations": invocations,
                "candidate_mappings": {
                    tex_sha: {
                        "candidate_hash": tex_sha,
                        "pdf_sha256": pdf_sha,
                        "mapping_sha256": recomputed_mapping["mapping_sha256"],
                        "candidate_only_pages": recomputed_mapping["candidate_only_pages"],
                        "map": recomputed_mapping["map"],
                    }
                },
                "compile_invocations": [{
                    "candidate_hash": tex_sha,
                    "reason": "final atomic compile",
                    "run_number": 1,
                    "ok": True,
                    "pdf_hash": pdf_sha,
                    "passes_requested": 2,
                    "passes_attempted": 2,
                    "passes_completed": 2,
                    "compile_workdir": compile_workdir,
                    "compile_input_sha256": compile_input_manifest[
                        "manifest_sha256"
                    ],
                    "same_workdir_verified": True,
                }],
                "final_reviews": reviews,
                "ledger": [],
                "verification_evidence": machine_evidence,
                "performance": {
                    "input_tokens": len(transport) * 10,
                    "output_tokens": len(transport) * 5,
                    "cached_tokens": len(transport) * 2,
                    "total_tokens": len(transport) * 15,
                    "usage_complete": True,
                    "observed_input_tokens": len(transport) * 10,
                    "observed_output_tokens": len(transport) * 5,
                    "observed_cached_tokens": len(transport) * 2,
                    "observed_total_tokens": len(transport) * 15,
                    "orchestration_invocation_count": len(transport),
                    "transport_call_count": len(transport),
                    "usage_observed_call_count": len(transport),
                    "usage_missing_call_count": 0,
                    "transport_attempt_count": len(transport),
                    "observed_transport_attempt_count": len(transport),
                    "usage_observed_attempt_count": len(transport),
                    "usage_missing_attempt_count": 0,
                    "attempt_evidence_complete": True,
                    "cache_hit_evidence_count": 0,
                },
                "stop_reasons": [],
            },
        },
    }
    verification_bytes = (json.dumps(verification) + "\n").encode()
    members = {
        "inputs/source.pdf": source,
        "stages/30_current.tex": current_tex,
        "previews/current.pdf": current_pdf,
        "audit/compile_current.log": compile_log,
        "audit/verification.json": verification_bytes,
        "evidence/page-records.json": page_records_bytes,
        "evidence/runtime-page-records.json": runtime_page_records_bytes,
        "baseline/baseline.tex": baseline_tex,
        "baseline/baseline.pdf": baseline_pdf,
    }
    manifest = {
        "workflow": "OCR_ANALYSIS_REVIEW",
        "source_run_status": "SUCCESS",
        "terminal_status": "SUCCESS",
        "verification_status": "VERIFIED",
        "packaging_status": "SUCCESS",
        "audit_package_status": "VALID",
        "project_id": PROJECT_ID,
        "run_id": RUN_ID,
        "app_version": "2.0.0",
        "blockers": [],
        "missing_expected_roles": [],
        "provenance": {
            "runtime": {
                "identity_status": "RECORDED",
                "app_version": "2.0.0",
                "git_commit": TEST_COMMIT,
                "build_id": TEST_BUILD_ID,
            }
        },
        "source_pdf": {
            "page_count": config.expected_pages,
            "selected_page_range": {
                "start": 1,
                "end": config.expected_pages,
                "pages": list(range(1, config.expected_pages + 1)),
            },
        },
        "artifacts": [
            _artifact("SOURCE_PDF", "inputs/source.pdf", source),
            _artifact("CURRENT_TEX", "stages/30_current.tex", current_tex),
            _artifact(
                "CURRENT_PREVIEW",
                "previews/current.pdf",
                current_pdf,
                preview_status="COMPILED",
            ),
            _artifact(
                "COMPILE_CURRENT_LOG", "audit/compile_current.log", compile_log
            ),
            _artifact(
                "VERIFICATION", "audit/verification.json", verification_bytes
            ),
            _artifact(
                "PAGE_RECORDS",
                "evidence/page-records.json",
                page_records_bytes,
            ),
            _artifact(
                "RUNTIME_PAGE_RECORDS",
                "evidence/runtime-page-records.json",
                runtime_page_records_bytes,
            ),
            _artifact("BASELINE_TEX", "baseline/baseline.tex", baseline_tex),
            _artifact("BASELINE_PDF", "baseline/baseline.pdf", baseline_pdf),
        ],
    }
    return members, manifest


def _mutate_verification(members, manifest, mutator) -> None:
    path = "audit/verification.json"
    payload = json.loads(members[path])
    mutator(payload)
    body = (json.dumps(payload) + "\n").encode()
    members[path] = body
    record = next(
        item for item in manifest["artifacts"] if item["artifact_role"] == "VERIFICATION"
    )
    digest = MODULE._sha256_bytes(body)
    record["bytes_sha256"] = digest
    record["source_bytes_sha256"] = digest
    record["byte_count"] = len(body)


def _rebind_page_risk_and_snapshot(analysis: dict) -> None:
    admission = analysis["page_risk_admission"]
    admission_body = {
        key: value for key, value in admission.items() if key != "admission_sha256"
    }
    digest = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(admission_body)
    admission["admission_sha256"] = digest
    configuration = analysis["analysis_configuration"]
    configuration["page_risk_admission"] = admission_body
    configuration["page_risk_admission_hash"] = digest
    configuration["page_risk_source_admission_hash"] = digest
    config_digest = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(configuration)
    analysis["analysis_configuration_sha256"] = config_digest
    snapshot = analysis["snapshot"]
    snapshot["evidence_hashes"]["page_risk_admission_hash"] = digest
    snapshot["evidence_hashes"]["analysis_config_hash"] = config_digest
    snapshot["config_hash"] = config_digest
    snapshot_without_hash = {
        key: value for key, value in snapshot.items() if key != "snapshot_hash"
    }
    snapshot_hash = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
        snapshot_without_hash
    )
    snapshot["snapshot_hash"] = snapshot_hash
    for transport in analysis["transport_invocations"]:
        transport["snapshot_hash"] = snapshot_hash
    for invocation in analysis["invocations"]:
        invocation["binding"]["snapshot_hash"] = snapshot_hash
    route = analysis["page_route_closure"]
    route["admission_sha256"] = digest
    for call in route["route_call_keys"]:
        call["snapshot_hash"] = snapshot_hash
    route["route_call_keys_sha256"] = (
        MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
            route["route_call_keys"]
        )
    )
    route_body = {
        key: value for key, value in route.items() if key != "closure_sha256"
    }
    route["closure_sha256"] = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
        route_body
    )


def _replace_page_risk_admission(analysis: dict, pages: list[dict]) -> None:
    """Build a self-consistent typed admission around deliberately altered pages."""

    from latexstruct.core.analysis_risk import _sampling_evidence
    from latexstruct.core.analysis_schema import (
        PageRiskAdmission,
        PageRiskAdmissionPage,
        canonical_json_bytes,
        sha256_bytes,
    )

    previous = analysis["page_risk_admission"]
    typed_pages = tuple(
        PageRiskAdmissionPage(
            summary=row["summary"],
            summary_sha256=row["summary_sha256"],
            risk_level=row["risk_level"],
            risk_reasons=tuple(row["risk_reasons"]),
        )
        for row in pages
    )
    page_ids_sha256 = sha256_bytes(canonical_json_bytes([
        page.summary.source_page_id for page in typed_pages
    ]))
    sampling = _sampling_evidence(
        pages=typed_pages,
        source_pdf_sha256=previous["source_pdf_sha256"],
        ocr_page_records_sha256=previous["ocr_page_records_sha256"],
        ocr_runtime_page_records_sha256=(
            previous["ocr_runtime_page_records_sha256"]
        ),
        baseline_tex_sha256=previous["baseline_tex_sha256"],
        page_ids_sha256=page_ids_sha256,
    )
    replacement = PageRiskAdmission(
        source_pdf_sha256=previous["source_pdf_sha256"],
        ocr_page_records_sha256=previous["ocr_page_records_sha256"],
        ocr_runtime_page_records_sha256=(
            previous["ocr_runtime_page_records_sha256"]
        ),
        baseline_tex_sha256=previous["baseline_tex_sha256"],
        baseline_pdf_sha256=previous["baseline_pdf_sha256"],
        classifier_policy_sha256=previous["classifier_policy_sha256"],
        page_ids_sha256=page_ids_sha256,
        pages=typed_pages,
        low_risk_sampling=sampling,
    )
    analysis["page_risk_admission"] = replacement.to_dict()
    analysis["analysis_configuration"]["page_risks"] = [
        {
            "source_page_number": page.summary.source_page_number,
            "risk_level": page.risk_level.value,
            "risk_reasons": list(page.risk_reasons),
        }
        for page in replacement.pages
    ]
    _rebind_page_risk_and_snapshot(analysis)


def _rebind_page_route_closure(analysis: dict) -> None:
    route = analysis["page_route_closure"]
    route["route_call_keys"].sort(key=lambda item: (
        item["role"],
        item["operation"],
        item["source_page_id"],
        item["candidate_hash"],
        item["issue_id"],
    ))
    route["pages_sha256"] = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
        route["pages"]
    )
    route["route_call_keys_sha256"] = (
        MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
            route["route_call_keys"]
        )
    )
    route_body = {
        key: value for key, value in route.items() if key != "closure_sha256"
    }
    route["closure_sha256"] = MODULE.RELEASE_INTEGRITY._canonical_json_sha256(
        route_body
    )


def _audit_zip(*, corrupt_digest: bool = False) -> bytes:
    source = b"%PDF-1.7\nsource\n"
    manifest = {
        "artifacts": [
            {
                "artifact_role": "SOURCE_PDF",
                "path": "inputs/source.pdf",
                "bytes_sha256": MODULE._sha256_bytes(source),
                "byte_count": len(source),
            }
        ]
    }
    members = {
        "submission_manifest.json": MODULE._json_bytes(manifest),
        "audit/packaging-integrity.json": MODULE._json_bytes(
            {
                "valid": True,
                "packaging_status": "SUCCESS",
                "audit_package_status": "VALID",
            }
        ),
        "inputs/source.pdf": source,
    }
    sums = []
    for name, body in members.items():
        digest = MODULE._sha256_bytes(body)
        if corrupt_digest and name == "inputs/source.pdf":
            digest = "0" * 64
        sums.append(f"{digest}  {name}")
    members["audit/SHA256SUMS"] = ("\n".join(sums) + "\n").encode()
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def test_direct_cli_help_can_import_workspace_package():
    result = subprocess.run(
        [sys.executable, str(TOOL), "--help"],
        cwd=TOOL.parents[1],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "analysis-37" in result.stdout
    assert "--exe-sha256" in result.stdout
    assert "--service-pid" in result.stdout


def test_analysis_37_config_rejects_non_high_and_wrong_template(
    tmp_path: Path, monkeypatch
):
    config = _config(tmp_path)
    monkeypatch.setattr(MODULE, "_process_image_path", lambda _pid: config.executable)
    monkeypatch.setattr(MODULE, "_listening_pids", lambda _port: {config.service_pid})
    monkeypatch.setattr(MODULE, "_process_parent_map", lambda: {config.service_pid: 0})
    with pytest.raises(MODULE.AcceptanceError, match="quality tier high"):
        MODULE._validate_config(replace(config, quality_tier="recommended"))
    with pytest.raises(MODULE.AcceptanceError, match="faithfulbook"):
        MODULE._validate_config(replace(config, template="other"))
    with pytest.raises(MODULE.AcceptanceError, match="model/effort is not allowed"):
        MODULE._validate_config(
            replace(config, expected_reasoning_effort="medium")
        )


def test_analysis_37_config_binds_running_service_image(tmp_path: Path, monkeypatch):
    config = _config(tmp_path)
    other = tmp_path / "other.exe"
    other.write_bytes(b"different service")
    monkeypatch.setattr(MODULE, "_process_image_path", lambda _pid: other)
    with pytest.raises(MODULE.AcceptanceError, match="not running the supplied"):
        MODULE._validate_config(config)


def test_analysis_37_rejects_base_url_owned_by_another_process(
    tmp_path: Path, monkeypatch
):
    config = _config(tmp_path)
    other_pid = config.service_pid + 10000
    monkeypatch.setattr(MODULE, "_process_image_path", lambda _pid: config.executable)
    monkeypatch.setattr(MODULE, "_listening_pids", lambda _port: {other_pid})
    monkeypatch.setattr(MODULE, "_process_parent_map", lambda: {other_pid: 0})
    with pytest.raises(MODULE.AcceptanceError, match="listener is not the supplied"):
        MODULE._validate_config(config)


def test_local_http_api_post_json_uses_real_post_body(monkeypatch):
    captured = {}

    # Return the concrete transport value expected by ``post_json`` while
    # retaining the outgoing request for assertions.
    def request_json(_self, path, **kwargs):
        captured.update(path=path, **kwargs)
        http_module = sys.modules[MODULE.LocalHttpApi.__module__]
        return http_module.HttpDownload(b'{"ok":true}', {}, 201)

    monkeypatch.setattr(MODULE.LocalHttpApi, "_request", request_json)
    api = MODULE.LocalHttpApi("http://127.0.0.1:8080")

    value = api.post_json("/api/example", {"标题": "测试"})

    assert value == {"ok": True}
    assert captured["path"] == "/api/example"
    assert captured["method"] == "POST"
    assert json.loads(captured["body"].decode("utf-8")) == {"标题": "测试"}
    assert captured["headers"]["Content-Type"].startswith("application/json")


def test_fresh_import_identity_accepts_exact_project_and_process_ids():
    response = {
        "id": PROJECT_ID,
        "processed": False,
        "reused": False,
        "process": {"id": RUN_ID, "pid": PROJECT_ID},
    }

    assert MODULE._fresh_import_identity(response) == (PROJECT_ID, RUN_ID)
    response.pop("reused")
    assert MODULE._fresh_import_identity(response) == (PROJECT_ID, RUN_ID)


@pytest.mark.parametrize(
    "project_id",
    ["d" * 11, "d" * 13, "d" * 32, "D" * 12, "../project-id", 123, None],
)
def test_fresh_import_identity_rejects_invalid_project_ids(project_id: object):
    response = {
        "id": project_id,
        "processed": False,
        "reused": False,
        "process": {"id": RUN_ID, "pid": project_id},
    }

    with pytest.raises(MODULE.AcceptanceError, match="invalid project id"):
        MODULE._fresh_import_identity(response)


@pytest.mark.parametrize(
    "process_id", ["e" * 11, "e" * 13, "E" * 12, "../process", 123, None]
)
def test_fresh_import_identity_rejects_invalid_process_ids(process_id: object):
    response = {
        "id": PROJECT_ID,
        "processed": False,
        "reused": False,
        "process": {"id": process_id, "pid": PROJECT_ID},
    }

    with pytest.raises(MODULE.AcceptanceError, match="valid analysis task"):
        MODULE._fresh_import_identity(response)


@pytest.mark.parametrize("reused", [True, None, 0, 1, "false", "true"])
def test_fresh_import_identity_rejects_invalid_reused_state(reused: object):
    response = {
        "id": PROJECT_ID,
        "processed": False,
        "reused": reused,
        "process": {"id": RUN_ID, "pid": PROJECT_ID},
    }
    with pytest.raises(MODULE.AcceptanceError, match="unexpectedly reused"):
        MODULE._fresh_import_identity(response)


@pytest.mark.parametrize("processed", [True, None, 0, 1, "false"])
def test_fresh_import_identity_rejects_invalid_processed_state(processed: object):
    response = {
        "id": PROJECT_ID,
        "processed": processed,
        "reused": False,
        "process": {"id": RUN_ID, "pid": PROJECT_ID},
    }
    with pytest.raises(MODULE.AcceptanceError, match="unprocessed project"):
        MODULE._fresh_import_identity(response)


@pytest.mark.parametrize("process_pid", ["a" * 12, 123, None])
def test_fresh_import_identity_rejects_cross_project_analysis_task(
    process_pid: object,
):
    response = {
        "id": PROJECT_ID,
        "processed": False,
        "reused": False,
        "process": {"id": RUN_ID, "pid": process_pid},
    }

    with pytest.raises(MODULE.AcceptanceError, match="different project"):
        MODULE._fresh_import_identity(response)


@pytest.mark.parametrize("process", [None, [], "task"])
def test_fresh_import_identity_requires_process_object(process: object):
    response = {
        "id": PROJECT_ID,
        "processed": False,
        "reused": False,
        "process": process,
    }

    with pytest.raises(MODULE.AcceptanceError, match="process task"):
        MODULE._fresh_import_identity(response)


def test_audit_zip_requires_recomputable_sha256sums():
    members, manifest = MODULE._read_audit_zip(_audit_zip())

    assert manifest["artifacts"][0]["artifact_role"] == "SOURCE_PDF"
    assert members["inputs/source.pdf"].startswith(b"%PDF-")
    with pytest.raises(MODULE.AcceptanceError, match="digest mismatch"):
        MODULE._read_audit_zip(_audit_zip(corrupt_digest=True))


def test_verified_bundle_publishes_analysis_37_evidence_bindings(
    tmp_path: Path, monkeypatch
):
    config = _config(tmp_path)
    config.output_dir.mkdir()
    members, manifest = _verified_bundle(config)
    facts = MODULE._verified_bundle_facts(
        config=config,
        members=members,
        manifest=manifest,
        source_pages=37,
        source_sha256=MODULE._sha256_file(config.source),
        backend="api",
        expected_project_id=PROJECT_ID,
        expected_run_id=RUN_ID,
    )
    evidence = MODULE.AnalysisRunEvidence(
        measurement_started_at="2026-08-24T00:00:00Z",
        ended_at="2026-08-24T00:02:00Z",
        wall_time_seconds=120.0,
        completed_terminal_run=True,
        real_execution=True,
        runtime_model_configuration={
            "analysis_backend": "codex_cli",
            "codex_model": "gpt-5.4-mini",
            "codex_reasoning_effort": "high",
            "codex_triage_model": "gpt-5.4-mini",
            "codex_triage_reasoning_effort": "high",
        },
    )
    ocr_dir = config.output_dir / "ocr-prerequisite"
    ocr_dir.mkdir()
    baseline_sha256 = "7" * 64
    baseline_run_id = "8" * 32
    (ocr_dir / "acceptance-attestation.json").write_text(
        json.dumps({
            "ocr_baseline": {
                "package_directory": MODULE.RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY,
                "manifest_filename": (
                    f"{MODULE.RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY}/"
                    f"{MODULE.RELEASE_INTEGRITY.OCR_BASELINE_MANIFEST_MEMBER}"
                ),
                "manifest_sha256": baseline_sha256,
                "run_id": baseline_run_id,
            }
        }) + "\n",
        encoding="utf-8",
    )
    for name in ("performance.json", "validation-report.json"):
        (ocr_dir / name).write_text("{}\n", encoding="utf-8")
    baseline_manifest = (
        ocr_dir
        / MODULE.RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY
        / MODULE.RELEASE_INTEGRITY.OCR_BASELINE_MANIFEST_MEMBER
    )
    baseline_manifest.parent.mkdir(parents=True)
    baseline_manifest.write_text("{}\n", encoding="utf-8")
    (config.output_dir / MODULE.AUDIT_ZIP_FILENAME).write_bytes(
        b"PK\x03\x04verified-private-audit"
    )
    monkeypatch.setattr(
        MODULE.RELEASE_INTEGRITY,
        "verify_analysis_attestation",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(MODULE, "_process_image_path", lambda _pid: config.executable)
    monkeypatch.setattr(MODULE, "_listening_pids", lambda _port: {config.service_pid})
    monkeypatch.setattr(
        MODULE, "_process_parent_map", lambda: {config.service_pid: 0}
    )

    validation = MODULE._publish_pass(config, evidence, facts)
    attestation = json.loads(
        (config.output_dir / "analysis-attestation.json").read_text(encoding="utf-8")
    )
    performance = json.loads(
        (config.output_dir / "analysis-performance.json").read_text(encoding="utf-8")
    )

    assert validation["terminal_status"] == "VERIFIED"
    assert attestation["result"] == "PASS"
    assert (
        attestation["snapshot_binding"]["release_model_policy"][
            "declared_model_id"
        ]
        == "gpt-5.4-mini"
    )
    assert attestation["profile"] == "analysis-37"
    assert attestation["ocr_prerequisite"]["profile"] == "ocr-37"
    assert attestation["ocr_prerequisite"]["run_id"] == baseline_run_id
    assert (
        attestation["ocr_prerequisite"]["baseline_manifest_sha256"]
        == baseline_sha256
    )
    assert attestation["visual_verification"]["pages_checked"] == 37
    assert attestation["visual_verification"]["model_calls"] == 74
    assert attestation["audit_submission"]["published_to_github"] is False
    assert attestation["quality_tier"] == "high"
    assert attestation["template"] == "faithfulbook"
    assert performance["target_status"] == "NOT_EVALUATED"
    assert performance["target_met"] is None
    assert performance["thresholds"] == {"maximum_wall_time_seconds": None}
    assert attestation["page_layout"]["candidate_page_count"] == 38
    assert attestation["service_binding"]["listener_pid"] == config.service_pid
    assert attestation["service_binding"]["listener_pid_verified"] is True
    assert len(attestation["independent_final_reviews"]) == 2
    expected_artifacts = {
        "candidate_tex": members["stages/30_current.tex"],
        "candidate_pdf": members["previews/current.pdf"],
        "compile_log": members["audit/compile_current.log"],
    }
    for role, payload in expected_artifacts.items():
        record = attestation["artifacts"][role]
        path = config.output_dir / record["filename"]
        assert path.read_bytes() == payload
        assert record["bytes"] == len(payload)
        assert record["sha256"] == MODULE._sha256_bytes(payload)


def test_verified_bundle_rejects_current_tex_that_is_not_the_packaged_candidate(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)
    current = next(
        item for item in manifest["artifacts"]
        if item["artifact_role"] == "CURRENT_TEX"
    )
    current["source_bytes_sha256"] = "f" * 64

    with pytest.raises(
        MODULE.AcceptanceError,
        match="CURRENT_TEX bytes differ from the compiled candidate",
    ):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_self_consistent_mapping_from_a_different_pdf(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)
    alternate_pdf = _pdf_bytes(_source_page_texts(config.expected_pages))
    forged = MODULE._recompute_production_alignment(
        source_pdf=members["inputs/source.pdf"],
        candidate_pdf=alternate_pdf,
        selected_source_pages=list(range(1, config.expected_pages + 1)),
    )

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        mapping = analysis["candidate_mappings"][analysis["result_tex_sha256"]]
        mapping["mapping_sha256"] = forged["mapping_sha256"]
        mapping["candidate_only_pages"] = forged["candidate_only_pages"]
        mapping["map"] = forged["map"]

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="differs from production alignment"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_self_consistent_transport_subset(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["analysis_v2"]["transport_invocations"].pop()

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="does not close over orchestration"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_empty_transport_attempt_ledger(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["analysis_v2"]["transport_invocations"][0][
            "attempts"
        ] = []

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="empty attempt ledger"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_attempt_token_algebra_tampering(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        attempt_usage = payload["verification"]["analysis_v2"][
            "transport_invocations"
        ][0]["attempts"][0]["usage"]
        next(row for row in attempt_usage if row[0] == "total_tokens")[1] = 999

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="total_tokens"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_attempt_without_subscription_billing(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        usage = payload["verification"]["analysis_v2"]["transport_invocations"][
            0
        ]["attempts"][0]["usage"]
        usage[:] = [row for row in usage if row[0] != "billing_mode"]

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="subscription billing"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_performance_missing_attempt_count(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["analysis_v2"]["performance"][
            "usage_missing_attempt_count"
        ] = 1

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="usage_missing_attempt_count"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_missing_transport_budget_claim(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        del payload["verification"]["analysis_v2"]["transport_invocations"][0][
            "budget_claim"
        ]

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="fields are incomplete"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


@pytest.mark.parametrize(
    ("target", "field"),
    (("transport", "endpoint"), ("claim", "reserved_prompt")),
)
def test_verified_bundle_rejects_unsupported_transport_budget_fields(
    tmp_path: Path,
    target: str,
    field: str,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        invocation = payload["verification"]["analysis_v2"][
            "transport_invocations"
        ][0]
        if target == "transport":
            invocation[field] = "forged"
        else:
            invocation["budget_claim"][field] = 1

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="incomplete or unsupported"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_transport_actual_usage_tampering(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["analysis_v2"]["transport_invocations"][0][
            "budget_actual_usage"
        ]["input_tokens"] += 1

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="differs from complete attempts"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_attempts_beyond_budget_claim(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        row = payload["verification"]["analysis_v2"]["transport_invocations"][0]
        terminal = row["attempts"][0]
        terminal["succeeded"] = False
        terminal["failure_stage"] = "timeout"
        row["attempts"].append({
            **terminal,
            "attempt_number": 2,
            "succeeded": True,
            "failure_stage": "",
        })

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="reserved request bound"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_strong_call_claim_for_non_ai6(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["analysis_v2"]["transport_invocations"][0][
            "budget_claim"
        ]["strong_model_calls"] = 1

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="frozen transport contract"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (("max_retries", 1), ("max_tokens", 21)),
)
def test_verified_bundle_rejects_budget_claim_outside_frozen_transport_contract(
    tmp_path: Path, field: str, value: int
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        analysis["snapshot"]["transport_contracts"][0][field] = value
        _rebind_page_risk_and_snapshot(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="frozen transport contract"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_secret_shaped_transport_contract_extension(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        analysis["snapshot"]["transport_contracts"][0]["endpoint"] = (
            "https://secret.invalid/api"
        )
        _rebind_page_risk_and_snapshot(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="unsupported fields: endpoint"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_secret_shaped_transport_client_type(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        analysis["snapshot"]["transport_contracts"][0]["client_type"] = (
            "api_key=forged-secret"
        )
        _rebind_page_risk_and_snapshot(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="not authoritative"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_self_consistent_disallowed_model_policy(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        snapshot = analysis["snapshot"]
        snapshot["models"][0]["model_id"] = "gpt-5.4"
        snapshot["transport_contracts"][0]["model_id"] = "gpt-5.4"
        _rebind_page_risk_and_snapshot(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="release model policy"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_runtime_model_configuration_must_match_declared_release_policy(
    tmp_path: Path,
):
    config = _config(tmp_path)
    runtime = {
        "analysis_backend": "codex_cli",
        "codex_model": "gpt-5.4-mini",
        "codex_reasoning_effort": "high",
        "codex_triage_model": "gpt-5.4-mini",
        "codex_triage_reasoning_effort": "high",
        "unrelated_non_secret_setting": True,
    }
    assert MODULE._verified_runtime_model_configuration(config, runtime) == {
        key: runtime[key]
        for key in (
            "analysis_backend",
            "codex_model",
            "codex_reasoning_effort",
            "codex_triage_model",
            "codex_triage_reasoning_effort",
        )
    }
    runtime["codex_triage_model"] = "gpt-5.4"
    with pytest.raises(MODULE.AcceptanceError, match="declared release policy"):
        MODULE._verified_runtime_model_configuration(config, runtime)


def test_verified_bundle_rejects_forged_budget_aggregate(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis_v2 = payload["verification"]["analysis_v2"]
        for usage in (
            analysis_v2["budget_usage"],
            analysis_v2["budget_state"]["usage"],
        ):
            usage["requests"] += 1
            usage["unknown"]["cost_requests"] += 1

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="recomputed transport claims"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_recovery_budget_residual(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["analysis_v2"]["stop_reasons"].append(
            "recovery_budget_evidence_ahead_of_checkpoint"
        )

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="recovery budget residual"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_self_consistent_missing_risk_page(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        pages = analysis["page_risk_admission"]["pages"][:-1]
        _replace_page_risk_admission(analysis, pages)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="does not cover every source page"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_self_consistent_forged_classifier_result(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        pages = analysis["page_risk_admission"]["pages"]
        pages[0]["risk_level"] = "R2"
        pages[0]["risk_reasons"] = ["math_dense"]
        _replace_page_risk_admission(analysis, pages)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="page-risk admission is invalid"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_admission_row_not_in_ocr_page_records(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        pages = analysis["page_risk_admission"]["pages"]
        summary = pages[0]["summary"]
        summary["source_page_object_hash"] = "f" * 64
        pages[0]["summary_sha256"] = (
            MODULE.RELEASE_INTEGRITY._canonical_json_sha256(summary)
        )
        _replace_page_risk_admission(analysis, pages)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="preflight facts"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_tampered_runtime_page_records(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)
    member = "evidence/runtime-page-records.json"
    runtime = json.loads(members[member])
    runtime["pages"][0]["retry_count"] = 1
    body = MODULE._json_bytes(runtime)
    members[member] = body
    descriptor = next(
        artifact
        for artifact in manifest["artifacts"]
        if artifact["artifact_role"] == "RUNTIME_PAGE_RECORDS"
    )
    descriptor["bytes_sha256"] = MODULE._sha256_bytes(body)
    descriptor["source_bytes_sha256"] = MODULE._sha256_bytes(body)
    descriptor["byte_count"] = len(body)

    with pytest.raises(MODULE.AcceptanceError, match="RUNTIME_PAGE_RECORDS bytes"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_fixed_sample_tampering(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        admission = analysis["page_risk_admission"]
        sample = admission["low_risk_sampling"]
        selected = list(sample["selected_page_ids"])
        omitted = next(
            page_id
            for page_id in sample["population_page_ids"]
            if page_id not in selected
        )
        mandatory = set(sample["mandatory_page_ids"])
        replaced = next(page_id for page_id in selected if page_id not in mandatory)
        selected[selected.index(replaced)] = omitted
        page_order = {
            page["summary"]["source_page_id"]: page["summary"][
                "source_page_number"
            ]
            for page in admission["pages"]
        }
        selected.sort(key=page_order.get)
        sample["selected_page_ids"] = selected
        sample["selected_page_ids_sha256"] = (
            MODULE.RELEASE_INTEGRITY._canonical_json_sha256(selected)
        )
        _rebind_page_risk_and_snapshot(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="page-risk admission is invalid"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_ai1_missing_one_admitted_page(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        rows = analysis["transport_invocations"]
        first_index = next(i for i, row in enumerate(rows) if row["role"] == "AI-1")
        replacement = next(
            row["source_page_id"]
            for row in rows[first_index + 1 :]
            if row["role"] == "AI-1"
        )
        rows[first_index]["source_page_id"] = replacement
        analysis["invocations"][first_index]["binding"]["source_page_id"] = replacement

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="transport invocation ledger"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_missing_ai3_full_book_triage(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        rows = analysis["transport_invocations"]
        first_index = next(
            index
            for index, row in enumerate(rows)
            if row["operation"] == "visual-triage"
        )
        replacement = next(
            row["source_page_id"]
            for row in rows[first_index + 1 :]
            if row["operation"] == "visual-triage"
        )
        original = rows[first_index]["source_page_id"]
        rows[first_index]["source_page_id"] = replacement
        analysis["invocations"][first_index]["binding"][
            "source_page_id"
        ] = replacement
        route_call = next(
            call
            for call in analysis["page_route_closure"]["route_call_keys"]
            if call["operation"] == "visual-triage"
            and call["source_page_id"] == original
        )
        route_call["source_page_id"] = replacement
        _rebind_page_route_closure(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="visual triage"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_modified_page_without_three_rechecks(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        page = analysis["page_route_closure"]["pages"][0]
        page["modified"] = True
        page["deep_review_required"] = True
        _rebind_page_route_closure(analysis)

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(MODULE.AcceptanceError, match="modified-page recheck"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_legacy_two_independent_compile_rows(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        analysis = payload["verification"]["analysis_v2"]
        strong = analysis["compile_invocations"][0]
        analysis["compile_invocations"] = [
            {
                "candidate_hash": strong["candidate_hash"],
                "run_number": number,
                "ok": True,
                "pdf_hash": strong["pdf_hash"],
            }
            for number in (1, 2)
        ]

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(
        MODULE.AcceptanceError,
        match="one atomic final-candidate compile",
    ):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_verified_bundle_rejects_tampered_compile_workdir_proof(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)

    def mutate(payload):
        payload["verification"]["compile_after"]["compile_workdir"] = (
            "a different workdir"
        )

    _mutate_verification(members, manifest, mutate)
    with pytest.raises(
        MODULE.AcceptanceError,
        match="same-workdir input closure",
    ):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_test_doubles_only_emit_fail_diagnostics(tmp_path: Path):
    class FakeApi:
        pass

    class FakeUi:
        pass

    config = _config(tmp_path)
    result = MODULE.run_analysis_acceptance(
        config,
        api=FakeApi(),
        ui_driver=FakeUi(),
        pdf_page_counter=lambda _path: 37,
    )
    attestation = json.loads(
        (config.output_dir / "analysis-attestation.json").read_text(encoding="utf-8")
    )

    assert result["acceptance_passed"] is False
    assert result["terminal_status"] == "UNVERIFIED"
    assert attestation["result"] == "FAIL"
    assert attestation["execution"]["real_execution"] is False
    assert not (config.output_dir / MODULE.AUDIT_ZIP_FILENAME).exists()
    with pytest.raises(MODULE.RELEASE_INTEGRITY.ReleaseIntegrityError):
        MODULE.RELEASE_INTEGRITY.verify_analysis_attestation(
            config.output_dir,
            expected_pages=37,
            version="2.0.0",
            commit=TEST_COMMIT,
        )


def test_unverified_audit_manifest_is_never_promoted(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)
    manifest["verification_status"] = "UNVERIFIED"

    with pytest.raises(MODULE.AcceptanceError, match="not VERIFIED"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=37,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )

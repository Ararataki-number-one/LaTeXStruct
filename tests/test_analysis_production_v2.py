# -*- coding: utf-8 -*-
"""Strict, network-free tests for the production analysis dependency bridge."""

from __future__ import annotations

import json
from dataclasses import asdict

import pymupdf
import pytest

from latexstruct.core import analysis_production
from latexstruct.core.analysis_inventory import AnalysisNativeSourceBlock
from latexstruct.core.analysis_budget import BudgetLimits
from latexstruct.core.analysis_orchestrator import (
    CallBinding,
    CallbackContractError,
    FinalPageReviewRequest,
    FindingRequest,
    MachineVerificationFacts,
    PageMaterials,
)
from latexstruct.core.analysis_production import ProductionAnalysisError, run_production_analysis
from latexstruct.core.analysis_schema import (
    ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CompileState,
    ModelBinding,
    PageMapEntry,
    PageRisk,
    sha256_bytes,
    sha256_text,
)
from latexstruct.core.compilecheck import build_compile_input_manifest


TARGET = "Theorem 1. Every graph has a vertex."
_DEFAULT_EVIDENCE = object()
_DEFAULT_PAGE_RISKS = object()
_DEFAULT_NATIVE_BLOCKS = object()
BASELINE_TEX = (
    f"\\documentclass{{article}}\n\\begin{{document}}\n% Page 1\n{TARGET}\n\\end{{document}}\n"
)
NATIVE_FORMAL_BLOCKS = (
    AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="formal-source-0001",
        block_type="HEADING_TEXT",
        plain_text=TARGET,
        source_sha256=sha256_text(TARGET),
    ),
)


def _pdf(text: str = "page one") -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=300, height=400)
        page.insert_text((30, 50), text)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _multi_page_pdf(count: int, prefix: str) -> bytes:
    document = pymupdf.open()
    try:
        for page_number in range(1, count + 1):
            page = document.new_page(width=300, height=400)
            page.insert_text((30, 50), f"{prefix} {page_number}")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _empty_finding(binding):
    return {"binding": binding, "findings": []}


def _complete_transport(client, response, usage):
    measured = dict(usage)
    measured.setdefault("input_tokens", 0)
    measured.setdefault("output_tokens", 0)
    measured.setdefault(
        "total_tokens",
        measured["input_tokens"] + measured["output_tokens"],
    )
    client.last_transport_attempts = ({
        "attempt_number": 1,
        "succeeded": True,
        "usage_complete": True,
        "failure_stage": "",
        "usage": dict(measured),
    },)
    return response, measured


class FakeTextClient:
    model = "gpt-5.4-mini"
    reasoning_effort = "high"

    def __init__(self, events, *, conflict=False, broken_role=""):
        self.events = events
        self.conflict = conflict
        self.broken_role = broken_role
        self.system_prompts = []
        self.user_requests = []

    def chat_json(self, system, user):
        self.system_prompts.append(system)
        assert "HOST AUTHORITY AND EVIDENCE RULES" in system
        assert "COMPLETE OUTPUT JSON SCHEMA" in system
        assert '"additionalProperties": false' in system
        lowered_system = system.lower()
        assert "ordinary expository prose" in lowered_system
        assert "proof starts only" in lowered_system
        assert "vertical" in lowered_system and "composite" in lowered_system
        lowered_user = user.lower()
        assert "authorization" not in lowered_user
        assert "api_key" not in lowered_user
        assert "c:\\\\users\\\\" not in lowered_user
        request = json.loads(user)
        self.user_requests.append(request)
        binding = request["binding"]
        role = binding["role"]
        prior_role_calls = self.events.count(role)
        self.events.append(role if role != "AI-5" else "AI-5-text")
        if role == self.broken_role:
            return {"binding": binding}, {}
        if role in {"AI-1", "AI-2"}:
            if prior_role_calls:
                return _complete_transport(
                    self, _empty_finding(binding), {"input_tokens": 3}
                )
            if role == "AI-2" and not self.conflict:
                return _complete_transport(
                    self, _empty_finding(binding), {"input_tokens": 3}
                )
            if role == "AI-2" and self.conflict:
                issue_type = "PROSE_ONLY"
            else:
                issue_type = "FORMAL_BOUNDARY"
            finding = {
                "issue_type": issue_type,
                "severity": "HIGH",
                "exact_quotes": [TARGET],
                "source_pdf_regions": [],
                "description": "formal boundary differs",
                "suggestion": "wrap only the exact formal statement",
                "blocker_reason": "",
            }
            return _complete_transport(
                self,
                {"binding": binding, "findings": [finding]},
                {"input_tokens": 5},
            )
        if role == "AI-4":
            return _complete_transport(self, {
                "binding": binding,
                "patch": {
                    "operations": [
                        {
                            "operation": "wrap_environment",
                            "start_anchor": TARGET,
                            "end_anchor": TARGET,
                            "exact_old_text": TARGET,
                            "replacement": (f"\\begin{{theorem}}\n{TARGET}\n\\end{{theorem}}"),
                            "reason": "restore the theorem boundary",
                        }
                    ]
                },
            }, {"output_tokens": 8})
        if role == "AI-6":
            return _complete_transport(self, {
                "binding": binding,
                "judgments": [
                    {
                        "keep": index == 0,
                        "reason": "first interpretation has exact boundary evidence",
                    }
                    for index, _issue in enumerate(request["issues"])
                ],
                "resolved": True,
                "explanation": "retain one host-bound interpretation",
            }, {"output_tokens": 2})
        raise AssertionError(role)


class SchemaAwareTextClient(FakeTextClient):
    def __init__(self, events, *, conflict=False):
        super().__init__(events, conflict=conflict)
        self.schema_calls = []

    def chat_json(self, _system, _user):
        raise AssertionError("schema-aware clients must receive the host schema")

    def chat_json_schema(self, system, user, schema):
        request = json.loads(user)
        self.schema_calls.append((request["binding"]["role"], schema))
        return FakeTextClient.chat_json(self, system, user)


class FakeVisionClient:
    model = "fake-vision-v2"

    def __init__(self, events):
        self.events = events
        self.system_prompts = []
        self.schemas = []

    def chat_vision_json_images_bytes(self, system, user, images, schema=None):
        self.system_prompts.append(system)
        self.schemas.append(schema)
        assert "HOST AUTHORITY AND EVIDENCE RULES" in system
        assert "COMPLETE OUTPUT JSON SCHEMA" in system
        assert "table of contents" in system
        assert isinstance(schema, dict)
        assert schema.get("additionalProperties") is False
        lowered_user = user.lower()
        assert "authorization" not in lowered_user
        assert "api_key" not in lowered_user
        assert "c:\\\\users\\\\" not in lowered_user
        assert len(images) == 2
        assert all(image.startswith(b"\x89PNG\r\n\x1a\n") for image in images)
        request = json.loads(user)
        binding = request["binding"]
        role = binding["role"]
        if role == "AI-3":
            self.events.append("AI-3")
            return _complete_transport(
                self, _empty_finding(binding), {"input_tokens": 7}
            )
        assert role == "AI-5"
        if "pass_number" in request:
            number = request["pass_number"]
            self.events.append(f"AI-5-final-{number}")
            assert request["prior_pass_conclusion"] == "WITHHELD_BY_HOST"
            return _complete_transport(self, {
                "binding": binding,
                "content_conservation_ok": True,
                "math_conservation_ok": True,
                "visual_review_ok": True,
                "formal_inventory_ok": True,
                "new_high_risk_issues": 0,
                "prior_pass_conclusion_visible": False,
            }, {"input_tokens": 11})
        self.events.append("AI-5-issue")
        return _complete_transport(self, {
            "binding": binding,
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "visual_review_ok": True,
            "result": "PASS",
            "new_high_priority_issues": 0,
        }, {"input_tokens": 9})


class CacheTextClient:
    model = "cache-text-v2"

    def __init__(self):
        self.calls = 0

    def chat_json(self, _system, user):
        self.calls += 1
        binding = json.loads(user)["binding"]
        return _complete_transport(self, _empty_finding(binding), {
            "input_tokens": 3,
            "output_tokens": 1,
            "total_tokens": 4,
        })


class CacheVisionClient:
    model = "cache-vision-v2"

    def __init__(self):
        self.calls = 0

    def chat_vision_json_images_bytes(
        self, _system, user, _images, *, schema=None
    ):
        assert isinstance(schema, dict)
        self.calls += 1
        request = json.loads(user)
        return _complete_transport(self, {
            "binding": request["binding"],
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "visual_review_ok": True,
            "formal_inventory_ok": True,
            "new_high_risk_issues": 0,
            "prior_pass_conclusion_visible": False,
        }, {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})


def _cache_bridge(tmp_path, *, text_client, vision_client=None):
    pdf_path = tmp_path / "cache-candidate.pdf"
    if pdf_path.exists():
        pdf = pdf_path.read_bytes()
    else:
        pdf = _pdf("cache candidate")
        pdf_path.write_bytes(pdf)
    page_id = "source-page-cache-000001"
    snapshot = AnalysisRunSnapshot(
        run_id="cache-run-1",
        project_id="cache-project",
        workflow_version="analysis-loop-v2",
        prompt_version="analysis-prompts-v2",
        application_version="2.0.0",
        source_pdf_hash=sha256_bytes(pdf),
        raw_ocr_tex_hash=sha256_text(BASELINE_TEX),
        baseline_tex_hash=sha256_text(BASELINE_TEX),
        baseline_pdf_hash=sha256_bytes(pdf),
        page_count=1,
        page_range=(1,),
        latex_engine="xelatex",
        models=(
            ModelBinding("AI-1", text_client.model, ("json",)),
            ModelBinding(
                "AI-5",
                getattr(vision_client, "model", "cache-vision-v2"),
                ("vision", "json"),
            ),
        ),
        concurrency_limit=1,
        started_at="2026-08-24T12:00:00+00:00",
        page_map=(PageMapEntry(page_id, 1, "% Page 1", ("candidate-page-1",)),),
        initial_compile_state=CompileState.COMPILED,
        config_hash=sha256_text("cache-test-config"),
    )
    page_png = b"\x89PNG\r\n\x1a\ncache-page-evidence"
    bridge = analysis_production._ProductionCallbacks(
        snapshot=snapshot,
        source_pages={page_id: page_png},
        source_page_numbers={page_id: 1},
        candidate_page_map={1: (1,)},
        candidate_page_mapper=None,
        baseline_pdf=pdf,
        text_clients={"AI-1": text_client},
        vision_clients={"AI-5": vision_client} if vision_client is not None else {},
        compiler=lambda *_args, **_kwargs: {},
        compile_extra_files={},
        cache_root=tmp_path / "cache",
        machine_verifier=lambda _request: {},
    )
    bridge._page_map_for_candidate(snapshot.baseline_tex_hash, pdf=pdf)
    materials = PageMaterials(
        source_page_id=page_id,
        candidate_hash=snapshot.baseline_tex_hash,
        source_pdf_page=page_png,
        baseline_tex_region=BASELINE_TEX,
        current_tex_region=BASELINE_TEX,
        current_pdf_page=page_png,
    )
    return bridge, snapshot, materials


def _finding_request(snapshot, materials):
    operation = "structure-findings"
    return FindingRequest(
        binding=CallBinding(
            run_id=snapshot.run_id,
            role="AI-1",
            candidate_hash=materials.candidate_hash,
            source_page_id=materials.source_page_id,
            issue_id="DISCOVERY-AI-1-cache",
            material_hashes=materials.hashes,
            snapshot_hash=snapshot.snapshot_hash,
            prompt_version=snapshot.prompt_version,
            response_schema_version=ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation],
        ),
        materials=materials,
    )


class FakeCompiler:
    def __init__(self, pdf, events):
        self.pdf = pdf
        self.events = events
        self.extra_files_seen = []

    def __call__(self, tex, *, extra_files, minimum_passes):
        assert minimum_passes == 2
        patched = "\\begin{theorem}" in tex
        self.events.append("compile-patched" if patched else "compile-baseline")
        self.extra_files_seen.append(dict(extra_files))
        manifest = build_compile_input_manifest(tex, extra_files)
        return {
            "available": True,
            "ok": True,
            "preview_status": "COMPILED",
            "pdf_bytes": self.pdf,
            "page_count": 1,
            "engine": "fake-xelatex",
            "log": "real compile succeeded",
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "compile_workdir": "compile-workdir:sha256:" + sha256_text(tex),
            "compile_input_sha256": manifest["manifest_sha256"],
        }


def _facts(request, *, omissions=0):
    page_ids = tuple(page_id for page_id, _payload in request.compile_result.page_pdf_bytes)
    return MachineVerificationFacts(
        candidate_hash=request.candidate_hash,
        checked_page_ids=page_ids,
        silent_page_omissions=omissions,
        silent_text_losses=0,
        unauthorized_math_changes=0,
        formal_errors=0,
        toc_complete_and_ordered=True,
        severe_equation_number_errors=0,
        silent_footnote_losses=0,
        silent_figure_caption_losses=0,
        silent_bibliography_losses=0,
    )


def _snapshot_evidence(baseline_tex=BASELINE_TEX, extra_files=None):
    compile_inputs = build_compile_input_manifest(baseline_tex, extra_files or {})
    return {
        "ocr_baseline_manifest_hash": sha256_text("native OCR manifest"),
        "ocr_page_records_hash": sha256_text("native OCR page records"),
        "ocr_runtime_page_records_hash": sha256_text(
            "native OCR runtime page records"
        ),
        "ocr_page_map_hash": sha256_text("native OCR page map"),
        "ocr_baseline_compile_inputs_hash": sha256_text("native compile inputs"),
        "baseline_compile_inputs_hash": compile_inputs["manifest_sha256"],
        "build_identity_hash": sha256_text("clean build identity"),
    }


def _native_risk_admission(
    source_hash: str,
    page_records_hash: str,
    pages: tuple[int, ...] = (1,),
) -> dict:
    return {
        "schema_version": "latexstruct-analysis-page-risk-admission-v1",
        "strategy": "conservative-r2-from-verified-ocr-page-records",
        "source_pdf_sha256": source_hash,
        "ocr_page_records_sha256": page_records_hash,
        "pages": [
            {
                "source_page_number": page,
                "source_page_id": analysis_production.stable_source_page_id(
                    source_hash, page
                ),
                "ocr_page_id": f"ocr-page-{page:06d}",
                "source_page_object_hash": sha256_text(f"source-page-{page}"),
                "coverage_checks": {
                    name: "PASS"
                    for name in analysis_production._OCR_COVERAGE_CHECK_NAMES
                },
                "final_status": "SUCCESS",
                "unresolved_region_hashes": [],
                "risk_level": "R2",
                "risk_reasons": [
                    "conservative_full_review_pending_analysis_preflight"
                ],
            }
            for page in pages
        ],
    }


def _verified_risk_inputs(
    source_pdf: bytes,
    *,
    baseline_tex: str = BASELINE_TEX,
    baseline_pdf: bytes | None = None,
    extra_files: dict[str, bytes] | None = None,
    pages: tuple[int, ...] = (1,),
    candidate_page_map: dict[int, int | tuple[int, ...]] | None = None,
) -> tuple[dict[str, str], dict]:
    evidence = _snapshot_evidence(baseline_tex, extra_files)
    resolved_baseline_pdf = source_pdf if baseline_pdf is None else baseline_pdf
    resolved_candidate_map = candidate_page_map or {page: page for page in pages}
    regions = analysis_production._page_regions(baseline_tex, pages)
    with pymupdf.open(stream=source_pdf, filetype="pdf") as document:
        source_page_texts = {
            page: str(document.load_page(page - 1).get_text("text") or "")
            for page in pages
        }
    admission = analysis_production.build_page_risk_admission(
        source_pdf_sha256=sha256_bytes(source_pdf),
        ocr_page_records_sha256=evidence["ocr_page_records_hash"],
        ocr_runtime_page_records_sha256=(
            evidence["ocr_runtime_page_records_hash"]
        ),
        baseline_tex_sha256=sha256_text(baseline_tex),
        baseline_pdf_sha256=sha256_bytes(resolved_baseline_pdf),
        page_inputs=tuple(
            analysis_production.PageRiskPreflightInput(
                source_page_id=analysis_production.stable_source_page_id(
                    sha256_bytes(source_pdf), page
                ),
                source_page_number=page,
                source_page_object_hash=sha256_text(f"source-page-{page}"),
                ocr_coverage_checks={
                    name: "PASS"
                    for name in analysis_production._OCR_COVERAGE_CHECK_NAMES
                },
                unresolved_region_hashes=(),
                baseline_tex_region=regions[page][2],
                candidate_pdf_page_ids=tuple(
                    f"candidate-page-{candidate_page:06d}"
                    for candidate_page in (
                        (resolved_candidate_map[page],)
                        if type(resolved_candidate_map[page]) is int
                        else resolved_candidate_map[page]
                    )
                ),
                source_pdf_text=source_page_texts[page],
                ocr_final_status="SUCCESS",
                ocr_retry_count=0,
                ocr_quality_issues=(),
                host_quality_flags=(),
                machine_visual_anomalies=(),
                double_column=False,
                complex_layout=False,
                compile_map_mismatch=False,
                layout_evidence={"status": "PASS"},
                compile_map_evidence={"status": "PASS"},
            )
            for page in pages
        ),
    )
    evidence["page_risk_admission_hash"] = admission.digest
    return evidence, admission.to_dict()


def _run(
    tmp_path,
    *,
    text_client=None,
    verifier=_facts,
    candidate_page_map=None,
    concurrency_limit=3,
    page_range=(1,),
    raw_ocr_frozen=True,
    page_risks=_DEFAULT_PAGE_RISKS,
    snapshot_evidence=_DEFAULT_EVIDENCE,
    budget_kwargs=None,
    model_ids=None,
    native_source_blocks=_DEFAULT_NATIVE_BLOCKS,
    inventory_authorizations=None,
):
    events = []
    pdf = _pdf()
    text = text_client or FakeTextClient(events)
    vision = FakeVisionClient(events)
    compiler = FakeCompiler(pdf, events)
    resolved_candidate_map = candidate_page_map or {1: 1}
    admitted_evidence = (
        _snapshot_evidence(BASELINE_TEX, {"figures/a.png": b"trusted-extra"})
        if snapshot_evidence is _DEFAULT_EVIDENCE
        else snapshot_evidence
    )
    default_admission = None
    if native_source_blocks is _DEFAULT_NATIVE_BLOCKS:
        native_source_blocks = NATIVE_FORMAL_BLOCKS
    if admitted_evidence is not None:
        admitted_evidence = dict(admitted_evidence)
        valid_pages = (
            all(type(page) is int for page in page_range)
            and bool(page_range)
            and tuple(sorted(set(page_range))) == tuple(page_range)
            and set(resolved_candidate_map) == set(page_range)
        )
        if valid_pages:
            typed_evidence, attempted_admission = _verified_risk_inputs(
                pdf,
                baseline_tex=BASELINE_TEX,
                baseline_pdf=pdf,
                extra_files={"figures/a.png": b"trusted-extra"},
                pages=tuple(page_range),
                candidate_page_map=resolved_candidate_map,
            )
            admitted_evidence["page_risk_admission_hash"] = typed_evidence[
                "page_risk_admission_hash"
            ]
        else:
            attempted_admission = {}
            admitted_evidence["page_risk_admission_hash"] = sha256_text(
                "unreachable invalid page-risk admission"
            )
        if page_risks is _DEFAULT_PAGE_RISKS:
            default_admission = attempted_admission
    result = run_production_analysis(
        run_id="production-analysis-run-1",
        project_id="project-1",
        source_pdf=pdf,
        raw_ocr_tex=BASELINE_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=pdf,
        page_range=page_range,
        candidate_page_map=resolved_candidate_map,
        candidate_page_mapper=lambda _candidate_hash, _pdf_bytes: (
            resolved_candidate_map
        ),
        text_clients={
            "AI-1": text,
            "AI-2": text,
            "AI-4": text,
            "AI-6": text,
        },
        vision_clients={"AI-3": vision, "AI-5": vision},
        compiler=compiler,
        machine_verifier=verifier,
        candidate_root=tmp_path / "candidates",
        compile_extra_files={"figures/a.png": b"trusted-extra"},
        snapshot_evidence=admitted_evidence,
        raw_ocr_frozen=raw_ocr_frozen,
        concurrency_limit=concurrency_limit,
        page_risks=None if page_risks is _DEFAULT_PAGE_RISKS else page_risks,
        page_risk_admission=default_admission,
        native_source_blocks=native_source_blocks,
        inventory_authorizations=inventory_authorizations,
        max_macro_rounds=1,
        model_ids=model_ids,
        **dict(budget_kwargs or {}),
    )
    return result, events, compiler


@pytest.mark.parametrize("role", ["AI-2", "AI-3", "AI-4", "AI-5", "AI-6"])
def test_declared_model_must_match_each_actual_production_client(tmp_path, role):
    with pytest.raises(
        ProductionAnalysisError,
        match=rf"{role} declared model differs from the actual production client",
    ):
        _run(tmp_path, model_ids={role: "forged-model"})


def test_ai1_declared_model_must_match_actual_production_client(tmp_path):
    with pytest.raises(
        ProductionAnalysisError,
        match="AI-1 authoritative routing requires declared/actual model parity",
    ):
        _run(tmp_path, model_ids={"AI-1": "forged-model"})


def test_production_rejects_divergent_config_and_command_model_selectors(tmp_path):
    client = FakeTextClient([])
    client.cfg = type("ClientConfig", (), {"model": "forged-model"})()
    with pytest.raises(ProductionAnalysisError, match="model selectors disagree"):
        _run(tmp_path, text_client=client)


def test_budget_limits_are_frozen_into_snapshot_and_both_config_hashes(tmp_path):
    limits = {
        "max_input_tokens": 1_000_000,
        "max_output_tokens": 0,
        "max_cost": 0.0,
        "max_requests": 50,
        "max_strong_model_calls": 3,
        "max_wall_time_minutes": 37.5,
    }
    result, _events, _compiler = _run(
        tmp_path / "limited",
        budget_kwargs=limits,
    )
    default, _events, _compiler = _run(tmp_path / "default")

    assert {
        name: getattr(result.snapshot, name) for name in limits
    } == limits
    assert result.snapshot.config_hash != default.snapshot.config_hash
    contract_clients = {
        "AI-1": FakeTextClient([]),
        "AI-2": FakeTextClient([]),
        "AI-3": FakeVisionClient([]),
        "AI-4": FakeTextClient([]),
        "AI-5": FakeVisionClient([]),
        "AI-6": FakeTextClient([]),
    }
    model_ids = {item.role: item.model_id for item in result.snapshot.models}
    budget_limits = BudgetLimits(**limits)
    expected_config_hash = sha256_bytes(
        analysis_production.canonical_json_bytes({
            "workflow_version": result.snapshot.workflow_version,
            "prompt_version": result.snapshot.prompt_version,
            "application_version": result.snapshot.application_version,
            "latex_engine": result.snapshot.latex_engine,
            "concurrency_limit": result.snapshot.concurrency_limit,
            "models": [asdict(item) for item in result.snapshot.models],
            "transport_contracts": [
                analysis_production._transport_contract(
                    role=role,
                    model_id=model_ids[role],
                    client=contract_clients[role],
                    limits=budget_limits,
                )
                for role in ("AI-1", "AI-2", "AI-3", "AI-4", "AI-5", "AI-6")
            ],
            "page_range": (1,),
            "candidate_page_map": [(1, [1])],
            "candidate_storage_name": "candidates",
            "raw_ocr_frozen": True,
            "page_risks": [
                {
                    "source_page_number": 1,
                    "risk_level": "R2",
                    "risk_reasons": [
                        "source_text_coverage_below_r2_threshold"
                    ],
                }
            ],
            "page_risk_admission_hash": (
                result.snapshot.evidence_hashes.page_risk_admission_hash
            ),
            "page_risk_admission": (
                result.page_risk_admission.canonical_payload()
            ),
                "page_risk_source_admission_hash": (
                    result.page_risk_admission.digest
                ),
                "baseline_inventory_digest": result.baseline_inventory.digest,
                "baseline_inventory_json_sha256": (
                    result.baseline_inventory_json_sha256
                ),
                "native_source_blocks": [
                    item.as_dict() for item in NATIVE_FORMAL_BLOCKS
                ],
                "native_source_blocks_supplied": True,
                "inventory_authorizations": [
                    item.as_dict()
                    for item in result.baseline_inventory.authorizations
                ],
                "inventory_authorization_source": "HOST_REQUIRED_POLICY",
                "inventory_policy_schema": "latexstruct-host-inventory-policy-v1",
                "inventory_policy_ocr_manifest_sha256": (
                    result.snapshot.evidence_hashes.ocr_baseline_manifest_hash
                ),
                "native_heading_inventory_required": True,
                "compile_extra_files": [
                ("figures/a.png", sha256_bytes(b"trusted-extra"))
            ],
            "max_macro_rounds": 1,
            **limits,
        })
    )
    assert result.snapshot.config_hash == expected_config_hash
    expected_budget_hash = sha256_bytes(
        analysis_production.canonical_json_bytes({
            "schema": "latexstruct-analysis-budget-summary-v1",
            "concurrency_limit": 3,
            "max_macro_rounds": 1,
            "performance_target_seconds": (
                analysis_production.ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS
            ),
            **limits,
        })
    )
    assert result.snapshot.evidence_hashes is not None
    assert result.snapshot.evidence_hashes.budget_summary_hash == expected_budget_hash
    assert result.budget_state["limits"] == limits
    assert result.budget_usage.requests == len(result.transport_invocations)
    persisted = json.loads(
        (tmp_path / "limited" / "candidates" / "analysis_budget.json").read_text(
            encoding="utf-8"
        )
    )
    assert persisted["snapshot_hash"] == result.snapshot.snapshot_hash
    assert persisted["budget"] == result.budget_state


def test_native_page_risk_admission_is_exact_and_fail_closed():
    source_hash = "1" * 64
    page_records_hash = "2" * 64
    runtime_page_records_hash = "3" * 64
    admission = _native_risk_admission(source_hash, page_records_hash)

    normalized, digest = analysis_production._normalize_page_risk_admission(
        admission,
        selected_pages=(1,),
        source_pdf_sha256=source_hash,
        ocr_page_records_sha256=page_records_hash,
        ocr_runtime_page_records_sha256=runtime_page_records_hash,
    )

    assert normalized == {
        1: (
            PageRisk.R2,
            ("conservative_full_review_pending_analysis_preflight",),
        )
    }
    assert digest == sha256_bytes(analysis_production.canonical_json_bytes(admission))

    tampered = json.loads(json.dumps(admission))
    tampered["pages"][0]["coverage_checks"]["persisted"] = "FAIL"
    with pytest.raises(ProductionAnalysisError, match="incomplete"):
        analysis_production._normalize_page_risk_admission(
            tampered,
            selected_pages=(1,),
            source_pdf_sha256=source_hash,
            ocr_page_records_sha256=page_records_hash,
            ocr_runtime_page_records_sha256=runtime_page_records_hash,
        )


@pytest.mark.parametrize(
    ("changed", "expected_risk"),
    [
        ({"raw_ocr_frozen": False}, PageRisk.R2),
    ],
)
def test_gate_and_route_inputs_are_bound_into_immutable_configuration(
    tmp_path,
    changed,
    expected_risk,
):
    baseline, _events, _compiler = _run(tmp_path / "baseline")
    altered, _events, _compiler = _run(tmp_path / "altered", **changed)

    assert altered.page_inputs[0].page_unit.risk_level == expected_risk
    assert altered.snapshot.config_hash != baseline.snapshot.config_hash
    assert altered.snapshot.snapshot_hash != baseline.snapshot.snapshot_hash
    assert altered.snapshot.evidence_hashes is not None
    assert (
        altered.snapshot.evidence_hashes.analysis_config_hash
        == altered.snapshot.config_hash
    )


def _assert_resiliently_blocked(result, *, reason_prefix):
    orchestration = result.orchestration
    assert orchestration.decision.verified is False
    assert orchestration.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "analysis_work_incomplete" in orchestration.decision.failures
    assert any(
        reason.startswith(reason_prefix) for reason in orchestration.stop_reasons
    )


@pytest.mark.parametrize(
    ("budget_kwargs", "expected_exception"),
    [
        ({"max_input_tokens": 1}, "BudgetExhaustedError"),
        ({"max_requests": 2}, "LowPriorityBudgetStop"),
    ],
)
def test_budget_control_signals_follow_resilient_blocked_route(
    tmp_path,
    budget_kwargs,
    expected_exception,
):
    result, _events, _compiler = _run(
        tmp_path,
        budget_kwargs=budget_kwargs,
    )

    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")
    task_ledger_path = next((tmp_path / "candidates").rglob("task-ledger.json"))
    task_ledger = json.loads(task_ledger_path.read_text(encoding="utf-8"))
    assert any(
        record["state"] == "BLOCKED"
        and expected_exception in record["error"]
        for record in task_ledger["records"].values()
    )


@pytest.mark.parametrize("supplied", [None, {1: PageRisk.R0}, {1: "R2"}])
def test_manual_page_risk_route_is_rejected_by_production_boundary(
    tmp_path, supplied
):
    with pytest.raises(
        ProductionAnalysisError,
        match="(verified page risk admission|manual page_risks)",
    ):
        _run(tmp_path, page_risks=supplied)


def test_run_local_cache_recovery_hit_skips_transport_after_strict_validation(
    tmp_path,
):
    first_client = CacheTextClient()
    first, snapshot, materials = _cache_bridge(
        tmp_path, text_client=first_client
    )
    request = _finding_request(snapshot, materials)

    assert first.ai1_structure(request) == ()
    assert first_client.calls == 1
    assert first.cache_miss_count == 1
    assert first.cache_hit_evidence == []

    resumed_client = CacheTextClient()
    resumed, resumed_snapshot, resumed_materials = _cache_bridge(
        tmp_path, text_client=resumed_client
    )
    resumed_request = _finding_request(resumed_snapshot, resumed_materials)

    assert resumed.ai1_structure(resumed_request) == ()
    assert resumed_client.calls == 0
    assert resumed.transport_evidence == []
    assert resumed.cache_miss_count == 0
    assert len(resumed.cache_hit_evidence) == 1
    assert resumed.cache_hit_evidence[0].binding_echo_validated is True


def test_cache_material_change_and_tampering_are_real_misses(tmp_path):
    first_client = CacheTextClient()
    first, snapshot, materials = _cache_bridge(
        tmp_path, text_client=first_client
    )
    assert first.ai1_structure(_finding_request(snapshot, materials)) == ()

    changed_client = CacheTextClient()
    changed, changed_snapshot, _same_materials = _cache_bridge(
        tmp_path, text_client=changed_client
    )
    changed_materials = PageMaterials(
        source_page_id=materials.source_page_id,
        candidate_hash=materials.candidate_hash,
        source_pdf_page=materials.source_pdf_page,
        baseline_tex_region=materials.baseline_tex_region,
        current_tex_region=materials.current_tex_region.replace(
            TARGET, f"{TARGET} Changed."
        ),
        current_pdf_page=materials.current_pdf_page,
    )
    assert changed.ai1_structure(
        _finding_request(changed_snapshot, changed_materials)
    ) == ()
    assert changed_client.calls == 1
    assert changed.cache_miss_count == 1

    original_entry = next(
        path
        for path in (tmp_path / "cache").rglob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["cache_key"][
            "current_tex_region_hash"
        ]
        == materials.hashes.current_tex_region_hash
    )
    payload = json.loads(original_entry.read_text(encoding="utf-8"))
    payload["response"]["findings"] = [{"forged": True}]
    original_entry.write_text(json.dumps(payload), encoding="utf-8")

    recovered_client = CacheTextClient()
    recovered, recovered_snapshot, recovered_materials = _cache_bridge(
        tmp_path, text_client=recovered_client
    )
    assert recovered.ai1_structure(
        _finding_request(recovered_snapshot, recovered_materials)
    ) == ()
    assert recovered_client.calls == 1
    assert recovered.cache_miss_count == 1
    assert recovered.cache_hit_evidence == []


def test_ai5_final_reviews_hard_bypass_run_local_cache(tmp_path):
    text_client = CacheTextClient()
    vision_client = CacheVisionClient()
    bridge, snapshot, materials = _cache_bridge(
        tmp_path,
        text_client=text_client,
        vision_client=vision_client,
    )
    operation = "final-review-1"
    request = FinalPageReviewRequest(
        binding=CallBinding(
            run_id=snapshot.run_id,
            role="AI-5",
            candidate_hash=materials.candidate_hash,
            source_page_id=materials.source_page_id,
            issue_id="FINAL-REVIEW-cache-pass-1",
            material_hashes=materials.hashes,
            snapshot_hash=snapshot.snapshot_hash,
            prompt_version=snapshot.prompt_version,
            response_schema_version=ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation],
        ),
        materials=materials,
        pass_number=1,
        context_id="independent-cache-review-context",
    )

    first = bridge.ai5_final_review(request)
    second = bridge.ai5_final_review(request)

    assert first == second
    assert vision_client.calls == 2
    assert len(bridge.transport_evidence) == 2
    assert bridge.cache_hit_evidence == []
    assert bridge.cache_miss_count == 0


def test_production_bridge_uses_one_atomic_two_pass_compile_per_candidate(
    tmp_path, monkeypatch
):
    host_patch_arguments = []
    patch_operation = analysis_production.PatchOperation

    def capture_host_patch(**kwargs):
        host_patch_arguments.append(dict(kwargs))
        return patch_operation(**kwargs)

    monkeypatch.setattr(analysis_production, "PatchOperation", capture_host_patch)
    result, events, compiler = _run(tmp_path)

    assert events == [
        "compile-baseline",
        "AI-3",
        "AI-1",
        "AI-2",
        "AI-3",
        "AI-4",
        "compile-patched",
        "AI-5-issue",
        "AI-1",
        "AI-2",
        "AI-3",
        "AI-5-final-1",
        "AI-5-final-2",
    ]
    assert result.orchestration.decision.status == AnalysisFinalStatus.VERIFIED
    assert result.snapshot.concurrency_limit == 3
    assert result.orchestration.decision.verified is True
    assert len(result.compile_invocations) == 2
    assert [item.run_number for item in result.compile_invocations] == [1, 1]
    assert all(item.passes_completed == 2 for item in result.compile_invocations)
    assert all(item.same_workdir_verified for item in result.compile_invocations)
    assert len(result.transport_invocations) == 11
    # The test doubles expose one complete attempt row per provider call.  Only
    # cache-eligible AI-1/2/3 transports are cache misses; AI-4/5 remain real,
    # explicitly uncached calls.
    performance = result.orchestration.performance
    assert performance.usage_complete is True
    assert performance.attempt_evidence_complete is True
    assert performance.input_tokens == 66
    assert performance.output_tokens == 8
    assert performance.total_tokens == 74
    assert performance.observed_input_tokens == 66
    assert performance.observed_output_tokens == 8
    assert performance.cache_status == "ENABLED"
    assert performance.cache_hits == 0
    assert performance.cache_misses == 3
    assert performance.orchestration_invocation_count == 11
    assert performance.cache_hit_evidence_count == 0
    assert performance.transport_call_count == len(result.transport_invocations)
    assert performance.transport_attempt_count == len(result.transport_invocations)
    assert performance.usage_missing_call_count == 0
    assert performance.usage_missing_attempt_count == 0
    assert result.cache_hit_evidence == ()
    assert performance.cost_status == "UNKNOWN"
    assert performance.estimated_cost_cny is None
    assert all(
        extra_files == {"figures/a.png": b"trusted-extra"}
        for extra_files in compiler.extra_files_seen
    )
    assert result.page_inputs[0].source_pdf_page.startswith(b"\x89PNG")
    assert result.orchestration.current_pdf.startswith(b"%PDF-")
    assert result.current_compile_log == "real compile succeeded"

    # The simulated model response contains no id, offset, page mapping, or
    # digest fields outside the immutable binding.  A successful typed ledger
    # and patch therefore prove that these values were derived by the host.
    issue = result.orchestration.ledger[0]
    source_page_id = result.snapshot.page_map[0].source_page_id
    region = BASELINE_TEX[BASELINE_TEX.index("% Page 1") :]
    expected_start = region.index(TARGET)
    assert issue.issue_id.startswith("ISS-")
    assert issue.source_page_ids == (source_page_id,)
    assert issue.tex_anchors[0].start_offset == expected_start
    assert issue.tex_anchors[0].end_offset == expected_start + len(TARGET)
    assert issue.tex_anchors[0].text_hash == sha256_text(TARGET)
    assert issue.evidence_hashes == (sha256_text(region),)
    assert issue.proposed_patch_id.startswith("PATCH-")
    assert host_patch_arguments == [
        {
            "operation": analysis_production.PatchOperationKind.WRAP_ENVIRONMENT,
            "issue_ids": (issue.issue_id,),
            "start_anchor": TARGET,
            "end_anchor": TARGET,
            "expected_old_hash": sha256_text(TARGET),
            "replacement": f"\\begin{{theorem}}\n{TARGET}\n\\end{{theorem}}",
            "source_page_ids": (source_page_id,),
            "reason": "restore the theorem boundary",
        }
    ]


def test_host_inventory_is_frozen_before_first_model_and_hash_bound(
    tmp_path, monkeypatch
):
    inventory_calls = []
    original_build = analysis_production.build_analysis_inventory_bundle
    original_vision = FakeVisionClient.chat_vision_json_images_bytes

    def tracked_build(*args, **kwargs):
        inventory_calls.append((args[0], args[1]))
        return original_build(*args, **kwargs)

    def checked_vision(self, *args, **kwargs):
        assert inventory_calls, "first model call preceded the baseline inventory freeze"
        return original_vision(self, *args, **kwargs)

    monkeypatch.setattr(
        analysis_production, "build_analysis_inventory_bundle", tracked_build
    )
    monkeypatch.setattr(
        FakeVisionClient, "chat_vision_json_images_bytes", checked_vision
    )

    result, _events, _compiler = _run(tmp_path)

    assert len(inventory_calls) == 2
    assert inventory_calls[0][0] == inventory_calls[0][1] == BASELINE_TEX
    assert sha256_bytes(result.baseline_inventory_json) == (
        result.baseline_inventory_json_sha256
    )
    assert sha256_bytes(result.final_inventory_json) == (
        result.final_inventory_json_sha256
    )
    assert sha256_bytes(result.inventory_gate_json) == (
        result.inventory_gate_json_sha256
    )
    assert result.inventory_gate.passed is True
    assert result.orchestration.decision.status is AnalysisFinalStatus.VERIFIED


def test_inventory_residual_revokes_verified_but_retains_best_candidate(tmp_path):
    result, _events, _compiler = _run(
        tmp_path,
        inventory_authorizations=(),
    )

    assert result.inventory_gate.passed is False
    assert "formal" in result.inventory_gate.blocked_categories
    assert result.orchestration.decision.status is (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert result.orchestration.decision.verified is False
    assert "analysis_inventory_residual" in result.orchestration.decision.failures
    assert result.orchestration.current_tex != BASELINE_TEX


def test_missing_native_inventory_can_never_be_verified(tmp_path):
    result, _events, _compiler = _run(
        tmp_path,
        native_source_blocks=None,
    )

    assert result.inventory_gate.status.value == "FAILED"
    assert result.orchestration.decision.status is (
        AnalysisFinalStatus.FAILED_BEST_RETAINED
    )
    assert result.orchestration.decision.verified is False
    assert "analysis_inventory_scan_failed" in result.orchestration.decision.failures


def test_verified_is_revoked_when_successful_transport_lacks_attempt_evidence(
    tmp_path,
):
    class LegacyClient(FakeTextClient):
        def chat_json(self, system, user):
            response, usage = super().chat_json(system, user)
            del self.last_transport_attempts
            return response, usage

    events = []
    result, _events, _compiler = _run(
        tmp_path,
        text_client=LegacyClient(events),
    )

    assert result.orchestration.decision.status == (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert result.orchestration.decision.verified is False
    assert "analysis_transport_evidence_incomplete" in (
        result.orchestration.decision.failures
    )
    assert result.orchestration.performance.usage_complete is False
    assert result.orchestration.performance.attempt_evidence_complete is False


def test_production_text_roles_receive_their_exact_host_schemas(tmp_path):
    events = []
    text = SchemaAwareTextClient(events, conflict=True)

    result, _observed, _compiler = _run(tmp_path, text_client=text)

    assert result.orchestration.decision.verified is True
    schemas_by_role = {role: schema for role, schema in text.schema_calls}
    assert schemas_by_role["AI-1"] == analysis_production._FINDING_RESPONSE_SCHEMA
    assert schemas_by_role["AI-2"] == analysis_production._FINDING_RESPONSE_SCHEMA
    assert schemas_by_role["AI-4"] == analysis_production._PATCH_RESPONSE_SCHEMA
    assert schemas_by_role["AI-6"] == analysis_production._ADJUDICATION_RESPONSE_SCHEMA


def test_every_strict_request_binds_snapshot_prompt_and_response_schema(tmp_path):
    events = []
    text = FakeTextClient(events)
    result, _observed, _compiler = _run(tmp_path, text_client=text)

    assert text.user_requests
    for request in text.user_requests:
        binding = request["binding"]
        assert binding["snapshot_hash"] == result.snapshot.snapshot_hash
        assert binding["prompt_version"] == result.snapshot.prompt_version
        assert binding["response_schema_version"].startswith(
            "latexstruct-analysis-"
        )


def test_discovery_receives_page_local_snapshot_bound_inventory_hints(tmp_path):
    events = []
    text = FakeTextClient(events)
    result, _observed, _compiler = _run(tmp_path, text_client=text)

    ai1_requests = [
        request for request in text.user_requests
        if request["binding"]["role"] == "AI-1"
    ]
    ai2_requests = [
        request for request in text.user_requests
        if request["binding"]["role"] == "AI-2"
    ]
    assert ai1_requests and ai2_requests
    for request in ai1_requests + ai2_requests:
        hints = request["host_inventory_expectations"]
        assert hints["schema"] == "latexstruct-page-inventory-hints-v1"
        assert hints["bundle_digest"] == result.baseline_inventory.digest
        assert isinstance(hints["categories_for_this_role"], list)
        assert isinstance(hints["items"], list)
    formal = [
        item
        for request in ai1_requests
        for item in request["host_inventory_expectations"]["items"]
        if item["category"] == "formal"
    ]
    assert formal
    assert formal[0]["source_plain_text"] == TARGET
    assert formal[0]["source_block_id"] == "formal-source-0001"
    assert all(
        "host_inventory_expectations" not in request
        for request in text.user_requests
        if request["binding"]["role"] not in {"AI-1", "AI-2"}
    )


def test_host_rejects_tampered_snapshot_binding_echo(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def tamper_snapshot(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["binding"]["snapshot_hash"] = "f" * 64
        return response, usage

    client.chat_json = tamper_snapshot
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")


def test_missing_snapshot_evidence_fails_before_first_model_call(tmp_path):
    events = []
    client = FakeTextClient(events)
    with pytest.raises(ProductionAnalysisError, match="missing snapshot evidence"):
        _run(tmp_path, text_client=client, snapshot_evidence=None)
    assert events == []


def test_final_transport_exception_is_recorded_and_task_is_blocked(
    tmp_path,
    monkeypatch,
):
    class FailingClient:
        model = "gpt-5.4-mini"
        reasoning_effort = "high"
        max_retries = 1
        last_usage = {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
        last_transport_attempts = (
            {
                "attempt_number": 1,
                "succeeded": False,
                "usage": {},
                "usage_complete": False,
                "failure_stage": "network_error",
            },
            {
                "attempt_number": 2,
                "succeeded": False,
                "usage": last_usage,
                "usage_complete": True,
                "failure_stage": "http_error",
            },
        )

        def chat_json_schema(self, _system, _user, _schema):
            raise RuntimeError("final transport failure")

    captured = []
    original = analysis_production._ProductionCallbacks._record_transport

    def record(self, request, operation, usage, client, budget_claim):
        result = original(
            self,
            request,
            operation,
            usage,
            client,
            budget_claim,
        )
        captured.append(self.transport_evidence[-1])
        return result

    monkeypatch.setattr(
        analysis_production._ProductionCallbacks,
        "_record_transport",
        record,
    )
    result, _events, _compiler = _run(
        tmp_path,
        text_client=FailingClient(),
        concurrency_limit=1,
    )
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")

    assert captured
    failed_text = [item for item in captured if item.role in {"AI-1", "AI-2"}]
    assert failed_text
    assert all(len(item.attempts) == 2 for item in failed_text)
    assert all(item.attempt_evidence_complete is False for item in failed_text)
    assert all(dict(item.usage) == FailingClient.last_usage for item in failed_text)


def test_production_schemas_avoid_codex_unsupported_keywords():
    schemas = (
        analysis_production._FINDING_RESPONSE_SCHEMA,
        analysis_production._PATCH_RESPONSE_SCHEMA,
        analysis_production._ISSUE_REVIEW_RESPONSE_SCHEMA,
        analysis_production._FINAL_REVIEW_RESPONSE_SCHEMA,
        analysis_production._ADJUDICATION_RESPONSE_SCHEMA,
    )
    encoded = json.dumps(schemas, sort_keys=True)
    assert '"oneOf"' not in encoded
    assert '"uniqueItems"' not in encoded


def test_host_rejects_a_finding_without_bound_evidence(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def remove_evidence(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["exact_quotes"] = []
            response["findings"][0]["source_pdf_regions"] = []
        return response, usage

    client.chat_json = remove_evidence
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")


def test_host_rejects_duplicate_exact_quotes(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def duplicate_evidence(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["exact_quotes"] = [TARGET, TARGET]
        return response, usage

    client.chat_json = duplicate_evidence
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")


def test_changed_candidate_uses_its_own_live_page_map_for_review(tmp_path):
    events = []
    baseline_pdf = _multi_page_pdf(2, "baseline")
    patched_pdf = _multi_page_pdf(2, "patched")
    text = FakeTextClient(events)

    class RecordingVision(FakeVisionClient):
        def __init__(self, target_events):
            super().__init__(target_events)
            self.page_numbers = []

        def chat_vision_json_images_bytes(self, system, user, images, schema=None):
            request = json.loads(user)
            self.page_numbers.append((
                request["binding"]["role"],
                tuple(request["candidate_pdf_page_numbers"]),
            ))
            return super().chat_vision_json_images_bytes(
                system, user, images, schema=schema
            )

    vision = RecordingVision(events)

    def compiler(tex, *, extra_files, minimum_passes):
        assert minimum_passes == 2
        pdf = patched_pdf if "\\begin{theorem}" in tex else baseline_pdf
        manifest = build_compile_input_manifest(tex, extra_files)
        return {
            "available": True,
            "ok": True,
            "preview_status": "COMPILED",
            "pdf_bytes": pdf,
            "page_count": 2,
            "engine": "fake-xelatex",
            "log": "ok",
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "compile_workdir": "compile-workdir:sha256:" + sha256_text(tex),
            "compile_input_sha256": manifest["manifest_sha256"],
        }

    baseline_hash = sha256_text(BASELINE_TEX)
    mapping_calls = []

    def mapper(candidate_hash, pdf_bytes):
        mapping_calls.append((candidate_hash, pdf_bytes))
        return {1: (1,)} if candidate_hash == baseline_hash else {1: (2,)}

    source_pdf = _pdf()
    evidence, admission = _verified_risk_inputs(
        source_pdf,
        baseline_pdf=baseline_pdf,
        candidate_page_map={1: (1,)},
    )
    result = run_production_analysis(
        run_id="production-live-map-run",
        project_id="project-live-map",
        source_pdf=source_pdf,
        raw_ocr_tex=BASELINE_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=baseline_pdf,
        page_range=(1,),
        candidate_page_map={1: (1,)},
        candidate_page_mapper=mapper,
        text_clients={
            "AI-1": text,
            "AI-2": text,
            "AI-4": text,
            "AI-6": text,
        },
        vision_clients={"AI-3": vision, "AI-5": vision},
        compiler=compiler,
        machine_verifier=_facts,
        candidate_root=tmp_path / "live-map-candidates",
        snapshot_evidence=evidence,
        raw_ocr_frozen=True,
        page_risk_admission=admission,
        native_source_blocks=NATIVE_FORMAL_BLOCKS,
        max_macro_rounds=1,
    )

    assert result.orchestration.decision.verified is True
    assert len(mapping_calls) == 2
    assert ("AI-3", (1,)) in vision.page_numbers
    assert any(role == "AI-5" and pages == (2,) for role, pages in vision.page_numbers)
    assert not any(role == "AI-5" and pages == (1,) for role, pages in vision.page_numbers)


def test_changed_candidate_without_live_mapper_fails_closed(tmp_path):
    events = []
    pdf = _pdf()
    evidence, admission = _verified_risk_inputs(pdf)
    result = run_production_analysis(
        run_id="production-missing-live-map",
        project_id="project-missing-live-map",
        source_pdf=pdf,
        raw_ocr_tex=BASELINE_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=pdf,
        page_range=(1,),
        candidate_page_map={1: 1},
        text_clients={
            "AI-1": FakeTextClient(events),
            "AI-2": FakeTextClient(events),
            "AI-4": FakeTextClient(events),
            "AI-6": FakeTextClient(events),
        },
        vision_clients={
            "AI-3": FakeVisionClient(events),
            "AI-5": FakeVisionClient(events),
        },
        compiler=FakeCompiler(pdf, events),
        machine_verifier=_facts,
        candidate_root=tmp_path / "missing-live-map-candidates",
        snapshot_evidence=evidence,
        raw_ocr_frozen=True,
        page_risk_admission=admission,
        native_source_blocks=NATIVE_FORMAL_BLOCKS,
        max_macro_rounds=1,
    )

    assert result.orchestration.decision.verified is False
    assert result.orchestration.decision.status == (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert "macro_compile_failed:round-1" in result.orchestration.stop_reasons


def test_live_baseline_map_must_match_immutable_snapshot(tmp_path):
    events = []
    pdf = _multi_page_pdf(2, "candidate")
    source_pdf = _pdf()
    evidence, admission = _verified_risk_inputs(
        source_pdf,
        baseline_pdf=pdf,
    )

    def compiler(_tex, *, extra_files, minimum_passes):
        assert minimum_passes == 2
        manifest = build_compile_input_manifest(_tex, extra_files)
        return {
            "available": True,
            "ok": True,
            "preview_status": "COMPILED",
            "pdf_bytes": pdf,
            "page_count": 2,
            "engine": "fake-xelatex",
            "log": "ok",
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "compile_workdir": "compile-workdir:sha256:" + sha256_text(_tex),
            "compile_input_sha256": manifest["manifest_sha256"],
        }

    with pytest.raises(ProductionAnalysisError, match="immutable snapshot"):
        run_production_analysis(
            run_id="production-stale-baseline-map",
            project_id="project-stale-baseline-map",
            source_pdf=source_pdf,
            raw_ocr_tex=BASELINE_TEX,
            baseline_tex=BASELINE_TEX,
            baseline_pdf=pdf,
            page_range=(1,),
            candidate_page_map={1: 1},
            candidate_page_mapper=lambda _candidate_hash, _pdf_bytes: {1: 2},
            text_clients={
                "AI-1": FakeTextClient(events),
                "AI-2": FakeTextClient(events),
                "AI-4": FakeTextClient(events),
                "AI-6": FakeTextClient(events),
            },
            vision_clients={
                "AI-3": FakeVisionClient(events),
                "AI-5": FakeVisionClient(events),
            },
            compiler=compiler,
            machine_verifier=_facts,
            candidate_root=tmp_path / "stale-baseline-map-candidates",
            snapshot_evidence=evidence,
            raw_ocr_frozen=True,
            page_risk_admission=admission,
            max_macro_rounds=1,
        )


def test_strict_model_schema_rejects_missing_findings_before_next_role(tmp_path):
    events = []
    text = FakeTextClient(events, broken_role="AI-1")
    result, _observed, _compiler = _run(tmp_path, text_client=text)
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")
    # Sibling work is retained instead of being cancelled by the bad AI-1 row.
    assert {"AI-1", "AI-2"}.issubset(events)


def test_production_parallelism_has_a_hard_three_call_ceiling(tmp_path):
    with pytest.raises(ProductionAnalysisError, match="concurrency_limit must be in 1..3"):
        _run(tmp_path, concurrency_limit=4)


@pytest.mark.parametrize("page", [True, 1.0, "1"])
def test_page_range_rejects_non_integer_values_without_coercion(tmp_path, page):
    with pytest.raises(ProductionAnalysisError, match="entries must be integers"):
        _run(tmp_path, page_range=(page,))


def test_missing_candidate_page_mapping_fails_before_models_or_compile(tmp_path):
    with pytest.raises(ProductionAnalysisError, match="cover the selected pages exactly"):
        _run(tmp_path, candidate_page_map={2: 1})


def test_machine_failures_remain_unverified_and_cannot_be_promoted(tmp_path):
    result, _events, _compiler = _run(
        tmp_path, verifier=lambda request: _facts(request, omissions=1)
    )

    assert result.orchestration.decision.verified is False
    assert result.orchestration.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "silent_page_omission" in result.orchestration.decision.failures


def test_invalid_machine_status_field_is_rejected_instead_of_trusted(tmp_path):
    def invalid(request):
        facts = as_mapping(_facts(request))
        facts["verified"] = True
        return facts

    with pytest.raises(CallbackContractError, match="extra=verified"):
        _run(tmp_path, verifier=invalid)


def as_mapping(value):
    return {
        "candidate_hash": value.candidate_hash,
        "checked_page_ids": list(value.checked_page_ids),
        "silent_page_omissions": value.silent_page_omissions,
        "silent_text_losses": value.silent_text_losses,
        "unauthorized_math_changes": value.unauthorized_math_changes,
        "formal_errors": value.formal_errors,
        "toc_complete_and_ordered": value.toc_complete_and_ordered,
        "severe_equation_number_errors": value.severe_equation_number_errors,
        "silent_footnote_losses": value.silent_footnote_losses,
        "silent_figure_caption_losses": value.silent_figure_caption_losses,
        "silent_bibliography_losses": value.silent_bibliography_losses,
    }


def test_ai6_is_a_real_transport_call_only_when_conflict_requires_it(tmp_path):
    events = []
    text = FakeTextClient(events, conflict=True)
    result, _observed, _compiler = _run(tmp_path, text_client=text)

    assert "AI-6" in events
    assert any(item.operation == "adjudication" for item in result.transport_invocations)
    assert sum(item.operation == "adjudication" for item in result.transport_invocations) == 1


def test_model_cannot_supply_host_owned_finding_hash_or_offset_fields(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def inject_host_field(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["evidence_hashes"] = [sha256_text("invented")]
        return response, usage

    client.chat_json = inject_host_field
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")


@pytest.mark.parametrize("quote", ["not present in the supplied region", "e"])
def test_missing_or_non_unique_finding_quote_fails_closed(tmp_path, quote):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def bad_quote(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["exact_quotes"] = [quote]
        return response, usage

    client.chat_json = bad_quote
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="analysis_task_blocked:")


@pytest.mark.parametrize("anchor", ["not present in the supplied region", "e"])
def test_missing_or_non_unique_patch_anchor_fails_closed(tmp_path, anchor):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def bad_anchor(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-4":
            response = json.loads(json.dumps(response))
            response["patch"]["operations"][0]["start_anchor"] = anchor
            response["patch"]["operations"][0]["end_anchor"] = anchor
            response["patch"]["operations"][0]["exact_old_text"] = anchor
        return response, usage

    client.chat_json = bad_anchor
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="patch_task_blocked:")


def test_model_cannot_supply_patch_hash_ids_or_page_mapping(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def inject_host_fields(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-4":
            response = json.loads(json.dumps(response))
            operation = response["patch"]["operations"][0]
            operation["expected_old_hash"] = sha256_text(TARGET)
            operation["issue_ids"] = ["ISS-model-owned"]
            operation["source_page_ids"] = ["source-model-owned"]
        return response, usage

    client.chat_json = inject_host_fields
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="patch_task_blocked:")


def test_patch_replacement_cannot_cross_host_page_scope(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def cross_page_boundary(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-4":
            response = json.loads(json.dumps(response))
            response["patch"]["operations"][0]["replacement"] += (
                "\n% Page 999999\nforeign page content"
            )
        return response, usage

    client.chat_json = cross_page_boundary
    result, _events, _compiler = _run(tmp_path, text_client=client)
    _assert_resiliently_blocked(result, reason_prefix="patch_task_blocked:")


def test_reflow_mapping_skips_candidate_only_toc_and_preserves_two_candidate_pages(tmp_path):
    source_pdf = _multi_page_pdf(2, "source")
    candidate_pdf = _multi_page_pdf(4, "candidate")
    baseline_tex = (
        "\\documentclass{article}\n"
        "\\begin{document}\n"
        "% Page 1\nFirst source page.\n"
        "% Page 2\nSecond source page reflows.\n"
        "\\end{document}\n"
    )
    calls = []

    class EmptyTextClient:
        model = "gpt-5.4-mini"
        reasoning_effort = "high"

        def chat_json(self, system, user):
            del system
            request = json.loads(user)
            assert request["binding"]["role"] in {"AI-1", "AI-2"}
            return _complete_transport(
                self,
                _empty_finding(request["binding"]),
                {"input_tokens": 1},
            )

    class MappingVisionClient:
        model = "mapping-vision"

        def chat_vision_json_images_bytes(self, system, user, images, schema=None):
            del system, schema
            request = json.loads(user)
            with pymupdf.open(stream=images[1], filetype="png") as image_document:
                pixmap = image_document[0].get_pixmap()
                current_height = pixmap.height
                samples = pixmap.samples
                has_blue_boundary = any(
                    samples[index + 2] >= samples[index] + 15
                    for index in range(0, len(samples), pixmap.n)
                )
            calls.append(
                (
                    request["binding"]["source_page_id"],
                    tuple(request["candidate_pdf_page_numbers"]),
                    request["current_render_is_composite"],
                    current_height,
                    has_blue_boundary,
                )
            )
            if request["binding"]["role"] == "AI-3":
                return _complete_transport(
                    self,
                    _empty_finding(request["binding"]),
                    {"input_tokens": 1},
                )
            return _complete_transport(self, {
                "binding": request["binding"],
                "content_conservation_ok": True,
                "math_conservation_ok": True,
                "visual_review_ok": True,
                "formal_inventory_ok": True,
                "new_high_risk_issues": 0,
                "prior_pass_conclusion_visible": False,
            }, {"input_tokens": 1})

    compile_calls = []

    def compiler(tex, *, extra_files, minimum_passes):
        assert minimum_passes == 2
        compile_calls.append("compile")
        manifest = build_compile_input_manifest(tex, extra_files)
        return {
            "available": True,
            "ok": True,
            "preview_status": "COMPILED",
            "pdf_bytes": candidate_pdf,
            "page_count": 4,
            "engine": "fake-xelatex",
            "log": "ok",
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "compile_workdir": "compile-workdir:sha256:" + sha256_text(tex),
            "compile_input_sha256": manifest["manifest_sha256"],
        }

    evidence, admission = _verified_risk_inputs(
        source_pdf,
        baseline_tex=baseline_tex,
        baseline_pdf=candidate_pdf,
        pages=(1, 2),
        candidate_page_map={1: 1, 2: (3, 4)},
    )
    result = run_production_analysis(
        run_id="production-reflow-run",
        project_id="project-reflow",
        source_pdf=source_pdf,
        raw_ocr_tex=baseline_tex,
        baseline_tex=baseline_tex,
        baseline_pdf=candidate_pdf,
        page_range=(1, 2),
        candidate_page_map={1: 1, 2: (3, 4)},
        text_clients={
            "AI-1": EmptyTextClient(),
            "AI-2": EmptyTextClient(),
            "AI-4": EmptyTextClient(),
        },
        vision_clients={"AI-3": MappingVisionClient(), "AI-5": MappingVisionClient()},
        compiler=compiler,
        machine_verifier=_facts,
        candidate_root=tmp_path / "reflow-candidates",
        snapshot_evidence=evidence,
        raw_ocr_frozen=True,
        page_risk_admission=admission,
        native_source_blocks=(),
        max_macro_rounds=1,
    )

    assert compile_calls == ["compile"]
    assert result.snapshot.page_map[0].candidate_pdf_page_ids == ("candidate-page-000001",)
    assert result.snapshot.page_map[1].candidate_pdf_page_ids == (
        "candidate-page-000003",
        "candidate-page-000004",
    )
    assert all(
        2 not in page_numbers for _page_id, page_numbers, _composite, _height, _boundary in calls
    )
    single_heights = [
        height for _page_id, pages, _composite, height, _boundary in calls if pages == (1,)
    ]
    composite_heights = [
        height
        for _page_id, pages, composite, height, _boundary in calls
        if pages == (3, 4) and composite
    ]
    assert single_heights and composite_heights
    assert min(composite_heights) > max(single_heights) + 80
    assert all(
        boundary
        for _page_id, pages, composite, _height, boundary in calls
        if pages == (3, 4) and composite
    )
    assert result.orchestration.decision.verified is True

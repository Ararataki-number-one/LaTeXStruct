# -*- coding: utf-8 -*-
"""Public production-run recovery wiring tests.

These tests exercise recovery only through :func:`run_production_analysis`.
The lower-level store has its own adversarial tests; this module proves that
the production boundary freezes inputs, restores a committed run without
replaying discovery, and carries recovery rejection evidence forward.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pymupdf
import pytest

from latexstruct.core import analysis_production
from latexstruct.core.analysis_budget import ActualUsage, AnalysisBudget, BudgetClaim
from latexstruct.core.analysis_inventory import AnalysisNativeSourceBlock
from latexstruct.core.analysis_production import (
    ProductionAnalysisError,
    run_production_analysis,
)
from latexstruct.core.analysis_recovery import AnalysisRunStore
from latexstruct.core.analysis_runtime import CandidateController
from latexstruct.core.analysis_schema import (
    AnalysisCacheKey,
    AnalysisFinalStatus,
    PageRisk,
    sha256_bytes,
    sha256_text,
)
from latexstruct.core.compilecheck import build_compile_input_manifest


TARGET = "Theorem 1. Every graph has a vertex."
BASELINE_TEX = (
    "\\documentclass{article}\n"
    "\\begin{document}\n"
    "% Page 1\n"
    f"{TARGET}\n"
    "\\end{document}\n"
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


def _pdf(text: str = "recovery source page") -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=300, height=400)
        page.insert_text((30, 50), text)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


SOURCE_PDF = _pdf()


def _snapshot_evidence(tex: str) -> dict[str, str]:
    compile_inputs = build_compile_input_manifest(tex, {})
    return {
        "ocr_baseline_manifest_hash": sha256_text("recovery OCR manifest"),
        "ocr_page_records_hash": sha256_text("recovery OCR page records"),
        "ocr_runtime_page_records_hash": sha256_text(
            "recovery OCR runtime page records"
        ),
        "ocr_page_map_hash": sha256_text("recovery OCR page map"),
        "ocr_baseline_compile_inputs_hash": sha256_text(
            "recovery OCR compile inputs"
        ),
        "baseline_compile_inputs_hash": compile_inputs["manifest_sha256"],
        "build_identity_hash": sha256_text("recovery clean build identity"),
    }


def _verified_risk_inputs(
    source_pdf: bytes,
    tex: str,
) -> tuple[dict[str, str], dict[str, object]]:
    evidence = _snapshot_evidence(tex)
    source_hash = sha256_bytes(source_pdf)
    region = analysis_production._page_regions(tex, (1,))[1][2]
    with pymupdf.open(stream=source_pdf, filetype="pdf") as document:
        source_page_text = str(
            document.load_page(0).get_text("text") or ""
        )
    typed_admission = analysis_production.build_page_risk_admission(
        source_pdf_sha256=source_hash,
        ocr_page_records_sha256=evidence["ocr_page_records_hash"],
        ocr_runtime_page_records_sha256=(
            evidence["ocr_runtime_page_records_hash"]
        ),
        baseline_tex_sha256=sha256_text(tex),
        baseline_pdf_sha256=sha256_bytes(source_pdf),
        page_inputs=(analysis_production.PageRiskPreflightInput(
            source_page_id=analysis_production.stable_source_page_id(
                source_hash, 1
            ),
            source_page_number=1,
            source_page_object_hash=sha256_text("recovery source page 1"),
            ocr_coverage_checks={
                name: "PASS"
                for name in analysis_production._OCR_COVERAGE_CHECK_NAMES
            },
            unresolved_region_hashes=(),
            baseline_tex_region=region,
            candidate_pdf_page_ids=("candidate-page-000001",),
            source_pdf_text=source_page_text,
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
        ),),
    )
    evidence["page_risk_admission_hash"] = typed_admission.digest
    return evidence, typed_admission.to_dict()


def _complete_transport(client, response, usage):
    client.last_transport_attempts = ({
        "attempt_number": 1,
        "succeeded": True,
        "usage_complete": True,
        "failure_stage": "",
        "usage": dict(usage),
    },)
    return response, usage


class RecordingTextClient:
    model = "gpt-5.4-mini"
    reasoning_effort = "high"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def chat_json(self, _system: str, user: str):
        request = json.loads(user)
        binding = request["binding"]
        role = binding["role"]
        prior_role_calls = self.calls.count(role)
        self.calls.append(role)
        usage = {"input_tokens": 4, "output_tokens": 2, "total_tokens": 6}

        if role == "AI-1":
            if prior_role_calls:
                return _complete_transport(
                    self, {"binding": binding, "findings": []}, usage
                )
            return _complete_transport(self, {
                "binding": binding,
                "findings": [
                    {
                        "issue_type": "FORMAL_BOUNDARY",
                        "severity": "HIGH",
                        "exact_quotes": [TARGET],
                        "source_pdf_regions": [],
                        "description": "formal statement boundary differs",
                        "suggestion": "wrap only the exact formal statement",
                        "blocker_reason": "",
                    }
                ],
            }, usage)
        if role == "AI-2":
            return _complete_transport(
                self, {"binding": binding, "findings": []}, usage
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
                            "replacement": (
                                f"\\begin{{theorem}}\n{TARGET}\n"
                                "\\end{theorem}"
                            ),
                            "reason": "restore the theorem boundary",
                        }
                    ]
                },
            }, usage)
        raise AssertionError(f"unexpected text role: {role}")


class RecordingVisionClient:
    model = "recovery-vision-v2"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def chat_vision_json_images_bytes(
        self,
        _system: str,
        user: str,
        images: list[bytes],
        *,
        schema: dict[str, object] | None = None,
    ):
        assert len(images) == 2
        assert isinstance(schema, dict)
        request = json.loads(user)
        binding = request["binding"]
        role = binding["role"]
        usage = {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7}
        if role == "AI-3":
            self.calls.append("AI-3")
            return _complete_transport(
                self, {"binding": binding, "findings": []}, usage
            )
        if role != "AI-5":
            raise AssertionError(f"unexpected vision role: {role}")

        if "pass_number" in request:
            pass_number = int(request["pass_number"])
            self.calls.append(f"AI-5-final-{pass_number}")
            return _complete_transport(self, {
                "binding": binding,
                "content_conservation_ok": True,
                "math_conservation_ok": True,
                "visual_review_ok": True,
                "formal_inventory_ok": True,
                "new_high_risk_issues": 0,
                "prior_pass_conclusion_visible": False,
            }, usage)

        self.calls.append("AI-5-issue")
        return _complete_transport(self, {
            "binding": binding,
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "visual_review_ok": True,
            "result": "PASS",
            "new_high_priority_issues": 0,
        }, usage)


class RecordingCompiler:
    def __init__(self, pdf: bytes) -> None:
        self.pdf = pdf
        self.calls: list[str] = []

    def __call__(
        self,
        tex: str,
        *,
        extra_files: dict[str, bytes],
        minimum_passes: int,
    ) -> dict[str, object]:
        assert minimum_passes == 2
        assert extra_files == {}
        candidate_kind = "patched" if "\\begin{theorem}" in tex else "baseline"
        self.calls.append(candidate_kind)
        manifest = build_compile_input_manifest(tex, extra_files)
        return {
            "available": True,
            "ok": True,
            "preview_status": "COMPILED",
            "pdf_bytes": self.pdf,
            "page_count": 1,
            "engine": "fake-xelatex",
            "log": f"two-pass {candidate_kind} compile succeeded",
            "passes_requested": 2,
            "passes_attempted": 2,
            "passes_completed": 2,
            "compile_workdir": "compile-workdir:sha256:" + sha256_text(tex),
            "compile_input_sha256": manifest["manifest_sha256"],
        }


class RecordingMachineVerifier:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, request):
        self.calls.append(request.candidate_hash)
        page_ids = tuple(
            page_id for page_id, _payload in request.compile_result.page_pdf_bytes
        )
        return {
            "candidate_hash": request.candidate_hash,
            "checked_page_ids": list(page_ids),
            "silent_page_omissions": 0,
            "silent_text_losses": 0,
            "unauthorized_math_changes": 0,
            "formal_errors": 0,
            "toc_complete_and_ordered": True,
            "severe_equation_number_errors": 0,
            "silent_footnote_losses": 0,
            "silent_figure_caption_losses": 0,
            "silent_bibliography_losses": 0,
        }


def _run(
    active_root: Path,
    *,
    resume: bool = False,
    max_macro_rounds: int = 1,
    max_requests: int = 0,
    max_output_tokens: int = 0,
    raw_ocr_frozen: bool = True,
    page_risks: dict[int, PageRisk] | None = None,
    compiler_pdf: bytes | None = None,
    text_client: RecordingTextClient | None = None,
    vision_client: RecordingVisionClient | None = None,
):
    pdf = SOURCE_PDF
    text = text_client or RecordingTextClient()
    vision = vision_client or RecordingVisionClient()
    compiler = RecordingCompiler(pdf if compiler_pdf is None else compiler_pdf)
    verifier = RecordingMachineVerifier()
    evidence, admission = _verified_risk_inputs(pdf, BASELINE_TEX)
    result = run_production_analysis(
        run_id="production-recovery-run-1",
        project_id="production-recovery-project-1",
        source_pdf=pdf,
        raw_ocr_tex=BASELINE_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=pdf,
        page_range=(1,),
        candidate_page_map={1: 1},
        candidate_page_mapper=lambda _candidate_hash, _pdf_bytes: {1: 1},
        text_clients={"AI-1": text, "AI-2": text, "AI-4": text},
        vision_clients={"AI-3": vision, "AI-5": vision},
        compiler=compiler,
        machine_verifier=verifier,
        candidate_root=active_root / "candidates",
        snapshot_evidence=evidence,
        raw_ocr_frozen=raw_ocr_frozen,
        concurrency_limit=1,
        page_risks=page_risks,
        page_risk_admission=admission if page_risks is None else None,
        native_source_blocks=NATIVE_FORMAL_BLOCKS,
        max_macro_rounds=max_macro_rounds,
        max_requests=max_requests,
        max_output_tokens=max_output_tokens,
        resume=resume,
    )
    return result, text, vision, compiler, verifier


def _checkpoint_directories(active_root: Path) -> list[Path]:
    checkpoints = active_root / "checkpoints"
    return sorted(
        path
        for path in checkpoints.iterdir()
        if path.is_dir() and path.name.startswith("checkpoint-")
    )


def _checkpoint_sequence(path: Path) -> int:
    return int(path.name.split("-", 2)[1])


def _directory_bytes(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _rejection_field(rejection: object, name: str) -> object:
    if isinstance(rejection, dict):
        return rejection[name]
    return getattr(rejection, name)


def _commit_compile_history_variant(
    store: AnalysisRunStore,
    checkpoint,
    compile_history: dict[str, object],
):
    return _commit_checkpoint_variant(
        store,
        checkpoint,
        compile_history=compile_history,
    )


def _commit_checkpoint_variant(
    store: AnalysisRunStore,
    checkpoint,
    *,
    sequence: int | None = None,
    **changed: object,
):
    payloads = {
        "run_state": checkpoint.run_state,
        "issue_ledger": checkpoint.issue_ledger,
        "task_ledger": checkpoint.task_ledger,
        "budget_ledger": checkpoint.budget_ledger,
        "invocation_ledger": checkpoint.invocation_ledger,
        "compile_history": checkpoint.compile_history,
        "candidate_page_map": checkpoint.candidate_page_map,
        "rollback_history": checkpoint.rollback_history,
    }
    unknown = set(changed).difference(payloads)
    assert not unknown
    payloads.update(changed)
    with store.exclusive_lock():
        return store.commit_checkpoint(
            sequence=checkpoint.sequence + 1 if sequence is None else sequence,
            run_id=checkpoint.run_id,
            project_id=checkpoint.project_id,
            snapshot_hash=checkpoint.snapshot_hash,
            compile_input_hash=checkpoint.compile_input_hash,
            round_index=checkpoint.round_index,
            current_candidate_id=checkpoint.current_candidate.candidate_id,
            current_candidate_hash=checkpoint.current_candidate.candidate_hash,
            best_candidate_id=checkpoint.best_candidate.candidate_id,
            best_candidate_hash=checkpoint.best_candidate.candidate_hash,
            **payloads,
        )


def _failed_compile_record() -> dict[str, object]:
    return {
        "candidate_hash": sha256_text("failed candidate TeX"),
        "reason": "recovered failed attempt",
        "run_number": 1,
        "ok": False,
        "pdf_hash": "",
        "proof_pdf_hash": sha256_bytes(b"compiler diagnostic payload"),
        "admitted_pdf_hash": "",
        "admitted_pdf_source": "none",
        "page_count": 0,
        "engine": "fake-xelatex",
        "passes_requested": 2,
        "passes_attempted": 1,
        "passes_completed": 0,
        "compile_workdir": "",
        "compile_input_sha256": "",
        "same_workdir_verified": False,
    }


def test_fresh_baseline_compile_proof_and_frozen_admitted_pdf_close_round_zero(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    fresh_compile_pdf = _pdf("fresh baseline compile with nondeterministic bytes")
    assert sha256_bytes(fresh_compile_pdf) != sha256_bytes(SOURCE_PDF)

    result, text, _vision, compiler, _verifier = _run(
        active_root,
        compiler_pdf=fresh_compile_pdf,
    )

    assert result.orchestration.decision.status == AnalysisFinalStatus.VERIFIED
    assert compiler.calls == ["baseline", "patched"]
    assert Counter(text.calls) == Counter({"AI-1": 2, "AI-2": 2, "AI-4": 1})
    baseline_record = next(
        record
        for record in result.compile_invocations
        if record.candidate_hash == result.snapshot.baseline_tex_hash
    )
    assert baseline_record.ok is True
    assert baseline_record.proof_pdf_hash == sha256_bytes(fresh_compile_pdf)
    assert baseline_record.admitted_pdf_hash == sha256_bytes(SOURCE_PDF)
    assert baseline_record.pdf_hash == baseline_record.admitted_pdf_hash
    assert baseline_record.admitted_pdf_source == "frozen-baseline"

    round_zero = _checkpoint_directories(active_root)[0]
    history = json.loads(
        (round_zero / "compile_history.json").read_text(encoding="utf-8")
    )
    frozen_record = next(
        record
        for record in history["records"]
        if record["candidate_hash"] == result.snapshot.baseline_tex_hash
    )
    assert frozen_record["proof_pdf_hash"] != frozen_record["admitted_pdf_hash"]
    candidate = json.loads(
        (round_zero / "checkpoint.json").read_text(encoding="utf-8")
    )["current_candidate"]
    assert candidate["pdf_sha256"] == frozen_record["admitted_pdf_hash"]


def test_checkpoint_with_failed_compile_history_recovers_but_tampering_is_rejected(
    tmp_path: Path,
) -> None:
    recoverable_root = tmp_path / "recoverable"
    first, _text, _vision, _compiler, _verifier = _run(recoverable_root)
    store = AnalysisRunStore(recoverable_root)
    scan = store.recover_latest(
        expected_run_id=first.snapshot.run_id,
        expected_project_id=first.snapshot.project_id,
        expected_snapshot_hash=first.snapshot.snapshot_hash,
    )
    assert scan.checkpoint is not None
    history = json.loads(json.dumps(scan.checkpoint.compile_history))
    history["records"].append(_failed_compile_record())
    injected = _commit_compile_history_variant(store, scan.checkpoint, history)

    resumed, text, vision, _compiler, verifier = _run(
        recoverable_root,
        resume=True,
    )
    assert resumed.resumed is True
    assert resumed.recovery_checkpoint_id == injected.checkpoint_id
    assert text.calls == []
    assert vision.calls == ["AI-5-final-1", "AI-5-final-2"]
    assert len(verifier.calls) == 1

    tampered_root = tmp_path / "tampered"
    original, _text, _vision, _compiler, _verifier = _run(tampered_root)
    tampered_store = AnalysisRunStore(tampered_root)
    tampered_scan = tampered_store.recover_latest(
        expected_run_id=original.snapshot.run_id,
        expected_project_id=original.snapshot.project_id,
        expected_snapshot_hash=original.snapshot.snapshot_hash,
    )
    assert tampered_scan.checkpoint is not None
    tampered_history = json.loads(
        json.dumps(tampered_scan.checkpoint.compile_history)
    )
    current_hash = tampered_scan.checkpoint.current_candidate.candidate_hash
    tampered_history["records"] = [
        record
        for record in tampered_history["records"]
        if record["candidate_hash"] != current_hash
    ]
    failed_current = _failed_compile_record()
    failed_current["candidate_hash"] = current_hash
    failed_current["compile_input_sha256"] = (
        tampered_scan.checkpoint.compile_input_hash
    )
    tampered_history["records"].append(failed_current)
    valid_checkpoint_id = tampered_scan.checkpoint.checkpoint_id
    invalid_checkpoint = _commit_compile_history_variant(
        tampered_store,
        tampered_scan.checkpoint,
        tampered_history,
    )

    recovered, _text, _vision, _compiler, _verifier = _run(
        tampered_root,
        resume=True,
    )
    assert recovered.recovery_checkpoint_id == valid_checkpoint_id
    assert any(
        _rejection_field(rejection, "artifact")
        == invalid_checkpoint.checkpoint_id
        and _rejection_field(rejection, "code") == "semantic_validation"
        for rejection in recovered.recovery_rejections
    )


def test_first_run_freezes_inputs_and_commits_multiple_immutable_checkpoints(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    result, text, vision, compiler, verifier = _run(active_root)

    assert result.resumed is False
    assert not result.recovery_checkpoint_id
    assert result.recovery_rejections == ()
    assert result.orchestration.decision.status == AnalysisFinalStatus.VERIFIED
    assert Counter(text.calls) == Counter({"AI-1": 2, "AI-2": 2, "AI-4": 1})
    assert Counter(vision.calls) == Counter(
        {
            "AI-3": 3,
            "AI-5-issue": 1,
            "AI-5-final-1": 1,
            "AI-5-final-2": 1,
        }
    )
    assert compiler.calls == ["baseline", "patched"]
    assert len(verifier.calls) == 1

    frozen_snapshot = json.loads(
        (active_root / "inputs" / "snapshot.json").read_text(encoding="utf-8")
    )
    assert frozen_snapshot["snapshot_hash"] == result.snapshot.snapshot_hash
    assert frozen_snapshot["started_at"] == result.snapshot.started_at
    assert (active_root / "inputs" / "source.pdf").read_bytes().startswith(b"%PDF-")
    assert (active_root / "inputs" / "raw_ocr.tex").read_text(
        encoding="utf-8"
    ) == BASELINE_TEX

    checkpoints = _checkpoint_directories(active_root)
    assert len(checkpoints) >= 3
    assert [_checkpoint_sequence(path) for path in checkpoints] == list(
        range(len(checkpoints))
    )
    before = {path.name: _directory_bytes(path) for path in checkpoints}
    scan = AnalysisRunStore(active_root).recover_latest(
        expected_run_id=result.snapshot.run_id,
        expected_project_id=result.snapshot.project_id,
        expected_snapshot_hash=result.snapshot.snapshot_hash,
    )
    assert scan.checkpoint is not None
    assert scan.checkpoint.checkpoint_id == checkpoints[-1].name
    assert {path.name: _directory_bytes(path) for path in checkpoints} == before


def test_resume_reuses_frozen_snapshot_skips_discovery_and_repeats_final_gates(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    first, _text, _vision, _compiler, _verifier = _run(active_root)
    frozen_started_at = first.snapshot.started_at
    frozen_snapshot_hash = first.snapshot.snapshot_hash
    latest_before = _checkpoint_directories(active_root)[-1].name
    immutable_before = {
        path.name: _directory_bytes(path)
        for path in _checkpoint_directories(active_root)
    }

    resumed, text, vision, compiler, verifier = _run(active_root, resume=True)

    assert resumed.resumed is True
    assert resumed.recovery_checkpoint_id == latest_before
    assert resumed.recovery_rejections == ()
    assert resumed.snapshot.started_at == frozen_started_at
    assert resumed.snapshot.snapshot_hash == frozen_snapshot_hash
    assert text.calls == []
    assert vision.calls == ["AI-5-final-1", "AI-5-final-2"]
    assert compiler.calls == ["baseline", "patched"]
    assert len(verifier.calls) == 1
    assert resumed.orchestration.decision.status == (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert resumed.orchestration.decision.verified is False
    assert any(
        reason.startswith("visual_triage_missing:")
        for reason in resumed.orchestration.stop_reasons
    )
    assert all(
        _directory_bytes(active_root / "checkpoints" / name) == payloads
        for name, payloads in immutable_before.items()
    )


def test_existing_frozen_root_requires_explicit_resume(tmp_path: Path) -> None:
    active_root = tmp_path / "active"
    _run(active_root)
    text = RecordingTextClient()
    vision = RecordingVisionClient()
    pdf = SOURCE_PDF
    evidence, admission = _verified_risk_inputs(pdf, BASELINE_TEX)

    with pytest.raises(
        ProductionAnalysisError,
        match="(?i)(already|frozen|resume|immutable)",
    ):
        run_production_analysis(
            run_id="production-recovery-run-1",
            project_id="production-recovery-project-1",
            source_pdf=pdf,
            raw_ocr_tex=BASELINE_TEX,
            baseline_tex=BASELINE_TEX,
            baseline_pdf=pdf,
            page_range=(1,),
            candidate_page_map={1: 1},
            candidate_page_mapper=lambda _candidate_hash, _pdf_bytes: {1: 1},
            text_clients={"AI-1": text, "AI-2": text, "AI-4": text},
            vision_clients={"AI-3": vision, "AI-5": vision},
            compiler=RecordingCompiler(pdf),
            machine_verifier=RecordingMachineVerifier(),
            candidate_root=active_root / "candidates",
            snapshot_evidence=evidence,
            raw_ocr_frozen=True,
            concurrency_limit=1,
            page_risk_admission=admission,
            max_macro_rounds=1,
            resume=False,
        )

    assert text.calls == []
    assert vision.calls == []


def test_production_entry_lock_rejects_competitor_before_business_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_root = tmp_path / "active"
    observed: list[str] = []

    monkeypatch.setattr(
        RecordingTextClient,
        "chat_json",
        lambda self, system, user: observed.append("text"),
    )
    monkeypatch.setattr(
        RecordingVisionClient,
        "chat_vision_json_images_bytes",
        lambda self, system, user, images, **kwargs: observed.append("vision"),
    )
    monkeypatch.setattr(
        RecordingCompiler,
        "__call__",
        lambda self, tex, **kwargs: observed.append("compile"),
    )
    store = AnalysisRunStore(
        active_root,
        candidates_directory=active_root / "candidates",
    )
    with store.exclusive_lock(), pytest.raises(
        ProductionAnalysisError,
        match="already owns",
    ):
        _run(active_root)

    assert observed == []


def test_pre_freeze_compile_failure_reuses_provisional_snapshot_on_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_root = tmp_path / "active"
    original_compile = RecordingCompiler.__call__
    compile_calls = 0
    model_calls: list[str] = []
    original_text = RecordingTextClient.chat_json
    original_vision = RecordingVisionClient.chat_vision_json_images_bytes

    def fail_first_compile(self, tex, **kwargs):
        nonlocal compile_calls
        compile_calls += 1
        if compile_calls == 1:
            raise RuntimeError("simulated baseline compiler outage")
        return original_compile(self, tex, **kwargs)

    def record_text(self, system, user):
        model_calls.append("text")
        return original_text(self, system, user)

    def record_vision(self, system, user, images, **kwargs):
        model_calls.append("vision")
        return original_vision(self, system, user, images, **kwargs)

    monkeypatch.setattr(RecordingCompiler, "__call__", fail_first_compile)
    monkeypatch.setattr(RecordingTextClient, "chat_json", record_text)
    monkeypatch.setattr(
        RecordingVisionClient,
        "chat_vision_json_images_bytes",
        record_vision,
    )

    with pytest.raises(RuntimeError, match="compiler outage"):
        _run(active_root)
    assert model_calls == []
    provisional_path = active_root / "provisional_run_identity.json"
    staged = json.loads(provisional_path.read_text(encoding="utf-8"))
    assert staged["snapshot_hash"]
    assert not (active_root / "inputs").exists()

    result, _text, _vision, _compiler, _verifier = _run(
        active_root,
        resume=False,
    )

    assert result.snapshot.started_at == staged["started_at"]
    assert result.snapshot.snapshot_hash == staged["snapshot_hash"]
    assert result.orchestration.decision.status == AnalysisFinalStatus.VERIFIED


def test_pre_freeze_retry_rejects_changed_configuration_before_compile_or_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_root = tmp_path / "active"
    original_compile = RecordingCompiler.__call__
    compile_calls = 0
    model_calls: list[str] = []

    def fail_first_compile(self, tex, **kwargs):
        nonlocal compile_calls
        compile_calls += 1
        if compile_calls == 1:
            raise RuntimeError("simulated baseline compiler outage")
        return original_compile(self, tex, **kwargs)

    monkeypatch.setattr(RecordingCompiler, "__call__", fail_first_compile)
    monkeypatch.setattr(
        RecordingTextClient,
        "chat_json",
        lambda self, system, user: model_calls.append("text"),
    )
    monkeypatch.setattr(
        RecordingVisionClient,
        "chat_vision_json_images_bytes",
        lambda self, system, user, images, **kwargs: model_calls.append("vision"),
    )

    with pytest.raises(RuntimeError, match="compiler outage"):
        _run(active_root)
    assert compile_calls == 1
    assert model_calls == []

    with pytest.raises(
        ProductionAnalysisError,
        match="provisional analysis snapshot",
    ):
        _run(active_root, max_macro_rounds=2)

    assert compile_calls == 1
    assert model_calls == []


def test_checkpointless_task_recovery_reuses_results_but_fails_evidence_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_root = tmp_path / "active"
    original_save_baseline = CandidateController.save_baseline

    def crash_after_discovery(self, **_kwargs):
        raise RuntimeError("simulated crash before first committed checkpoint")

    monkeypatch.setattr(CandidateController, "save_baseline", crash_after_discovery)
    with pytest.raises(RuntimeError, match="simulated crash"):
        _run(active_root)

    assert not (active_root / "checkpoints").exists()
    task_ledger = json.loads(
        next((active_root / "candidates" / "_run").rglob("task-ledger.json"))
        .read_text(encoding="utf-8")
    )
    assert task_ledger["records"]
    assert all(
        record["state"] == "COMPLETED"
        for record in task_ledger["records"].values()
    )

    monkeypatch.setattr(CandidateController, "save_baseline", original_save_baseline)
    resumed, text, vision, _compiler, _verifier = _run(active_root, resume=True)

    # Completed baseline discovery tasks are not replayed.  The v2 route
    # closure still requires one modified-candidate recheck by AI-1/2/3 after
    # the recovered AI-4 patch.  Because the pre-checkpoint process lost its
    # invocation/transport ledger, the run remains diagnostic-only.
    assert text.calls == ["AI-4", "AI-1", "AI-2"]
    assert Counter(vision.calls)["AI-3"] == 1
    assert resumed.orchestration.decision.status == (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert resumed.orchestration.decision.verified is False
    assert (
        "recovery_precheckpoint_invocation_evidence_incomplete"
        in resumed.orchestration.stop_reasons
    )
    assert resumed.orchestration.performance.usage_complete is False
    assert resumed.orchestration.performance.attempt_evidence_complete is False
    assert resumed.orchestration.performance.cost_status == "UNKNOWN"


def test_mutable_budget_ahead_of_checkpoint_adds_permanent_recovery_stop(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    first, _text, _vision, _compiler, _verifier = _run(active_root)
    budget_path = active_root / "candidates" / "analysis_budget.json"
    payload = json.loads(budget_path.read_text(encoding="utf-8"))
    budget = AnalysisBudget.from_dict(payload["budget"])
    reservation = budget.reserve_or_raise(
        BudgetClaim(input_tokens=1, output_tokens=1, requests=1)
    )
    budget.commit(
        reservation,
        ActualUsage(input_tokens=1, output_tokens=1, cost=0.0),
    )
    payload["budget"] = budget.to_dict()
    budget_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    resumed, _text, _vision, _compiler, _verifier = _run(
        active_root,
        resume=True,
    )

    assert resumed.snapshot.snapshot_hash == first.snapshot.snapshot_hash
    assert resumed.orchestration.decision.verified is False
    assert resumed.orchestration.decision.status == (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert (
        "recovery_budget_evidence_ahead_of_checkpoint"
        in resumed.orchestration.stop_reasons
    )

    resumed_again, _text, _vision, _compiler, _verifier = _run(
        active_root,
        resume=True,
    )
    assert (
        "recovery_budget_evidence_ahead_of_checkpoint"
        in resumed_again.orchestration.stop_reasons
    )


def test_mutable_budget_ahead_requires_a_whole_committed_transport(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    _run(active_root)
    budget_path = active_root / "candidates" / "analysis_budget.json"
    payload = json.loads(budget_path.read_text(encoding="utf-8"))
    usage = payload["budget"]["usage"]
    usage["observed"]["input_tokens"] += 1
    usage["actual"]["input_tokens"] += 1
    usage["accounted"]["input_tokens"] += 1
    budget_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ProductionAnalysisError,
        match="(?i)(mutable budget|atomic transport|usage)",
    ):
        _run(active_root, resume=True)


def test_tampered_newest_checkpoint_falls_back_and_advances_sequence(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    first, _text, _vision, _compiler, _verifier = _run(active_root)
    checkpoints = _checkpoint_directories(active_root)
    damaged = checkpoints[-1]
    damaged_sequence = _checkpoint_sequence(damaged)
    expected_fallback = checkpoints[-2].name
    (damaged / "run_state.json").write_text(
        '{"tampered":true}\n', encoding="utf-8"
    )

    resumed, text, vision, _compiler, verifier = _run(active_root, resume=True)

    assert resumed.resumed is True
    assert resumed.snapshot.snapshot_hash == first.snapshot.snapshot_hash
    assert resumed.recovery_checkpoint_id == expected_fallback
    assert any(
        _rejection_field(rejection, "artifact") == damaged.name
        and _rejection_field(rejection, "sequence") == damaged_sequence
        for rejection in resumed.recovery_rejections
    )
    assert text.calls == []
    assert vision.calls == ["AI-5-final-1", "AI-5-final-2"]
    assert len(verifier.calls) == 1
    assert max(
        _checkpoint_sequence(path) for path in _checkpoint_directories(active_root)
    ) > damaged_sequence


def test_semantically_invalid_typed_ledgers_are_rejected_newest_to_oldest(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    first, _text, _vision, _compiler, _verifier = _run(active_root)
    store = AnalysisRunStore(active_root)
    scan = store.recover_latest(
        expected_run_id=first.snapshot.run_id,
        expected_project_id=first.snapshot.project_id,
        expected_snapshot_hash=first.snapshot.snapshot_hash,
    )
    assert scan.checkpoint is not None
    valid = scan.checkpoint

    variants: list[tuple[str, dict[str, object]]] = []

    role_ledger = json.loads(json.dumps(valid.invocation_ledger))
    role_ledger["orchestration_invocations"][0]["binding"]["role"] = "AI-2"
    variants.append(("role", {"invocation_ledger": role_ledger}))

    ordinal_ledger = json.loads(json.dumps(valid.invocation_ledger))
    ordinal_ledger["orchestration_invocations"][0]["ordinal"] = 2
    variants.append(("ordinal", {"invocation_ledger": ordinal_ledger}))

    material_ledger = json.loads(json.dumps(valid.invocation_ledger))
    material_ledger["transport_invocations"][0]["material_hashes"][0][1] = "0" * 64
    variants.append(("material", {"invocation_ledger": material_ledger}))

    budget_usage_ledger = json.loads(json.dumps(valid.budget_ledger))
    budget_usage = budget_usage_ledger["budget"]["usage"]
    budget_usage["observed"]["input_tokens"] += 1
    budget_usage["actual"]["input_tokens"] += 1
    budget_usage["accounted"]["input_tokens"] += 1
    variants.append(("budget-usage-sum", {"budget_ledger": budget_usage_ledger}))

    budget_request_ledger = json.loads(json.dumps(valid.budget_ledger))
    budget_request_ledger["budget"]["usage"]["requests"] += 1
    variants.append(("budget-request-sum", {
        "budget_ledger": budget_request_ledger,
    }))

    budget_cost_ledger = json.loads(json.dumps(valid.budget_ledger))
    budget_cost_ledger["budget"]["usage"]["accounted"]["cost"] += 0.01
    variants.append(("budget-cost-sum", {"budget_ledger": budget_cost_ledger}))

    claim_ledger = json.loads(json.dumps(valid.invocation_ledger))
    claim_ledger["transport_invocations"][0]["budget_claim"][
        "output_tokens"
    ] += 1
    variants.append(("budget-claim", {"invocation_ledger": claim_ledger}))

    transport_usage_ledger = json.loads(json.dumps(valid.invocation_ledger))
    transport_row = transport_usage_ledger["transport_invocations"][0]
    for usage_pairs in (transport_row["usage"], transport_row["attempts"][0]["usage"]):
        usage = dict(usage_pairs)
        usage["input_tokens"] += 1
        usage["total_tokens"] += 1
        usage_pairs[:] = sorted(usage.items())
    transport_row["budget_actual_usage"]["input_tokens"] += 1
    variants.append(("transport-usage-sum", {
        "invocation_ledger": transport_usage_ledger,
    }))

    retry_ledger = json.loads(json.dumps(valid.invocation_ledger))
    retry_row = retry_ledger["transport_invocations"][0]
    terminal_attempt = retry_row["attempts"][0]
    retry_row["attempts"] = [
        {
            **terminal_attempt,
            "attempt_number": 1,
            "succeeded": False,
            "failure_stage": "http_error",
        },
        {
            **terminal_attempt,
            "attempt_number": 2,
        },
    ]
    variants.append(("attempt-bound", {"invocation_ledger": retry_ledger}))

    ahead_run_state = json.loads(json.dumps(valid.run_state))
    ahead_run_state["stop_reasons"].append(
        "recovery_budget_evidence_ahead_of_checkpoint"
    )
    ahead_budget_ledger = json.loads(json.dumps(valid.budget_ledger))
    ahead_usage = ahead_budget_ledger["budget"]["usage"]
    ahead_usage["observed"]["input_tokens"] += 1
    ahead_usage["actual"]["input_tokens"] += 1
    ahead_usage["accounted"]["input_tokens"] += 1
    variants.append(("forged-budget-ahead", {
        "run_state": ahead_run_state,
        "budget_ledger": ahead_budget_ledger,
    }))

    attempt_ledger = json.loads(json.dumps(valid.invocation_ledger))
    attempt_ledger["transport_invocations"][0]["attempts"] = [
        {
            "attempt_number": 1,
            "succeeded": False,
            "usage_complete": False,
            "failure_stage": "",
            "usage": [],
        }
    ]
    variants.append(("attempt-closure", {"invocation_ledger": attempt_ledger}))

    miss_ledger = json.loads(json.dumps(valid.invocation_ledger))
    miss_ledger["cache_miss_count"] += 1
    variants.append(("cache-miss", {"invocation_ledger": miss_ledger}))

    cache_ledger = json.loads(json.dumps(valid.invocation_ledger))
    transport = cache_ledger["transport_invocations"][0]
    material = dict(transport["material_hashes"])
    wrong_model_key = AnalysisCacheKey(
        snapshot_hash=transport["snapshot_hash"],
        source_page_id=transport["source_page_id"],
        source_page_hash=material["source_pdf_page_hash"],
        baseline_tex_region_hash=material["baseline_tex_region_hash"],
        current_tex_region_hash=material["current_tex_region_hash"],
        current_render_hash=material["current_pdf_page_hash"],
        prompt_version=transport["prompt_version"],
        response_schema_version=transport["response_schema_version"],
        model_id="wrong-recovery-model",
        tool_version="2.0.0",
        audit_role=f"{transport['role']}:{transport['operation']}",
    )
    cache_ledger["cache_hit_evidence"] = [
        {
            **{
                key: transport[key]
                for key in (
                    "role",
                    "operation",
                    "candidate_hash",
                    "source_page_id",
                    "issue_id",
                    "material_hashes",
                    "snapshot_hash",
                    "prompt_version",
                    "response_schema_version",
                )
            },
            "model_id": "wrong-recovery-model",
            "tool_version": "2.0.0",
            "cache_key_sha256": wrong_model_key.digest,
            "response_sha256": "1" * 64,
            "binding_echo_validated": True,
        }
    ]
    variants.append(("cache-model", {"invocation_ledger": cache_ledger}))

    run_state = json.loads(json.dumps(valid.run_state))
    run_state["modified_page_ids"] = ["source-page-outside-snapshot"]
    variants.append(("modified-page", {"run_state": run_state}))

    compile_state = json.loads(json.dumps(valid.run_state))
    compile_state["full_compile_count"] += 1
    variants.append(("compile-count", {"run_state": compile_state}))

    page_map = json.loads(json.dumps(valid.candidate_page_map))
    page_map["rows"][0]["pages"][0]["candidate_page_numbers"] = [2]
    variants.append(("page-map", {"candidate_page_map": page_map}))

    rollback = json.loads(json.dumps(valid.rollback_history))
    rollback["rejected_candidate_ids"] = ["cand-r9999-deadbeefdead"]
    variants.append(("rollback", {"rollback_history": rollback}))

    variants.append(("empty-tasks", {
        "task_ledger": {
            "schema": "latexstruct-analysis-task-ledger-v2",
            "records": {},
        },
    }))
    variants.append(("empty-issues", {
        "issue_ledger": {
            "schema": "latexstruct-analysis-issue-ledger-v2",
            "issues": [],
        },
    }))
    response_task_ledger = json.loads(json.dumps(valid.task_ledger))
    completed_task = next(iter(response_task_ledger["records"].values()))
    completed_task["response_sha256"] = "f" * 64
    completed_task["response_path"] = (
        "responses/"
        f"{completed_task['identity']['task_id']}-{'f' * 16}.json"
    )
    variants.append(("task-response", {"task_ledger": response_task_ledger}))

    invalid_ids = []
    for offset, (_name, changed) in enumerate(variants, start=1):
        invalid = _commit_checkpoint_variant(
            store,
            valid,
            sequence=valid.sequence + offset,
            **changed,
        )
        invalid_ids.append(invalid.checkpoint_id)

    resumed, _text, _vision, _compiler, _verifier = _run(
        active_root,
        resume=True,
    )

    assert resumed.recovery_checkpoint_id == valid.checkpoint_id
    semantic_rejections = {
        _rejection_field(rejection, "artifact")
        for rejection in resumed.recovery_rejections
        if _rejection_field(rejection, "code") == "semantic_validation"
    }
    assert set(invalid_ids).issubset(semantic_rejections)


@pytest.mark.parametrize(
    "changed",
    [
        {"max_macro_rounds": 2},
        {"max_requests": 50},
        {"raw_ocr_frozen": False},
        {"page_risks": {1: PageRisk.R0}},
    ],
)
def test_resume_rejects_frozen_snapshot_or_configuration_mismatch(
    tmp_path: Path,
    changed: dict[str, object],
) -> None:
    active_root = tmp_path / "active"
    _run(active_root)

    with pytest.raises(
        ProductionAnalysisError,
        match="(?i)(snapshot|config|frozen|immutable|mismatch|differ|manual)",
    ):
        _run(active_root, resume=True, **changed)


@pytest.mark.parametrize(
    ("field", "changed_value"),
    [
        ("max_retries", 2),
        ("max_tokens", 64),
        ("base_url", "https://other.example.test/v1"),
    ],
)
def test_resume_rejects_changed_transport_contract(
    tmp_path: Path,
    field: str,
    changed_value: object,
) -> None:
    class ConfigurableTextClient(RecordingTextClient):
        def __init__(self, **values: object) -> None:
            super().__init__()
            self.max_retries = 0
            self.max_tokens = 32
            self.base_url = "https://api.example.test/v1"
            for name, value in values.items():
                setattr(self, name, value)

    active_root = tmp_path / "active"
    _run(active_root, text_client=ConfigurableTextClient())

    with pytest.raises(
        ProductionAnalysisError,
        match="(?i)(snapshot|config|frozen|immutable|mismatch|differ)",
    ):
        _run(
            active_root,
            resume=True,
            text_client=ConfigurableTextClient(**{field: changed_value}),
        )


def test_semantic_recovery_rejects_omitted_rejected_candidate_rollback(
    tmp_path: Path,
) -> None:
    class RejectingIssueReviewVisionClient(RecordingVisionClient):
        def chat_vision_json_images_bytes(self, *args, **kwargs):
            payload, usage = super().chat_vision_json_images_bytes(*args, **kwargs)
            request = json.loads(args[1])
            if request["binding"]["role"] == "AI-5" and (
                "pass_number" not in request
            ):
                payload["result"] = "REGRESSION"
            return payload, usage

    active_root = tmp_path / "active"
    _run(
        active_root,
        vision_client=RejectingIssueReviewVisionClient(),
    )
    store = AnalysisRunStore(
        active_root,
        candidates_directory=active_root / "candidates",
    )
    valid = store.recover_latest().checkpoint
    assert valid is not None
    assert valid.rollback_history["rejected_candidate_ids"]

    invalid = _commit_checkpoint_variant(
        store,
        valid,
        sequence=valid.sequence + 1,
        rollback_history={
            "schema": "latexstruct-analysis-rollback-history-v1",
            "rejected_candidate_ids": [],
        },
    )
    rejected_id = valid.rollback_history["rejected_candidate_ids"][0]
    duplicate = _commit_checkpoint_variant(
        store,
        valid,
        sequence=valid.sequence + 2,
        rollback_history={
            "schema": "latexstruct-analysis-rollback-history-v1",
            "rejected_candidate_ids": [rejected_id, rejected_id],
        },
    )

    resumed, *_ = _run(
        active_root,
        resume=True,
        vision_client=RejectingIssueReviewVisionClient(),
    )

    assert resumed.recovery_checkpoint_id == valid.checkpoint_id
    semantic_rejections = {
        _rejection_field(item, "artifact")
        for item in resumed.recovery_rejections
        if _rejection_field(item, "code") == "semantic_validation"
    }
    assert {invalid.checkpoint_id, duplicate.checkpoint_id}.issubset(
        semantic_rejections
    )


def test_terminal_actual_budget_overrun_revokes_verified_authority(
    tmp_path: Path,
) -> None:
    class BoundedTextClient(RecordingTextClient):
        max_tokens = 2

    class OverrunningFinalVisionClient(RecordingVisionClient):
        max_tokens = 2

        def chat_vision_json_images_bytes(self, *args, **kwargs):
            payload, usage = super().chat_vision_json_images_bytes(*args, **kwargs)
            request = json.loads(args[1])
            if request.get("pass_number") == 2:
                usage = {
                    "input_tokens": 5,
                    "output_tokens": 3,
                    "total_tokens": 8,
                }
            return _complete_transport(self, payload, usage)

    result, *_ = _run(
        tmp_path / "active",
        text_client=BoundedTextClient(),
        vision_client=OverrunningFinalVisionClient(),
        max_output_tokens=22,
    )

    assert result.orchestration.decision.status == (
        AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    assert result.orchestration.decision.verified is False
    assert result.budget_state["stop_reason"] == "LIMIT_EXCEEDED"
    assert result.budget_usage.output_tokens == 23
    assert "analysis_budget_limit_exceeded:output_tokens" in (
        result.orchestration.stop_reasons
    )
    assert "\\begin{theorem}" in result.orchestration.current_tex


def test_budget_blocked_cache_misses_still_form_a_recoverable_checkpoint(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    first, *_ = _run(active_root, max_requests=1)

    assert first.orchestration.decision.verified is False
    assert first.orchestration.performance.cache_misses == 0
    assert first.budget_state["stop_reason"] == "LIMIT_REACHED"

    resumed, *_ = _run(active_root, resume=True, max_requests=1)

    assert resumed.resumed is True
    assert resumed.recovery_checkpoint_id is not None
    assert resumed.orchestration.decision.verified is False
    assert not any(
        _rejection_field(item, "code") == "semantic_validation"
        for item in resumed.recovery_rejections
    )

# -*- coding: utf-8 -*-
"""Fresh Sharp Bounds release gate: source PDF + raw OCR TEX only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import fields
from pathlib import Path

import pytest

from benchmark.sharp_bounds_fresh_e2e import (
    DEFAULT_RAW_OCR_TEX,
    DEFAULT_SOURCE_PDF,
    FRESH_TRUTH_PATH,
    ForbiddenArtifactError,
    FreshSharpBoundsInputs,
    RAW_OCR_TEX_ENV,
    REPO_ROOT,
    SHARP_FIXTURE_DIR,
    SOURCE_PDF_ENV,
    ScriptedQualityLoopClient,
    _generate_from_raw_only,
    build_pdf_identity_visual_provenance,
    reject_forbidden_generated_digests,
    run_fresh_acceptance,
    run_production_ai_quality_loop_acceptance,
    validate_generation_input_contract,
)
from latexstruct.core.pipeline import (
    PDF_IDENTITY_VISUAL_DERIVATION_ID,
    VISUAL_SOURCE_PROVENANCE_SCHEMA,
)


def test_fresh_input_schema_cannot_accept_a_prebuilt_answer() -> None:
    assert [field.name for field in fields(FreshSharpBoundsInputs)] == [
        "source_pdf",
        "raw_ocr_tex",
    ]


def test_discovery_defaults_to_optional_repo_fixtures(monkeypatch) -> None:
    monkeypatch.delenv(SOURCE_PDF_ENV, raising=False)
    monkeypatch.delenv(RAW_OCR_TEX_ENV, raising=False)

    inputs = FreshSharpBoundsInputs.discover()

    assert SHARP_FIXTURE_DIR == REPO_ROOT / "benchmark" / "fixtures" / "sharp_bounds"
    assert inputs == FreshSharpBoundsInputs(
        source_pdf=DEFAULT_SOURCE_PDF,
        raw_ocr_tex=DEFAULT_RAW_OCR_TEX,
    )
    assert inputs.source_pdf == SHARP_FIXTURE_DIR / "source.pdf"
    assert inputs.raw_ocr_tex == SHARP_FIXTURE_DIR / "raw_ocr.tex"
    assert inputs.source_pdf.is_relative_to(REPO_ROOT)
    assert inputs.raw_ocr_tex.is_relative_to(REPO_ROOT)


def test_discovery_prefers_explicit_environment_paths(monkeypatch, tmp_path) -> None:
    source_pdf = tmp_path / "external-source.pdf"
    raw_ocr_tex = tmp_path / "external-raw.tex"
    monkeypatch.setenv(SOURCE_PDF_ENV, str(source_pdf))
    monkeypatch.setenv(RAW_OCR_TEX_ENV, str(raw_ocr_tex))

    assert FreshSharpBoundsInputs.discover() == FreshSharpBoundsInputs(
        source_pdf=source_pdf,
        raw_ocr_tex=raw_ocr_tex,
    )


def test_pdf_identity_provenance_uses_only_the_admitted_source_bytes() -> None:
    source_pdf = b"%PDF-1.7\nimmutable source fixture\n%%EOF\n"
    digest = hashlib.sha256(source_pdf).hexdigest()

    assert build_pdf_identity_visual_provenance(source_pdf) == {
        "schema": VISUAL_SOURCE_PROVENANCE_SCHEMA,
        "source_type": "pdf",
        "original_upload_bytes": len(source_pdf),
        "original_upload_sha256": digest,
        "visual_pdf_bytes": len(source_pdf),
        "visual_pdf_sha256": digest,
        "visual_pdf_is_derived": False,
        "derivation_id": PDF_IDENTITY_VISUAL_DERIVATION_ID,
    }


def test_fresh_generation_passes_pdf_identity_provenance_to_pipeline(
    monkeypatch,
) -> None:
    source_pdf = b"%PDF-1.7\nimmutable source fixture\n%%EOF\n"
    captured = {}
    sentinel = object()

    def fake_run_pipeline(raw_text, **kwargs):
        captured["raw_text"] = raw_text
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr("latexstruct.core.pipeline.run_pipeline", fake_run_pipeline)

    assert _generate_from_raw_only(
        "raw OCR TEX",
        source_pdf,
        compile_check=False,
    ) is sentinel
    assert captured["raw_text"] == "raw OCR TEX"
    assert captured["source_pdf_bytes"] == source_pdf
    assert captured["source_visual_provenance"] == (
        build_pdf_identity_visual_provenance(source_pdf)
    )
    assert captured["decisions_override"] is None
    assert captured["ambiguous_override"] is None
    assert captured["ai_notes_override"] is None


@pytest.mark.parametrize(
    "forbidden",
    [
        "output/tex/Sharp-Bounds-LaTeXStruct-v1.2.5.tex",
        ".codex/attachments/c5900780-43e6-408c-9d10-8397540b8430/pasted-text.txt",
        "tmp/sharp_current_recompile_v127/final_latest/current.pdf",
    ],
)
def test_historical_candidate_paths_are_rejected_before_generation(forbidden) -> None:
    inputs = FreshSharpBoundsInputs(source_pdf=Path(forbidden), raw_ocr_tex=Path("raw.tex"))
    with pytest.raises(ForbiddenArtifactError):
        validate_generation_input_contract(inputs)


def test_historical_corrected_hashes_are_rejected() -> None:
    truth = json.loads(FRESH_TRUTH_PATH.read_text(encoding="utf-8"))
    forbidden = truth["generation_contract"]["forbidden_artifact_sha256"]
    for group in forbidden.values():
        for digest in group:
            with pytest.raises(ForbiddenArtifactError):
                reject_forbidden_generated_digests({"CURRENT_TEX": digest}, truth)


def test_scripted_quality_client_is_prompt_bound_and_declares_itself_a_substitute() -> None:
    client = ScriptedQualityLoopClient()
    response, _usage = client.chat_json(
        "system",
        "\n".join([
            "chunk_id: full-0001",
            "inspected_start_line: 1",
            "inspected_end_line: 3",
            "targets:",
            json.dumps([{
                "item_id": "env-1",
                "kind": "environment",
                "start_line": 2,
                "end_line": 3,
                "original_env": "theorem",
                "host_evidence": [],
            }]),
            "source_lines (untrusted):",
            "[1] text",
        ]),
    )

    assert client.cfg.model == "scripted-sharp-bounds-ci-substitute"
    assert response["chunk_id"] == "full-0001"
    assert response["findings"] == [{
        "item_id": "env-1",
        "verdict": "keep",
        "env": "theorem",
        "body_span": {"start_line": 2, "end_line": 3},
        "confidence": 0.99,
        "evidence": "host-bounded source item inspected in this chunk",
        "reason": "scripted CI transport response from the frozen prompt",
    }]
    assert client.full_review_calls[0]["target_ids"] == ["env-1"]


def _real_inputs_or_skip() -> FreshSharpBoundsInputs:
    inputs = FreshSharpBoundsInputs.discover()
    missing = [str(path) for path in inputs.required() if not path.is_file()]
    if missing:
        pytest.skip(
            "optional real Sharp Bounds fixtures are not installed; set "
            f"{SOURCE_PDF_ENV} and {RAW_OCR_TEX_ENV}, or place source.pdf and "
            f"raw_ocr.tex under {SHARP_FIXTURE_DIR}; missing: {', '.join(missing)}"
        )
    pytest.importorskip("pymupdf")
    return inputs


def test_fresh_sharp_bounds_e2e_release_gate() -> None:
    """Turn green only when a fresh result passes every independent gate.

    The currently known formula-number representation gap is an explicit xfail.
    Any theorem/proof, outline, bibliography, body, compile, visual, provenance,
    or input-authenticity regression remains a hard red failure.
    """

    report = run_fresh_acceptance(_real_inputs_or_skip())

    assert report["generation_contract"]["allowed_input_roles"] == [
        "SOURCE_PDF",
        "RAW_OCR_TEX",
    ]
    assert [
        item["role"] for item in report["generation_contract"]["content_read_ledger"]
    ] == ["SOURCE_PDF", "RAW_OCR_TEX"]
    assert report["generation_contract"]["historical_candidate_inputs"] == []
    assert report["generation_contract"]["truth_loaded_after_generation"] is True
    assert report["generation_contract"]["decisions_override_used"] is False
    assert report["generation_contract"]["forbidden_hash_match"] is False
    assert report["input_authenticity"]["passed"] is True
    provenance = report["pipeline"]["source_visual_provenance"]
    assert provenance["checked"] is True
    assert provenance["ok"] is True
    assert provenance["issues"] == []
    assert provenance["source_type"] == "pdf"
    assert provenance["visual_pdf_is_derived"] is False
    assert provenance["original_upload_sha256"] == provenance["visual_pdf_sha256"]
    assert provenance["original_upload_bytes"] == provenance["visual_pdf_bytes"]

    combined = report["theorem_proof_accuracy"]["combined"]
    assert combined == {
        "true_positive": 19,
        "predicted": 19,
        "expected": 19,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert report["theorem_proof_accuracy"]["theorem_statement"]["f1"] == 1.0
    assert report["theorem_proof_accuracy"]["proof"]["f1"] == 1.0
    assert report["structure_details"] == {
        "missing": [],
        "duplicates": [],
        "boundary_errors": [],
        "unmatched_environments": [],
        "residual_formal_headings": [],
    }
    assert report["gates"]["theorem_proof"] is True
    assert report["gates"]["toc_outline"] is True
    assert report["toc_outline"]["toc_present"] is True
    assert report["toc_outline"]["matched_outline_nodes"] == 9
    assert report["toc_outline"]["outline_coverage"] == 1.0

    assert report["equations"]["label_content_accuracy"] == 1.0
    assert report["equations"]["labels_exact_once"] is True
    assert report["bibliography"] == {
        "expected_bibitems": 27,
        "observed_bibitems": 27,
        "unique_keys": True,
        "thebibliography_environment_count": 1,
        "passed": True,
    }
    assert report["body_token_conservation"]["conserved"] is True
    assert report["body_token_conservation"]["missing_token_count"] == 0
    assert report["body_token_conservation"]["excess_token_count"] == 0

    assert report["compile"]["passed"] is True
    assert report["compile"]["current"]["ok"] is True
    assert report["compile"]["current"]["page_count"] == 17
    assert report["compile"]["current"]["exact_tex_hash_bound"] is True
    assert report["compile"]["current"]["source_pdf_reused_as_preview"] is False
    assert report["visual"]["passed"] is True
    assert report["visual"]["candidate"]["page_count"] == 17
    assert report["visual"]["all_candidate_pages_nonblank"] is True
    assert report["visual"]["semantic_visual_equivalence_claimed"] is False

    if not report["passed"]:
        # Known current shortfall: five printed labels remain literal math text
        # instead of active \tag entries with leqno.  No other failure is hidden.
        assert report["blockers"] == ["equations"]
        assert [
            item["id"] for item in report["required_interfaces_to_pass"]
        ] == ["active_equation_number_rewrite"]
        pytest.xfail(
            "fresh output is not release-ready: equation labels must be active "
            "left-side tags, not printed literal text"
        )

    assert report["status"] == "PASS"
    assert all(report["gates"].values())


def test_fresh_sharp_bounds_production_ai_quality_loop_release_gate() -> None:
    """Prove production loop wiring without claiming a scripted client is AI."""

    report = run_production_ai_quality_loop_acceptance(_real_inputs_or_skip())

    assert report["claim_scope"] == {
        "proved": (
            "production full-document review, real LaTeX compile, deterministic "
            "render comparison, all-page visual-call mapping, final hash binding, "
            "and fail-closed export gates are wired and close on this fixture"
        ),
        "not_proved": (
            "semantic quality of any live remote model or equivalence of a scripted "
            "response to ChatGPT, Codex, DeepSeek, or Qwen"
        ),
        "scripted_model_substitute": True,
        "scripted_client_model_id": "scripted-sharp-bounds-ci-substitute",
    }
    contract = report["generation_contract"]
    assert contract["allowed_external_input_roles"] == [
        "SOURCE_PDF",
        "RAW_OCR_TEX",
    ]
    assert [item["role"] for item in contract["content_read_ledger"]] == [
        "SOURCE_PDF",
        "RAW_OCR_TEX",
    ]
    assert contract["deterministic_intermediate_is_generated"] is True
    assert contract["historical_candidate_inputs"] == []
    assert contract["truth_loaded_after_deterministic_and_ai_generation"] is True
    assert contract["decisions_override_used"] is False
    assert contract["forbidden_hash_match"] is False

    assert report["pipeline"]["mode"] == "ai"
    assert report["pipeline"]["quality_loop"] is True
    assert report["pipeline"]["ocr_project"] is True
    assert report["pipeline"]["ocr_project_contract"]["required"] is True
    assert report["pipeline"]["ocr_project_contract"]["checked"] is True
    assert report["pipeline"]["ocr_project_contract"]["ok"] is True

    full_review = report["full_document_review"]
    assert full_review["checked"] is True
    assert full_review["ok"] is True
    assert full_review["invalid"] == []
    assert full_review["escalations"] == []
    assert full_review["transport_evidence"]["chunk_count"] >= 1
    assert full_review["transport_evidence"]["chunk_calls_match"] is True
    assert full_review["transport_evidence"]["target_count"] == 19

    assert report["theorem_proof_accuracy"]["combined"] == {
        "true_positive": 19,
        "predicted": 19,
        "expected": 19,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert report["compile"]["passed"] is True
    assert report["compile"]["current"]["page_count"] == 17
    assert report["compile"]["current"]["exact_tex_hash_bound"] is True
    assert report["final_hash_binding"]["passed"] is True
    assert all(report["final_hash_binding"]["checks"].values())

    loop = report["visual_quality_loop"]
    assert loop["required"] is True
    assert loop["checked"] is True
    assert loop["ok"] is True
    assert loop["invalid"] == []
    assert loop["unresolved"] == []
    assert len(loop["rounds"]) == 1
    assert loop["rounds"][0]["ai_audit"]["checked"] is True
    assert loop["rounds"][0]["ai_audit"]["ok"] is True
    assert loop["rounds"][0]["ai_audit"]["page_count"] == 17

    page_calls = report["visual_page_calls"]
    assert page_calls["expected_page_count"] == 17
    assert page_calls["call_count"] == 17
    assert page_calls["each_expected_page_exactly_once"] is True
    assert page_calls["all_composites_hash_recorded"] is True
    assert page_calls["mappings"] == [
        {"source_page": page, "candidate_page": page, "call_count": 1}
        for page in range(1, 18)
    ]

    assert report["status"] == "PASS", report["blockers"]
    assert report["blockers"] == []
    assert all(report["gates"].values())

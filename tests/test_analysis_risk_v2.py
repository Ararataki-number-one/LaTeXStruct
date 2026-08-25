from __future__ import annotations

from dataclasses import replace

import pytest

from latexstruct.core.analysis_risk import (
    PageRiskPreflightInput,
    build_page_risk_admission,
    verify_page_risk_admission,
)
from latexstruct.core.analysis_schema import PageRisk, sha256_text


def _input(
    number: int,
    tex: str,
    *,
    source_text: str | None = None,
    **changes: object,
) -> PageRiskPreflightInput:
    values: dict[str, object] = {
        "source_page_id": f"source-page-{number:06d}",
        "source_page_number": number,
        "source_page_object_hash": sha256_text(f"object-{number}"),
        "ocr_coverage_checks": {"persisted": "PASS", "syntax_checked": "PASS"},
        "unresolved_region_hashes": (),
        "baseline_tex_region": tex,
        "candidate_pdf_page_ids": (f"candidate-page-{number:06d}",),
        "source_pdf_text": tex if source_text is None else source_text,
        "ocr_final_status": "SUCCESS",
        "ocr_retry_count": 0,
        "ocr_quality_issues": (),
        "host_quality_flags": (),
        "machine_visual_anomalies": (),
        "double_column": False,
        "complex_layout": False,
        "compile_map_mismatch": False,
        "layout_evidence": {"algorithm": "fixture-layout-v1", "executed": True},
        "compile_map_evidence": {"algorithm": "fixture-map-v1", "matched": True},
    }
    values.update(changes)
    return PageRiskPreflightInput(**values)


def _admission(*pages: PageRiskPreflightInput):
    return build_page_risk_admission(
        source_pdf_sha256=sha256_text("source"),
        ocr_page_records_sha256=sha256_text("records"),
        ocr_runtime_page_records_sha256=sha256_text("runtime-records"),
        baseline_tex_sha256=sha256_text("baseline-tex"),
        baseline_pdf_sha256=sha256_text("baseline-pdf"),
        page_inputs=pages,
    )


@pytest.mark.parametrize(
    ("page", "expected", "reason"),
    (
        (_input(1, "Plain prose."), PageRisk.R0, "plain_page_all_machine_checks_pass"),
        (
            _input(
                1,
                r"\begin{theorem}Result\end{theorem}",
                source_text="theorem Result theorem",
            ),
            PageRisk.R1,
            "formal_candidate_present",
        ),
        (_input(1, r"See \ref{known}.", source_text="See known"), PageRisk.R1, "cross_reference_present"),
        (_input(1, r"One $x$.", source_text="One x"), PageRisk.R1, "sparse_math_present"),
        (
            _input(1, r"$x$ $x$ $x$ $x$", source_text="x x x x"),
            PageRisk.R2,
            "math_dense",
        ),
        (
            _input(1, r"\begin{equation}x\end{equation}", source_text="x"),
            PageRisk.R2,
            "equation_numbering_present",
        ),
        (
            _input(1, "alpha", source_text="alpha beta gamma delta epsilon"),
            PageRisk.R2,
            "source_text_coverage_below_r2_threshold",
        ),
        (
            _input(1, "OCR text", source_text=""),
            PageRisk.R2,
            "text_layer_unavailable",
        ),
        (
            _input(1, "Plain prose.", double_column=True),
            PageRisk.R2,
            "double_column_present",
        ),
        (
            _input(1, "Plain prose.", ocr_retry_count=1),
            PageRisk.R2,
            "ocr_retry_present",
        ),
        (
            _input(1, "Plain prose.", compile_map_mismatch=True),
            PageRisk.R3,
            "compile_or_page_map_mismatch",
        ),
        (
            _input(1, "Plain prose.", ocr_coverage_checks={"persisted": "FAIL"}),
            PageRisk.R3,
            "ocr_coverage_check_failed",
        ),
        (
            _input(1, "Plain prose.", machine_visual_anomalies=None),
            PageRisk.R3,
            "required_preflight_input_missing:machine_visual_anomalies",
        ),
    ),
)
def test_classifier_uses_frozen_explainable_risk_rules(
    page: PageRiskPreflightInput,
    expected: PageRisk,
    reason: str,
) -> None:
    result = _admission(page).pages[0]

    assert result.risk_level is expected
    assert reason in result.risk_reasons


def test_low_risk_sample_is_deterministic_five_percent_minimum_thirty_and_stratified() -> None:
    pages = tuple(_input(number, f"Plain prose page {number}.") for number in range(1, 101))

    first = _admission(*pages)
    second = _admission(*pages)
    sample = first.low_risk_sampling

    assert first.digest == second.digest
    assert sample.seed_sha256 == second.low_risk_sampling.seed_sha256
    assert sample.selected_page_ids == second.low_risk_sampling.selected_page_ids
    assert sample.target_count == 30
    assert len(sample.selected_page_ids) == 30
    selected_bands = {
        page.summary.position_band
        for page in first.pages
        if page.summary.source_page_id in sample.selected_page_ids
    }
    assert {band.value for band in selected_bands} == {"FRONT", "MIDDLE", "BACK"}


def test_admission_recomputation_rejects_forged_classification() -> None:
    admission = _admission(_input(1, "Plain prose."))
    forged_page = replace(
        admission.pages[0],
        risk_reasons=("heading_or_section_boundary_present",),
    )
    forged = replace(admission, pages=(forged_page,))

    with pytest.raises(ValueError, match="classification is forged"):
        verify_page_risk_admission(forged)


def test_runtime_records_and_feature_policy_hashes_are_seed_bound() -> None:
    admission = _admission(_input(1, "Plain prose."))

    with pytest.raises(ValueError, match="seed is not bound"):
        replace(
            admission,
            ocr_runtime_page_records_sha256=sha256_text("forged-runtime"),
        )
    with pytest.raises(ValueError, match="seed is not bound"):
        replace(
            admission,
            classifier_policy_sha256=sha256_text("forged-feature-policy"),
        )

from __future__ import annotations

from dataclasses import replace

import pytest

from latexstruct.core.analysis_risk import (
    PAGE_RISK_CLASSIFIER_POLICY,
    PAGE_RISK_CLASSIFIER_POLICY_SHA256,
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
            PageRisk.R1,
            "sparse_math_present",
        ),
        (
            _input(
                1,
                r"$x$ $x$ $x$ $x$ $x$ $x$ $x$ $x$",
                source_text="x x x x x x x x",
            ),
            PageRisk.R1,
            "math_dense_present",
        ),
        (
            _input(1, r"\begin{equation}x\end{equation}", source_text="x"),
            PageRisk.R1,
            "sparse_math_present",
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


def test_math_feature_extractor_counts_complete_regions_not_delimiter_tokens() -> None:
    page = _input(
        1,
        r"$a$ $$b$$ \(c\) \[d\] \begin{equation}e\end{equation}",
        source_text="a b c d equation e equation",
    )

    result = _admission(page).pages[0]

    assert result.summary.math_region_count == 5
    assert result.risk_level is PageRisk.R1
    assert result.risk_reasons == ("sparse_math_present",)


def test_math_feature_extractor_ignores_escaped_dollars_and_comments() -> None:
    page = _input(
        1,
        "Price \\$5. % $commented$\nPlain text.",
        source_text="Price 5 Plain text",
    )

    result = _admission(page).pages[0]

    assert result.summary.math_region_count == 0
    assert result.risk_level is PageRisk.R0


@pytest.mark.parametrize(
    ("tex", "source_text", "counter"),
    (
        (
            r"\[x\tag{1}\]",
            "x 1",
            "equation_number_count",
        ),
        (r"Text\footnote{note}.", "Text note", "footnote_count"),
        (
            r"\begin{figure}\includegraphics{a}\end{figure}",
            "figure a figure",
            "figure_table_count",
        ),
        (
            r"\begin{table}cell\end{table}",
            "table cell table",
            "figure_table_count",
        ),
        (
            r"\caption{Cap}",
            "Cap",
            "caption_count",
        ),
    ),
)
def test_verified_content_presence_is_inventory_only_not_an_r2_anomaly(
    tex: str,
    source_text: str,
    counter: str,
) -> None:
    result = _admission(_input(1, tex, source_text=source_text)).pages[0]

    assert getattr(result.summary, counter) > 0
    assert result.risk_level is not PageRisk.R2
    assert not set(result.risk_reasons).intersection(
        PAGE_RISK_CLASSIFIER_POLICY["presence_only_features"]
    )


def test_benign_quality_and_host_evidence_rows_do_not_raise_risk() -> None:
    result = _admission(_input(
        1,
        "Plain prose.",
        ocr_quality_issues=({
            "code": "INFORMATIONAL_CHECK",
            "severity": "info",
        },),
        host_quality_flags=({
            "type": "visual_verifier",
            "verdict": "PASS",
            "needs_review": False,
        }, {
            "type": "equation_tag_integrity_evidence",
            "status": "source_geometry_and_active_match",
        }),
    )).pages[0]
    empty = _admission(_input(1, "Plain prose.")).pages[0]

    assert result.summary.ocr_quality_issue_count == 0
    assert result.summary.host_quality_flag_count == 0
    assert (
        result.summary.ocr_quality_issues_hash
        != empty.summary.ocr_quality_issues_hash
    )
    assert (
        result.summary.host_quality_flags_hash
        != empty.summary.host_quality_flags_hash
    )
    assert result.risk_level is PageRisk.R0


@pytest.mark.parametrize(
    ("changes", "reason"),
    (
        (
            {"host_quality_flags": ({
                "type": "equation_number_mismatch",
                # Explicit mismatch evidence remains risky even if a producer
                # accidentally marks the generic review bit false.
                "needs_review": False,
            },)},
            "host_quality_flag_present",
        ),
        (
            {"ocr_quality_issues": ({
                "code": "MISSING_CAPTION",
                "severity": "error",
            },)},
            "ocr_quality_issue_present",
        ),
        (
            {"machine_visual_anomalies": ({"type": "figure_shift"},)},
            "machine_visual_anomaly_present",
        ),
    ),
)
def test_affirmative_anomaly_or_mismatch_evidence_remains_r2(
    changes: dict[str, object],
    reason: str,
) -> None:
    result = _admission(_input(1, "Plain prose.", **changes)).pages[0]

    assert result.risk_level is PageRisk.R2
    assert reason in result.risk_reasons


def test_math_density_only_contextualizes_an_independent_r2_anomaly() -> None:
    dense_tex = r"$x$ $x$ $x$ $x$ $x$ $x$ $x$ $x$"
    source_text = "x x x x x x x x"

    dense_only = _admission(_input(
        1,
        dense_tex,
        source_text=source_text,
    )).pages[0]
    with_anomaly = _admission(_input(
        1,
        dense_tex,
        source_text=source_text,
        machine_visual_anomalies=({"type": "figure_shift"},),
    )).pages[0]

    assert dense_only.risk_level is PageRisk.R1
    assert dense_only.risk_reasons == ("math_dense_present",)
    assert with_anomaly.risk_level is PageRisk.R2
    assert with_anomaly.risk_reasons == (
        "machine_visual_anomaly_present",
        "math_dense_with_r2_anomaly",
    )


def test_policy_version_records_presence_only_and_real_region_semantics() -> None:
    assert PAGE_RISK_CLASSIFIER_POLICY["schema_version"] == (
        "latexstruct-page-risk-classifier-policy-v4"
    )
    assert PAGE_RISK_CLASSIFIER_POLICY["feature_extractor_version"] == (
        "latexstruct-page-risk-feature-extractor-v3"
    )
    assert PAGE_RISK_CLASSIFIER_POLICY["thresholds"] == {
        "source_text_r2_minimum_coverage_ppm": 970_000,
        "math_dense_minimum_region_count": 8,
    }
    assert set(PAGE_RISK_CLASSIFIER_POLICY["presence_only_features"]).isdisjoint(
        PAGE_RISK_CLASSIFIER_POLICY["r2"]
    )
    assert "math_dense_present" in PAGE_RISK_CLASSIFIER_POLICY[
        "presence_only_features"
    ]
    assert "math_dense" not in PAGE_RISK_CLASSIFIER_POLICY["r2"]
    assert "math_dense_with_r2_anomaly" in PAGE_RISK_CLASSIFIER_POLICY["r2"]
    assert PAGE_RISK_CLASSIFIER_POLICY_SHA256 == (
        "23222cdccc1ce86320996ae3b851c272df59e5b12974cedaf815bb8f56ca911d"
    )


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

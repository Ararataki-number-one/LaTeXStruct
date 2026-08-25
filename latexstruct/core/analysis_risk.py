# -*- coding: utf-8 -*-
"""Deterministic page-risk admission, sampling, and route evidence helpers.

This module is deliberately model-free.  It turns already-verified OCR and
baseline facts into a content-free risk summary, classifies it with a frozen
host policy, and selects the low-risk audit cohort without run ids, clocks, or
caller-provided randomness.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import Mapping, Sequence

from .analysis_schema import (
    LowRiskSamplingEvidence,
    LowRiskSamplingPolicy,
    LowRiskSamplingSeed,
    PagePositionBand,
    PageRisk,
    PageRiskAdmission,
    PageRiskAdmissionPage,
    PageRiskInputSummary,
    canonical_json_bytes,
    sha256_bytes,
    sha256_text,
)


SOURCE_TEXT_R2_MINIMUM_COVERAGE_PPM = 970_000
MATH_DENSE_MINIMUM_SIGNAL_COUNT = 8

PAGE_RISK_CLASSIFIER_POLICY = {
    "schema_version": "latexstruct-page-risk-classifier-policy-v2",
    "feature_extractor_version": "latexstruct-page-risk-feature-extractor-v2",
    "visual_layout_algorithm_version": "latexstruct-visual-layout-preflight-v1",
    "machine_visual_algorithm_version": "latexstruct-machine-visual-preflight-v1",
    "compile_map_algorithm_version": "latexstruct-compile-map-preflight-v1",
    "thresholds": {
        "source_text_r2_minimum_coverage_ppm": (
            SOURCE_TEXT_R2_MINIMUM_COVERAGE_PPM
        ),
        "math_dense_minimum_signal_count": MATH_DENSE_MINIMUM_SIGNAL_COUNT,
    },
    "required_preflight_inputs": [
        "compile_map_mismatch",
        "compile_map_evidence",
        "complex_layout",
        "double_column",
        "host_quality_flags",
        "layout_evidence",
        "machine_visual_anomalies",
        "ocr_coverage_checks",
        "ocr_final_status",
        "ocr_quality_issues",
        "ocr_retry_count",
        "source_page_object_hash",
        "source_pdf_text",
    ],
    "r3": [
        "baseline_region_missing",
        "candidate_page_mapping_missing",
        "compile_or_page_map_mismatch",
        "ocr_coverage_check_failed",
        "ocr_page_not_successful",
        "required_preflight_input_missing",
        "unresolved_ocr_evidence",
        "tex_syntax_unbalanced",
    ],
    "r2": [
        "candidate_page_mapping_spans_multiple_pages",
        "caption_present",
        "complex_layout_present",
        "double_column_present",
        "equation_numbering_present",
        "figure_or_table_present",
        "footnote_present",
        "host_quality_flag_present",
        "machine_visual_anomaly_present",
        "math_dense",
        "ocr_quality_issue_present",
        "ocr_retry_present",
        "source_text_coverage_below_r2_threshold",
        "text_layer_unavailable",
    ],
    "r1": [
        "cross_reference_present",
        "formal_candidate_present",
        "hard_page_break_present",
        "heading_or_section_boundary_present",
        "sparse_math_present",
        "structural_boundary_present",
    ],
    "r0": ["plain_page_all_machine_checks_pass"],
}
PAGE_RISK_CLASSIFIER_POLICY_SHA256 = sha256_bytes(
    canonical_json_bytes(PAGE_RISK_CLASSIFIER_POLICY)
)

_HEADING_RE = re.compile(
    r"\\(?:part|chapter|section|subsection|subsubsection)\*?\s*\{([^{}]*)\}",
    re.IGNORECASE,
)
_FORMAL_RE = re.compile(
    r"\\begin\{(?:theorem|lemma|definition|proposition|corollary|proof|remark|example)\*?\}",
    re.IGNORECASE,
)
_MATH_RE = re.compile(
    r"(?:\\begin\{(?:equation|align|gather|multline|displaymath|math)\*?\}|\\\[|\\\(|(?<!\\)\$)",
    re.IGNORECASE,
)
_FIGURE_TABLE_RE = re.compile(
    r"\\begin\{(?:figure|table)\*?\}|\\includegraphics\b|\\caption\b",
    re.IGNORECASE,
)
_FOOTNOTE_RE = re.compile(r"\\footnote\b", re.IGNORECASE)
_CROSS_REFERENCE_RE = re.compile(
    r"\\(?:label|ref|eqref|pageref|cite|bibliography)\b", re.IGNORECASE
)
_EQUATION_NUMBER_RE = re.compile(
    r"\\begin\{(?:equation|align|gather|multline)\}|\\tag\s*\{",
    re.IGNORECASE,
)
_CAPTION_RE = re.compile(r"\\caption\b", re.IGNORECASE)
_HARD_PAGE_BREAK_RE = re.compile(
    r"\\(?:newpage|clearpage|pagebreak)\b", re.IGNORECASE
)
_BOUNDARY_RE = re.compile(
    r"\\(?:part|chapter)\*?\s*\{|"
    r"\\begin\{thebibliography\}|\\bibliography\b|"
    r"\\(?:frontmatter|mainmatter|backmatter|appendix)\b",
    re.IGNORECASE,
)
_TEX_COMMAND_RE = re.compile(r"\\[A-Za-z@]+\*?")
_TEX_COMMENT_RE = re.compile(r"(?m)(?<!\\)%.*$")
_TEXT_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass(frozen=True, slots=True)
class PageRiskPreflightInput:
    source_page_id: str
    source_page_number: int
    source_page_object_hash: str
    ocr_coverage_checks: Mapping[str, object] | None
    unresolved_region_hashes: tuple[str, ...]
    baseline_tex_region: str
    candidate_pdf_page_ids: tuple[str, ...]
    source_pdf_text: str | None = None
    ocr_final_status: str | None = None
    ocr_retry_count: int | None = None
    ocr_quality_issues: tuple[object, ...] | None = None
    host_quality_flags: tuple[object, ...] | None = None
    machine_visual_anomalies: tuple[object, ...] | None = None
    double_column: bool | None = None
    complex_layout: bool | None = None
    compile_map_mismatch: bool | None = None
    layout_evidence: object | None = None
    compile_map_evidence: object | None = None


def _position_band(page_number: int, page_count: int) -> PagePositionBand:
    bucket = min(2, ((page_number - 1) * 3) // page_count)
    return tuple(PagePositionBand)[bucket]


def _balanced_tex_braces(value: str) -> bool:
    depth = 0
    escaped = False
    for character in value:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _text_tokens(value: str) -> tuple[str, ...]:
    return tuple(
        match.group(0).casefold()
        for match in _TEXT_TOKEN_RE.finditer(value)
    )


def _baseline_plain_text(value: str) -> str:
    without_comments = _TEX_COMMENT_RE.sub(" ", value)
    without_commands = _TEX_COMMAND_RE.sub(" ", without_comments)
    return " ".join(_text_tokens(without_commands))


def _source_coverage(
    source_text: str,
    baseline_plain_text: str,
) -> tuple[int, int, int, int]:
    source_tokens = _text_tokens(source_text)
    baseline_tokens = _text_tokens(baseline_plain_text)
    covered = sum((Counter(source_tokens) & Counter(baseline_tokens)).values())
    coverage_ppm = (
        covered * 1_000_000 // len(source_tokens)
        if source_tokens
        else 0
    )
    return len(source_tokens), len(baseline_tokens), covered, coverage_ppm


def _section_ids(inputs: Sequence[PageRiskPreflightInput]) -> dict[int, str]:
    current = "section:frontmatter"
    output: dict[int, str] = {}
    for item in inputs:
        headings = _HEADING_RE.findall(item.baseline_tex_region)
        if headings:
            normalized = " ".join(headings[-1].split()).casefold()
            current = f"section:{sha256_text(normalized)[:16]}"
        output[item.source_page_number] = current
    return output


def classify_page_risk(summary: PageRiskInputSummary) -> tuple[PageRisk, tuple[str, ...]]:
    """Recompute the exact risk tier and sorted reason tokens."""

    r3 = [
        f"required_preflight_input_missing:{name}"
        for name in summary.required_evidence_missing
    ]
    if summary.baseline_tex_bytes == 0:
        r3.append("baseline_region_missing")
    if summary.candidate_page_count == 0:
        r3.append("candidate_page_mapping_missing")
    if summary.compile_map_mismatch:
        r3.append("compile_or_page_map_mismatch")
    if not summary.ocr_coverage_all_pass:
        r3.append("ocr_coverage_check_failed")
    if not summary.ocr_final_success:
        r3.append("ocr_page_not_successful")
    if summary.unresolved_region_count:
        r3.append("unresolved_ocr_evidence")
    if not summary.syntax_balanced:
        r3.append("tex_syntax_unbalanced")
    if r3:
        return PageRisk.R3, tuple(sorted(set(r3)))

    r2: list[str] = []
    if summary.candidate_page_count > 1:
        r2.append("candidate_page_mapping_spans_multiple_pages")
    if summary.text_layer_unavailable:
        r2.append("text_layer_unavailable")
    elif summary.source_text_coverage_ppm < SOURCE_TEXT_R2_MINIMUM_COVERAGE_PPM:
        r2.append("source_text_coverage_below_r2_threshold")
    if summary.ocr_retry_count:
        r2.append("ocr_retry_present")
    if summary.ocr_quality_issue_count:
        r2.append("ocr_quality_issue_present")
    if summary.host_quality_flag_count:
        r2.append("host_quality_flag_present")
    if summary.machine_visual_anomaly_count:
        r2.append("machine_visual_anomaly_present")
    if summary.double_column:
        r2.append("double_column_present")
    if summary.complex_layout:
        r2.append("complex_layout_present")
    if summary.math_region_count >= MATH_DENSE_MINIMUM_SIGNAL_COUNT:
        r2.append("math_dense")
    if summary.equation_number_count:
        r2.append("equation_numbering_present")
    if summary.figure_table_count:
        r2.append("figure_or_table_present")
    if summary.caption_count:
        r2.append("caption_present")
    if summary.footnote_count:
        r2.append("footnote_present")
    if r2:
        return PageRisk.R2, tuple(sorted(set(r2)))
    r1: list[str] = []
    if summary.formal_candidate_count:
        r1.append("formal_candidate_present")
    if summary.cross_reference_count:
        r1.append("cross_reference_present")
    if summary.heading_count:
        r1.append("heading_or_section_boundary_present")
    if summary.hard_page_break_count:
        r1.append("hard_page_break_present")
    if summary.boundary_count:
        r1.append("structural_boundary_present")
    if summary.math_region_count:
        r1.append("sparse_math_present")
    if r1:
        return PageRisk.R1, tuple(sorted(set(r1)))
    return PageRisk.R0, ("plain_page_all_machine_checks_pass",)


def _rank(seed_sha256: str, source_page_id: str) -> str:
    return sha256_bytes(canonical_json_bytes({
        "schema_version": "latexstruct-low-risk-rank-v1",
        "seed_sha256": seed_sha256,
        "source_page_id": source_page_id,
    }))


def _sampling_evidence(
    *,
    pages: Sequence[PageRiskAdmissionPage],
    source_pdf_sha256: str,
    ocr_page_records_sha256: str,
    ocr_runtime_page_records_sha256: str,
    baseline_tex_sha256: str,
    page_ids_sha256: str,
) -> LowRiskSamplingEvidence:
    policy = LowRiskSamplingPolicy()
    seed = LowRiskSamplingSeed(
        source_pdf_sha256=source_pdf_sha256,
        ocr_page_records_sha256=ocr_page_records_sha256,
        ocr_runtime_page_records_sha256=ocr_runtime_page_records_sha256,
        baseline_tex_sha256=baseline_tex_sha256,
        classifier_policy_sha256=PAGE_RISK_CLASSIFIER_POLICY_SHA256,
        page_ids_sha256=page_ids_sha256,
    )
    low_pages = tuple(
        item
        for item in pages
        if item.risk_level in {PageRisk.R0, PageRisk.R1}
    )
    population = tuple(item.summary.source_page_id for item in low_pages)
    rank_by_id = {
        item.summary.source_page_id: _rank(seed.digest, item.summary.source_page_id)
        for item in low_pages
    }
    by_id = {item.summary.source_page_id: item for item in low_pages}
    mandatory: set[str] = set()
    for band in PagePositionBand:
        cohort = [
            item for item in low_pages if item.summary.position_band == band
        ]
        if cohort:
            mandatory.add(min(
                cohort,
                key=lambda item: (
                    rank_by_id[item.summary.source_page_id],
                    item.summary.source_page_number,
                ),
            ).summary.source_page_id)
    for section_id in sorted({item.summary.section_id for item in low_pages}):
        cohort = [
            item for item in low_pages if item.summary.section_id == section_id
        ]
        mandatory.add(min(
            cohort,
            key=lambda item: (
                rank_by_id[item.summary.source_page_id],
                item.summary.source_page_number,
            ),
        ).summary.source_page_id)
    population_count = len(population)
    target = min(
        population_count,
        max(
            math.ceil(
                population_count * policy.rate_numerator / policy.rate_denominator
            ),
            min(policy.minimum_pages, population_count),
            len(mandatory),
        ),
    )
    selected = set(mandatory)
    ranked_remaining = sorted(
        (page_id for page_id in population if page_id not in selected),
        key=lambda page_id: (
            rank_by_id[page_id],
            by_id[page_id].summary.source_page_number,
        ),
    )
    selected.update(ranked_remaining[: max(0, target - len(selected))])
    order = {
        item.summary.source_page_id: item.summary.source_page_number for item in low_pages
    }
    mandatory_ids = tuple(sorted(mandatory, key=order.get))
    selected_ids = tuple(sorted(selected, key=order.get))
    return LowRiskSamplingEvidence(
        policy=policy,
        policy_sha256=policy.digest,
        seed_material=seed,
        seed_sha256=seed.digest,
        population_page_ids=population,
        population_page_ids_sha256=sha256_bytes(canonical_json_bytes(list(population))),
        mandatory_page_ids=mandatory_ids,
        mandatory_page_ids_sha256=sha256_bytes(
            canonical_json_bytes(list(mandatory_ids))
        ),
        target_count=target,
        selected_page_ids=selected_ids,
        selected_page_ids_sha256=sha256_bytes(
            canonical_json_bytes(list(selected_ids))
        ),
        all_low_risk_selected=len(selected_ids) == population_count,
    )


def build_page_risk_admission(
    *,
    source_pdf_sha256: str,
    ocr_page_records_sha256: str,
    ocr_runtime_page_records_sha256: str,
    baseline_tex_sha256: str,
    baseline_pdf_sha256: str,
    page_inputs: Sequence[PageRiskPreflightInput],
) -> PageRiskAdmission:
    """Build an immutable v2 admission from exact pre-model page inputs."""

    inputs = tuple(page_inputs)
    numbers = tuple(item.source_page_number for item in inputs)
    if not inputs or numbers != tuple(sorted(numbers)) or len(numbers) != len(set(numbers)):
        raise ValueError("page-risk preflight inputs must be non-empty, unique, and ordered")
    page_count = len(inputs)
    sections = _section_ids(inputs)
    pages: list[PageRiskAdmissionPage] = []
    for ordinal, item in enumerate(inputs, start=1):
        missing: list[str] = []
        if item.ocr_coverage_checks is None:
            missing.append("ocr_coverage_checks")
            checks: dict[str, object] = {}
        else:
            checks = dict(item.ocr_coverage_checks)
        coverage_all_pass = bool(checks) and all(
            value == "PASS" for value in checks.values()
        )
        source_text = item.source_pdf_text
        if source_text is None:
            missing.append("source_pdf_text")
            source_text = ""
        baseline_plain_text = _baseline_plain_text(item.baseline_tex_region)
        (
            source_token_count,
            baseline_token_count,
            covered_token_count,
            coverage_ppm,
        ) = _source_coverage(source_text, baseline_plain_text)
        retry_count = item.ocr_retry_count
        if type(retry_count) is not int or retry_count < 0:
            missing.append("ocr_retry_count")
            retry_count = 0

        def evidence_values(
            value: tuple[object, ...] | None,
            field_name: str,
        ) -> tuple[str, ...]:
            if value is None:
                missing.append(field_name)
                return ()
            return tuple(
                sha256_bytes(canonical_json_bytes(entry)) for entry in value
            )

        quality_issues = evidence_values(
            item.ocr_quality_issues,
            "ocr_quality_issues",
        )
        host_flags = evidence_values(
            item.host_quality_flags,
            "host_quality_flags",
        )
        visual_anomalies = evidence_values(
            item.machine_visual_anomalies,
            "machine_visual_anomalies",
        )
        bool_evidence: dict[str, bool] = {}
        for field_name in (
            "double_column",
            "complex_layout",
            "compile_map_mismatch",
        ):
            value = getattr(item, field_name)
            if type(value) is not bool:
                missing.append(field_name)
                value = False
            bool_evidence[field_name] = value
        opaque_evidence: dict[str, object] = {}
        for field_name in ("layout_evidence", "compile_map_evidence"):
            value = getattr(item, field_name)
            if value is None:
                missing.append(field_name)
                value = {"status": "MISSING"}
            opaque_evidence[field_name] = value
        final_status = item.ocr_final_status
        if final_status is None:
            missing.append("ocr_final_status")
        source_object_hash = str(item.source_page_object_hash or "").lower()
        if re.fullmatch(r"[0-9a-f]{64}", source_object_hash) is None:
            missing.append("source_page_object_hash")
            source_object_hash = sha256_text("missing-source-page-object")
        candidate_ids = tuple(str(value).strip() for value in item.candidate_pdf_page_ids)
        candidate_ids_valid = (
            all(candidate_ids)
            and len(candidate_ids) == len(set(candidate_ids))
        ) if candidate_ids else True
        compile_map_mismatch = (
            bool_evidence["compile_map_mismatch"] or not candidate_ids_valid
        )
        summary = PageRiskInputSummary(
            source_page_id=item.source_page_id,
            source_page_number=item.source_page_number,
            source_page_object_hash=source_object_hash,
            source_pdf_text_hash=sha256_text(source_text),
            baseline_tex_region_hash=sha256_text(item.baseline_tex_region),
            baseline_plain_text_hash=sha256_text(baseline_plain_text),
            baseline_tex_bytes=len(item.baseline_tex_region.encode("utf-8")),
            candidate_page_count=len(candidate_ids),
            candidate_page_ids_hash=sha256_bytes(
                canonical_json_bytes(list(candidate_ids))
            ),
            ocr_coverage_hash=sha256_bytes(canonical_json_bytes(checks)),
            ocr_coverage_all_pass=coverage_all_pass,
            ocr_final_success=final_status == "SUCCESS",
            ocr_retry_count=retry_count,
            ocr_quality_issue_count=len(quality_issues),
            ocr_quality_issues_hash=sha256_bytes(
                canonical_json_bytes(list(quality_issues))
            ),
            host_quality_flag_count=len(host_flags),
            host_quality_flags_hash=sha256_bytes(
                canonical_json_bytes(list(host_flags))
            ),
            machine_visual_anomaly_count=len(visual_anomalies),
            machine_visual_anomalies_hash=sha256_bytes(
                canonical_json_bytes(list(visual_anomalies))
            ),
            section_id=sections[item.source_page_number],
            # Page ranges need not start at source page one.  Positional
            # strata are therefore computed from the admitted cohort ordinal,
            # not from an absolute source page number.
            position_band=_position_band(ordinal, page_count),
            syntax_balanced=_balanced_tex_braces(item.baseline_tex_region),
            compile_map_mismatch=compile_map_mismatch,
            compile_map_evidence_hash=sha256_bytes(canonical_json_bytes(
                opaque_evidence["compile_map_evidence"]
            )),
            double_column=bool_evidence["double_column"],
            complex_layout=bool_evidence["complex_layout"],
            layout_evidence_hash=sha256_bytes(canonical_json_bytes(
                opaque_evidence["layout_evidence"]
            )),
            required_evidence_missing=tuple(sorted(set(missing))),
            source_text_token_count=source_token_count,
            baseline_text_token_count=baseline_token_count,
            source_text_covered_token_count=covered_token_count,
            source_text_coverage_ppm=coverage_ppm,
            text_layer_unavailable=not source_token_count,
            unresolved_region_count=len(tuple(item.unresolved_region_hashes)),
            unresolved_region_hashes_hash=sha256_bytes(canonical_json_bytes(
                list(item.unresolved_region_hashes)
            )),
            math_region_count=len(_MATH_RE.findall(item.baseline_tex_region)),
            equation_number_count=len(
                _EQUATION_NUMBER_RE.findall(item.baseline_tex_region)
            ),
            formal_candidate_count=len(_FORMAL_RE.findall(item.baseline_tex_region)),
            figure_table_count=len(_FIGURE_TABLE_RE.findall(item.baseline_tex_region)),
            caption_count=len(_CAPTION_RE.findall(item.baseline_tex_region)),
            footnote_count=len(_FOOTNOTE_RE.findall(item.baseline_tex_region)),
            cross_reference_count=len(_CROSS_REFERENCE_RE.findall(item.baseline_tex_region)),
            heading_count=len(_HEADING_RE.findall(item.baseline_tex_region)),
            hard_page_break_count=len(
                _HARD_PAGE_BREAK_RE.findall(item.baseline_tex_region)
            ),
            boundary_count=len(_BOUNDARY_RE.findall(item.baseline_tex_region)),
        )
        risk, reasons = classify_page_risk(summary)
        pages.append(PageRiskAdmissionPage(
            summary=summary,
            summary_sha256=summary.digest,
            risk_level=risk,
            risk_reasons=reasons,
        ))
    page_tuple = tuple(pages)
    page_ids = tuple(item.summary.source_page_id for item in page_tuple)
    page_ids_sha256 = sha256_bytes(canonical_json_bytes(list(page_ids)))
    sampling = _sampling_evidence(
        pages=page_tuple,
        source_pdf_sha256=source_pdf_sha256,
        ocr_page_records_sha256=ocr_page_records_sha256,
        ocr_runtime_page_records_sha256=ocr_runtime_page_records_sha256,
        baseline_tex_sha256=baseline_tex_sha256,
        page_ids_sha256=page_ids_sha256,
    )
    return PageRiskAdmission(
        source_pdf_sha256=source_pdf_sha256,
        ocr_page_records_sha256=ocr_page_records_sha256,
        ocr_runtime_page_records_sha256=ocr_runtime_page_records_sha256,
        baseline_tex_sha256=baseline_tex_sha256,
        baseline_pdf_sha256=baseline_pdf_sha256,
        classifier_policy_sha256=PAGE_RISK_CLASSIFIER_POLICY_SHA256,
        page_ids_sha256=page_ids_sha256,
        pages=page_tuple,
        low_risk_sampling=sampling,
    )


def verify_page_risk_admission(admission: PageRiskAdmission) -> PageRiskAdmission:
    """Independently recompute classification and deterministic sampling."""

    if admission.classifier_policy_sha256 != PAGE_RISK_CLASSIFIER_POLICY_SHA256:
        raise ValueError("page-risk classifier policy hash is unsupported")
    for page in admission.pages:
        expected_risk, expected_reasons = classify_page_risk(page.summary)
        if page.risk_level != expected_risk or page.risk_reasons != expected_reasons:
            raise ValueError(
                f"page-risk classification is forged for page {page.summary.source_page_number}"
            )
    expected_sampling = _sampling_evidence(
        pages=admission.pages,
        source_pdf_sha256=admission.source_pdf_sha256,
        ocr_page_records_sha256=admission.ocr_page_records_sha256,
        ocr_runtime_page_records_sha256=(
            admission.ocr_runtime_page_records_sha256
        ),
        baseline_tex_sha256=admission.baseline_tex_sha256,
        page_ids_sha256=admission.page_ids_sha256,
    )
    if admission.low_risk_sampling.canonical_payload() != expected_sampling.canonical_payload():
        raise ValueError("low-risk sampling evidence differs from the fixed algorithm")
    return admission


def coerce_page_risk_admission(value: object) -> PageRiskAdmission:
    if isinstance(value, PageRiskAdmission):
        return verify_page_risk_admission(value)
    if not isinstance(value, Mapping):
        raise ValueError("page-risk admission must be an object")
    raw = dict(value)
    claimed_digest = raw.pop("admission_sha256", None)
    required = {
        "schema_version",
        "strategy",
        "classifier_version",
        "source_pdf_sha256",
        "ocr_page_records_sha256",
        "ocr_runtime_page_records_sha256",
        "baseline_tex_sha256",
        "baseline_pdf_sha256",
        "classifier_policy_sha256",
        "page_ids_sha256",
        "pages",
        "low_risk_sampling",
    }
    if set(raw) != required:
        raise ValueError("page-risk admission fields are not exact")
    admission = PageRiskAdmission(**raw)
    if claimed_digest is not None and claimed_digest != admission.digest:
        raise ValueError("page-risk admission digest is forged")
    return verify_page_risk_admission(admission)


__all__ = [
    "PAGE_RISK_CLASSIFIER_POLICY",
    "PAGE_RISK_CLASSIFIER_POLICY_SHA256",
    "PageRiskPreflightInput",
    "build_page_risk_admission",
    "classify_page_risk",
    "coerce_page_risk_admission",
    "verify_page_risk_admission",
]

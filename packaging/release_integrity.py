#!/usr/bin/env python3
"""Fail-closed release attestation and Windows asset integrity utilities."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.pricing import estimate_call_cost


RELEASE_ATTESTATION_SCHEMA = "latexstruct-release-acceptance/11"
RUN_ATTESTATION_SCHEMA = "latexstruct-v2-ocr-acceptance-attestation/2"
ANALYSIS_ATTESTATION_SCHEMA = "latexstruct-v2-analysis-acceptance-attestation/10"
ANALYSIS_PERFORMANCE_SCHEMA = "latexstruct-v2-analysis-performance/2"
ANALYSIS_PERFORMANCE_CLAIM_SCHEMA = (
    "latexstruct-v2-analysis-performance-claim/1"
)
ANALYSIS_VALIDATION_SCHEMA = "latexstruct-v2-analysis-validation/1"
ANALYSIS_MACHINE_VERIFICATION_SCHEMA = "latexstruct-v2-analysis-machine-verification/1"
CANDIDATE_PAGE_MAPPING_SCHEMA = "latexstruct-v2-candidate-page-mapping/1"
RENDER_COMPARE_CLOSED_LOOP_SCHEMA = "latexstruct-v2-render-compare-closed-loop/1"
ANALYSIS_TRANSPORT_CLOSURE_SCHEMA = "latexstruct-v2-analysis-transport-closure/1"
ANALYSIS_BUDGET_CLOSURE_SCHEMA = "latexstruct-v2-analysis-budget-closure/2"
ANALYSIS_PAGE_RISK_CLOSURE_SCHEMA = "latexstruct-v2-analysis-page-risk-closure/2"
PAGE_RISK_ADMISSION_SCHEMA = "latexstruct-analysis-page-risk-admission-v2"
PAGE_RISK_ADMISSION_STRATEGY = (
    "deterministic-preflight-and-fixed-low-risk-sampling-v2"
)
PAGE_RISK_ROUTE_CLOSURE_SCHEMA = "latexstruct-analysis-page-route-closure-v2"
OCR_COVERAGE_CHECK_NAMES = (
    "source_hash_bound",
    "candidate_created",
    "visual_authority_checked",
    "reading_order_checked",
    "text_coverage_checked",
    "math_region_coverage_checked",
    "syntax_checked",
    "persisted",
)
DISCOVERY_ROLE_OPERATIONS = {
    "AI-1": "structure-findings",
    "AI-2": "content-math-findings",
    "AI-3": "visual-findings",
}
ANALYSIS_OPERATION_ROLES = {
    "structure-findings": "AI-1",
    "content-math-findings": "AI-2",
    "visual-triage": "AI-3",
    "visual-findings": "AI-3",
    "structure-recheck": "AI-1",
    "content-math-recheck": "AI-2",
    "visual-recheck": "AI-3",
    "local-patch": "AI-4",
    "issue-review": "AI-5",
    "final-review-1": "AI-5",
    "final-review-2": "AI-5",
    "adjudication": "AI-6",
}
ANALYSIS_RELEASE_MODEL_POLICY_SCHEMA = "latexstruct-analysis-release-model-policy/1"
ANALYSIS_RELEASE_ALLOWED_MODEL_IDS = frozenset({"gpt-5.4-mini"})
ANALYSIS_RELEASE_ALLOWED_REASONING_EFFORTS = frozenset({"high"})
# Compatibility names used by the acceptance fixture and the production budget
# calculator.  The release verifier does not trust these aliases alone: it also
# closes the declared, runtime, model-binding, and transport-contract identities.
ANALYSIS_STABLE_MODEL_ID = "gpt-5.4-mini"
ANALYSIS_STABLE_REASONING_EFFORT = "high"
ANALYSIS_STABLE_MODEL_ROLES = tuple(f"AI-{index}" for index in range(1, 7))
ANALYSIS_STABLE_BACKEND_AUTHORITY_SHA256 = hashlib.sha256(b"unspecified").hexdigest()
ANALYSIS_STABLE_BACKEND_CONFIGURATION_SHA256 = hashlib.sha256(b"").hexdigest()
ASSET_MANIFEST_SCHEMA = "latexstruct-release-assets/1"
GITHUB_ACCEPTANCE_REFERENCE_SCHEMA = "latexstruct-github-acceptance-reference/2"
GITHUB_ACCEPTANCE_ROOT_SCHEMA = "latexstruct-github-acceptance-root/2"
GITHUB_ACCEPTANCE_CLOSURE_SCHEMA = "latexstruct-github-acceptance-closure/2"
GITHUB_ACCEPTANCE_WORKFLOW = ".github/workflows/analysis-37-acceptance.yml"
GITHUB_CANDIDATE_WORKFLOW = ".github/workflows/build.yml"
GITHUB_ACCEPTANCE_EVENT = "workflow_dispatch"
GITHUB_ACCEPTANCE_WORKFLOWS = frozenset(
    {GITHUB_ACCEPTANCE_WORKFLOW, GITHUB_CANDIDATE_WORKFLOW}
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
GITHUB_RUN_ID_RE = re.compile(r"[1-9][0-9]*")
GITHUB_ACCEPTANCE_RUNNER_LABEL_RE = re.compile(
    r"latexstruct-acceptance-[0-9a-f]{32}"
)
RAMSEY_37_SOURCE_SHA256 = (
    "29074289719d99d7fc89f528cc0b140c27be679ea5d2477fe517eff741e7757c"
)
PROFILE_SPECS = {"analysis-37": ("analysis", 37)}
MIN_ANALYSIS_37_CANDIDATE_PAGES = 32
MAX_ANALYSIS_37_CANDIDATE_PAGES = 42
ANALYSIS_EVIDENCE_HASH_FIELDS = frozenset({
    "ocr_baseline_manifest_hash",
    "ocr_page_records_hash",
    "ocr_runtime_page_records_hash",
    "ocr_page_map_hash",
    "ocr_baseline_compile_inputs_hash",
    "baseline_compile_inputs_hash",
    "build_identity_hash",
    "response_schema_hash",
    "analysis_config_hash",
    "budget_summary_hash",
    "page_risk_admission_hash",
})
ANALYSIS_ARTIFACT_SPECS = {
    "candidate_tex": ("candidate.tex", "candidate_tex_sha256"),
    "candidate_pdf": ("candidate.pdf", "candidate_pdf_sha256"),
    "compile_log": ("compile.log", "compile_log_sha256"),
}
OCR_BASELINE_PACKAGE_DIRECTORY = "artifacts/ocr-baseline"
OCR_BASELINE_MANIFEST_MEMBER = "baseline/ocr_baseline_manifest.json"


class ReleaseIntegrityError(RuntimeError):
    """A release candidate lacks required immutable evidence."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pdf_page_count(path: Path) -> int:
    try:
        import pymupdf

        with pymupdf.open(path) as document:
            _require(not document.needs_pass, f"PDF artifact is encrypted: {path.name}")
            count = int(document.page_count)
    except ReleaseIntegrityError:
        raise
    except Exception as exc:
        raise ReleaseIntegrityError(
            f"cannot open PDF artifact {path.name}: {exc}"
        ) from exc
    _require(count > 0, f"PDF artifact has no pages: {path.name}")
    return count


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseIntegrityError(f"cannot read JSON evidence {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseIntegrityError(f"JSON evidence {path.name} is not an object")
    return value


def _load_json_bytes(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseIntegrityError(f"cannot read JSON evidence {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseIntegrityError(f"JSON evidence {label} is not an object")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseIntegrityError(message)


def _safe_relative_member(value: object) -> Path:
    text = str(value or "").replace("\\", "/")
    candidate = Path(text)
    _require(
        bool(text)
        and not candidate.is_absolute()
        and ".." not in candidate.parts
        and ":" not in text,
        "attestation contains an unsafe or absolute path",
    )
    return candidate


def _require_exact_fields(
    value: object,
    *,
    required: set[str],
    label: str,
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"missing or invalid {label}")
    optional = optional or set()
    actual = {str(key) for key in value}
    missing = required - actual
    unknown = actual - required - optional
    _require(not missing, f"{label} is missing fields: {', '.join(sorted(missing))}")
    _require(not unknown, f"{label} contains unsupported fields: {', '.join(sorted(unknown))}")
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"missing or invalid {label}")
    return value


def _require_list(value: object, label: str) -> list[Any]:
    _require(isinstance(value, list), f"missing or invalid {label}")
    return value


def _canonical_json_sha256(value: object) -> str:
    """Digest one JSON value using the production snapshot canonical form."""

    return _sha256_bytes((
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8"))


def _analysis_37_performance_claim(report_record: object) -> dict[str, Any]:
    """Build the only performance claim permitted in a stable projection."""

    report = _require_exact_fields(
        report_record,
        required={"filename", "sha256"},
        label="analysis-37 performance report binding",
    )
    digest = str(report.get("sha256") or "").lower()
    _require(
        report.get("filename") == "analysis-performance.json"
        and SHA256_RE.fullmatch(digest) is not None,
        "analysis-37 performance report binding is invalid",
    )
    return {
        "schema_version": ANALYSIS_PERFORMANCE_CLAIM_SCHEMA,
        "acceptance_profile": "analysis-37",
        "acceptance_sample_pages": 37,
        "performance_target_pages": 600,
        "performance_target_maximum_wall_time_seconds": 7200,
        "target_status": "NOT_EVALUATED",
        "target_met": None,
        "performance_report_filename": "analysis-performance.json",
        "performance_report_sha256": digest,
    }


def _verify_analysis_37_performance_claim(
    value: object,
    *,
    report_record: object,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "acceptance_profile",
        "acceptance_sample_pages",
        "performance_target_pages",
        "performance_target_maximum_wall_time_seconds",
        "target_status",
        "target_met",
        "performance_report_filename",
        "performance_report_sha256",
    }
    claim = dict(_require_exact_fields(
        value,
        required=required,
        label="analysis-37 public performance claim",
    ))
    expected = _analysis_37_performance_claim(report_record)
    _require(
        claim == expected,
        "analysis-37 public performance claim must remain NOT_EVALUATED; "
        "a 600-page target cannot be promoted by the 37-page profile",
    )
    return claim


def page_id_sequence_sha256(page_ids: Sequence[object]) -> str:
    """Return the reproducible digest used for one ordered visual-review scope."""

    _require(
        isinstance(page_ids, Sequence) and not isinstance(page_ids, (str, bytes)),
        "visual page ids must be a sequence",
    )
    normalized = list(page_ids)
    _require(
        bool(normalized)
        and len(normalized) == len(set(normalized))
        and all(isinstance(page_id, str) and bool(page_id.strip()) for page_id in normalized),
        "visual page ids must be unique non-empty strings",
    )
    return _canonical_json_sha256(normalized)


def review_context_sha256(
    *,
    pass_number: int,
    context_id: str,
    candidate_tex_sha256: str,
    checked_page_ids: Sequence[object],
) -> str:
    """Recompute the context identity retained in a release projection."""

    _require(pass_number in {1, 2}, "final-review pass number is invalid")
    _require(bool(str(context_id or "").strip()), "final-review context id is missing")
    candidate_digest = str(candidate_tex_sha256 or "").lower()
    _require(
        SHA256_RE.fullmatch(candidate_digest) is not None,
        "final-review candidate digest is invalid",
    )
    checked = list(checked_page_ids)
    page_id_sequence_sha256(checked)
    return _canonical_json_sha256({
        "pass_number": pass_number,
        "context_id": context_id,
        "candidate_hash": candidate_digest,
        "checked_page_ids": checked,
    })


def build_candidate_page_mapping(
    *,
    source_page_count: int,
    candidate_page_count: int,
    candidate_tex_sha256: str,
    candidate_pdf_sha256: str,
    upstream_mapping_sha256: str,
    canonical_rows: Sequence[Mapping[str, object]],
    candidate_only_pages: Sequence[int],
) -> dict[str, Any]:
    """Build and self-verify the canonical mapping projected into release evidence."""

    payload: dict[str, Any] = {
        "schema_version": CANDIDATE_PAGE_MAPPING_SCHEMA,
        "source_page_count": source_page_count,
        "candidate_page_count": candidate_page_count,
        "candidate_tex_sha256": str(candidate_tex_sha256 or "").lower(),
        "candidate_pdf_sha256": str(candidate_pdf_sha256 or "").lower(),
        "upstream_mapping_sha256": str(upstream_mapping_sha256 or "").lower(),
        "canonical_rows": [dict(row) for row in canonical_rows],
        "candidate_only_pages": list(candidate_only_pages),
    }
    payload["mapping_sha256"] = _canonical_json_sha256(payload)
    return verify_candidate_page_mapping(
        payload,
        expected_source_pages=source_page_count,
        expected_candidate_pages=candidate_page_count,
        expected_candidate_tex_sha256=candidate_tex_sha256,
        expected_candidate_pdf_sha256=candidate_pdf_sha256,
    )


def verify_candidate_page_mapping(
    value: object,
    *,
    expected_source_pages: int,
    expected_candidate_pages: int,
    expected_candidate_tex_sha256: str,
    expected_candidate_pdf_sha256: str,
) -> dict[str, Any]:
    """Recompute a page map and prove both axes are fully, monotonically covered."""

    mapping = dict(_require_exact_fields(
        value,
        required={
            "schema_version",
            "source_page_count",
            "candidate_page_count",
            "candidate_tex_sha256",
            "candidate_pdf_sha256",
            "upstream_mapping_sha256",
            "canonical_rows",
            "candidate_only_pages",
            "mapping_sha256",
        },
        label="canonical candidate page mapping",
    ))
    _require(
        mapping.get("schema_version") == CANDIDATE_PAGE_MAPPING_SCHEMA,
        "unsupported candidate page mapping schema",
    )
    source_count = mapping.get("source_page_count")
    candidate_count = mapping.get("candidate_page_count")
    _require(
        type(source_count) is int
        and source_count == expected_source_pages == 37,
        "candidate page mapping source count is invalid",
    )
    _require(
        type(candidate_count) is int
        and candidate_count == expected_candidate_pages
        and MIN_ANALYSIS_37_CANDIDATE_PAGES
        <= candidate_count
        <= MAX_ANALYSIS_37_CANDIDATE_PAGES,
        "candidate page mapping candidate count is outside the 32-42 release range",
    )
    for field, expected in (
        ("candidate_tex_sha256", expected_candidate_tex_sha256),
        ("candidate_pdf_sha256", expected_candidate_pdf_sha256),
    ):
        digest = str(mapping.get(field) or "").lower()
        _require(
            SHA256_RE.fullmatch(digest) is not None
            and digest == str(expected or "").lower(),
            f"candidate page mapping {field} is invalid",
        )
    _require(
        SHA256_RE.fullmatch(
            str(mapping.get("upstream_mapping_sha256") or "").lower()
        )
        is not None,
        "candidate page mapping lacks its host alignment digest",
    )
    raw_rows = mapping.get("canonical_rows")
    _require(
        isinstance(raw_rows, list) and len(raw_rows) == source_count,
        "candidate page mapping does not carry one canonical row per source page",
    )
    rows: list[dict[str, Any]] = []
    mapped_pages: set[int] = set()
    previous_last = 0
    for expected_source_page, raw_row in enumerate(raw_rows, 1):
        row = _require_exact_fields(
            raw_row,
            required={"source_page", "candidate_pages"},
            label=f"candidate page mapping row {expected_source_page}",
        )
        candidate_pages = row.get("candidate_pages")
        _require(
            type(row.get("source_page")) is int
            and row.get("source_page") == expected_source_page
            and isinstance(candidate_pages, list)
            and bool(candidate_pages)
            and all(
                type(page) is int and 1 <= page <= candidate_count
                for page in candidate_pages
            )
            and candidate_pages == sorted(set(candidate_pages)),
            f"candidate page mapping row {expected_source_page} is not canonical",
        )
        # Adjacent source pages may legitimately share a boundary candidate
        # page after reflow, but content may never move backwards.
        _require(
            previous_last <= candidate_pages[0],
            "candidate page mapping is not monotonic",
        )
        previous_last = candidate_pages[-1]
        mapped_pages.update(candidate_pages)
        rows.append({
            "source_page": expected_source_page,
            "candidate_pages": list(candidate_pages),
        })
    candidate_only = mapping.get("candidate_only_pages")
    _require(
        isinstance(candidate_only, list)
        and candidate_only == sorted(set(candidate_only))
        and all(
            type(page) is int and 1 <= page <= candidate_count
            for page in candidate_only
        ),
        "candidate-only page evidence is not canonical",
    )
    candidate_only_set = set(candidate_only)
    _require(
        not mapped_pages.intersection(candidate_only_set)
        and mapped_pages.union(candidate_only_set)
        == set(range(1, candidate_count + 1)),
        "candidate page mapping does not cover every candidate page exactly by role",
    )
    supplied_digest = str(mapping.get("mapping_sha256") or "").lower()
    canonical_payload = {
        key: mapping[key] for key in mapping if key != "mapping_sha256"
    }
    recomputed_digest = _canonical_json_sha256(canonical_payload)
    _require(
        SHA256_RE.fullmatch(supplied_digest) is not None
        and supplied_digest == recomputed_digest,
        "candidate page mapping digest mismatch",
    )
    mapping["canonical_rows"] = rows
    mapping["candidate_only_pages"] = list(candidate_only)
    mapping["mapping_sha256"] = recomputed_digest
    return mapping


def verify_render_compare_closed_loop(value: object) -> dict[str, Any]:
    """Verify the compact, recomputable issue/fix/recompile/review projection."""

    evidence = dict(_require_exact_fields(
        value,
        required={
            "schema_version",
            "branch",
            "detected_issue_count",
            "fixed_issue_count",
            "rejected_false_positive_count",
            "fixes",
            "final_review_context_sha256s",
            "final_candidate_tex_sha256",
            "final_candidate_pdf_sha256",
            "evidence_sha256",
        },
        label="render/compare closed-loop evidence",
    ))
    _require(
        evidence.get("schema_version") == RENDER_COMPARE_CLOSED_LOOP_SCHEMA,
        "unsupported render/compare closed-loop schema",
    )
    for field in (
        "detected_issue_count",
        "fixed_issue_count",
        "rejected_false_positive_count",
    ):
        _require(
            type(evidence.get(field)) is int and int(evidence[field]) >= 0,
            f"render/compare closed-loop {field} is invalid",
        )
    fixes = evidence.get("fixes")
    _require(isinstance(fixes, list), "render/compare closed-loop fixes are invalid")
    normalized_fixes: list[dict[str, Any]] = []
    issue_ids: set[str] = set()
    patch_ids: set[str] = set()
    for index, raw_fix in enumerate(fixes, 1):
        fix = _require_exact_fields(
            raw_fix,
            required={
                "issue_id",
                "patch_id",
                "candidate_tex_sha256",
                "candidate_pdf_sha256",
                "compile_run_numbers",
                "review_result",
            },
            label=f"render/compare fix {index}",
        )
        issue_id = str(fix.get("issue_id") or "")
        patch_id = str(fix.get("patch_id") or "")
        _require(
            re.fullmatch(r"ISS-[0-9a-f]{12}(?:-[0-9]+)?", issue_id) is not None
            and issue_id not in issue_ids
            and bool(patch_id)
            and patch_id not in patch_ids
            and fix.get("compile_run_numbers") == [1, 2]
            and fix.get("review_result") == "PASS"
            and SHA256_RE.fullmatch(
                str(fix.get("candidate_tex_sha256") or "").lower()
            )
            is not None
            and SHA256_RE.fullmatch(
                str(fix.get("candidate_pdf_sha256") or "").lower()
            )
            is not None,
            f"render/compare fix {index} lacks reviewed double-compile evidence",
        )
        issue_ids.add(issue_id)
        patch_ids.add(patch_id)
        normalized_fixes.append(dict(fix))
    detected = int(evidence["detected_issue_count"])
    fixed = int(evidence["fixed_issue_count"])
    rejected = int(evidence["rejected_false_positive_count"])
    _require(
        fixed == len(normalized_fixes) and detected == fixed + rejected,
        "render/compare closed-loop issue counts are inconsistent",
    )
    branch = evidence.get("branch")
    _require(
        (
            branch == "NO_FIX_NEEDED"
            and fixed == 0
            and detected == rejected
        )
        or (
            branch == "FIX_REVIEW_RECOMPILE"
            and fixed > 0
        ),
        "render/compare closed-loop branch is inconsistent with fix evidence",
    )
    contexts = evidence.get("final_review_context_sha256s")
    _require(
        isinstance(contexts, list)
        and len(contexts) == 2
        and len(set(contexts)) == 2
        and all(SHA256_RE.fullmatch(str(item).lower()) is not None for item in contexts),
        "render/compare closed-loop lacks two independent final-review digests",
    )
    for field in ("final_candidate_tex_sha256", "final_candidate_pdf_sha256"):
        _require(
            SHA256_RE.fullmatch(str(evidence.get(field) or "").lower()) is not None,
            f"render/compare closed-loop {field} is invalid",
        )
    supplied_digest = str(evidence.get("evidence_sha256") or "").lower()
    recomputed_digest = _canonical_json_sha256({
        key: evidence[key] for key in evidence if key != "evidence_sha256"
    })
    _require(
        SHA256_RE.fullmatch(supplied_digest) is not None
        and supplied_digest == recomputed_digest,
        "render/compare closed-loop evidence digest mismatch",
    )
    evidence["fixes"] = normalized_fixes
    evidence["evidence_sha256"] = recomputed_digest
    return evidence


def _path_is_reparse_point(path: Path) -> bool:
    """Reject links and Windows junctions in immutable release evidence."""

    try:
        metadata = path.lstat()
    except OSError:
        return False
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return path.is_symlink() or bool(flag and attributes & flag)


def _strict_posix_member(value: object, label: str) -> str:
    """Return one canonical package member without host-path ambiguity."""

    _require(isinstance(value, str), f"{label} must be a relative POSIX path")
    text = str(value)
    pure = PurePosixPath(text)
    _require(
        bool(text)
        and "\\" not in text
        and not text.startswith("/")
        and not re.match(r"^[A-Za-z]:", text)
        and not text.startswith("//")
        and "://" not in text
        and "\x00" not in text
        and text == pure.as_posix()
        and all(
            part not in {"", ".", ".."}
            and ":" not in part
            and part.rstrip(" .") == part
            for part in pure.parts
        ),
        f"{label} must be a normalized relative POSIX path",
    )
    return text


def _expected_package_directories(paths: set[str]) -> set[str]:
    expected: set[str] = set()
    for logical_path in paths:
        parent = PurePosixPath(logical_path).parent
        while parent.as_posix() != ".":
            expected.add(parent.as_posix())
            parent = parent.parent
    return expected


def _verify_ocr_baseline_package(
    run_dir: Path,
    record: object,
    *,
    expected_pages: int,
    version: str,
    commit: str,
    runtime: Mapping[str, Any],
    source: Mapping[str, Any],
    selected: Mapping[str, Any],
    pages: Mapping[str, Any],
    model: Mapping[str, Any],
    compilation: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute the exact OCR-only package instead of trusting summaries.

    The package is private release evidence.  Every file is enumerated without
    following links, its manifest is verified by the production recomputation
    code, and release-only requirements (measured compile execution plus exact
    candidate provenance) are then checked against the independently collected
    acceptance attestation.
    """

    binding = _require_exact_fields(
        record,
        required={
            "package_directory",
            "manifest_filename",
            "manifest_sha256",
            "run_id",
        },
        label="OCR recomputable baseline binding",
    )
    package_directory = _strict_posix_member(
        binding.get("package_directory"), "OCR baseline package directory"
    )
    manifest_filename = _strict_posix_member(
        binding.get("manifest_filename"), "OCR baseline manifest filename"
    )
    _require(
        package_directory == OCR_BASELINE_PACKAGE_DIRECTORY,
        "OCR baseline package directory is not canonical",
    )
    expected_manifest_filename = (
        PurePosixPath(package_directory) / OCR_BASELINE_MANIFEST_MEMBER
    ).as_posix()
    _require(
        manifest_filename == expected_manifest_filename,
        "OCR baseline manifest filename is not canonical",
    )
    declared_manifest_sha = str(binding.get("manifest_sha256") or "").lower()
    _require(
        SHA256_RE.fullmatch(declared_manifest_sha) is not None,
        "OCR baseline manifest SHA-256 is invalid",
    )
    declared_run_id = str(binding.get("run_id") or "")
    _require(
        re.fullmatch(r"[0-9a-f]{16,64}", declared_run_id) is not None,
        "OCR baseline run_id is invalid",
    )

    package_root = run_dir.joinpath(*PurePosixPath(package_directory).parts)
    _require(
        package_root.is_dir() and not _path_is_reparse_point(package_root),
        "OCR recomputable baseline package is missing or is a link",
    )
    manifest_path = package_root.joinpath(
        *PurePosixPath(OCR_BASELINE_MANIFEST_MEMBER).parts
    )
    _require(
        manifest_path.is_file() and not _path_is_reparse_point(manifest_path),
        "OCR recomputable baseline manifest is missing or is a link",
    )
    manifest_bytes = manifest_path.read_bytes()
    _require(
        _sha256_bytes(manifest_bytes) == declared_manifest_sha,
        "OCR baseline manifest digest mismatch",
    )
    manifest_hint = _load_json(manifest_path)
    descriptors_hint = manifest_hint.get("artifacts")
    _require(
        isinstance(descriptors_hint, list) and bool(descriptors_hint),
        "OCR baseline manifest has no artifact inventory",
    )
    logical_paths: list[str] = []
    for index, raw_descriptor in enumerate(descriptors_hint, start=1):
        descriptor = _require_exact_fields(
            raw_descriptor,
            required={"role", "path", "bytes", "sha256"},
            label=f"OCR baseline artifact descriptor {index}",
        )
        logical_paths.append(
            _strict_posix_member(
                descriptor.get("path"),
                f"OCR baseline artifact descriptor {index} path",
            )
        )
    _require(
        len(logical_paths) == len(set(logical_paths))
        and len(logical_paths) == len({path.casefold() for path in logical_paths}),
        "OCR baseline artifact paths are not unique",
    )
    expected_files = {OCR_BASELINE_MANIFEST_MEMBER, *logical_paths}
    expected_directories = _expected_package_directories(expected_files)
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for entry in package_root.rglob("*"):
        relative = entry.relative_to(package_root).as_posix()
        _require(
            not _path_is_reparse_point(entry),
            f"OCR baseline package contains a link: {relative}",
        )
        if entry.is_dir():
            actual_directories.add(relative)
            _require(
                relative in expected_directories,
                f"OCR baseline package contains an extra directory: {relative}",
            )
        elif entry.is_file():
            actual_files.add(relative)
            _require(
                relative in expected_files,
                f"OCR baseline package contains an extra file: {relative}",
            )
        else:
            raise ReleaseIntegrityError(
                f"OCR baseline package contains an unsupported entry: {relative}"
            )
    _require(
        actual_files == expected_files
        and actual_directories.issubset(expected_directories),
        "OCR baseline package file coverage differs from its manifest",
    )
    artifact_bytes = {
        logical_path: package_root.joinpath(
            *PurePosixPath(logical_path).parts
        ).read_bytes()
        for logical_path in logical_paths
    }
    try:
        from latexstruct.core.ocr_manifest import (
            OcrBaselineManifestError,
            verify_ocr_baseline_manifest,
        )

        verified = verify_ocr_baseline_manifest(
            manifest_bytes,
            artifact_bytes,
            expected_source_sha256=str(source.get("sha256") or "").lower(),
        )
    except ImportError as exc:
        raise ReleaseIntegrityError(
            "OCR baseline recomputation code is unavailable"
        ) from exc
    except OcrBaselineManifestError as exc:
        raise ReleaseIntegrityError(
            f"OCR baseline package failed recomputation: {exc}"
        ) from exc
    payload = verified.to_dict()
    _require(
        verified.sha256 == declared_manifest_sha,
        "OCR baseline canonical manifest digest mismatch",
    )
    _require(payload.get("run_id") == declared_run_id, "OCR baseline run_id mismatch")
    _require(
        payload.get("status")
        == {
            "run_status": "SUCCESS",
            "ocr_status": "COMPLETED",
            "compile_status": "COMPILED",
        },
        "OCR baseline manifest is not a successful completed compile",
    )
    _require(
        payload.get("source")
        == {
            "sha256": str(source.get("sha256") or "").lower(),
            "page_count": expected_pages,
            "selected_pages": list(range(1, expected_pages + 1)),
        },
        "OCR baseline source/page selection differs from the acceptance run",
    )
    _require(
        selected
        == {"start_page": 1, "end_page": expected_pages, "expected_pages": expected_pages},
        "OCR selected range is not canonical",
    )
    coverage = payload.get("coverage")
    _require(isinstance(coverage, Mapping), "OCR baseline coverage is missing")
    _require(
        int(coverage.get("selected") or 0) == expected_pages
        and int(coverage.get("completed") or 0) == expected_pages
        and int(coverage.get("success") or 0) == expected_pages
        and int(coverage.get("needs_review") or 0) == 0
        and int(coverage.get("failed") or 0) == 0
        and int(coverage.get("cancelled") or 0) == 0
        and int(coverage.get("incomplete") or 0) == 0
        and int(coverage.get("unresolved_pages") or 0) == 0
        and coverage.get("all_selected_pages_present") is True,
        "OCR baseline page coverage is not a strict all-page SUCCESS",
    )
    _require(
        int(pages.get("successful") or 0) == int(coverage.get("success") or 0)
        and int(pages.get("needs_review") or 0)
        == int(coverage.get("needs_review") or 0)
        and int(pages.get("failed") or 0) == int(coverage.get("failed") or 0)
        and int(pages.get("pending") or 0) == int(coverage.get("incomplete") or 0),
        "OCR attestation page summary differs from recomputed coverage",
    )

    descriptors = {
        str(item["role"]): item for item in payload.get("artifacts") or []
    }
    bindings = payload.get("bindings")
    _require(isinstance(bindings, Mapping), "OCR baseline artifact bindings are missing")
    snapshot_descriptor = descriptors.get("RUN_SNAPSHOT")
    _require(isinstance(snapshot_descriptor, Mapping), "OCR snapshot binding is missing")
    snapshot_payload = json.loads(
        artifact_bytes[str(snapshot_descriptor["path"])].decode("utf-8")
    )
    _require(isinstance(snapshot_payload, Mapping), "OCR snapshot is not an object")
    _require(
        snapshot_payload.get("run_id") == declared_run_id
        and snapshot_payload.get("source_sha256")
        == str(source.get("sha256") or "").lower()
        and int(snapshot_payload.get("source_total_pages") or 0) == expected_pages
        and snapshot_payload.get("selected_pages")
        == list(range(1, expected_pages + 1))
        and Path(str(snapshot_payload.get("original_filename") or "")).name
        == Path(str(source.get("filename") or "")).name,
        "OCR immutable snapshot differs from source/run acceptance evidence",
    )
    contract = snapshot_payload.get("pipeline_contract")
    _require(isinstance(contract, Mapping), "OCR snapshot pipeline contract is missing")
    page_strategies = contract.get("page_strategies")
    strategy_page_ids = [
        str(item.get("page_id") or "")
        for item in page_strategies
        if isinstance(item, Mapping)
    ] if isinstance(page_strategies, list) else []
    _require(
        str(contract.get("git_commit") or "").lower() == commit.lower()
        and str(contract.get("build_id") or "") == str(runtime.get("build_id") or "")
        and contract.get("dirty") is False
        and strategy_page_ids
        == [f"ocr-page-{index:06d}" for index in range(1, expected_pages + 1)],
        "OCR snapshot is not bound to the exact clean candidate/page strategies",
    )
    producer = payload.get("producer")
    _require(isinstance(producer, Mapping), "OCR baseline producer is missing")
    _require(
        producer.get("app_version") == version
        and str(producer.get("git_commit") or "").lower() == commit.lower()
        and str(producer.get("build_id") or "")
        == str(runtime.get("build_id") or "")
        and producer.get("ocr_model") == model.get("id")
        and producer.get("api_backend") == model.get("backend"),
        "OCR baseline producer differs from the exact tested candidate/model",
    )
    _require(
        str(validation.get("job_id") or "") == declared_run_id,
        "OCR validation report job_id differs from the immutable run_id",
    )

    compile_evidence = payload.get("compile")
    _require(isinstance(compile_evidence, Mapping), "OCR compile evidence is missing")
    passes = compile_evidence.get("passes")
    _require(
        isinstance(passes, list) and len(passes) >= 2,
        "OCR baseline lacks two measured compile invocations",
    )
    for index, compile_pass in enumerate(passes, start=1):
        measured_fields = {
            "command",
            "command_history",
            "compile_workdir",
            "input_inventory",
            "compile_input_sha256",
            "input_artifact_roles",
        }
        _require(
            isinstance(compile_pass, Mapping)
            and measured_fields.issubset(compile_pass)
            and isinstance(compile_pass.get("command"), list)
            and bool(compile_pass.get("command"))
            and isinstance(compile_pass.get("command_history"), list)
            and bool(compile_pass.get("command_history"))
            and bool(str(compile_pass.get("compile_workdir") or ""))
            and isinstance(compile_pass.get("input_inventory"), list)
            and bool(compile_pass.get("input_inventory"))
            and isinstance(compile_pass.get("input_artifact_roles"), list)
            and len(compile_pass.get("input_artifact_roles") or [])
            == len(compile_pass.get("input_inventory") or [])
            and SHA256_RE.fullmatch(
                str(compile_pass.get("compile_input_sha256") or "").lower()
            )
            is not None,
            f"OCR compile pass {index} lacks measured command/input inventory evidence",
        )
        for file_index, (inventory_item, input_role) in enumerate(zip(
            compile_pass["input_inventory"],
            compile_pass["input_artifact_roles"],
            strict=True,
        ), start=1):
            _require(
                isinstance(inventory_item, Mapping),
                f"OCR compile pass {index} input inventory is invalid",
            )
            input_path = str(inventory_item.get("path") or "")
            expected_role = f"COMPILE_INPUT_PASS_{index:02d}_{file_index:04d}"
            matching_descriptor = descriptors.get(str(input_role or ""))
            _require(
                input_role == expected_role
                and isinstance(matching_descriptor, Mapping)
                and matching_descriptor.get("path")
                == f"compile/inputs/pass-{index:02d}/{input_path}"
                and matching_descriptor.get("bytes") == inventory_item.get("bytes")
                and matching_descriptor.get("sha256") == inventory_item.get("sha256"),
                f"OCR compile pass {index} input {input_path!r} has no exact package bytes",
            )
    final_two = passes[-2:]
    _require(
        int(compile_evidence.get("successful_passes") or 0) >= 2
        and all(item.get("exit_code") == 0 for item in final_two)
        and all(
            item.get("input_tex_sha256") == compile_evidence.get("input_tex_sha256")
            for item in final_two
        ),
        "OCR baseline lacks two successful measured passes on the final TeX",
    )
    native_compile_inputs_hash = _canonical_json_sha256({
        "schema": "latexstruct-native-ocr-compile-input-summary-v1",
        "engine": str(compile_evidence.get("engine") or ""),
        "input_tex_sha256": str(compile_evidence.get("input_tex_sha256") or ""),
        "passes": [
            {
                "input_tex_sha256": item["input_tex_sha256"],
                "compile_input_sha256": item["compile_input_sha256"],
                "input_artifact_roles": list(
                    item.get("input_artifact_roles") or []
                ),
            }
            for item in final_two
        ],
    })
    baseline_pdf = descriptors.get("BASELINE_PDF")
    page_map = descriptors.get("PAGE_MAP")
    page_records = descriptors.get(str(bindings.get("page_records") or ""))
    runtime_page_records = descriptors.get(
        str(bindings.get("runtime_page_records") or "")
    )
    _require(
        isinstance(baseline_pdf, Mapping)
        and isinstance(page_map, Mapping)
        and isinstance(page_records, Mapping)
        and isinstance(runtime_page_records, Mapping),
        "OCR compiled baseline lacks PDF/page-record/runtime/page-map artifacts",
    )
    final_log_role = str(passes[-1].get("log_role") or "")
    final_log = descriptors.get(final_log_role)
    _require(isinstance(final_log, Mapping), "OCR final compile log binding is missing")
    _require(
        compilation.get("status") == "COMPILED"
        and int(compilation.get("successful_passes") or 0)
        == int(compile_evidence.get("successful_passes") or 0)
        and compilation.get("exit_code") == passes[-1].get("exit_code") == 0
        and str(compilation.get("baseline_pdf_sha256") or "").lower()
        == str(baseline_pdf.get("sha256") or "").lower()
        and str(compilation.get("compile_log_sha256") or "").lower()
        == str(final_log.get("sha256") or "").lower(),
        "OCR compile attestation differs from measured package evidence",
    )
    return {
        "package_directory": package_directory,
        "manifest_filename": manifest_filename,
        "manifest_sha256": declared_manifest_sha,
        "run_id": declared_run_id,
        "recomputed_evidence_hashes": {
            "ocr_baseline_manifest_hash": declared_manifest_sha,
            "ocr_page_records_hash": str(page_records.get("sha256") or "").lower(),
            "ocr_runtime_page_records_hash": str(
                runtime_page_records.get("sha256") or ""
            ).lower(),
            "ocr_page_map_hash": str(page_map.get("sha256") or "").lower(),
            "ocr_baseline_compile_inputs_hash": native_compile_inputs_hash,
        },
        "ocr_producer": dict(producer),
    }


def _verify_artifact_reference(
    run_dir: Path,
    record: object,
    expected_filename: str,
) -> dict[str, Any]:
    """Verify one immutable analysis artifact against its declared bytes."""

    artifact = _require_exact_fields(
        record,
        required={"filename", "bytes", "sha256"},
        label=f"analysis artifact {expected_filename}",
    )
    relative = _safe_relative_member(artifact.get("filename"))
    _require(
        relative == Path(expected_filename),
        f"unexpected analysis artifact filename: {relative}",
    )
    byte_count = artifact.get("bytes")
    _require(
        isinstance(byte_count, int)
        and not isinstance(byte_count, bool)
        and byte_count > 0,
        f"analysis artifact byte count is invalid: {expected_filename}",
    )
    digest = str(artifact.get("sha256") or "").lower()
    _require(
        SHA256_RE.fullmatch(digest) is not None,
        f"analysis artifact SHA-256 is invalid: {expected_filename}",
    )
    path = run_dir / relative
    _require(path.is_file(), f"analysis artifact is missing: {expected_filename}")
    _require(
        path.stat().st_size == byte_count,
        f"analysis artifact byte count mismatch: {expected_filename}",
    )
    _require(
        _sha256_file(path) == digest,
        f"analysis artifact digest mismatch: {expected_filename}",
    )
    return {
        "filename": relative.as_posix(),
        "bytes": byte_count,
        "sha256": digest,
    }


def analysis_attestation_json_schema() -> dict[str, Any]:
    """Return the strict, producer-facing schema for real analysis attestations.

    The OCR acceptance runner intentionally cannot emit this document.  A later
    ``tools/v2_analysis_acceptance.py`` may write one only after it has collected two independent
    final-review contexts and the machine-verification result.
    """

    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    nonempty = {"type": "string", "minLength": 1}
    runtime = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "version",
            "commit",
            "build_id",
            "executable_filename",
            "executable_sha256",
        ],
        "properties": {
            "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
            "commit": {"type": "string", "pattern": "^[0-9a-f]{40,64}$"},
            "build_id": {"type": "string", "pattern": r"^[1-9][0-9]*$"},
            "executable_filename": {"const": "LaTeXStruct.exe"},
            "executable_sha256": sha,
        },
    }
    source = {
        "type": "object",
        "additionalProperties": False,
        "required": ["filename", "sha256", "total_pages"],
        "properties": {
            "filename": {"type": "string", "minLength": 1, "pattern": r"\.pdf$"},
            "sha256": {"const": RAMSEY_37_SOURCE_SHA256},
            "total_pages": {"const": 37},
        },
    }
    review = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "pass_number",
            "review_id",
            "context_id",
            "context_sha256",
            "independent",
            "result",
            "candidate_tex_sha256",
            "pages_checked",
            "expected_page_ids",
            "checked_page_ids",
            "checked_page_ids_sha256",
            "model_id",
            "backend",
            "calls",
        ],
        "properties": {
            "pass_number": {"type": "integer", "minimum": 1, "maximum": 2},
            "review_id": nonempty,
            "context_id": nonempty,
            "context_sha256": sha,
            "independent": {"const": True},
            "result": {"const": "PASS"},
            "candidate_tex_sha256": sha,
            "pages_checked": {"const": 37},
            "expected_page_ids": {
                "type": "array",
                "minItems": 37,
                "maxItems": 37,
                "uniqueItems": True,
                "items": nonempty,
            },
            "checked_page_ids": {
                "type": "array",
                "minItems": 37,
                "maxItems": 37,
                "uniqueItems": True,
                "items": nonempty,
            },
            "checked_page_ids_sha256": sha,
            "model_id": {"const": ANALYSIS_STABLE_MODEL_ID},
            "backend": nonempty,
            "calls": {"type": "integer", "minimum": 1},
        },
    }
    candidate_mapping = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "source_page_count",
            "candidate_page_count",
            "candidate_tex_sha256",
            "candidate_pdf_sha256",
            "upstream_mapping_sha256",
            "canonical_rows",
            "candidate_only_pages",
            "mapping_sha256",
        ],
        "properties": {
            "schema_version": {"const": CANDIDATE_PAGE_MAPPING_SCHEMA},
            "source_page_count": {"const": 37},
            "candidate_page_count": {
                "type": "integer",
                "minimum": MIN_ANALYSIS_37_CANDIDATE_PAGES,
                "maximum": MAX_ANALYSIS_37_CANDIDATE_PAGES,
            },
            "candidate_tex_sha256": sha,
            "candidate_pdf_sha256": sha,
            "upstream_mapping_sha256": sha,
            "canonical_rows": {
                "type": "array",
                "minItems": 37,
                "maxItems": 37,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["source_page", "candidate_pages"],
                    "properties": {
                        "source_page": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 37,
                        },
                        "candidate_pages": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": True,
                            "items": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": MAX_ANALYSIS_37_CANDIDATE_PAGES,
                            },
                        },
                    },
                },
            },
            "candidate_only_pages": {
                "type": "array",
                "uniqueItems": True,
                "items": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_ANALYSIS_37_CANDIDATE_PAGES,
                },
            },
            "mapping_sha256": sha,
        },
    }
    closed_loop = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "branch",
            "detected_issue_count",
            "fixed_issue_count",
            "rejected_false_positive_count",
            "fixes",
            "final_review_context_sha256s",
            "final_candidate_tex_sha256",
            "final_candidate_pdf_sha256",
            "evidence_sha256",
        ],
        "properties": {
            "schema_version": {"const": RENDER_COMPARE_CLOSED_LOOP_SCHEMA},
            "branch": {"enum": ["NO_FIX_NEEDED", "FIX_REVIEW_RECOMPILE"]},
            "detected_issue_count": {"type": "integer", "minimum": 0},
            "fixed_issue_count": {"type": "integer", "minimum": 0},
            "rejected_false_positive_count": {"type": "integer", "minimum": 0},
            "fixes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "issue_id",
                        "patch_id",
                        "candidate_tex_sha256",
                        "candidate_pdf_sha256",
                        "compile_run_numbers",
                        "review_result",
                    ],
                    "properties": {
                        "issue_id": nonempty,
                        "patch_id": nonempty,
                        "candidate_tex_sha256": sha,
                        "candidate_pdf_sha256": sha,
                        "compile_run_numbers": {
                            "type": "array",
                            "prefixItems": [{"const": 1}, {"const": 2}],
                            "minItems": 2,
                            "maxItems": 2,
                        },
                        "review_result": {"const": "PASS"},
                    },
                },
            },
            "final_review_context_sha256s": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "uniqueItems": True,
                "items": sha,
            },
            "final_candidate_tex_sha256": sha,
            "final_candidate_pdf_sha256": sha,
            "evidence_sha256": sha,
        },
    }
    report = {
        "type": "object",
        "additionalProperties": False,
        "required": ["filename", "sha256"],
        "properties": {"filename": nonempty, "sha256": sha},
    }
    artifact_properties = {
        role: {
            "type": "object",
            "additionalProperties": False,
            "required": ["filename", "bytes", "sha256"],
            "properties": {
                "filename": {"const": filename},
                "bytes": {"type": "integer", "minimum": 1},
                "sha256": sha,
            },
        }
        for role, (filename, _compilation_field) in ANALYSIS_ARTIFACT_SPECS.items()
    }
    budget_limits = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "max_input_tokens",
            "max_output_tokens",
            "max_cost",
            "max_requests",
            "max_strong_model_calls",
            "max_wall_time_minutes",
        ],
        "properties": {
            "max_input_tokens": {"type": "integer", "minimum": 0},
            "max_output_tokens": {"type": "integer", "minimum": 0},
            "max_cost": {"type": "number", "minimum": 0},
            "max_requests": {"type": "integer", "minimum": 0},
            "max_strong_model_calls": {"type": "integer", "minimum": 0},
            "max_wall_time_minutes": {
                "type": "number",
                "exclusiveMinimum": 0,
            },
        },
    }
    measured_budget = {
        "type": "object",
        "additionalProperties": False,
        "required": ["input_tokens", "output_tokens", "cost"],
        "properties": {
            "input_tokens": {"type": "integer", "minimum": 0},
            "output_tokens": {"type": "integer", "minimum": 0},
            "cost": {"type": "number", "minimum": 0},
        },
    }
    actual_budget = {
        "type": "object",
        "additionalProperties": False,
        "required": ["input_tokens", "output_tokens", "cost"],
        "properties": {
            "input_tokens": {
                "anyOf": [
                    {"type": "integer", "minimum": 0},
                    {"type": "null"},
                ]
            },
            "output_tokens": {
                "anyOf": [
                    {"type": "integer", "minimum": 0},
                    {"type": "null"},
                ]
            },
            "cost": {
                "anyOf": [
                    {"type": "number", "minimum": 0},
                    {"type": "null"},
                ]
            },
        },
    }
    model_binding_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["role", "model_id", "capabilities", "reasoning_effort"],
        "properties": {
            "role": {"pattern": r"^AI-[1-6]$"},
            "model_id": nonempty,
            "capabilities": {
                "type": "array",
                "uniqueItems": True,
                "items": nonempty,
            },
            "reasoning_effort": {"const": ANALYSIS_STABLE_REASONING_EFFORT},
        },
    }
    transport_contract_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "role",
            "model_id",
            "reasoning_effort",
            "operations",
            "client_type",
            "method",
            "max_retries",
            "max_tokens",
            "backend_authority_sha256",
            "backend_configuration_sha256",
        ],
        "properties": {
            "role": {"pattern": r"^AI-[1-6]$"},
            "model_id": {"const": ANALYSIS_STABLE_MODEL_ID},
            "reasoning_effort": {"const": ANALYSIS_STABLE_REASONING_EFFORT},
            "operations": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"enum": sorted(ANALYSIS_OPERATION_ROLES)},
            },
            "client_type": {"const": "latexstruct.core.codex_cli.CodexCLIClient"},
            "method": {
                "enum": [
                    "chat_json",
                    "chat_json_schema",
                    "chat_vision_json_images_bytes",
                ]
            },
            "max_retries": {"type": "integer", "minimum": 0},
            "max_tokens": {"type": "integer", "minimum": 0},
            "backend_authority_sha256": {
                "const": ANALYSIS_STABLE_BACKEND_AUTHORITY_SHA256
            },
            "backend_configuration_sha256": {
                "const": ANALYSIS_STABLE_BACKEND_CONFIGURATION_SHA256
            },
        },
    }
    budget_claim_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "input_tokens",
            "output_tokens",
            "cost",
            "requests",
            "strong_model_calls",
        ],
        "properties": {
            "input_tokens": {"type": "integer", "minimum": 0},
            "output_tokens": {"type": "integer", "minimum": 0},
            "cost": {"type": "number", "minimum": 0},
            "requests": {"type": "integer", "minimum": 1},
            "strong_model_calls": {"type": "integer", "minimum": 0},
        },
    }
    budget_attempt_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "attempt_number",
            "succeeded",
            "usage_complete",
            "failure_stage",
            "input_tokens",
            "output_tokens",
            "cached_tokens",
            "billing_mode",
            "cost",
            "cost_provenance",
        ],
        "properties": {
            "attempt_number": {"type": "integer", "minimum": 1},
            "succeeded": {"type": "boolean"},
            "usage_complete": {"const": True},
            "failure_stage": {"type": "string"},
            "input_tokens": {"type": "integer", "minimum": 0},
            "output_tokens": {"type": "integer", "minimum": 0},
            "cached_tokens": {"type": "integer", "minimum": 0},
            "billing_mode": {"const": "chatgpt_subscription"},
            "cost": {"anyOf": [{"type": "number", "minimum": 0}, {"type": "null"}]},
            "cost_provenance": {"const": "chatgpt_subscription"},
        },
    }
    budget_ledger_schema = {
        "type": "array",
        "minItems": 1,
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "ordinal",
                "role",
                "budget_claim",
                "budget_actual_usage",
                "attempts",
            ],
            "properties": {
                "ordinal": {"type": "integer", "minimum": 1},
                "role": {"pattern": r"^AI-[1-6]$"},
                "budget_claim": budget_claim_schema,
                "budget_actual_usage": actual_budget,
                "attempts": {
                    "type": "array",
                    "minItems": 1,
                    "items": budget_attempt_schema,
                },
            },
        },
    }
    budget_closure = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "budget_state_sha256",
            "budget_state",
            "budget_usage_sha256",
            "budget_usage",
            "limits_sha256",
            "limits",
            "transport_contracts_sha256",
            "transport_contracts",
            "transport_budget_ledger_sha256",
            "transport_budget_ledger",
            "observed",
            "actual",
            "accounted",
            "requests",
            "strong_model_calls",
            "unknown",
            "transport_claim_count",
            "committed_reservations",
            "cancelled_reservations",
            "active_reservations",
            "wall_time_minutes",
            "unbounded_unknown_dimensions",
            "all_claims_verified",
            "all_actual_usage_verified",
            "exact_aggregate_verified",
        ],
        "properties": {
            "schema_version": {"const": ANALYSIS_BUDGET_CLOSURE_SCHEMA},
            "budget_state_sha256": sha,
            "budget_state": {"type": "object"},
            "budget_usage_sha256": sha,
            "budget_usage": {"type": "object"},
            "limits_sha256": sha,
            "limits": budget_limits,
            "transport_contracts_sha256": sha,
            "transport_contracts": {
                "type": "array",
                "minItems": 6,
                "maxItems": 6,
                "uniqueItems": True,
                "items": transport_contract_schema,
            },
            "transport_budget_ledger_sha256": sha,
            "transport_budget_ledger": budget_ledger_schema,
            "observed": measured_budget,
            "actual": actual_budget,
            "accounted": measured_budget,
            "requests": {"type": "integer", "minimum": 1},
            "strong_model_calls": {"type": "integer", "minimum": 0},
            "unknown": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "input_token_requests",
                    "output_token_requests",
                    "cost_requests",
                ],
                "properties": {
                    "input_token_requests": {"type": "integer", "minimum": 0},
                    "output_token_requests": {"type": "integer", "minimum": 0},
                    "cost_requests": {"type": "integer", "minimum": 0},
                },
            },
            "transport_claim_count": {"type": "integer", "minimum": 1},
            "committed_reservations": {"type": "integer", "minimum": 1},
            "cancelled_reservations": {"const": 0},
            "active_reservations": {"const": 0},
            "wall_time_minutes": {"type": "number", "minimum": 0},
            "unbounded_unknown_dimensions": {
                "type": "array",
                "uniqueItems": True,
                "items": {"enum": ["input_tokens", "output_tokens", "cost"]},
            },
            "all_claims_verified": {"const": True},
            "all_actual_usage_verified": {"const": True},
            "exact_aggregate_verified": {"const": True},
        },
    }
    transport_closure = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "transport_evidence_sha256",
            "orchestration_invocation_count",
            "transport_invocation_count",
            "transport_attempt_count",
            "usage_observed_call_count",
            "usage_observed_attempt_count",
            "usage_missing_call_count",
            "usage_missing_attempt_count",
            "input_tokens",
            "output_tokens",
            "cached_tokens",
            "total_tokens",
            "usage_complete",
            "attempt_evidence_complete",
            "budget_closure",
        ],
        "properties": {
            "schema_version": {"const": ANALYSIS_TRANSPORT_CLOSURE_SCHEMA},
            "transport_evidence_sha256": sha,
            "orchestration_invocation_count": {"type": "integer", "minimum": 1},
            "transport_invocation_count": {"type": "integer", "minimum": 1},
            "transport_attempt_count": {"type": "integer", "minimum": 1},
            "usage_observed_call_count": {"type": "integer", "minimum": 1},
            "usage_observed_attempt_count": {"type": "integer", "minimum": 1},
            "usage_missing_call_count": {"const": 0},
            "usage_missing_attempt_count": {"const": 0},
            "input_tokens": {"type": "integer", "minimum": 1},
            "output_tokens": {"type": "integer", "minimum": 1},
            "cached_tokens": {"type": "integer", "minimum": 0},
            "total_tokens": {"type": "integer", "minimum": 2},
            "usage_complete": {"const": True},
            "attempt_evidence_complete": {"const": True},
            "budget_closure": budget_closure,
        },
    }
    page_risk_closure = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "admission_sha256",
            "admission",
            "preflight_sha256",
            "preflight",
            "route_closure_sha256",
            "route_closure",
            "page_count",
            "page_ids_sha256",
            "risk_counts",
            "low_risk_sampling",
            "all_preflight_bindings_verified",
            "all_route_bindings_verified",
        ],
        "properties": {
            "schema_version": {"const": ANALYSIS_PAGE_RISK_CLOSURE_SCHEMA},
            "admission_sha256": sha,
            "admission": {"type": "object"},
            "preflight_sha256": sha,
            "preflight": {"type": "object"},
            "route_closure_sha256": sha,
            "route_closure": {"type": "object"},
            "page_count": {"const": 37},
            "page_ids_sha256": sha,
            "risk_counts": {"type": "object"},
            "low_risk_sampling": {"type": "object"},
            "all_preflight_bindings_verified": {"const": True},
            "all_route_bindings_verified": {"const": True},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": ANALYSIS_ATTESTATION_SCHEMA,
        "title": "LaTeXStruct real analysis acceptance attestation",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "profile_kind",
            "profile",
            "result",
            "acceptance_passed",
            "terminal_status",
            "quality_tier",
            "template",
            "generated_at",
            "execution",
            "runtime_identity",
            "service_binding",
            "snapshot_binding",
            "page_risk_admission",
            "source",
            "selected_range",
            "models",
            "compilation",
            "artifacts",
            "timing",
            "ocr_prerequisite",
            "independent_final_reviews",
            "visual_verification",
            "page_layout",
            "machine_verification",
            "audit_submission",
            "reports",
        ],
        "properties": {
            "schema_version": {"const": ANALYSIS_ATTESTATION_SCHEMA},
            "profile_kind": {"const": "analysis"},
            "profile": {"const": "analysis-37"},
            "result": {"const": "PASS"},
            "acceptance_passed": {"const": True},
            "terminal_status": {"const": "VERIFIED"},
            "quality_tier": {"const": "high"},
            "template": {"const": "faithfulbook"},
            "generated_at": {"type": "string", "minLength": 1},
            "execution": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "real_execution",
                    "test_double",
                    "simulated",
                    "api_client",
                    "ui_driver",
                    "workflow",
                    "producer",
                ],
                "properties": {
                    "real_execution": {"const": True},
                    "test_double": {"const": False},
                    "simulated": {"const": False},
                    "api_client": {"const": "LocalHttpApi"},
                    "ui_driver": {"const": "PlaywrightUiDriver"},
                    "workflow": {"const": "OCR_ANALYSIS_REVIEW"},
                    "producer": nonempty,
                },
            },
            "runtime_identity": runtime,
            "service_binding": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "verified",
                    "pid",
                    "process_image_filename",
                    "process_image_sha256",
                    "listener_port",
                    "listener_pid",
                    "listener_pid_verified",
                    "listener_image_filename",
                    "listener_image_sha256",
                ],
                "properties": {
                    "verified": {"const": True},
                    "pid": {"type": "integer", "minimum": 1},
                    "process_image_filename": {"const": "LaTeXStruct.exe"},
                    "process_image_sha256": sha,
                    "listener_port": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                    },
                    "listener_pid": {"type": "integer", "minimum": 1},
                    "listener_pid_verified": {"const": True},
                    "listener_image_filename": {"const": "LaTeXStruct.exe"},
                    "listener_image_sha256": sha,
                },
            },
            "snapshot_binding": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "snapshot_hash",
                    "prompt_version",
                    "response_schema_hash",
                    "evidence_hashes",
                    "model_bindings",
                    "model_bindings_sha256",
                    "transport_contracts_sha256",
                    "analysis_configuration",
                    "analysis_configuration_sha256",
                    "release_model_policy",
                    "transport_invocation_count",
                    "transport_closure",
                    "all_transport_bindings_verified",
                ],
                "properties": {
                    "snapshot_hash": sha,
                    "prompt_version": nonempty,
                    "response_schema_hash": sha,
                    "evidence_hashes": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(ANALYSIS_EVIDENCE_HASH_FIELDS),
                        "properties": {
                            name: sha for name in ANALYSIS_EVIDENCE_HASH_FIELDS
                        },
                    },
                    "model_bindings": {
                        "type": "array",
                        "minItems": 6,
                        "maxItems": 6,
                        "uniqueItems": True,
                        "items": model_binding_schema,
                    },
                    "model_bindings_sha256": sha,
                    "transport_contracts_sha256": sha,
                    "analysis_configuration": {"type": "object"},
                    "analysis_configuration_sha256": sha,
                    "release_model_policy": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "schema_version",
                            "declared_model_id",
                            "declared_reasoning_effort",
                            "runtime_configuration",
                            "runtime_configuration_sha256",
                            "model_bindings_sha256",
                            "transport_contracts_sha256",
                            "runtime_matches_declared",
                            "all_role_bindings_match_declared",
                            "all_transport_contracts_match_declared",
                            "allowed_by_release",
                        ],
                        "properties": {
                            "schema_version": {
                                "const": ANALYSIS_RELEASE_MODEL_POLICY_SCHEMA
                            },
                            "declared_model_id": {
                                "enum": sorted(ANALYSIS_RELEASE_ALLOWED_MODEL_IDS)
                            },
                            "declared_reasoning_effort": {
                                "enum": sorted(
                                    ANALYSIS_RELEASE_ALLOWED_REASONING_EFFORTS
                                )
                            },
                            "runtime_configuration": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "analysis_backend",
                                    "codex_model",
                                    "codex_reasoning_effort",
                                    "codex_triage_model",
                                    "codex_triage_reasoning_effort",
                                ],
                                "properties": {
                                    "analysis_backend": {"const": "codex_cli"},
                                    "codex_model": nonempty,
                                    "codex_reasoning_effort": nonempty,
                                    "codex_triage_model": nonempty,
                                    "codex_triage_reasoning_effort": nonempty,
                                },
                            },
                            "runtime_configuration_sha256": sha,
                            "model_bindings_sha256": sha,
                            "transport_contracts_sha256": sha,
                            "runtime_matches_declared": {"const": True},
                            "all_role_bindings_match_declared": {"const": True},
                            "all_transport_contracts_match_declared": {
                                "const": True
                            },
                            "allowed_by_release": {"const": True},
                        },
                    },
                    "transport_invocation_count": {
                        "type": "integer",
                        "minimum": 1,
                    },
                    "transport_closure": transport_closure,
                    "all_transport_bindings_verified": {"const": True},
                },
            },
            "page_risk_admission": page_risk_closure,
            "source": source,
            "selected_range": {
                "type": "object",
                "additionalProperties": False,
                "required": ["start_page", "end_page", "expected_pages"],
                "properties": {
                    "start_page": {"const": 1},
                    "end_page": {"const": 37},
                    "expected_pages": {"const": 37},
                },
            },
            "models": {
                "type": "object",
                "additionalProperties": False,
                "required": ["calls_total", "roles"],
                "properties": {
                    "calls_total": {"type": "integer", "minimum": 1},
                    "roles": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["role", "model_id", "backend", "calls"],
                            "properties": {
                                "role": {
                                    "enum": [
                                        "structure",
                                        "analysis",
                                        "review",
                                        "visual_review",
                                    ]
                                },
                                "model_id": nonempty,
                                "backend": nonempty,
                                "calls": {"type": "integer", "minimum": 1},
                            },
                        },
                    },
                },
            },
            "compilation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "status",
                    "successful_passes",
                    "pass_exit_codes",
                    "compile_log_sha256",
                    "candidate_tex_sha256",
                    "candidate_pdf_sha256",
                ],
                "properties": {
                    "status": {"const": "COMPILED"},
                    "successful_passes": {"type": "integer", "minimum": 2},
                    "pass_exit_codes": {
                        "type": "array",
                        "minItems": 2,
                        "items": {"const": 0},
                    },
                    "compile_log_sha256": sha,
                    "candidate_tex_sha256": sha,
                    "candidate_pdf_sha256": sha,
                },
            },
            "artifacts": {
                "type": "object",
                "additionalProperties": False,
                "required": list(ANALYSIS_ARTIFACT_SPECS),
                "properties": artifact_properties,
            },
            "timing": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "measurement",
                    "started_at",
                    "ended_at",
                    "wall_time_seconds",
                    "timed_out",
                    "completed_terminal_run",
                ],
                "properties": {
                    "measurement": {
                        "type": "string",
                        "pattern": "before browser upload/start click",
                    },
                    "started_at": nonempty,
                    "ended_at": nonempty,
                    "wall_time_seconds": {"type": "number", "exclusiveMinimum": 0},
                    "timed_out": {"const": False},
                    "completed_terminal_run": {"const": True},
                },
            },
            "ocr_prerequisite": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "profile",
                    "attestation_filename",
                    "attestation_sha256",
                    "result",
                    "acceptance_passed",
                    "successful_pages",
                    "source_sha256",
                    "run_id",
                    "baseline_manifest_sha256",
                    "runtime_identity",
                    "selected_range",
                ],
                "properties": {
                    "profile": {"const": "ocr-37"},
                    "attestation_filename": {
                        "const": "ocr-prerequisite/acceptance-attestation.json"
                    },
                    "attestation_sha256": sha,
                    "result": {"const": "PASS"},
                    "acceptance_passed": {"const": True},
                    "successful_pages": {"const": 37},
                    "source_sha256": {"const": RAMSEY_37_SOURCE_SHA256},
                    "run_id": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{16,64}$",
                    },
                    "baseline_manifest_sha256": sha,
                    "runtime_identity": runtime,
                    "selected_range": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["start_page", "end_page", "expected_pages"],
                        "properties": {
                            "start_page": {"const": 1},
                            "end_page": {"const": 37},
                            "expected_pages": {"const": 37},
                        },
                    },
                },
            },
            "independent_final_reviews": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": review,
            },
            "visual_verification": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "passed",
                    "expected_pages",
                    "pages_checked",
                    "independent_review_passes",
                    "model_calls",
                    "page_id_set_sha256",
                    "candidate_tex_sha256",
                    "candidate_pdf_sha256",
                    "render_compare_closed_loop",
                    "closed_loop_evidence",
                ],
                "properties": {
                    "passed": {"const": True},
                    "expected_pages": {"const": 37},
                    "pages_checked": {"const": 37},
                    "independent_review_passes": {"const": 2},
                    "model_calls": {"const": 74},
                    "page_id_set_sha256": sha,
                    "candidate_tex_sha256": sha,
                    "candidate_pdf_sha256": sha,
                    "render_compare_closed_loop": {"const": True},
                    "closed_loop_evidence": closed_loop,
                },
            },
            "page_layout": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source_page_count",
                    "candidate_page_count",
                    "minimum_candidate_pages",
                    "maximum_candidate_pages",
                    "page_growth",
                    "candidate_only_pages",
                    "candidate_mapping_sha256",
                    "candidate_mapping",
                    "no_abnormal_page_inflation",
                    "active_tableofcontents_count",
                    "template",
                ],
                "properties": {
                    "source_page_count": {"const": 37},
                    "candidate_page_count": {
                        "type": "integer",
                        "minimum": MIN_ANALYSIS_37_CANDIDATE_PAGES,
                        "maximum": MAX_ANALYSIS_37_CANDIDATE_PAGES,
                    },
                    "minimum_candidate_pages": {
                        "const": MIN_ANALYSIS_37_CANDIDATE_PAGES
                    },
                    "maximum_candidate_pages": {
                        "const": MAX_ANALYSIS_37_CANDIDATE_PAGES
                    },
                    "page_growth": {
                        "type": "integer",
                        "minimum": -5,
                        "maximum": 5,
                    },
                    "candidate_only_pages": {
                        "type": "array",
                        "maxItems": 5,
                        "uniqueItems": True,
                        "items": {"type": "integer", "minimum": 1, "maximum": 42},
                    },
                    "candidate_mapping_sha256": sha,
                    "candidate_mapping": candidate_mapping,
                    "no_abnormal_page_inflation": {"const": True},
                    "active_tableofcontents_count": {"const": 1},
                    "template": {"const": "faithfulbook"},
                },
            },
            "machine_verification": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "passed",
                    "candidate_tex_sha256",
                    "pages_checked",
                    "silent_omissions",
                    "text_loss",
                    "unauthorized_math_changes",
                    "unclosed_formal_environments",
                    "open_critical_issues",
                    "open_high_issues",
                    "regressions",
                    "verification_json_sha256",
                ],
                "properties": {
                    "passed": {"const": True},
                    "candidate_tex_sha256": sha,
                    "pages_checked": {"type": "integer", "minimum": 1},
                    "silent_omissions": {"const": 0},
                    "text_loss": {"const": 0},
                    "unauthorized_math_changes": {"const": 0},
                    "unclosed_formal_environments": {"const": 0},
                    "open_critical_issues": {"const": 0},
                    "open_high_issues": {"const": 0},
                    "regressions": {"const": 0},
                    "verification_json_sha256": sha,
                },
            },
            "audit_submission": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "filename",
                    "bytes",
                    "sha256",
                    "packaging_status",
                    "audit_package_status",
                    "verification_status",
                    "published_to_github",
                ],
                "properties": {
                    "filename": {"const": "analysis-audit-submission.zip"},
                    "bytes": {"type": "integer", "minimum": 1},
                    "sha256": sha,
                    "packaging_status": {"const": "SUCCESS"},
                    "audit_package_status": {"const": "VALID"},
                    "verification_status": {"const": "VERIFIED"},
                    "published_to_github": {"const": False},
                },
            },
            "reports": {
                "type": "object",
                "additionalProperties": False,
                "required": ["performance", "validation", "verification"],
                "properties": {
                    "performance": report,
                    "validation": report,
                    "verification": report,
                },
            },
        },
    }


def build_portable_archive(
    *,
    executable: Path,
    license_file: Path,
    notices_file: Path,
    output: Path,
) -> dict[str, str]:
    sources = {
        "LaTeXStruct.exe": executable,
        "LICENSE": license_file,
        "THIRD_PARTY_NOTICES.txt": notices_file,
    }
    for member, source in sources.items():
        _require(source.is_file(), f"portable archive source is missing: {member}")
        _require(source.stat().st_size > 0, f"portable archive source is empty: {member}")
    output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    os.close(handle)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for member, source in sources.items():
                info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, source.read_bytes())
        with zipfile.ZipFile(temporary, "r") as archive:
            names = archive.namelist()
            _require(
                names == list(sources),
                f"portable archive member mismatch: {names}",
            )
            for member, source in sources.items():
                _require(
                    archive.read(member) == source.read_bytes(),
                    f"portable archive bytes differ for {member}",
                )
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {member: _sha256_file(source) for member, source in sources.items()}


def write_asset_manifest(
    *,
    assets: Sequence[Path],
    version: str,
    commit: str,
    build_id: str,
    output: Path,
    checksums_output: Path,
) -> dict[str, Any]:
    normalized_commit = str(commit or "").strip().lower()
    _require(COMMIT_RE.fullmatch(normalized_commit) is not None, "invalid release commit")
    normalized_build_id = str(build_id or "").strip()
    _require(
        GITHUB_RUN_ID_RE.fullmatch(normalized_build_id) is not None,
        "release build id must be a numeric GitHub Actions run id",
    )
    _require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None, "invalid version")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in assets:
        _require(path.is_file(), f"release asset is missing: {path.name}")
        _require(path.name not in seen, f"duplicate release asset name: {path.name}")
        seen.add(path.name)
        records.append(
            {
                "filename": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    records.sort(key=lambda item: str(item["filename"]).casefold())
    payload = {
        "schema_version": ASSET_MANIFEST_SCHEMA,
        "version": version,
        "commit": normalized_commit,
        "build_id": normalized_build_id,
        "assets": records,
    }
    _atomic_json(output, payload)
    sums = "".join(f"{item['sha256']}  {item['filename']}\n" for item in records)
    _atomic_write(checksums_output, sums.encode("utf-8"))
    return payload


_PAGE_600_RE = re.compile(
    r"(?i)(?:\b600\b|\bsix\s*-?\s*hundred\b|六\s*百)"
    r"\s*-?\s*(?:页|pages?)"
)
_MINUTES_30_RE = re.compile(
    r"(?i)(?:(?:\b30\b|\bthirty\b|三\s*十)\s*-?\s*"
    r"(?:分钟|minutes?|mins?))"
)
_MINUTES_120_RE = re.compile(
    r"(?i)(?:(?:\b120\b|\bone\s+hundred(?:\s+and)?\s+twenty\b|"
    r"一\s*百\s*二\s*十)\s*-?\s*(?:分钟|minutes?|mins?)|"
    r"(?:\b2\b|\btwo\b|两)\s*-?\s*(?:小时|hours?))"
)
_PERFORMANCE_PROMOTION_RE = re.compile(
    r"(?i)\b(?:VERIFIED|PASS(?:ED|ES)?|MET|ACHIEVED|VALIDATED|PROVEN|"
    r"SATISFIED|COMPLIANT)\b|"
    r"已(?:经)?\s*(?:通过|验证|达标|达到|实现|满足)|"
    r"(?:性能|目标|SLO)\s*(?:已(?:经)?)?\s*(?:通过|验证|达标|达到|实现|满足)|"
    r"(?:通过|达标|达到|实现|满足)\s*(?:了)?\s*(?:性能|目标|SLO)"
)
_PROMOTION_NEGATION_RE = re.compile(
    r"(?i)(?:\b(?:not|never|without)\b(?:\s+\w+){0,3}|"
    r"(?:尚未|没有|未|不)\s*)$"
)


def _normalize_release_claim_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return normalized.translate(str.maketrans({"–": "-", "—": "-", "‑": "-"}))


def _target_spans(text: str, time_pattern: re.Pattern[str]) -> list[tuple[int, int]]:
    pages = list(_PAGE_600_RE.finditer(text))
    times = list(time_pattern.finditer(text))
    spans: list[tuple[int, int]] = []
    for page in pages:
        for timing in times:
            if min(abs(page.start() - timing.end()), abs(timing.start() - page.end())) <= 96:
                spans.append(
                    (min(page.start(), timing.start()), max(page.end(), timing.end()))
                )
    return spans


def _require_truthful_600_documentation(text: str, *, label: str) -> None:
    normalized = _normalize_release_claim_text(text)
    targets_30 = _target_spans(normalized, _MINUTES_30_RE)
    targets_120 = _target_spans(normalized, _MINUTES_120_RE)
    _require(
        bool(targets_30) and bool(targets_120),
        f"{label} must name both 600-page / 30-minute and 600-page / "
        "120-minute targets",
    )
    status_positions = [
        match.start()
        for match in re.finditer(r"(?i)\bNOT_EVALUATED\b", normalized)
    ]
    _require(
        bool(status_positions)
        and all(
            any(abs(status - start) <= 320 for status in status_positions)
            for start, _end in (*targets_30, *targets_120)
        ),
        f"{label} must explicitly keep both 600-page targets NOT_EVALUATED",
    )

    paragraphs = re.split(r"\r?\n(?=-\s)|\r?\n\s*\r?\n", normalized)
    for paragraph in paragraphs:
        if _PAGE_600_RE.search(paragraph) is None:
            continue
        flat = re.sub(r"\s*\r?\n\s*", " ", paragraph)
        sentences = [
            sentence
            for sentence in re.split(
                r"(?<=[。！？!?；;])|(?<=\.)\s+(?=[A-Z0-9])",
                flat,
            )
            if sentence
        ]
        for index, sentence in enumerate(sentences):
            if _PAGE_600_RE.search(sentence) is None:
                continue
            context = " ".join(
                sentences[max(0, index - 1) : min(len(sentences), index + 2)]
            )
            for promotion in _PERFORMANCE_PROMOTION_RE.finditer(context):
                prefix = context[: promotion.start()].rstrip()
                if _PROMOTION_NEGATION_RE.search(prefix[-48:]):
                    continue
                raise ReleaseIntegrityError(
                    f"{label} makes a forbidden VERIFIED/PASS claim for "
                    "600-page performance"
                )


def verify_release_readme(readme: Path, version: str) -> None:
    try:
        text = readme.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseIntegrityError(f"cannot read README: {exc}") from exc
    escaped = re.escape(version)
    match = re.search(
        rf"(?ms)^## 当前状态（?v{escaped}）?[^\r\n]*\r?\n"
        rf"(?P<body>.*?)(?=^## |\Z)",
        text,
    )
    _require(
        match is not None and bool(match.group("body").strip()),
        f"README missing current-status section for v{version}",
    )
    body = match.group("body")
    _require("analysis-37" in body, "README must name the analysis-37 release scope")
    _require_truthful_600_documentation(body, label=f"README v{version}")


def verify_release_notes(
    changelog: Path,
    version: str,
    *,
    readme: Path | None = None,
) -> None:
    try:
        text = changelog.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseIntegrityError(f"cannot read CHANGELOG: {exc}") from exc
    escaped = re.escape(version)
    match = re.search(
        rf"(?ms)^## v{escaped}(?=（|[ \t]|\r?$)[^\r\n]*\r?\n(?P<body>.*?)(?=^## |\Z)",
        text,
    )
    _require(match is not None and bool(match.group("body").strip()), f"CHANGELOG missing v{version}")
    body = match.group("body")
    _require_truthful_600_documentation(body, label=f"CHANGELOG v{version}")
    if version == "2.0.0":
        required_phrases = (
            "analysis-37",
            "37 页",
            "NOT_EVALUATED",
            "95% 准确率",
            "不构成出版质量证明",
            "不公开上传",
        )
        for phrase in required_phrases:
            _require(
                phrase in body,
                f"CHANGELOG v2.0.0 must state the release limitation: {phrase}",
            )
        banned_claims = (
            r"(?:达到|实现|保证|超过|不低于|≥)\s*95\s*%",
            r"(?:达到|实现|保证|已具备|VERIFIED).{0,32}(?:出版级|出版质量)",
            r"(?:出版级|出版质量).{0,32}(?:已(?:通过|验证|达标)|达到|实现|保证|VERIFIED)",
        )
        for pattern in banned_claims:
            _require(
                re.search(pattern, body, flags=re.IGNORECASE | re.DOTALL) is None,
                "CHANGELOG v2.0.0 makes a forbidden 600-page, 95%, or publication-quality claim",
            )
    for paragraph in re.split(r"\r?\n(?=-\s)|\r?\n\s*\r?\n", body):
        has_digest = re.search(r"(?i)\b[0-9a-f]{64}\b", paragraph) is not None
        describes_asset = re.search(
            r"(?i)LaTeXStruct(?:\.exe|-portable|-setup)|"
            r"(?:CI|发布|构建).{0,24}(?:资产|候选|产物)|"
            r"(?:资产|候选|产物).{0,24}SHA-?256",
            paragraph,
        ) is not None
        _require(
            not (has_digest and describes_asset),
            "current CHANGELOG section hard-codes a future CI asset SHA-256; "
            "publish dynamic dist/SHA256SUMS.txt instead",
        )
    if readme is not None:
        verify_release_readme(readme, version)


def _verify_report_reference(
    run_dir: Path,
    record: object,
    expected_filename: str,
) -> dict[str, Any]:
    _require(isinstance(record, Mapping), f"missing {expected_filename} report reference")
    relative = _safe_relative_member(record.get("filename"))
    _require(relative == Path(expected_filename), f"unexpected report filename: {relative}")
    digest = str(record.get("sha256") or "").lower()
    _require(SHA256_RE.fullmatch(digest) is not None, f"invalid {expected_filename} SHA-256")
    path = run_dir / relative
    _require(path.is_file(), f"missing report evidence: {expected_filename}")
    _require(_sha256_file(path) == digest, f"report digest mismatch: {expected_filename}")
    return _load_json(path)


def verify_run_attestation(
    run_dir: Path,
    *,
    expected_pages: int,
    version: str,
    commit: str,
    expected_source_sha256: str | None = None,
) -> dict[str, Any]:
    _require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None, "invalid version")
    _require(COMMIT_RE.fullmatch(commit.lower()) is not None, "invalid expected commit")
    path = run_dir / "acceptance-attestation.json"
    attestation = _load_json(path)
    _require(attestation.get("schema_version") == RUN_ATTESTATION_SCHEMA, "unsupported run attestation schema")
    _require(attestation.get("profile_kind") == "ocr", "run attestation is not an OCR profile")
    _require(attestation.get("result") == "PASS", "run attestation is not PASS")
    _require(attestation.get("acceptance_passed") is True, "run acceptance did not pass")

    execution = attestation.get("execution")
    _require(isinstance(execution, Mapping), "missing execution evidence")
    _require(execution.get("real_execution") is True, "test-double execution cannot release")
    _require(execution.get("test_double") is False, "test-double execution cannot release")
    _require(execution.get("simulated") is False, "simulated OCR execution cannot release")
    _require(execution.get("api_client") == "LocalHttpApi", "acceptance did not use LocalHttpApi")
    _require(execution.get("ui_driver") == "PlaywrightUiDriver", "acceptance did not use PlaywrightUiDriver")

    runtime = attestation.get("runtime_identity")
    _require(isinstance(runtime, Mapping), "missing runtime identity")
    _require(str(runtime.get("version") or "") == version, "attested version mismatch")
    _require(str(runtime.get("commit") or "").lower() == commit.lower(), "attested commit mismatch")
    _require(
        GITHUB_RUN_ID_RE.fullmatch(str(runtime.get("build_id") or "").strip())
        is not None,
        "attested build id must be a numeric GitHub Actions run id",
    )
    _require(
        SHA256_RE.fullmatch(str(runtime.get("executable_sha256") or "").lower()) is not None,
        "attested executable SHA-256 is missing",
    )
    _require(Path(str(runtime.get("executable_filename") or "")).name == "LaTeXStruct.exe", "tested executable filename is invalid")

    source = attestation.get("source")
    selected = attestation.get("selected_range")
    pages = attestation.get("pages")
    _require(isinstance(source, Mapping) and isinstance(selected, Mapping) and isinstance(pages, Mapping), "missing source/page evidence")
    _require(SHA256_RE.fullmatch(str(source.get("sha256") or "").lower()) is not None, "source SHA-256 is missing")
    if expected_source_sha256 is not None:
        _require(
            str(source.get("sha256") or "").lower()
            == expected_source_sha256.lower(),
            "OCR prerequisite source PDF SHA-256 mismatch",
        )
        _require(
            int(source.get("total_pages") or 0) == expected_pages,
            "OCR prerequisite must use the exact 37-page source PDF",
        )
    _require(int(source.get("total_pages") or 0) >= expected_pages, "source PDF page count is too small")
    _require(
        int(selected.get("start_page") or 0) == 1
        and int(selected.get("end_page") or 0) == expected_pages
        and int(selected.get("expected_pages") or 0) == expected_pages,
        f"attestation does not cover pages 1-{expected_pages}",
    )
    _require(int(pages.get("successful") or 0) == expected_pages, "successful page coverage mismatch")
    _require(
        int(pages.get("needs_review") or 0) == 0
        and int(pages.get("failed") or 0) == 0
        and int(pages.get("pending") or 0) == 0,
        "acceptance contains non-success pages",
    )

    model = attestation.get("model")
    _require(isinstance(model, Mapping), "missing model evidence")
    _require(bool(str(model.get("id") or "").strip()), "model id is missing")
    _require(bool(str(model.get("backend") or "").strip()), "model backend is missing")
    _require(int(model.get("calls") or 0) > 0, "model call count is missing")

    compilation = attestation.get("compilation")
    _require(isinstance(compilation, Mapping), "missing compilation evidence")
    _require(compilation.get("status") == "COMPILED", "baseline was not truly compiled")
    _require(int(compilation.get("successful_passes") or 0) >= 2, "baseline lacks two successful compile passes")
    _require(compilation.get("exit_code") == 0, "baseline compile exit code is not zero")
    for field in ("compile_log_sha256", "baseline_pdf_sha256"):
        _require(SHA256_RE.fullmatch(str(compilation.get(field) or "").lower()) is not None, f"missing {field}")

    timing = attestation.get("timing")
    _require(isinstance(timing, Mapping), "missing timing evidence")
    _require(timing.get("timed_out") is False, "timed-out acceptance is incomplete")
    _require(timing.get("completed_terminal_run") is True, "acceptance did not reach terminal state")
    _require(float(timing.get("wall_time_seconds") or 0) > 0, "wall time is missing")
    _require("before browser upload/start click" in str(timing.get("measurement") or ""), "timing did not start before the UI click")

    reports = attestation.get("reports")
    _require(isinstance(reports, Mapping), "missing report digest bindings")
    performance = _verify_report_reference(run_dir, reports.get("performance"), "performance.json")
    validation = _verify_report_reference(run_dir, reports.get("validation"), "validation-report.json")
    _require(performance.get("acceptance_passed") is True, "performance report is not PASS")
    _require(validation.get("acceptance_passed") is True, "validation report is not PASS")
    _require(validation.get("result") == "PASS", "validation result is not PASS")
    _require(performance.get("runtime_identity") == runtime, "runtime identity differs across reports")
    _require(validation.get("runtime_identity") == runtime, "runtime identity differs across reports")
    _require(performance.get("model") == model, "model evidence differs across reports")
    _require(validation.get("model") == model, "model evidence differs across reports")
    _require(validation.get("execution") == execution, "execution evidence differs across reports")
    attestation["ocr_baseline"] = _verify_ocr_baseline_package(
        run_dir,
        attestation.get("ocr_baseline"),
        expected_pages=expected_pages,
        version=version,
        commit=commit,
        runtime=runtime,
        source=source,
        selected=selected,
        pages=pages,
        model=model,
        compilation=compilation,
        validation=validation,
    )
    if expected_pages == 600:
        thresholds = performance.get("thresholds")
        _require(isinstance(thresholds, Mapping), "600-page thresholds are missing")
        _require(
            float(thresholds.get("minimum_successful_pages_per_minute") or 0) >= 20,
            "600-page throughput threshold is below 20 pages/minute",
        )
        _require(
            0 < float(thresholds.get("maximum_wall_time_seconds") or 0) <= 1800,
            "600-page wall-time threshold exceeds 1800 seconds",
        )
        _require(
            float(performance.get("successful_pages_per_minute") or 0) >= 20,
            "600-page measured throughput is below 20 pages/minute",
        )
        _require(
            0 < float(performance.get("wall_time_seconds") or 0) <= 1800,
            "600-page measured wall time exceeds 1800 seconds",
        )
    return attestation


def _validated_analysis_transport_contracts(
    value: object,
    *,
    model_bindings: object | None = None,
    require_stable_policy: bool = False,
) -> list[dict[str, Any]]:
    """Validate the complete non-secret transport policy frozen in a snapshot."""

    if not isinstance(value, list) or not value:
        raise ReleaseIntegrityError("analysis transport contracts are missing")
    expected_fields = {
        "role",
        "model_id",
        "reasoning_effort",
        "operations",
        "client_type",
        "method",
        "max_retries",
        "max_tokens",
        "backend_authority_sha256",
        "backend_configuration_sha256",
    }
    normalized_models: dict[str, dict[str, Any]] = {}
    if model_bindings is not None:
        if not isinstance(model_bindings, list) or not model_bindings:
            raise ReleaseIntegrityError("analysis model bindings are missing")
        for index, raw_model in enumerate(model_bindings, 1):
            model = dict(_require_exact_fields(
                raw_model,
                required={
                    "role",
                    "model_id",
                    "capabilities",
                    "reasoning_effort",
                },
                label=f"analysis model binding {index}",
            ))
            role = str(model.get("role") or "")
            effort = str(model.get("reasoning_effort") or "")
            capabilities = model.get("capabilities")
            _require(
                re.fullmatch(r"AI-[1-6]", role) is not None
                and role not in normalized_models
                and bool(str(model.get("model_id") or "").strip())
                and effort in {"", "low", "medium", "high", "xhigh"}
                and isinstance(capabilities, list)
                and capabilities == sorted(set(capabilities))
                and all(isinstance(item, str) and bool(item) for item in capabilities),
                f"analysis model binding {index} is malformed",
            )
            normalized_models[role] = model
        if require_stable_policy:
            declared_profiles = {
                (
                    str(model.get("model_id") or ""),
                    str(model.get("reasoning_effort") or ""),
                )
                for model in normalized_models.values()
            }
            _require(
                tuple(sorted(normalized_models, key=lambda item: int(item.split("-")[1])))
                == ANALYSIS_STABLE_MODEL_ROLES
                and len(declared_profiles) == 1
                and next(iter(declared_profiles))[0]
                in ANALYSIS_RELEASE_ALLOWED_MODEL_IDS
                and next(iter(declared_profiles))[1]
                in ANALYSIS_RELEASE_ALLOWED_REASONING_EFFORTS,
                "analysis-37 release model policy is not an allowed uniform model/effort declaration",
            )

    contracts: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    for index, raw_contract in enumerate(value, 1):
        contract = dict(_require_exact_fields(
            raw_contract,
            required=expected_fields,
            label=f"analysis transport contract {index}",
        ))
        role = str(contract.get("role") or "")
        model_id = str(contract.get("model_id") or "").strip()
        effort = str(contract.get("reasoning_effort") or "")
        operations = contract.get("operations")
        client_type = str(contract.get("client_type") or "")
        method = str(contract.get("method") or "")
        expected_operations = sorted(
            operation
            for operation, operation_role in ANALYSIS_OPERATION_ROLES.items()
            if operation_role == role
        )
        _require(
            re.fullmatch(r"AI-[1-6]", role) is not None
            and role not in seen_roles
            and bool(model_id)
            and effort in {"", "low", "medium", "high", "xhigh"}
            and isinstance(operations, list)
            and operations == expected_operations
            and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+",
                client_type,
            )
            is not None
            and method
            in {"chat_json", "chat_json_schema", "chat_vision_json_images_bytes"}
            and type(contract.get("max_retries")) is int
            and contract["max_retries"] >= 0
            and type(contract.get("max_tokens")) is int
            and contract["max_tokens"] >= 0
            and all(
                SHA256_RE.fullmatch(str(contract.get(name) or "").lower())
                is not None
                for name in (
                    "backend_authority_sha256",
                    "backend_configuration_sha256",
                )
            )
            and ("codex" not in client_type.lower() or bool(effort))
            and (
                not require_stable_policy
                or client_type == "latexstruct.core.codex_cli.CodexCLIClient"
            )
            and (
                not require_stable_policy
                or (
                    contract.get("backend_authority_sha256")
                    == ANALYSIS_STABLE_BACKEND_AUTHORITY_SHA256
                    and contract.get("backend_configuration_sha256")
                    == ANALYSIS_STABLE_BACKEND_CONFIGURATION_SHA256
                )
            ),
            f"analysis transport contract {index} is malformed or not authoritative",
        )
        if normalized_models:
            model = normalized_models.get(role)
            _require(
                model is not None
                and model.get("model_id") == model_id
                and model.get("reasoning_effort") == effort,
                f"analysis transport contract {index} differs from its model binding",
            )
        seen_roles.add(role)
        contracts.append(contract)
    _require(
        [item["role"] for item in contracts]
        == sorted(seen_roles, key=lambda item: int(item.split("-")[1]))
        and (not normalized_models or seen_roles == set(normalized_models)),
        "analysis transport contracts do not exactly cover the frozen model roles",
    )
    return contracts


def _verify_analysis_release_model_policy(
    value: object,
    *,
    model_bindings: object,
    transport_contracts: object,
) -> dict[str, Any]:
    """Close the workflow declaration against runtime and frozen call policy."""

    policy = _require_exact_fields(
        value,
        required={
            "schema_version",
            "declared_model_id",
            "declared_reasoning_effort",
            "runtime_configuration",
            "runtime_configuration_sha256",
            "model_bindings_sha256",
            "transport_contracts_sha256",
            "runtime_matches_declared",
            "all_role_bindings_match_declared",
            "all_transport_contracts_match_declared",
            "allowed_by_release",
        },
        label="analysis release model policy",
    )
    runtime = _require_exact_fields(
        policy.get("runtime_configuration"),
        required={
            "analysis_backend",
            "codex_model",
            "codex_reasoning_effort",
            "codex_triage_model",
            "codex_triage_reasoning_effort",
        },
        label="analysis runtime model configuration",
    )
    declared_model = str(policy.get("declared_model_id") or "").strip()
    declared_effort = str(policy.get("declared_reasoning_effort") or "").strip()
    _require(
        policy.get("schema_version") == ANALYSIS_RELEASE_MODEL_POLICY_SCHEMA
        and declared_model in ANALYSIS_RELEASE_ALLOWED_MODEL_IDS
        and declared_effort in ANALYSIS_RELEASE_ALLOWED_REASONING_EFFORTS,
        "analysis release model declaration is not allowed",
    )
    _require(
        runtime
        == {
            "analysis_backend": "codex_cli",
            "codex_model": declared_model,
            "codex_reasoning_effort": declared_effort,
            "codex_triage_model": declared_model,
            "codex_triage_reasoning_effort": declared_effort,
        }
        and str(policy.get("runtime_configuration_sha256") or "").lower()
        == _canonical_json_sha256(runtime),
        "analysis runtime model configuration differs from its declared policy",
    )
    bindings = _require_list(model_bindings, "analysis release model bindings")
    normalized_contracts = _validated_analysis_transport_contracts(
        transport_contracts,
        model_bindings=bindings,
        require_stable_policy=True,
    )
    _require(
        len(bindings) == len(ANALYSIS_STABLE_MODEL_ROLES)
        and all(
            isinstance(binding, Mapping)
            and binding.get("model_id") == declared_model
            and binding.get("reasoning_effort") == declared_effort
            for binding in bindings
        )
        and all(
            contract.get("model_id") == declared_model
            and contract.get("reasoning_effort") == declared_effort
            for contract in normalized_contracts
        ),
        "analysis frozen model bindings/contracts differ from the declared policy",
    )
    _require(
        str(policy.get("model_bindings_sha256") or "").lower()
        == _canonical_json_sha256(bindings)
        and str(policy.get("transport_contracts_sha256") or "").lower()
        == _canonical_json_sha256(normalized_contracts)
        and policy.get("runtime_matches_declared") is True
        and policy.get("all_role_bindings_match_declared") is True
        and policy.get("all_transport_contracts_match_declared") is True
        and policy.get("allowed_by_release") is True,
        "analysis release model policy closure is incomplete",
    )
    return dict(policy)


def _verify_analysis_budget_closure(
    value: object,
    *,
    expected_invocations: int,
    model_bindings: object,
    expected_contracts_sha256: str,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "budget_state_sha256",
        "budget_state",
        "budget_usage_sha256",
        "budget_usage",
        "limits_sha256",
        "limits",
        "transport_contracts_sha256",
        "transport_contracts",
        "transport_budget_ledger_sha256",
        "transport_budget_ledger",
        "observed",
        "actual",
        "accounted",
        "requests",
        "strong_model_calls",
        "unknown",
        "transport_claim_count",
        "committed_reservations",
        "cancelled_reservations",
        "active_reservations",
        "wall_time_minutes",
        "unbounded_unknown_dimensions",
        "all_claims_verified",
        "all_actual_usage_verified",
        "exact_aggregate_verified",
    }
    closure = _require_exact_fields(
        value, required=required, label="analysis transport budget closure"
    )
    budget_state = _require_exact_fields(
        closure.get("budget_state"),
        required={
            "schema_version",
            "limits",
            "usage",
            "low_priority_threshold",
            "stop_reason",
            "stop_details",
            "unbounded_unknown_dimensions",
            "reservations",
        },
        label="analysis persisted budget state",
    )
    budget_usage = _require_exact_fields(
        closure.get("budget_usage"),
        required={
            "observed",
            "actual",
            "accounted",
            "requests",
            "strong_model_calls",
            "unknown",
            "committed_reservations",
            "cancelled_reservations",
            "wall_time_minutes",
        },
        label="analysis persisted budget usage",
    )
    limits = _require_exact_fields(
        closure.get("limits"),
        required={
            "max_input_tokens",
            "max_output_tokens",
            "max_cost",
            "max_requests",
            "max_strong_model_calls",
            "max_wall_time_minutes",
        },
        label="analysis transport budget limits",
    )
    contracts = _validated_analysis_transport_contracts(
        closure.get("transport_contracts"),
        model_bindings=model_bindings,
        require_stable_policy=True,
    )
    contract_by_role = {str(item["role"]): item for item in contracts}
    ledger = closure.get("transport_budget_ledger")
    _require(
        isinstance(ledger, list) and bool(ledger),
        "analysis transport budget ledger is missing",
    )
    observed = _require_exact_fields(
        closure.get("observed"),
        required={"input_tokens", "output_tokens", "cost"},
        label="analysis observed budget usage",
    )
    actual = _require_exact_fields(
        closure.get("actual"),
        required={"input_tokens", "output_tokens", "cost"},
        label="analysis actual budget usage",
    )
    accounted = _require_exact_fields(
        closure.get("accounted"),
        required={"input_tokens", "output_tokens", "cost"},
        label="analysis accounted budget usage",
    )
    unknown = _require_exact_fields(
        closure.get("unknown"),
        required={
            "input_token_requests",
            "output_token_requests",
            "cost_requests",
        },
        label="analysis unknown budget usage",
    )

    def finite_nonnegative(value: object) -> bool:
        return bool(
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
            and float(value) >= 0
        )

    integer_limit_names = {
        "max_input_tokens",
        "max_output_tokens",
        "max_requests",
        "max_strong_model_calls",
    }
    _require(
        closure.get("schema_version") == ANALYSIS_BUDGET_CLOSURE_SCHEMA
        and all(
            SHA256_RE.fullmatch(str(closure.get(name) or "").lower()) is not None
            for name in (
                "budget_state_sha256",
                "budget_usage_sha256",
                "limits_sha256",
                "transport_contracts_sha256",
                "transport_budget_ledger_sha256",
            )
        )
        and all(
            type(limits.get(name)) is int and limits[name] >= 0
            for name in integer_limit_names
        )
        and finite_nonnegative(limits.get("max_cost"))
        and finite_nonnegative(limits.get("max_wall_time_minutes"))
        and float(limits["max_wall_time_minutes"]) > 0,
        "analysis transport budget identity/limits are malformed",
    )
    _require(
        str(closure.get("limits_sha256") or "").lower()
        == _canonical_json_sha256(limits),
        "analysis transport budget limits digest is invalid",
    )
    _require(
        str(closure.get("budget_state_sha256") or "").lower()
        == _canonical_json_sha256(budget_state)
        and str(closure.get("budget_usage_sha256") or "").lower()
        == _canonical_json_sha256(budget_usage)
        and str(closure.get("transport_contracts_sha256") or "").lower()
        == _canonical_json_sha256(contracts)
        == str(expected_contracts_sha256 or "").lower()
        and str(closure.get("transport_budget_ledger_sha256") or "").lower()
        == _canonical_json_sha256(ledger),
        "analysis transport budget state/contracts/ledger digest is invalid",
    )
    _require(
        budget_state.get("schema_version") == "analysis-budget-v1"
        and budget_state.get("limits") == limits
        and budget_state.get("usage") == budget_usage
        and budget_usage.get("observed") == observed
        and budget_usage.get("actual") == actual
        and budget_usage.get("accounted") == accounted
        and budget_usage.get("unknown") == unknown
        and isinstance(budget_state.get("reservations"), list)
        and budget_state["reservations"] == []
        and isinstance(budget_state.get("stop_details"), list)
        and all(
            isinstance(item, str) and bool(item)
            for item in budget_state["stop_details"]
        )
        and budget_state.get("stop_reason")
        in {None, "STOP_LOW_PRIORITY", "LIMIT_REACHED", "LIMIT_EXCEEDED", "UNKNOWN_USAGE"},
        "analysis persisted budget state is not the projected terminal closure",
    )
    for usage in (observed, accounted):
        _require(
            type(usage.get("input_tokens")) is int
            and usage["input_tokens"] >= 0
            and type(usage.get("output_tokens")) is int
            and usage["output_tokens"] >= 0
            and finite_nonnegative(usage.get("cost")),
            "analysis transport budget token/cost aggregate is malformed",
        )
    for name in ("input_tokens", "output_tokens"):
        _require(
            actual.get(name) is None
            or (type(actual[name]) is int and actual[name] >= 0),
            "analysis transport actual token aggregate is malformed",
        )
    _require(
        actual.get("cost") is None or finite_nonnegative(actual.get("cost")),
        "analysis transport actual cost aggregate is malformed",
    )

    def number_equal(left: object, right: object) -> bool:
        if left is None or right is None:
            return left is right
        return bool(
            not isinstance(left, bool)
            and not isinstance(right, bool)
            and isinstance(left, (int, float))
            and isinstance(right, (int, float))
            and math.isclose(
                float(left), float(right), rel_tol=1e-12, abs_tol=1e-12
            )
        )

    recomputed: dict[str, int | float] = {
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
    }
    recomputed_attempt_tokens = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "total_tokens": 0,
        "attempt_count": 0,
    }
    recomputed_unbounded: set[str] = set()
    claim_fields = {
        "input_tokens",
        "output_tokens",
        "cost",
        "requests",
        "strong_model_calls",
    }
    actual_fields = {"input_tokens", "output_tokens", "cost"}
    attempt_fields = {
        "attempt_number",
        "succeeded",
        "usage_complete",
        "failure_stage",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "billing_mode",
        "cost",
        "cost_provenance",
    }
    allowed_failure_stages = {
        "http_error",
        "invalid_json",
        "invalid_response_envelope",
        "missing_turn_evidence",
        "network_error",
        "runtime_failure_without_turn_evidence",
        "timeout",
        "turn_failed",
    }
    for index, raw_row in enumerate(ledger, 1):
        row = _require_exact_fields(
            raw_row,
            required={
                "ordinal",
                "role",
                "budget_claim",
                "budget_actual_usage",
                "attempts",
            },
            label=f"analysis transport budget ledger row {index}",
        )
        role = str(row.get("role") or "")
        contract = contract_by_role.get(role)
        claim = _require_exact_fields(
            row.get("budget_claim"),
            required=claim_fields,
            label=f"analysis transport budget claim {index}",
        )
        row_actual = _require_exact_fields(
            row.get("budget_actual_usage"),
            required=actual_fields,
            label=f"analysis transport budget actual usage {index}",
        )
        attempts = row.get("attempts")
        _require(
            type(row.get("ordinal")) is int
            and row["ordinal"] == index
            and contract is not None
            and all(
                type(claim.get(name)) is int and claim[name] >= 0
                for name in (
                    "input_tokens",
                    "output_tokens",
                    "requests",
                    "strong_model_calls",
                )
            )
            and finite_nonnegative(claim.get("cost"))
            and isinstance(attempts, list)
            and bool(attempts),
            f"analysis transport budget ledger row {index} is malformed",
        )
        attempt_bound = int(contract["max_retries"]) + 1
        expected_claim_cost = 0.0
        if float(limits["max_cost"]) > 0:
            per_attempt_input = int(claim["input_tokens"]) // attempt_bound
            estimate = (
                estimate_call_cost(
                    str(contract["model_id"]),
                    {
                        "input_tokens": per_attempt_input,
                        "output_tokens": int(contract["max_tokens"]),
                    },
                )
                if int(contract["max_tokens"]) > 0
                else None
            )
            expected_claim_cost = (
                float(estimate["cny"]) * attempt_bound
                if estimate is not None
                else float(limits["max_cost"])
            )
        _require(
            int(claim["requests"]) == attempt_bound
            and int(claim["strong_model_calls"])
            == (attempt_bound if role == "AI-6" else 0)
            and int(claim["input_tokens"]) % attempt_bound == 0
            and int(claim["output_tokens"])
            == int(contract["max_tokens"]) * attempt_bound
            and number_equal(claim["cost"], expected_claim_cost)
            and len(attempts) <= attempt_bound,
            f"analysis transport budget claim {index} differs from its contract",
        )
        for claim_name, limit_name in (
            ("input_tokens", "max_input_tokens"),
            ("output_tokens", "max_output_tokens"),
            ("cost", "max_cost"),
            ("requests", "max_requests"),
            ("strong_model_calls", "max_strong_model_calls"),
        ):
            maximum = float(limits[limit_name])
            _require(
                maximum <= 0 or float(claim[claim_name]) <= maximum,
                f"analysis transport budget claim {index} exceeds {limit_name}",
            )
        invocation_tokens = {"input_tokens": 0, "output_tokens": 0}
        invocation_costs: list[float | None] = []
        for attempt_index, raw_attempt in enumerate(attempts, 1):
            attempt = _require_exact_fields(
                raw_attempt,
                required=attempt_fields,
                label=f"analysis transport budget attempt {index}.{attempt_index}",
            )
            input_tokens = attempt.get("input_tokens")
            output_tokens = attempt.get("output_tokens")
            cached_tokens = attempt.get("cached_tokens")
            succeeded = attempt.get("succeeded")
            failure_stage = attempt.get("failure_stage")
            provenance = attempt.get("cost_provenance")
            billing_mode = attempt.get("billing_mode")
            _require(
                type(attempt.get("attempt_number")) is int
                and attempt["attempt_number"] == attempt_index
                and type(succeeded) is bool
                and succeeded is (attempt_index == len(attempts))
                and attempt.get("usage_complete") is True
                and isinstance(failure_stage, str)
                and (
                    (succeeded is True and failure_stage == "")
                    or (
                        succeeded is False
                        and failure_stage in allowed_failure_stages
                    )
                )
                and type(input_tokens) is int
                and input_tokens >= 0
                and type(output_tokens) is int
                and output_tokens >= 0
                and type(cached_tokens) is int
                and 0 <= cached_tokens <= input_tokens
                and provenance
                in {"chatgpt_subscription", "pricing_table", "unknown_price"},
                f"analysis transport budget attempt {index}.{attempt_index} is malformed",
            )
            if billing_mode == "chatgpt_subscription":
                _require(
                    provenance == "chatgpt_subscription",
                    f"analysis transport budget attempt {index}.{attempt_index} has false subscription provenance",
                )
                expected_cost = None
            else:
                _require(
                    False,
                    f"analysis transport budget attempt {index}.{attempt_index} is not Codex subscription billed",
                )
                expected_cost = None
            _require(
                number_equal(attempt.get("cost"), expected_cost),
                f"analysis transport budget attempt {index}.{attempt_index} cost is forged",
            )
            invocation_tokens["input_tokens"] += input_tokens
            invocation_tokens["output_tokens"] += output_tokens
            invocation_costs.append(expected_cost)
            recomputed_attempt_tokens["input_tokens"] += input_tokens
            recomputed_attempt_tokens["output_tokens"] += output_tokens
            recomputed_attempt_tokens["cached_tokens"] += cached_tokens
            recomputed_attempt_tokens["total_tokens"] += input_tokens + output_tokens
            recomputed_attempt_tokens["attempt_count"] += 1
        expected_actual = {
            **invocation_tokens,
            "cost": (
                sum(value for value in invocation_costs if value is not None)
                if all(value is not None for value in invocation_costs)
                else None
            ),
        }
        _require(
            all(number_equal(row_actual[name], expected_actual[name]) for name in actual_fields),
            f"analysis transport budget actual usage {index} differs from attempts",
        )
        recomputed["requests"] += attempt_bound
        recomputed["strong_model_calls"] += int(claim["strong_model_calls"])
        for dimension, observed_name, accounted_name, unknown_name, limit_name in (
            (
                "input_tokens",
                "observed_input_tokens",
                "accounted_input_tokens",
                "unknown_input_token_requests",
                "max_input_tokens",
            ),
            (
                "output_tokens",
                "observed_output_tokens",
                "accounted_output_tokens",
                "unknown_output_token_requests",
                "max_output_tokens",
            ),
            (
                "cost",
                "observed_cost",
                "accounted_cost",
                "unknown_cost_requests",
                "max_cost",
            ),
        ):
            actual_value = expected_actual[dimension]
            if actual_value is None:
                recomputed[accounted_name] += claim[dimension]
                recomputed[unknown_name] += attempt_bound
                if float(claim[dimension]) == 0 and float(limits[limit_name]) > 0:
                    recomputed_unbounded.add(dimension)
            else:
                recomputed[observed_name] += actual_value
                recomputed[accounted_name] += actual_value
    integer_fields = (
        "requests",
        "strong_model_calls",
        "transport_claim_count",
        "committed_reservations",
        "cancelled_reservations",
        "active_reservations",
    )
    _require(
        all(type(closure.get(name)) is int and closure[name] >= 0 for name in integer_fields)
        and all(type(value) is int and value >= 0 for value in unknown.values())
        and finite_nonnegative(closure.get("wall_time_minutes")),
        "analysis transport budget counters are malformed",
    )
    expected_observed = {
        "input_tokens": recomputed["observed_input_tokens"],
        "output_tokens": recomputed["observed_output_tokens"],
        "cost": recomputed["observed_cost"],
    }
    expected_accounted = {
        "input_tokens": recomputed["accounted_input_tokens"],
        "output_tokens": recomputed["accounted_output_tokens"],
        "cost": recomputed["accounted_cost"],
    }
    expected_unknown = {
        "input_token_requests": recomputed["unknown_input_token_requests"],
        "output_token_requests": recomputed["unknown_output_token_requests"],
        "cost_requests": recomputed["unknown_cost_requests"],
    }
    expected_actual = {
        "input_tokens": (
            None
            if recomputed["unknown_input_token_requests"]
            else recomputed["observed_input_tokens"]
        ),
        "output_tokens": (
            None
            if recomputed["unknown_output_token_requests"]
            else recomputed["observed_output_tokens"]
        ),
        "cost": (
            None
            if recomputed["unknown_cost_requests"]
            else recomputed["observed_cost"]
        ),
    }
    _require(
        dict(observed) == expected_observed
        and dict(accounted) == expected_accounted
        and dict(actual) == expected_actual
        and dict(unknown) == expected_unknown,
        "analysis transport budget aggregates differ from the sanitized attempt ledger",
    )
    requests = int(closure["requests"])
    committed = int(closure["committed_reservations"])
    _require(
        expected_invocations > 0
        and int(closure["transport_claim_count"])
        == committed
        == expected_invocations
        and requests == int(recomputed["requests"])
        and int(closure["strong_model_calls"])
        == int(recomputed["strong_model_calls"])
        and all(int(value) <= requests for value in unknown.values())
        and closure["cancelled_reservations"] == 0
        and closure["active_reservations"] == 0
        and closure.get("all_claims_verified") is True
        and closure.get("all_actual_usage_verified") is True
        and closure.get("exact_aggregate_verified") is True,
        "analysis transport budget reservations/claims do not close",
    )
    dimension_rows = (
        (
            "input_tokens",
            "input_token_requests",
            "max_input_tokens",
        ),
        (
            "output_tokens",
            "output_token_requests",
            "max_output_tokens",
        ),
        ("cost", "cost_requests", "max_cost"),
    )
    for dimension, unknown_name, limit_name in dimension_rows:
        unknown_count = int(unknown[unknown_name])
        observed_value = observed[dimension]
        accounted_value = accounted[dimension]
        _require(
            float(accounted_value) + 1e-12 >= float(observed_value)
            and (
                (unknown_count == 0 and actual[dimension] == observed_value)
                or (unknown_count > 0 and actual[dimension] is None)
            ),
            f"analysis transport budget {dimension} observed/unknown algebra is invalid",
        )
        maximum = float(limits[limit_name])
        _require(
            maximum <= 0 or float(accounted_value) <= maximum,
            f"analysis transport budget exceeds frozen {limit_name}",
        )
    _require(
        int(closure["requests"]) <= int(limits["max_requests"])
        if int(limits["max_requests"]) > 0
        else True,
        "analysis transport budget exceeds frozen max_requests",
    )
    _require(
        int(closure["strong_model_calls"])
        <= int(limits["max_strong_model_calls"])
        if int(limits["max_strong_model_calls"]) > 0
        else True,
        "analysis transport budget exceeds frozen max_strong_model_calls",
    )
    _require(
        float(closure["wall_time_minutes"])
        <= float(limits["max_wall_time_minutes"]),
        "analysis transport budget exceeds frozen max_wall_time_minutes",
    )
    unbounded = closure.get("unbounded_unknown_dimensions")
    _require(
        isinstance(unbounded, list)
        and unbounded == sorted(set(unbounded))
        and set(unbounded).issubset({"input_tokens", "output_tokens", "cost"})
        and unbounded == sorted(recomputed_unbounded)
        and budget_state.get("unbounded_unknown_dimensions") == unbounded,
        "analysis unbounded unknown budget dimensions are invalid",
    )
    _require(
        finite_nonnegative(budget_state.get("low_priority_threshold"))
        and 0 < float(budget_state["low_priority_threshold"]) <= 1,
        "analysis persisted low-priority budget threshold is invalid",
    )
    usage_payload = {
        "observed": dict(observed),
        "actual": dict(actual),
        "accounted": dict(accounted),
        "requests": closure["requests"],
        "strong_model_calls": closure["strong_model_calls"],
        "unknown": dict(unknown),
        "committed_reservations": closure["committed_reservations"],
        "cancelled_reservations": closure["cancelled_reservations"],
        "wall_time_minutes": closure["wall_time_minutes"],
    }
    _require(
        str(closure.get("budget_usage_sha256") or "").lower()
        == _canonical_json_sha256(usage_payload),
        "analysis transport budget usage digest is not recomputable",
    )
    verified = dict(closure)
    verified["_recomputed_attempt_tokens"] = recomputed_attempt_tokens
    return verified


def _verify_analysis_transport_closure(
    value: object,
    *,
    expected_invocations: int,
    model_bindings: object,
    expected_contracts_sha256: str,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "transport_evidence_sha256",
        "orchestration_invocation_count",
        "transport_invocation_count",
        "transport_attempt_count",
        "usage_observed_call_count",
        "usage_observed_attempt_count",
        "usage_missing_call_count",
        "usage_missing_attempt_count",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "total_tokens",
        "usage_complete",
        "attempt_evidence_complete",
        "budget_closure",
    }
    closure = _require_exact_fields(
        value, required=required, label="analysis transport attempt/usage closure"
    )
    integer_fields = (
        "orchestration_invocation_count",
        "transport_invocation_count",
        "transport_attempt_count",
        "usage_observed_call_count",
        "usage_observed_attempt_count",
        "usage_missing_call_count",
        "usage_missing_attempt_count",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "total_tokens",
    )
    _require(
        closure.get("schema_version") == ANALYSIS_TRANSPORT_CLOSURE_SCHEMA
        and SHA256_RE.fullmatch(
            str(closure.get("transport_evidence_sha256") or "").lower()
        )
        is not None
        and all(type(closure.get(name)) is int for name in integer_fields),
        "analysis transport closure fields are malformed",
    )
    invocation_count = int(closure["transport_invocation_count"])
    attempt_count = int(closure["transport_attempt_count"])
    input_tokens = int(closure["input_tokens"])
    output_tokens = int(closure["output_tokens"])
    cached_tokens = int(closure["cached_tokens"])
    _require(
        expected_invocations > 0
        and int(closure["orchestration_invocation_count"])
        == invocation_count
        == int(closure["usage_observed_call_count"])
        == expected_invocations
        and attempt_count >= invocation_count
        and int(closure["usage_observed_attempt_count"]) == attempt_count
        and closure["usage_missing_call_count"] == 0
        and closure["usage_missing_attempt_count"] == 0
        and input_tokens > 0
        and output_tokens > 0
        and 0 <= cached_tokens <= input_tokens
        and closure["total_tokens"] == input_tokens + output_tokens
        and closure.get("usage_complete") is True
        and closure.get("attempt_evidence_complete") is True,
        "analysis transport attempts/tokens do not form a complete closed ledger",
    )
    budget = _verify_analysis_budget_closure(
        closure.get("budget_closure"),
        expected_invocations=expected_invocations,
        model_bindings=model_bindings,
        expected_contracts_sha256=expected_contracts_sha256,
    )
    ledger_tokens = budget.pop("_recomputed_attempt_tokens")
    _require(
        ledger_tokens
        == {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "total_tokens": int(closure["total_tokens"]),
            "attempt_count": attempt_count,
        },
        "analysis transport totals differ from the sanitized budget ledger",
    )
    return dict(closure)


def _stable_source_page_id(source_sha256: str, page_number: int) -> str:
    return f"src-{source_sha256[:12]}-p{page_number:06d}"


def _verify_analysis_configuration(
    value: object,
    *,
    claimed_sha256: object,
    expected_pages: int,
    admission: object,
    model_bindings: object,
    expected_contracts_sha256: str,
    snapshot_config_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate the full sanitized configuration frozen before model calls."""

    configuration = _require_exact_fields(
        value,
        required={
            "workflow_version",
            "prompt_version",
            "application_version",
            "latex_engine",
            "concurrency_limit",
            "models",
            "transport_contracts",
            "page_range",
            "candidate_page_map",
            "candidate_storage_name",
            "raw_ocr_frozen",
            "page_risks",
            "page_risk_admission",
            "page_risk_admission_hash",
            "page_risk_source_admission_hash",
            "compile_extra_files",
            "max_macro_rounds",
            "max_input_tokens",
            "max_output_tokens",
            "max_cost",
            "max_requests",
            "max_strong_model_calls",
            "max_wall_time_minutes",
        },
        label="analysis frozen configuration",
    )
    digest = _canonical_json_sha256(configuration)
    claimed = str(claimed_sha256 or "").lower()
    _require(
        SHA256_RE.fullmatch(claimed) is not None
        and claimed == digest
        and (snapshot_config_sha256 is None or claimed == snapshot_config_sha256.lower()),
        "analysis frozen configuration digest is invalid",
    )
    _require(
        isinstance(configuration.get("workflow_version"), str)
        and bool(str(configuration["workflow_version"]).strip())
        and isinstance(configuration.get("prompt_version"), str)
        and bool(str(configuration["prompt_version"]).strip())
        and isinstance(configuration.get("application_version"), str)
        and bool(str(configuration["application_version"]).strip())
        and isinstance(configuration.get("latex_engine"), str)
        and bool(str(configuration["latex_engine"]).strip())
        and type(configuration.get("concurrency_limit")) is int
        and 1 <= int(configuration["concurrency_limit"]) <= 3,
        "analysis frozen configuration runtime fields are invalid",
    )
    normalized_bindings = [
        dict(_require_exact_fields(
            item,
            required={"role", "model_id", "capabilities", "reasoning_effort"},
            label="analysis configuration model binding",
        ))
        for item in _require_list(configuration.get("models"), "analysis configuration models")
    ]
    _require(
        normalized_bindings == model_bindings,
        "analysis configuration model bindings differ from the snapshot",
    )
    contracts = _validated_analysis_transport_contracts(
        configuration.get("transport_contracts"),
        model_bindings=normalized_bindings,
        require_stable_policy=True,
    )
    _require(
        _canonical_json_sha256(contracts) == expected_contracts_sha256.lower(),
        "analysis configuration transport contracts differ from the snapshot",
    )
    page_range = configuration.get("page_range")
    _require(
        page_range == list(range(1, expected_pages + 1)),
        "analysis configuration page range is not the exact 37-page cohort",
    )
    candidate_map = _require_list(
        configuration.get("candidate_page_map"),
        "analysis configuration candidate page map",
    )
    _require(
        len(candidate_map) == expected_pages,
        "analysis configuration candidate page map is incomplete",
    )
    for page_number, row in enumerate(candidate_map, 1):
        _require(
            isinstance(row, list)
            and len(row) == 2
            and row[0] == page_number
            and isinstance(row[1], list)
            and bool(row[1])
            and all(type(page) is int and page > 0 for page in row[1])
            and row[1] == sorted(set(row[1])),
            f"analysis configuration candidate page map row {page_number} is invalid",
        )
    _require(
        configuration.get("candidate_storage_name") == "candidate.tex"
        and configuration.get("raw_ocr_frozen") is True,
        "analysis configuration does not freeze the canonical candidate/raw OCR",
    )
    try:
        from latexstruct.core.analysis_risk import coerce_page_risk_admission

        admitted = coerce_page_risk_admission(admission)
    except (ImportError, TypeError, ValueError) as exc:
        raise ReleaseIntegrityError("analysis page-risk admission is invalid") from exc
    _require(
        _canonical_json_sha256(configuration.get("page_risk_admission"))
        == admitted.digest
        and configuration.get("page_risk_admission_hash") == admitted.digest
        and configuration.get("page_risk_source_admission_hash") == admitted.digest,
        "analysis configuration page-risk binding is invalid",
    )
    risk_rows = _require_list(
        configuration.get("page_risks"), "analysis configuration page risks"
    )
    expected_risks = [
        {
            "source_page_number": page.summary.source_page_number,
            "risk_level": page.risk_level.value,
            "risk_reasons": list(page.risk_reasons),
        }
        for page in admitted.pages
    ]
    _require(
        risk_rows == expected_risks,
        "analysis configuration page-risk rows differ from the admission",
    )
    extras = _require_list(
        configuration.get("compile_extra_files"),
        "analysis configuration compile extras",
    )
    normalized_extras: list[list[str]] = []
    for row in extras:
        _require(
            isinstance(row, list) and len(row) == 2,
            "analysis configuration compile-extra row is invalid",
        )
        relative = _safe_relative_member(row[0])
        digest_value = str(row[1] or "").lower()
        _require(
            SHA256_RE.fullmatch(digest_value) is not None,
            "analysis configuration compile-extra digest is invalid",
        )
        normalized_extras.append([relative.as_posix(), digest_value])
    _require(
        normalized_extras == sorted(normalized_extras)
        and len({row[0].casefold() for row in normalized_extras})
        == len(normalized_extras),
        "analysis configuration compile-extra paths are not canonical",
    )
    _require(
        type(configuration.get("max_macro_rounds")) is int
        and int(configuration["max_macro_rounds"]) > 0,
        "analysis configuration max_macro_rounds is invalid",
    )
    for field in (
        "max_input_tokens",
        "max_output_tokens",
        "max_requests",
        "max_strong_model_calls",
    ):
        _require(
            type(configuration.get(field)) is int and int(configuration[field]) >= 0,
            f"analysis configuration {field} is invalid",
        )
    for field in ("max_cost", "max_wall_time_minutes"):
        raw = configuration.get(field)
        _require(
            not isinstance(raw, bool)
            and isinstance(raw, (int, float))
            and math.isfinite(float(raw))
            and float(raw) >= 0
            and (field != "max_wall_time_minutes" or float(raw) > 0),
            f"analysis configuration {field} is invalid",
        )
    return dict(configuration)


def _coerce_page_route_closure(value: object) -> object:
    """Parse the exact typed v2 route closure and reject forged inner hashes."""

    raw = _require_exact_fields(
        value,
        required={
            "schema_version",
            "admission_sha256",
            "final_candidate_hash",
            "pages",
            "pages_sha256",
            "risk_counts",
            "route_call_keys",
            "route_call_keys_sha256",
            "closure_sha256",
        },
        label="analysis page-route closure",
    )
    try:
        from latexstruct.core.analysis_schema import (
            PageRiskRouteClosure,
            PageRouteCallKey,
            PageRouteRecord,
        )

        pages = tuple(
            PageRouteRecord(**dict(_require_mapping(
                row, "analysis page-route record"
            )))
            for row in _require_list(raw.get("pages"), "analysis page-route pages")
        )
        calls = tuple(
            PageRouteCallKey(**dict(_require_mapping(
                row, "analysis page-route call"
            )))
            for row in _require_list(
                raw.get("route_call_keys"), "analysis page-route calls"
            )
        )
        closure = PageRiskRouteClosure(
            schema_version=str(raw.get("schema_version") or ""),
            admission_sha256=str(raw.get("admission_sha256") or ""),
            final_candidate_hash=str(raw.get("final_candidate_hash") or ""),
            pages=pages,
            route_call_keys=calls,
        )
    except (ImportError, TypeError, ValueError) as exc:
        raise ReleaseIntegrityError("analysis page-route closure is invalid") from exc
    _require(
        raw == closure.to_dict(),
        "analysis page-route closure payload or digest is forged",
    )
    return closure


def _tex_page_regions(tex: str, page_numbers: Sequence[int]) -> dict[int, str]:
    marker = re.compile(r"(?m)^% Page (?P<page>[1-9][0-9]*)[ \t]*$")
    matches = list(marker.finditer(tex))
    regions: dict[int, str] = {}
    for index, match in enumerate(matches):
        page = int(match.group("page"))
        _require(page not in regions, "baseline TeX contains duplicate page markers")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(tex)
        regions[page] = tex[match.start():end]
    _require(
        all(page in regions for page in page_numbers),
        "baseline TeX does not contain every admitted source-page marker",
    )
    return {page: regions[page] for page in page_numbers}


def _runtime_page_records(data: bytes, *, expected_run_id: str | None = None) -> tuple[object, ...]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseIntegrityError("OCR runtime page records are not strict JSON") from exc
    wrapper = _require_exact_fields(
        value,
        required={"schema_version", "run_id", "pages"},
        label="OCR runtime page records",
    )
    _require(
        wrapper.get("schema_version") == "latexstruct-ocr-page-records-v1"
        and isinstance(wrapper.get("run_id"), str)
        and bool(str(wrapper["run_id"]).strip())
        and (expected_run_id is None or wrapper["run_id"] == expected_run_id),
        "OCR runtime page-record schema/run binding is invalid",
    )
    try:
        from latexstruct.core.ocr_runtime import OcrPageRecord

        records = tuple(
            OcrPageRecord.from_dict(_require_mapping(row, "OCR runtime page row"))
            for row in _require_list(wrapper.get("pages"), "OCR runtime pages")
        )
    except (ImportError, TypeError, ValueError) as exc:
        raise ReleaseIntegrityError("OCR runtime page records violate OcrPageRecord") from exc
    return records


def _hash_evidence_entries(values: Sequence[object]) -> str:
    # Match ``analysis_risk.build_page_risk_admission`` exactly: evidence is
    # sanitized to one canonical digest per entry before the ordered digest
    # list is bound into the content-free summary.
    return _canonical_json_sha256([
        _canonical_json_sha256(value) for value in values
    ])


def _verify_analysis_page_risk_closure(
    value: object,
    *,
    expected_pages: int,
    source_sha256: str,
    evidence_hashes: Mapping[str, Any],
    page_records_bytes: bytes | None = None,
    runtime_page_records_bytes: bytes | None = None,
    source_pdf_bytes: bytes | None = None,
    baseline_tex_bytes: bytes | None = None,
    baseline_pdf_bytes: bytes | None = None,
    analysis_configuration: Mapping[str, Any] | None = None,
    final_candidate_sha256: str | None = None,
) -> dict[str, Any]:
    """Recompute the v2 risk classifier, sample, and per-page route closure."""

    projected = _require_exact_fields(
        value,
        required={
            "schema_version",
            "admission_sha256",
            "admission",
            "preflight_sha256",
            "preflight",
            "route_closure_sha256",
            "route_closure",
            "page_count",
            "page_ids_sha256",
            "risk_counts",
            "low_risk_sampling",
            "all_preflight_bindings_verified",
            "all_route_bindings_verified",
        },
        label="analysis page-risk admission closure",
    )
    _require(
        projected.get("schema_version") == ANALYSIS_PAGE_RISK_CLOSURE_SCHEMA,
        "analysis page-risk projection schema is unsupported",
    )
    try:
        from latexstruct.core.analysis_risk import (
            PAGE_RISK_CLASSIFIER_POLICY,
            PAGE_RISK_CLASSIFIER_POLICY_SHA256,
            PageRiskPreflightInput,
            build_page_risk_admission,
            coerce_page_risk_admission,
        )
        from latexstruct.core.analysis_schema import PageRisk

        admission = coerce_page_risk_admission(projected.get("admission"))
    except (ImportError, TypeError, ValueError) as exc:
        raise ReleaseIntegrityError("analysis page-risk admission is invalid") from exc
    admission_sha = admission.digest
    _require(
        admission.schema_version == PAGE_RISK_ADMISSION_SCHEMA
        and admission.strategy == PAGE_RISK_ADMISSION_STRATEGY
        and admission.classifier_policy_sha256 == PAGE_RISK_CLASSIFIER_POLICY_SHA256
        and admission.source_pdf_sha256 == source_sha256.lower()
        and admission.ocr_page_records_sha256
        == str(evidence_hashes.get("ocr_page_records_hash") or "").lower()
        and admission.ocr_runtime_page_records_sha256
        == str(evidence_hashes.get("ocr_runtime_page_records_hash") or "").lower()
        and str(projected.get("admission_sha256") or "").lower() == admission_sha
        and str(evidence_hashes.get("page_risk_admission_hash") or "").lower()
        == admission_sha
        and type(projected.get("page_count")) is int
        and projected["page_count"] == expected_pages
        and projected.get("all_preflight_bindings_verified") is True
        and projected.get("all_route_bindings_verified") is True,
        "analysis page-risk admission identity/hash closure is invalid",
    )
    _require(
        len(admission.pages) == expected_pages,
        "analysis page-risk admission does not cover every source page",
    )
    expected_ids = tuple(
        _stable_source_page_id(source_sha256.lower(), page)
        for page in range(1, expected_pages + 1)
    )
    _require(
        tuple(page.summary.source_page_number for page in admission.pages)
        == tuple(range(1, expected_pages + 1))
        and tuple(page.summary.source_page_id for page in admission.pages) == expected_ids,
        "analysis page-risk admission source-page identity/order is invalid",
    )
    page_records: tuple[object, ...] | None = None
    if page_records_bytes is not None:
        _require(
            _sha256_bytes(page_records_bytes)
            == str(evidence_hashes.get("ocr_page_records_hash") or "").lower(),
            "nested OCR PAGE_RECORDS bytes differ from snapshot evidence",
        )
        try:
            from latexstruct.core.ocr_page_evidence import parse_page_records

            ocr_run_id, records_source, page_records = parse_page_records(
                page_records_bytes
            )
        except (ImportError, TypeError, ValueError) as exc:
            raise ReleaseIntegrityError(
                "nested OCR PAGE_RECORDS payload is invalid"
            ) from exc
        _require(
            records_source == source_sha256.lower()
            and len(page_records) == expected_pages,
            "nested OCR PAGE_RECORDS does not cover the analysis source exactly",
        )
    runtime_records: tuple[object, ...] | None = None
    if runtime_page_records_bytes is not None:
        _require(
            _sha256_bytes(runtime_page_records_bytes)
            == str(evidence_hashes.get("ocr_runtime_page_records_hash") or "").lower(),
            "nested OCR RUNTIME_PAGE_RECORDS bytes differ from snapshot evidence",
        )
        runtime_records = _runtime_page_records(
            runtime_page_records_bytes,
            expected_run_id=(ocr_run_id if page_records is not None else None),
        )
        _require(
            len(runtime_records) == expected_pages,
            "nested OCR runtime page records do not cover every source page",
        )
    preflight_root = _require_exact_fields(
        projected.get("preflight"),
        required={
            "schema",
            "source_pdf_sha256",
            "baseline_tex_sha256",
            "baseline_pdf_sha256",
            "ocr_page_records_sha256",
            "ocr_runtime_page_records_sha256",
            "inputs",
            "preflight_sha256",
        },
        label="analysis page-risk preflight",
    )
    preflight_body = {
        key: item
        for key, item in preflight_root.items()
        if key != "preflight_sha256"
    }
    preflight_digest = _canonical_json_sha256(preflight_body)
    _require(
        preflight_root.get("schema")
        == "latexstruct-analysis-risk-preflight-inputs-v2"
        and str(preflight_root.get("source_pdf_sha256") or "").lower()
        == admission.source_pdf_sha256
        and str(preflight_root.get("baseline_tex_sha256") or "").lower()
        == admission.baseline_tex_sha256
        and str(preflight_root.get("baseline_pdf_sha256") or "").lower()
        == admission.baseline_pdf_sha256
        and str(preflight_root.get("ocr_page_records_sha256") or "").lower()
        == admission.ocr_page_records_sha256
        and str(
            preflight_root.get("ocr_runtime_page_records_sha256") or ""
        ).lower()
        == admission.ocr_runtime_page_records_sha256
        and str(preflight_root.get("preflight_sha256") or "").lower()
        == preflight_digest
        and str(projected.get("preflight_sha256") or "").lower()
        == preflight_digest,
        "analysis page-risk preflight root/hash binding is invalid",
    )
    preflight = _require_list(
        preflight_root.get("inputs"), "analysis page-risk preflight inputs"
    )
    _require(
        len(preflight) == expected_pages,
        "analysis page-risk preflight ledger is incomplete",
    )
    preflight_fields = {
        "source_page_id",
        "source_page_number",
        "source_page_object_hash",
        "ocr_page_id",
        "ocr_coverage_checks",
        "unresolved_region_hashes",
        "ocr_final_status",
        "ocr_retry_count",
        "ocr_quality_issues",
        "host_quality_flags",
        "candidate_pdf_page_ids",
        "source_pdf_text_sha256",
        "baseline_tex_region_sha256",
        "machine_visual_anomalies",
        "machine_visual_evidence",
        "double_column",
        "complex_layout",
        "layout_evidence",
        "compile_map_mismatch",
        "compile_map_evidence",
    }
    source_texts: dict[int, str] = {}
    if source_pdf_bytes is not None:
        _require(
            _sha256_bytes(source_pdf_bytes) == admission.source_pdf_sha256,
            "packaged source PDF bytes differ from the page-risk admission",
        )
        try:
            import pymupdf

            with pymupdf.open(stream=source_pdf_bytes, filetype="pdf") as document:
                _require(
                    document.page_count >= expected_pages,
                    "packaged source PDF is shorter than the admitted cohort",
                )
                source_texts = {
                    page: str(document.load_page(page - 1).get_text("text") or "")
                    for page in range(1, expected_pages + 1)
                }
        except (ImportError, RuntimeError, ValueError) as exc:
            raise ReleaseIntegrityError("cannot extract admitted source PDF text") from exc
    baseline_regions: dict[int, str] = {}
    if baseline_tex_bytes is not None:
        _require(
            _sha256_bytes(baseline_tex_bytes) == admission.baseline_tex_sha256,
            "nested OCR baseline TeX bytes differ from the page-risk admission",
        )
        try:
            baseline_tex = baseline_tex_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseIntegrityError("nested OCR baseline TeX is not UTF-8") from exc
        baseline_regions = _tex_page_regions(
            baseline_tex, range(1, expected_pages + 1)
        )
    if baseline_pdf_bytes is not None:
        _require(
            _sha256_bytes(baseline_pdf_bytes) == admission.baseline_pdf_sha256,
            "nested OCR baseline PDF bytes differ from the page-risk admission",
        )
    rebuilt_inputs: list[object] = []
    policy_version_fields = (
        "feature_extractor_version",
        "visual_layout_algorithm_version",
        "machine_visual_algorithm_version",
        "compile_map_algorithm_version",
    )
    for page_number, raw_row in enumerate(preflight, 1):
        row = _require_exact_fields(
            raw_row,
            required=preflight_fields,
            label=f"analysis page-risk preflight page {page_number}",
        )
        checks = _require_exact_fields(
            row.get("ocr_coverage_checks"),
            required=set(OCR_COVERAGE_CHECK_NAMES),
            label=f"analysis page-risk OCR checks {page_number}",
        )
        quality_issues = _require_list(
            row.get("ocr_quality_issues"),
            f"analysis page-risk OCR quality issues {page_number}",
        )
        host_flags = _require_list(
            row.get("host_quality_flags"),
            f"analysis page-risk host quality flags {page_number}",
        )
        anomalies = _require_list(
            row.get("machine_visual_anomalies"),
            f"analysis page-risk visual anomalies {page_number}",
        )
        unresolved = _require_list(
            row.get("unresolved_region_hashes"),
            f"analysis page-risk unresolved regions {page_number}",
        )
        candidate_ids = _require_list(
            row.get("candidate_pdf_page_ids"),
            f"analysis page-risk candidate pages {page_number}",
        )
        layout = _require_mapping(
            row.get("layout_evidence"),
            f"analysis page-risk layout evidence {page_number}",
        )
        machine_visual = _require_mapping(
            row.get("machine_visual_evidence"),
            f"analysis page-risk machine visual evidence {page_number}",
        )
        compile_map = _require_mapping(
            row.get("compile_map_evidence"),
            f"analysis page-risk compile-map evidence {page_number}",
        )
        for evidence_label, evidence in (
            ("layout", layout),
            ("machine visual", machine_visual),
            ("compile map", compile_map),
        ):
            _require(
                all(
                    evidence.get(field) == PAGE_RISK_CLASSIFIER_POLICY[field]
                    for field in policy_version_fields
                ),
                f"analysis page-risk {evidence_label} policy drift on page {page_number}",
            )
        _require(
            row.get("source_page_number") == page_number
            and row.get("source_page_id") == expected_ids[page_number - 1]
            and row.get("ocr_page_id") == f"ocr-page-{page_number:06d}"
            and SHA256_RE.fullmatch(
                str(row.get("source_page_object_hash") or "").lower()
            )
            is not None
            and type(row.get("ocr_retry_count")) is int
            and int(row["ocr_retry_count"]) >= 0
            and all(isinstance(item, Mapping) for item in quality_issues)
            and all(isinstance(item, Mapping) for item in host_flags)
            and all(isinstance(item, Mapping) for item in anomalies)
            and all(SHA256_RE.fullmatch(str(item or "").lower()) for item in unresolved)
            and candidate_ids
            and candidate_ids == sorted(set(candidate_ids))
            and all(re.fullmatch(r"candidate-page-[0-9]{6}", str(item)) for item in candidate_ids)
            and type(row.get("double_column")) is bool
            and type(row.get("complex_layout")) is bool
            and type(row.get("compile_map_mismatch")) is bool,
            f"analysis page-risk preflight identity/facts are invalid on page {page_number}",
        )
        source_text = source_texts.get(page_number)
        baseline_region = baseline_regions.get(page_number)
        if source_text is not None:
            _require(
                _sha256_bytes(source_text.encode("utf-8"))
                == str(row.get("source_pdf_text_sha256") or "").lower(),
                f"analysis page-risk source text digest differs on page {page_number}",
            )
        if baseline_region is not None:
            _require(
                _sha256_bytes(baseline_region.encode("utf-8"))
                == str(row.get("baseline_tex_region_sha256") or "").lower(),
                f"analysis page-risk baseline TeX region differs on page {page_number}",
            )
        admitted_page = admission.pages[page_number - 1]
        summary = admitted_page.summary
        _require(
            summary.source_page_object_hash == row.get("source_page_object_hash")
            and summary.ocr_coverage_hash == _canonical_json_sha256(checks)
            and summary.ocr_coverage_all_pass
            == (bool(checks) and all(value == "PASS" for value in checks.values()))
            and summary.ocr_final_success == (row.get("ocr_final_status") == "SUCCESS")
            and summary.ocr_retry_count == row.get("ocr_retry_count")
            and summary.ocr_quality_issue_count == len(quality_issues)
            and summary.ocr_quality_issues_hash == _hash_evidence_entries(quality_issues)
            and summary.host_quality_flag_count == len(host_flags)
            and summary.host_quality_flags_hash == _hash_evidence_entries(host_flags)
            and summary.machine_visual_anomaly_count == len(anomalies)
            and summary.machine_visual_anomalies_hash == _hash_evidence_entries(anomalies)
            and summary.candidate_page_count == len(candidate_ids)
            and summary.candidate_page_ids_hash == _canonical_json_sha256(candidate_ids)
            and summary.unresolved_region_count == len(unresolved)
            and summary.unresolved_region_hashes_hash == _canonical_json_sha256(unresolved)
            and summary.double_column == row.get("double_column")
            and summary.complex_layout == row.get("complex_layout")
            and summary.compile_map_mismatch == row.get("compile_map_mismatch")
            and summary.layout_evidence_hash == _canonical_json_sha256(layout)
            and summary.compile_map_evidence_hash == _canonical_json_sha256(compile_map),
            f"analysis page-risk summary differs from preflight facts on page {page_number}",
        )
        if page_records is not None:
            page_record = page_records[page_number - 1]
            _require(
                getattr(page_record, "selected_index", None) == page_number
                and getattr(page_record, "source_page_number", None) == page_number
                and getattr(page_record, "page_id", None) == row.get("ocr_page_id")
                and getattr(page_record, "source_sha256", None)
                == source_sha256.lower()
                and getattr(page_record, "source_page_object_hash", None)
                == row.get("source_page_object_hash")
                and page_record.checks.to_dict() == dict(checks)
                and page_record.checks.all_pass is True
                and getattr(page_record, "evidence_complete", False) is True
                and getattr(page_record, "completed", False) is True
                and getattr(page_record, "final_status", None) is not None
                and page_record.final_status.value == row.get("ocr_final_status")
                and list(getattr(page_record, "unresolved_region_hashes", ()))
                == unresolved,
                f"analysis source page {page_number} admission differs from nested OCR PAGE_RECORDS",
            )
        if runtime_records is not None:
            runtime = runtime_records[page_number - 1]
            _require(
                getattr(runtime, "task_index", None) == page_number
                and getattr(runtime, "source_page", None) == page_number
                and getattr(runtime, "page_id", None) == row.get("ocr_page_id")
                and getattr(getattr(runtime, "status", None), "value", None)
                == row.get("ocr_final_status")
                and getattr(runtime, "retry_count", None) == row.get("ocr_retry_count")
                and list(getattr(runtime, "quality_issues", ())) == quality_issues
                and list(getattr(runtime, "host_quality_flags", ())) == host_flags,
                f"analysis source page {page_number} preflight differs from runtime OCR records",
            )
        if source_text is not None and baseline_region is not None:
            rebuilt_inputs.append(PageRiskPreflightInput(
                source_page_id=str(row["source_page_id"]),
                source_page_number=page_number,
                source_page_object_hash=str(row["source_page_object_hash"]),
                ocr_coverage_checks=dict(checks),
                unresolved_region_hashes=tuple(unresolved),
                baseline_tex_region=baseline_region,
                candidate_pdf_page_ids=tuple(str(item) for item in candidate_ids),
                source_pdf_text=source_text,
                ocr_final_status=str(row["ocr_final_status"]),
                ocr_retry_count=int(row["ocr_retry_count"]),
                ocr_quality_issues=tuple(quality_issues),
                host_quality_flags=tuple(host_flags),
                machine_visual_anomalies=tuple(anomalies),
                double_column=bool(row["double_column"]),
                complex_layout=bool(row["complex_layout"]),
                compile_map_mismatch=bool(row["compile_map_mismatch"]),
                layout_evidence=dict(layout),
                compile_map_evidence=dict(compile_map),
            ))
    if rebuilt_inputs:
        try:
            rebuilt = build_page_risk_admission(
                source_pdf_sha256=admission.source_pdf_sha256,
                ocr_page_records_sha256=admission.ocr_page_records_sha256,
                ocr_runtime_page_records_sha256=(
                    admission.ocr_runtime_page_records_sha256
                ),
                baseline_tex_sha256=admission.baseline_tex_sha256,
                baseline_pdf_sha256=admission.baseline_pdf_sha256,
                page_inputs=tuple(rebuilt_inputs),
            )
        except (TypeError, ValueError) as exc:
            raise ReleaseIntegrityError(
                "analysis page-risk admission cannot be rebuilt from frozen inputs"
            ) from exc
        _require(
            rebuilt.to_dict() == admission.to_dict(),
            "analysis page-risk classifier/sampling differs from independently rebuilt inputs",
        )
    page_ids_sha = page_id_sequence_sha256(expected_ids)
    _require(
        str(projected.get("page_ids_sha256") or "").lower() == page_ids_sha,
        "analysis page-risk page-id digest is invalid",
    )
    route = _coerce_page_route_closure(projected.get("route_closure"))
    _require(
        str(projected.get("route_closure_sha256") or "").lower() == route.digest
        and route.admission_sha256 == admission.digest
        and (final_candidate_sha256 is None or route.final_candidate_hash == final_candidate_sha256)
        and tuple(record.source_page_id for record in route.pages) == expected_ids
        and tuple(record.source_page_number for record in route.pages)
        == tuple(range(1, expected_pages + 1)),
        "analysis page-route closure is not bound to the admission/final candidate",
    )
    admitted_by_id = {
        page.summary.source_page_id: page for page in admission.pages
    }
    sampled_ids = set(admission.low_risk_sampling.selected_page_ids)
    for record in route.pages:
        admitted_page = admitted_by_id[record.source_page_id]
        expected_effective = admitted_page.risk_level
        if record.triage_outcome.value == "BLOCKED":
            expected_effective = PageRisk.R3
        elif (
            record.triage_outcome.value == "ANOMALY"
            and admitted_page.risk_level in {PageRisk.R0, PageRisk.R1}
        ):
            expected_effective = PageRisk.R2
        _require(
            record.admitted_risk == admitted_page.risk_level
            and record.effective_risk == expected_effective
            and record.sampled_low_risk == (record.source_page_id in sampled_ids)
            and record.effective_risk is not PageRisk.R3,
            f"analysis page-route risk/sampling is invalid for {record.source_page_id}",
        )
    calls = route.route_call_keys
    _require(
        all(call.succeeded for call in calls)
        and all(ANALYSIS_OPERATION_ROLES.get(call.operation) == call.role for call in calls),
        "analysis page-route call ledger contains a failed or role-mismatched call",
    )

    def successful_pages(role: str, operation: str) -> Counter[str]:
        return Counter(
            call.source_page_id
            for call in calls
            if call.role == role and call.operation == operation and call.succeeded
        )

    all_pages = Counter(expected_ids)
    _require(
        successful_pages("AI-3", "visual-triage") == all_pages,
        "AI-3 visual triage does not cover all 37 pages exactly once",
    )
    for operation in ("final-review-1", "final-review-2"):
        _require(
            successful_pages("AI-5", operation) == all_pages
            and all(
                call.candidate_hash == route.final_candidate_hash
                for call in calls
                if call.role == "AI-5" and call.operation == operation
            ),
            f"AI-5 {operation} does not cover the exact final 37-page candidate",
        )
    ai1_expected: Counter[str] = Counter()
    deep_expected: Counter[str] = Counter()
    recheck_expected: Counter[str] = Counter()
    for record in route.pages:
        if record.effective_risk in {PageRisk.R1, PageRisk.R2} or record.sampled_low_risk:
            ai1_expected[record.source_page_id] = 1
        if record.effective_risk is PageRisk.R2 or record.sampled_low_risk:
            deep_expected[record.source_page_id] = 1
        if record.modified:
            recheck_expected[record.source_page_id] = 1
    _require(
        successful_pages("AI-1", "structure-findings") == ai1_expected
        and successful_pages("AI-2", "content-math-findings") == deep_expected
        and successful_pages("AI-3", "visual-findings") == deep_expected,
        "analysis risk-tier discovery/deep-review routing is incomplete",
    )
    for role, operation in (
        ("AI-1", "structure-recheck"),
        ("AI-2", "content-math-recheck"),
        ("AI-3", "visual-recheck"),
    ):
        _require(
            successful_pages(role, operation) == recheck_expected
            and all(
                call.candidate_hash == route.final_candidate_hash
                for call in calls
                if call.role == role and call.operation == operation
            ),
            f"{role} modified-page recheck closure is incomplete",
        )
    _require(
        projected.get("risk_counts") == route.risk_counts
        and projected.get("low_risk_sampling")
        == admission.low_risk_sampling.canonical_payload(),
        "analysis attested risk counts or low-risk sample differs from typed evidence",
    )
    if analysis_configuration is not None:
        config_map = {
            int(row[0]): tuple(int(page) for page in row[1])
            for row in analysis_configuration["candidate_page_map"]
        }
        for page_number, raw_row in enumerate(preflight, 1):
            row = _require_mapping(raw_row, "analysis preflight row")
            _require(
                row.get("candidate_pdf_page_ids")
                == [
                    f"candidate-page-{page:06d}"
                    for page in config_map[page_number]
                ],
                f"analysis preflight candidate map differs on page {page_number}",
            )
    return dict(projected)


def _verified_nested_ocr_artifact_bytes(
    ocr_dir: Path,
    baseline: Mapping[str, Any],
    *,
    role: str,
) -> bytes:
    """Read one exact artifact after the enclosing OCR package was verified."""

    package_directory = str(baseline.get("package_directory") or "")
    manifest_filename = str(baseline.get("manifest_filename") or "")
    _require(
        package_directory == OCR_BASELINE_PACKAGE_DIRECTORY
        and manifest_filename
        == f"{OCR_BASELINE_PACKAGE_DIRECTORY}/{OCR_BASELINE_MANIFEST_MEMBER}",
        "nested OCR baseline paths are not canonical",
    )
    package_root = ocr_dir / package_directory
    manifest = _load_json(ocr_dir / manifest_filename)
    descriptors = [
        item
        for item in manifest.get("artifacts") or []
        if isinstance(item, Mapping) and item.get("role") == role
    ]
    _require(
        len(descriptors) == 1,
        f"nested OCR baseline must contain exactly one {role} artifact",
    )
    descriptor = _require_exact_fields(
        descriptors[0],
        required={"role", "path", "bytes", "sha256"},
        label=f"nested OCR {role} descriptor",
    )
    relative = _safe_relative_member(descriptor.get("path"))
    path = package_root / relative
    _require(
        path.is_file() and not path.is_symlink(),
        f"nested OCR {role} artifact is missing or unsafe",
    )
    payload = path.read_bytes()
    _require(
        type(descriptor.get("bytes")) is int
        and descriptor["bytes"] == len(payload)
        and str(descriptor.get("sha256") or "").lower() == _sha256_bytes(payload),
        f"nested OCR {role} descriptor differs from its bytes",
    )
    return payload


def _verified_nested_ocr_page_records_bytes(
    ocr_dir: Path, baseline: Mapping[str, Any]
) -> bytes:
    return _verified_nested_ocr_artifact_bytes(
        ocr_dir, baseline, role="PAGE_RECORDS"
    )


def verify_analysis_attestation(
    run_dir: Path,
    *,
    expected_pages: int,
    version: str,
    commit: str,
) -> dict[str, Any]:
    """Verify evidence produced by a real analysis/review acceptance runner.

    This deliberately does not infer or synthesize missing analysis evidence from
    an OCR run.  In particular, PASS requires a VERIFIED terminal state, two
    distinct final-review contexts, and machine verification of the exact compiled
    TeX candidate.
    """

    _require(expected_pages == 37, "stable analysis profile must cover exactly 37 pages")
    _require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None, "invalid version")
    _require(COMMIT_RE.fullmatch(commit.lower()) is not None, "invalid expected commit")
    path = run_dir / "analysis-attestation.json"
    attestation = _load_json(path)
    root = _require_exact_fields(
        attestation,
        required={
            "schema_version",
            "profile_kind",
            "profile",
            "result",
            "acceptance_passed",
            "terminal_status",
            "quality_tier",
            "template",
            "generated_at",
            "execution",
            "runtime_identity",
            "service_binding",
            "snapshot_binding",
            "page_risk_admission",
            "source",
            "selected_range",
            "models",
            "compilation",
            "artifacts",
            "timing",
            "ocr_prerequisite",
            "independent_final_reviews",
            "visual_verification",
            "page_layout",
            "machine_verification",
            "audit_submission",
            "reports",
        },
        label="analysis attestation",
    )
    _require(root.get("schema_version") == ANALYSIS_ATTESTATION_SCHEMA, "unsupported analysis attestation schema")
    _require(root.get("profile_kind") == "analysis", "attestation is not an analysis profile")
    _require(root.get("profile") == f"analysis-{expected_pages}", "analysis profile/page mismatch")
    _require(root.get("result") == "PASS", "analysis attestation is not PASS")
    _require(root.get("acceptance_passed") is True, "analysis acceptance did not pass")
    _require(
        root.get("terminal_status") == "VERIFIED",
        "analysis PASS requires terminal_status VERIFIED",
    )
    _require(root.get("quality_tier") == "high", "analysis-37 requires quality tier high")
    _require(root.get("template") == "faithfulbook", "analysis-37 requires faithfulbook")
    _require(bool(str(root.get("generated_at") or "").strip()), "analysis generation time is missing")

    execution = _require_exact_fields(
        root.get("execution"),
        required={
            "real_execution",
            "test_double",
            "simulated",
            "api_client",
            "ui_driver",
            "workflow",
            "producer",
        },
        label="analysis execution evidence",
    )
    _require(execution.get("real_execution") is True, "test-double analysis execution cannot release")
    _require(execution.get("test_double") is False, "test-double analysis execution cannot release")
    _require(execution.get("simulated") is False, "simulated analysis execution cannot release")
    _require(execution.get("api_client") == "LocalHttpApi", "analysis did not use LocalHttpApi")
    _require(execution.get("ui_driver") == "PlaywrightUiDriver", "analysis did not use PlaywrightUiDriver")
    _require(execution.get("workflow") == "OCR_ANALYSIS_REVIEW", "unexpected analysis workflow")
    producer = str(execution.get("producer") or "").strip()
    _require(bool(producer), "analysis producer is missing")
    _require(
        re.search(r"(?i)(?:fake|stub|mock|pytest|test[-_ ]?double)", producer) is None,
        "test substitute cannot mint a release PASS",
    )

    runtime = _require_exact_fields(
        root.get("runtime_identity"),
        required={
            "version",
            "commit",
            "build_id",
            "executable_filename",
            "executable_sha256",
        },
        label="analysis runtime identity",
    )
    _require(str(runtime.get("version") or "") == version, "analysis version mismatch")
    _require(str(runtime.get("commit") or "").lower() == commit.lower(), "analysis tested commit mismatch")
    _require(
        GITHUB_RUN_ID_RE.fullmatch(str(runtime.get("build_id") or "").strip())
        is not None,
        "analysis build id must be a numeric GitHub Actions run id",
    )
    _require(Path(str(runtime.get("executable_filename") or "")).name == "LaTeXStruct.exe", "analysis executable filename is invalid")
    _require(
        SHA256_RE.fullmatch(str(runtime.get("executable_sha256") or "").lower()) is not None,
        "analysis executable SHA-256 is missing",
    )
    service_binding = _require_exact_fields(
        root.get("service_binding"),
        required={"verified", "pid", "process_image_filename", "process_image_sha256", "listener_port", "listener_pid", "listener_pid_verified", "listener_image_filename", "listener_image_sha256"},
        label="candidate service executable binding",
    )
    _require(
        service_binding.get("verified") is True
        and int(service_binding.get("pid") or 0) > 0
        and service_binding.get("process_image_filename") == "LaTeXStruct.exe"
        and str(service_binding.get("process_image_sha256") or "").lower()
        == str(runtime.get("executable_sha256") or "").lower()
        and 0 < int(service_binding.get("listener_port") or 0) <= 65535
        and int(service_binding.get("listener_pid") or 0) > 0
        and service_binding.get("listener_pid_verified") is True
        and service_binding.get("listener_image_filename") == "LaTeXStruct.exe"
        and str(service_binding.get("listener_image_sha256") or "").lower()
        == str(runtime.get("executable_sha256") or "").lower(),
        "candidate service process is not bound to the tested executable bytes",
    )
    snapshot_binding = _require_exact_fields(
        root.get("snapshot_binding"),
        required={
            "snapshot_hash",
            "prompt_version",
            "response_schema_hash",
            "evidence_hashes",
            "model_bindings",
            "model_bindings_sha256",
            "transport_contracts_sha256",
            "analysis_configuration",
            "analysis_configuration_sha256",
            "release_model_policy",
            "transport_invocation_count",
            "transport_closure",
            "all_transport_bindings_verified",
        },
        label="analysis snapshot binding",
    )
    snapshot_evidence_hashes = _require_exact_fields(
        snapshot_binding.get("evidence_hashes"),
        required=set(ANALYSIS_EVIDENCE_HASH_FIELDS),
        label="analysis snapshot evidence hashes",
    )
    _require(
        SHA256_RE.fullmatch(
            str(snapshot_binding.get("snapshot_hash") or "").lower()
        )
        is not None
        and bool(str(snapshot_binding.get("prompt_version") or "").strip())
        and SHA256_RE.fullmatch(
            str(snapshot_binding.get("response_schema_hash") or "").lower()
        )
        is not None
        and all(
            SHA256_RE.fullmatch(str(value or "").lower()) is not None
            for value in snapshot_evidence_hashes.values()
        )
        and snapshot_binding.get("response_schema_hash")
        == snapshot_evidence_hashes.get("response_schema_hash")
        and SHA256_RE.fullmatch(
            str(snapshot_binding.get("model_bindings_sha256") or "").lower()
        )
        is not None
        and SHA256_RE.fullmatch(
            str(snapshot_binding.get("transport_contracts_sha256") or "").lower()
        )
        is not None
        and str(snapshot_binding.get("model_bindings_sha256") or "").lower()
        == _canonical_json_sha256(snapshot_binding.get("model_bindings"))
        and type(snapshot_binding.get("transport_invocation_count")) is int
        and int(snapshot_binding["transport_invocation_count"]) > 0
        and snapshot_binding.get("all_transport_bindings_verified") is True,
        "analysis snapshot/transport binding is incomplete",
    )
    _verify_analysis_transport_closure(
        snapshot_binding.get("transport_closure"),
        expected_invocations=int(snapshot_binding["transport_invocation_count"]),
        model_bindings=snapshot_binding.get("model_bindings"),
        expected_contracts_sha256=str(
            snapshot_binding.get("transport_contracts_sha256") or ""
        ),
    )
    raw_page_risk_projection = _require_mapping(
        root.get("page_risk_admission"), "analysis page-risk projection"
    )
    raw_admission = _require_mapping(
        raw_page_risk_projection.get("admission"), "analysis page-risk admission"
    )
    analysis_configuration = _verify_analysis_configuration(
        snapshot_binding.get("analysis_configuration"),
        claimed_sha256=snapshot_binding.get("analysis_configuration_sha256"),
        expected_pages=expected_pages,
        admission=raw_admission,
        model_bindings=snapshot_binding.get("model_bindings"),
        expected_contracts_sha256=str(
            snapshot_binding.get("transport_contracts_sha256") or ""
        ),
        snapshot_config_sha256=str(
            snapshot_evidence_hashes.get("analysis_config_hash") or ""
        ),
    )
    release_model_policy = _verify_analysis_release_model_policy(
        snapshot_binding.get("release_model_policy"),
        model_bindings=snapshot_binding.get("model_bindings"),
        transport_contracts=analysis_configuration.get("transport_contracts"),
    )

    source = _require_exact_fields(
        root.get("source"),
        required={"filename", "sha256", "total_pages"},
        label="analysis source evidence",
    )
    source_name = _safe_relative_member(source.get("filename"))
    _require(source_name.suffix.lower() == ".pdf", "analysis source must be a PDF")
    _require(
        str(source.get("sha256") or "").lower() == RAMSEY_37_SOURCE_SHA256,
        "analysis-37 source PDF SHA-256 mismatch",
    )
    _require(
        int(source.get("total_pages") or 0) == expected_pages,
        "analysis-37 must use the exact 37-page source PDF",
    )
    selected = _require_exact_fields(
        root.get("selected_range"),
        required={"start_page", "end_page", "expected_pages"},
        label="analysis selected range",
    )
    _require(
        int(selected.get("start_page") or 0) == 1
        and int(selected.get("end_page") or 0) == expected_pages
        and int(selected.get("expected_pages") or 0) == expected_pages,
        f"analysis attestation does not cover pages 1-{expected_pages}",
    )

    ocr_prerequisite = _require_exact_fields(
        root.get("ocr_prerequisite"),
        required={
            "profile",
            "attestation_filename",
            "attestation_sha256",
            "result",
            "acceptance_passed",
            "successful_pages",
            "source_sha256",
            "run_id",
            "baseline_manifest_sha256",
            "runtime_identity",
            "selected_range",
        },
        label="nested OCR prerequisite",
    )
    _require(ocr_prerequisite.get("profile") == "ocr-37", "nested OCR profile is not ocr-37")
    ocr_relative = _safe_relative_member(ocr_prerequisite.get("attestation_filename"))
    _require(
        ocr_relative == Path("ocr-prerequisite") / "acceptance-attestation.json",
        "nested OCR attestation path is not canonical",
    )
    ocr_path = run_dir / ocr_relative
    ocr_digest = str(ocr_prerequisite.get("attestation_sha256") or "").lower()
    _require(
        ocr_path.is_file()
        and SHA256_RE.fullmatch(ocr_digest) is not None
        and _sha256_file(ocr_path) == ocr_digest,
        "nested OCR attestation digest mismatch",
    )
    _require(
        ocr_prerequisite.get("result") == "PASS"
        and ocr_prerequisite.get("acceptance_passed") is True
        and int(ocr_prerequisite.get("successful_pages") or 0) == expected_pages
        and str(ocr_prerequisite.get("source_sha256") or "").lower()
        == RAMSEY_37_SOURCE_SHA256,
        "nested OCR prerequisite summary is not a 37-page PASS",
    )
    _require(
        ocr_prerequisite.get("runtime_identity") == runtime
        and ocr_prerequisite.get("selected_range") == selected,
        "nested OCR prerequisite summary is not bound to the analysis runtime/range",
    )
    verified_ocr = verify_run_attestation(
        ocr_path.parent,
        expected_pages=expected_pages,
        version=version,
        commit=commit,
        expected_source_sha256=RAMSEY_37_SOURCE_SHA256,
    )
    _require(
        verified_ocr.get("runtime_identity") == runtime,
        "nested OCR prerequisite tested a different commit/build/executable",
    )
    verified_ocr_baseline = verified_ocr.get("ocr_baseline")
    _require(
        isinstance(verified_ocr_baseline, Mapping)
        and ocr_prerequisite.get("run_id")
        == verified_ocr_baseline.get("run_id")
        and str(ocr_prerequisite.get("baseline_manifest_sha256") or "").lower()
        == str(verified_ocr_baseline.get("manifest_sha256") or "").lower(),
        "nested OCR prerequisite is not bound to the exact recomputable baseline",
    )
    page_records_bytes = _verified_nested_ocr_page_records_bytes(
        ocr_path.parent, verified_ocr_baseline
    )
    runtime_page_records_bytes = _verified_nested_ocr_artifact_bytes(
        ocr_path.parent,
        verified_ocr_baseline,
        role="RUNTIME_PAGE_RECORDS",
    )
    source_pdf_bytes = _verified_nested_ocr_artifact_bytes(
        ocr_path.parent,
        verified_ocr_baseline,
        role="SOURCE",
    )
    baseline_tex_bytes = _verified_nested_ocr_artifact_bytes(
        ocr_path.parent,
        verified_ocr_baseline,
        role="BASELINE_TEX",
    )
    baseline_pdf_bytes = _verified_nested_ocr_artifact_bytes(
        ocr_path.parent,
        verified_ocr_baseline,
        role="BASELINE_PDF",
    )
    _verify_analysis_page_risk_closure(
        root.get("page_risk_admission"),
        expected_pages=expected_pages,
        source_sha256=str(source.get("sha256") or "").lower(),
        evidence_hashes=snapshot_evidence_hashes,
        page_records_bytes=page_records_bytes,
        runtime_page_records_bytes=runtime_page_records_bytes,
        source_pdf_bytes=source_pdf_bytes,
        baseline_tex_bytes=baseline_tex_bytes,
        baseline_pdf_bytes=baseline_pdf_bytes,
        analysis_configuration=analysis_configuration,
        final_candidate_sha256=str(
            _require_mapping(root.get("compilation"), "analysis compilation").get(
                "candidate_tex_sha256"
            )
            or ""
        ).lower(),
    )
    recomputed_ocr_hashes = _require_exact_fields(
        verified_ocr_baseline.get("recomputed_evidence_hashes"),
        required={
            "ocr_baseline_manifest_hash",
            "ocr_page_records_hash",
            "ocr_runtime_page_records_hash",
            "ocr_page_map_hash",
            "ocr_baseline_compile_inputs_hash",
        },
        label="nested OCR recomputed snapshot hashes",
    )
    for name, digest in recomputed_ocr_hashes.items():
        _require(
            str(snapshot_evidence_hashes.get(name) or "").lower()
            == str(digest or "").lower(),
            f"analysis snapshot {name} differs from the recomputed nested OCR package",
        )
    _require(
        str(snapshot_evidence_hashes.get("ocr_baseline_manifest_hash") or "").lower()
        == str(verified_ocr_baseline.get("manifest_sha256") or "").lower(),
        "analysis snapshot OCR manifest hash differs from nested OCR attestation",
    )
    ocr_producer = _require_exact_fields(
        verified_ocr_baseline.get("ocr_producer"),
        required={
            "schema_version",
            "app_version",
            "git_commit",
            "build_id",
            "ocr_model",
            "verification_model",
            "prompt_version",
            "api_backend",
        },
        label="nested OCR producer identity",
    )
    expected_build_identity_hash = _canonical_json_sha256({
        "schema": "latexstruct-analysis-build-identity-v1",
        "ocr_producer": dict(ocr_producer),
        "analysis_runtime": {
            "app_version": version,
            "build_id": str(runtime.get("build_id") or ""),
            "commit": str(runtime.get("commit") or "").lower(),
            "prompt_version": str(snapshot_binding.get("prompt_version") or ""),
        },
    })
    _require(
        str(snapshot_evidence_hashes.get("build_identity_hash") or "").lower()
        == expected_build_identity_hash,
        "analysis snapshot build identity differs from nested OCR/current runtime",
    )
    _require(verified_ocr.get("source") == source, "nested OCR source differs from analysis")
    _require(
        verified_ocr.get("selected_range") == selected,
        "nested OCR selected range differs from analysis",
    )

    models = _require_exact_fields(
        root.get("models"),
        required={"calls_total", "roles"},
        label="analysis model evidence",
    )
    roles = models.get("roles")
    _require(isinstance(roles, list) and bool(roles), "analysis model roles are missing")
    role_calls = 0
    declared_review_calls = 0
    review_model_pairs: set[tuple[str, str]] = set()
    allowed_roles = {"structure", "analysis", "review", "visual_review"}
    for index, value in enumerate(roles, start=1):
        role = _require_exact_fields(
            value,
            required={"role", "model_id", "backend", "calls"},
            label=f"analysis model role {index}",
        )
        _require(role.get("role") in allowed_roles, f"unsupported analysis model role {index}")
        _require(
            role.get("model_id")
            == release_model_policy.get("declared_model_id"),
            f"analysis model id {index} differs from the declared release policy",
        )
        _require(
            role.get("backend") == "codex_cli",
            f"analysis model backend {index} is not the declared Codex runtime",
        )
        calls = int(role.get("calls") or 0)
        _require(calls > 0, f"analysis model role {index} has no real calls")
        role_calls += calls
        if role.get("role") in {"review", "visual_review"}:
            declared_review_calls += calls
            review_model_pairs.add(
                (str(role.get("model_id")), str(role.get("backend")))
            )
    _require(int(models.get("calls_total") or 0) == role_calls > 0, "analysis model call total is invalid")
    _require(
        int(snapshot_binding.get("transport_invocation_count") or 0) == role_calls,
        "analysis snapshot binding does not cover every model invocation",
    )

    compilation = _require_exact_fields(
        root.get("compilation"),
        required={
            "status",
            "successful_passes",
            "pass_exit_codes",
            "compile_log_sha256",
            "candidate_tex_sha256",
            "candidate_pdf_sha256",
        },
        label="analysis compilation evidence",
    )
    _require(compilation.get("status") == "COMPILED", "analysis candidate was not truly compiled")
    _require(int(compilation.get("successful_passes") or 0) >= 2, "analysis candidate lacks two successful compile passes")
    pass_exit_codes = compilation.get("pass_exit_codes")
    _require(
        isinstance(pass_exit_codes, list)
        and len(pass_exit_codes) >= 2
        and all(code == 0 for code in pass_exit_codes),
        "analysis double-pass compilation did not exit cleanly",
    )
    for field in (
        "compile_log_sha256",
        "candidate_tex_sha256",
        "candidate_pdf_sha256",
    ):
        _require(
            SHA256_RE.fullmatch(str(compilation.get(field) or "").lower()) is not None,
            f"analysis compilation is missing {field}",
        )
    candidate_sha = str(compilation.get("candidate_tex_sha256")).lower()

    artifact_root = _require_exact_fields(
        root.get("artifacts"),
        required=set(ANALYSIS_ARTIFACT_SPECS),
        label="analysis artifact bindings",
    )
    verified_artifacts: dict[str, dict[str, Any]] = {}
    for role, (filename, compilation_field) in ANALYSIS_ARTIFACT_SPECS.items():
        record = _verify_artifact_reference(run_dir, artifact_root.get(role), filename)
        _require(
            record["sha256"]
            == str(compilation.get(compilation_field) or "").lower(),
            f"analysis artifact digest differs from compilation evidence: {filename}",
        )
        verified_artifacts[role] = record

    timing = _require_exact_fields(
        root.get("timing"),
        required={
            "measurement",
            "started_at",
            "ended_at",
            "wall_time_seconds",
            "timed_out",
            "completed_terminal_run",
        },
        label="analysis timing evidence",
    )
    _require("before browser upload/start click" in str(timing.get("measurement") or ""), "analysis timing did not start before the UI click")
    _require(bool(str(timing.get("started_at") or "").strip()), "analysis start time is missing")
    _require(bool(str(timing.get("ended_at") or "").strip()), "analysis end time is missing")
    _require(float(timing.get("wall_time_seconds") or 0) > 0, "analysis wall time is missing")
    _require(timing.get("timed_out") is False, "timed-out analysis is incomplete")
    _require(timing.get("completed_terminal_run") is True, "analysis did not reach a terminal state")

    reviews = root.get("independent_final_reviews")
    _require(isinstance(reviews, list) and len(reviews) == 2, "analysis requires exactly two independent final reviews")
    review_ids: set[str] = set()
    context_ids: set[str] = set()
    context_hashes: set[str] = set()
    observed_review_calls = 0
    for index, value in enumerate(reviews, start=1):
        review = _require_exact_fields(
            value,
            required={
                "pass_number",
                "review_id",
                "context_id",
                "context_sha256",
                "independent",
                "result",
                "candidate_tex_sha256",
                "pages_checked",
                "expected_page_ids",
                "checked_page_ids",
                "checked_page_ids_sha256",
                "model_id",
                "backend",
                "calls",
            },
            label=f"independent final review {index}",
        )
        review_id = str(review.get("review_id") or "").strip()
        context_id = str(review.get("context_id") or "").strip()
        context_sha = str(review.get("context_sha256") or "").lower()
        expected_page_ids = review.get("expected_page_ids")
        checked_page_ids = review.get("checked_page_ids")
        checked_digest = str(review.get("checked_page_ids_sha256") or "").lower()
        _require(bool(review_id) and review_id not in review_ids, "final-review ids must be distinct")
        _require(bool(context_id) and context_id not in context_ids, "final reviews must use distinct context ids")
        _require(SHA256_RE.fullmatch(context_sha) is not None and context_sha not in context_hashes, "final reviews must use distinct context hashes")
        review_ids.add(review_id)
        context_ids.add(context_id)
        context_hashes.add(context_sha)
        _require(review.get("independent") is True, f"final review {index} is not independent")
        _require(review.get("result") == "PASS", f"final review {index} did not PASS")
        _require(
            review.get("pass_number") == index,
            "final-review pass numbers are not canonical",
        )
        _require(str(review.get("candidate_tex_sha256") or "").lower() == candidate_sha, f"final review {index} checked a different candidate")
        _require(int(review.get("pages_checked") or 0) == expected_pages, f"final review {index} page coverage mismatch")
        _require(
            isinstance(expected_page_ids, list)
            and isinstance(checked_page_ids, list)
            and len(expected_page_ids) == expected_pages
            and checked_page_ids == expected_page_ids
            and len(set(expected_page_ids)) == expected_pages,
            f"final review {index} checked_page_ids differ from expected_page_ids",
        )
        recomputed_page_digest = page_id_sequence_sha256(checked_page_ids)
        _require(
            checked_digest == recomputed_page_digest,
            f"final review {index} page-id digest mismatch",
        )
        _require(
            context_sha == review_context_sha256(
                pass_number=index,
                context_id=context_id,
                candidate_tex_sha256=candidate_sha,
                checked_page_ids=checked_page_ids,
            ),
            f"final review {index} context digest mismatch",
        )
        _require(bool(str(review.get("model_id") or "").strip()), f"final review {index} model id is missing")
        _require(bool(str(review.get("backend") or "").strip()), f"final review {index} backend is missing")
        review_calls = int(review.get("calls") or 0)
        _require(review_calls > 0, f"final review {index} has no real model calls")
        _require(
            (str(review.get("model_id")), str(review.get("backend")))
            in review_model_pairs,
            f"final review {index} is not bound to a declared review model",
        )
        observed_review_calls += review_calls
    _require(
        observed_review_calls <= declared_review_calls,
        "final-review calls exceed the declared real review-model calls",
    )

    visual = _require_exact_fields(
        root.get("visual_verification"),
        required={
            "passed",
            "expected_pages",
            "pages_checked",
            "independent_review_passes",
            "model_calls",
            "page_id_set_sha256",
            "candidate_tex_sha256",
            "candidate_pdf_sha256",
            "render_compare_closed_loop",
            "closed_loop_evidence",
        },
        label="full-page visual verification",
    )
    _require(visual.get("passed") is True, "full-page visual verification did not pass")
    _require(
        int(visual.get("expected_pages") or 0) == expected_pages
        and int(visual.get("pages_checked") or 0) == expected_pages,
        "full-page visual verification does not cover pages 1-37",
    )
    _require(
        int(visual.get("independent_review_passes") or 0) == 2
        and int(visual.get("model_calls") or 0) == expected_pages * 2,
        "full-page visual verification lacks two one-call-per-page review passes",
    )
    _require(
        str(visual.get("page_id_set_sha256") or "").lower()
        == page_id_sequence_sha256(reviews[0]["expected_page_ids"])
        and all(
            review["expected_page_ids"] == reviews[0]["expected_page_ids"]
            for review in reviews
        ),
        "visual page-id coverage digest is not bound to both review scopes",
    )
    _require(
        str(visual.get("candidate_tex_sha256") or "").lower() == candidate_sha
        and str(visual.get("candidate_pdf_sha256") or "").lower()
        == str(compilation.get("candidate_pdf_sha256") or "").lower(),
        "visual verification checked different candidate bytes",
    )
    closed_loop = verify_render_compare_closed_loop(
        visual.get("closed_loop_evidence")
    )
    _require(
        visual.get("render_compare_closed_loop") is True
        and closed_loop.get("final_review_context_sha256s")
        == [str(review["context_sha256"]).lower() for review in reviews]
        and closed_loop.get("final_candidate_tex_sha256") == candidate_sha
        and closed_loop.get("final_candidate_pdf_sha256")
        == str(compilation.get("candidate_pdf_sha256") or "").lower(),
        "compile-render-compare-fix-recompile loop evidence is inconsistent",
    )

    page_layout = _require_exact_fields(
        root.get("page_layout"),
        required={
            "source_page_count",
            "candidate_page_count",
            "minimum_candidate_pages",
            "maximum_candidate_pages",
            "page_growth",
            "candidate_only_pages",
            "candidate_mapping_sha256",
            "candidate_mapping",
            "no_abnormal_page_inflation",
            "active_tableofcontents_count",
            "template",
        },
        label="analysis-37 final page-layout evidence",
    )
    candidate_page_count = int(page_layout.get("candidate_page_count") or 0)
    candidate_only_pages = page_layout.get("candidate_only_pages")
    _require(
        int(page_layout.get("source_page_count") or 0) == 37
        and MIN_ANALYSIS_37_CANDIDATE_PAGES
        <= candidate_page_count
        <= MAX_ANALYSIS_37_CANDIDATE_PAGES
        and int(page_layout.get("minimum_candidate_pages") or 0)
        == MIN_ANALYSIS_37_CANDIDATE_PAGES
        and int(page_layout.get("maximum_candidate_pages") or 0)
        == MAX_ANALYSIS_37_CANDIDATE_PAGES
        and int(page_layout.get("page_growth") or 0) == candidate_page_count - 37
        and int(page_layout.get("page_growth") or 0) >= -5
        and int(page_layout.get("page_growth") or 0) <= 5,
        "analysis-37 final PDF has abnormal page inflation",
    )
    _require(
        _pdf_page_count(run_dir / "candidate.pdf") == candidate_page_count,
        "analysis-37 candidate PDF page count differs from the declared layout evidence",
    )
    _require(
        isinstance(candidate_only_pages, list)
        and len(candidate_only_pages) == len(set(candidate_only_pages))
        and all(
            isinstance(page, int) and 1 <= page <= candidate_page_count
            for page in candidate_only_pages
        )
        ,
        "analysis-37 candidate-only page mapping is invalid",
    )
    verified_mapping = verify_candidate_page_mapping(
        page_layout.get("candidate_mapping"),
        expected_source_pages=37,
        expected_candidate_pages=candidate_page_count,
        expected_candidate_tex_sha256=candidate_sha,
        expected_candidate_pdf_sha256=str(
            compilation.get("candidate_pdf_sha256") or ""
        ).lower(),
    )
    _require(
        list(candidate_only_pages) == verified_mapping["candidate_only_pages"]
        and str(page_layout.get("candidate_mapping_sha256") or "").lower()
        == verified_mapping["mapping_sha256"],
        "analysis-37 page-layout projection differs from its recomputed mapping",
    )
    _require(
        page_layout.get("no_abnormal_page_inflation") is True
        and int(page_layout.get("active_tableofcontents_count") or 0) == 1
        and page_layout.get("template") == "faithfulbook",
        "analysis-37 layout/automatic-TOC gate did not pass",
    )

    machine = _require_exact_fields(
        root.get("machine_verification"),
        required={
            "passed",
            "candidate_tex_sha256",
            "pages_checked",
            "silent_omissions",
            "text_loss",
            "unauthorized_math_changes",
            "unclosed_formal_environments",
            "open_critical_issues",
            "open_high_issues",
            "regressions",
            "verification_json_sha256",
        },
        label="analysis machine verification",
    )
    _require(machine.get("passed") is True, "analysis machine verification did not pass")
    _require(str(machine.get("candidate_tex_sha256") or "").lower() == candidate_sha, "machine verification checked a different candidate")
    _require(int(machine.get("pages_checked") or 0) == expected_pages, "machine verification page coverage mismatch")
    for field in (
        "silent_omissions",
        "text_loss",
        "unauthorized_math_changes",
        "unclosed_formal_environments",
        "open_critical_issues",
        "open_high_issues",
        "regressions",
    ):
        _require(int(machine.get(field) or 0) == 0, f"machine verification found {field}")
    _require(
        SHA256_RE.fullmatch(str(machine.get("verification_json_sha256") or "").lower()) is not None,
        "machine verification JSON digest is missing",
    )

    audit = _require_exact_fields(
        root.get("audit_submission"),
        required={
            "filename",
            "bytes",
            "sha256",
            "packaging_status",
            "audit_package_status",
            "verification_status",
            "published_to_github",
        },
        label="AI audit submission binding",
    )
    audit_relative = _safe_relative_member(audit.get("filename"))
    _require(
        audit_relative == Path("analysis-audit-submission.zip"),
        "AI audit submission filename is not canonical",
    )
    audit_path = run_dir / audit_relative
    audit_bytes = audit.get("bytes")
    audit_sha = str(audit.get("sha256") or "").lower()
    _require(
        isinstance(audit_bytes, int)
        and not isinstance(audit_bytes, bool)
        and audit_bytes > 0
        and audit_path.is_file()
        and audit_path.stat().st_size == audit_bytes
        and SHA256_RE.fullmatch(audit_sha) is not None
        and _sha256_file(audit_path) == audit_sha,
        "AI audit submission bytes or SHA-256 do not match",
    )
    _require(
        audit.get("packaging_status") == "SUCCESS"
        and audit.get("audit_package_status") == "VALID"
        and audit.get("verification_status") == "VERIFIED",
        "AI audit submission is not a verified VALID package",
    )
    _require(
        audit.get("published_to_github") is False,
        "private AI audit submission must not be marked for GitHub publication",
    )

    reports = _require_exact_fields(
        root.get("reports"),
        required={"performance", "validation", "verification"},
        label="analysis report bindings",
    )
    performance = _verify_report_reference(
        run_dir, reports.get("performance"), "analysis-performance.json"
    )
    validation = _verify_report_reference(
        run_dir, reports.get("validation"), "analysis-validation-report.json"
    )
    verification = _verify_report_reference(
        run_dir, reports.get("verification"), "analysis-machine-verification.json"
    )
    _require(performance.get("schema_version") == ANALYSIS_PERFORMANCE_SCHEMA, "unsupported analysis performance schema")
    _require(validation.get("schema_version") == ANALYSIS_VALIDATION_SCHEMA, "unsupported analysis validation schema")
    _require(
        verification.get("schema_version") == ANALYSIS_MACHINE_VERIFICATION_SCHEMA,
        "unsupported analysis machine-verification schema",
    )
    for report_name, report in (("performance", performance), ("validation", validation)):
        _require(report.get("result") == "PASS", f"analysis {report_name} report is not PASS")
        _require(report.get("acceptance_passed") is True, f"analysis {report_name} acceptance did not pass")
        _require(report.get("runtime_identity") == runtime, f"analysis runtime identity differs in {report_name} report")
        _require(report.get("source") == source, f"analysis source differs in {report_name} report")
    _require(performance.get("selected_range") == selected, "analysis selected range differs in performance report")
    _require(performance.get("models") == models, "analysis model evidence differs in performance report")
    _require(performance.get("compilation") == compilation, "analysis compilation evidence differs in performance report")
    _require(performance.get("timing") == timing, "analysis timing evidence differs in performance report")
    performance_thresholds = _require_exact_fields(
        performance.get("thresholds"),
        required={"maximum_wall_time_seconds"},
        label="analysis-37 performance thresholds",
    )
    _require(
        performance_thresholds.get("maximum_wall_time_seconds") is None
        and performance.get("target_status") == "NOT_EVALUATED"
        and performance.get("target_met") is None,
        "analysis-37 performance target must remain NOT_EVALUATED with target_met null",
    )
    _require(validation.get("execution") == execution, "analysis execution evidence differs in validation report")
    _require(validation.get("terminal_status") == "VERIFIED", "analysis validation terminal state is not VERIFIED")
    _require(validation.get("independent_final_reviews") == reviews, "final-review evidence differs in validation report")
    _require(validation.get("machine_verification") == machine, "machine verification differs in validation report")
    _require(
        str(machine.get("verification_json_sha256") or "").lower()
        == _sha256_file(run_dir / "analysis-machine-verification.json"),
        "machine verification JSON digest mismatch",
    )
    _require(verification.get("result") == "PASS", "machine-verification report is not PASS")
    for field in (
        "candidate_tex_sha256",
        "pages_checked",
        "silent_omissions",
        "text_loss",
        "unauthorized_math_changes",
        "unclosed_formal_environments",
        "open_critical_issues",
        "open_high_issues",
        "regressions",
    ):
        _require(
            verification.get(field) == machine.get(field),
            f"machine-verification report differs for {field}",
        )
    # Return normalized artifact bindings so callers that assemble a release
    # cannot accidentally copy a producer-supplied, non-canonical path.
    attestation["artifacts"] = verified_artifacts
    return attestation


def assemble_release_attestation(
    *,
    version: str,
    commit: str,
    run_dirs: Mapping[str, Path],
    output: Path,
) -> dict[str, Any]:
    normalized_commit = str(commit or "").strip().lower()
    _require(COMMIT_RE.fullmatch(normalized_commit) is not None, "invalid release commit")
    _require(
        set(run_dirs) == {"analysis-37"},
        "stable release requires exactly one strict analysis-37 run; "
        "its nested ocr-37 prerequisite is mandatory",
    )
    source_dir = run_dirs["analysis-37"]
    verified = verify_analysis_attestation(
        source_dir,
        expected_pages=37,
        version=version,
        commit=normalized_commit,
    )
    runtime = dict(verified["runtime_identity"])
    projection = {
        "profile": "analysis-37",
        "analysis_attestation_sha256": _sha256_file(
            source_dir / "analysis-attestation.json"
        ),
        "result": verified["result"],
        "acceptance_passed": verified["acceptance_passed"],
        "terminal_status": verified["terminal_status"],
        "quality_tier": verified["quality_tier"],
        "template": verified["template"],
        "execution": verified["execution"],
        "runtime_identity": runtime,
        "service_binding": verified["service_binding"],
        "snapshot_binding": verified["snapshot_binding"],
        "page_risk_admission": verified["page_risk_admission"],
        "source": verified["source"],
        "selected_range": verified["selected_range"],
        "models": verified["models"],
        "compilation": verified["compilation"],
        "artifacts": verified["artifacts"],
        "ocr_prerequisite": verified["ocr_prerequisite"],
        "independent_final_reviews": verified["independent_final_reviews"],
        "visual_verification": verified["visual_verification"],
        "page_layout": verified["page_layout"],
        "machine_verification": verified["machine_verification"],
        "audit_submission": verified["audit_submission"],
        "reports": verified["reports"],
    }
    payload = {
        "schema_version": RELEASE_ATTESTATION_SCHEMA,
        "version": version,
        "commit": normalized_commit,
        "required_profiles": list(PROFILE_SPECS),
        "runtime_identity": runtime,
        "tested_executable_sha256": str(runtime["executable_sha256"]).lower(),
        "source": dict(verified["source"]),
        "performance_claim": _analysis_37_performance_claim(
            verified["reports"]["performance"]
        ),
        "verification": {
            "profile_count": 1,
            "all_profiles_passed": True,
            "ocr_prerequisite_passed": True,
            "analysis_terminal_status": "VERIFIED",
            "visual_pages_checked": 37,
            "independent_review_passes": 2,
            "audit_package_verified": True,
        },
        "evidence_publication": {
            "projection_only": True,
            "source_pdf_published": False,
            "candidate_pdf_published": False,
            "page_images_published": False,
            "audit_zip_published": False,
        },
        "acceptance": projection,
    }
    _atomic_json(output, payload)
    return payload


def verify_release_attestation(
    manifest: Path,
    *,
    version: str,
    commit: str,
) -> dict[str, Any]:
    payload = dict(_require_exact_fields(
        _load_json(manifest),
        required={
            "schema_version",
            "version",
            "commit",
            "required_profiles",
            "runtime_identity",
            "tested_executable_sha256",
            "source",
            "performance_claim",
            "verification",
            "evidence_publication",
            "acceptance",
        },
        label="release attestation",
    ))
    normalized_commit = str(commit or "").strip().lower()
    _require(COMMIT_RE.fullmatch(normalized_commit) is not None, "invalid release commit")
    _require(payload.get("schema_version") == RELEASE_ATTESTATION_SCHEMA, "unsupported release attestation schema")
    _require(payload.get("version") == version, "release attestation version mismatch")
    _require(str(payload.get("commit") or "").lower() == normalized_commit, "release attestation commit mismatch")
    _require(
        payload.get("required_profiles") == list(PROFILE_SPECS),
        "release attestation required-profile summary is invalid",
    )
    runtime = _require_exact_fields(
        payload.get("runtime_identity"),
        required={"version", "commit", "build_id", "executable_filename", "executable_sha256"},
        label="release runtime identity",
    )
    _require(
        runtime.get("version") == version
        and str(runtime.get("commit") or "").lower() == normalized_commit
        and GITHUB_RUN_ID_RE.fullmatch(str(runtime.get("build_id") or "")) is not None
        and runtime.get("executable_filename") == "LaTeXStruct.exe"
        and SHA256_RE.fullmatch(str(runtime.get("executable_sha256") or "").lower()) is not None,
        "release runtime identity is invalid",
    )
    _require(
        str(payload.get("tested_executable_sha256") or "").lower()
        == str(runtime.get("executable_sha256") or "").lower(),
        "release tested-executable summary differs from the 37-page tested executable",
    )
    source = _require_exact_fields(
        payload.get("source"),
        required={"filename", "sha256", "total_pages"},
        label="release source",
    )
    _require(
        str(source.get("sha256") or "").lower() == RAMSEY_37_SOURCE_SHA256
        and int(source.get("total_pages") or 0) == 37
        and _safe_relative_member(source.get("filename")).suffix.lower() == ".pdf",
        "release source is not the fixed 37-page Ramsey PDF",
    )
    verification = _require_exact_fields(
        payload.get("verification"),
        required={
            "profile_count",
            "all_profiles_passed",
            "ocr_prerequisite_passed",
            "analysis_terminal_status",
            "visual_pages_checked",
            "independent_review_passes",
            "audit_package_verified",
        },
        label="release verification summary",
    )
    _require(
        verification
        == {
            "profile_count": 1,
            "all_profiles_passed": True,
            "ocr_prerequisite_passed": True,
            "analysis_terminal_status": "VERIFIED",
            "visual_pages_checked": 37,
            "independent_review_passes": 2,
            "audit_package_verified": True,
        },
        "release verification summary is not a strict analysis-37 VERIFIED PASS",
    )
    publication = _require_exact_fields(
        payload.get("evidence_publication"),
        required={
            "projection_only",
            "source_pdf_published",
            "candidate_pdf_published",
            "page_images_published",
            "audit_zip_published",
        },
        label="release evidence-publication policy",
    )
    _require(
        publication
        == {
            "projection_only": True,
            "source_pdf_published": False,
            "candidate_pdf_published": False,
            "page_images_published": False,
            "audit_zip_published": False,
        },
        "private 37-page evidence must remain local; only its hash projection may be committed",
    )
    projection = _require_exact_fields(
        payload.get("acceptance"),
        required={
            "profile",
            "analysis_attestation_sha256",
            "result",
            "acceptance_passed",
            "terminal_status",
            "quality_tier",
            "template",
            "execution",
            "runtime_identity",
            "service_binding",
            "snapshot_binding",
            "page_risk_admission",
            "source",
            "selected_range",
            "models",
            "compilation",
            "artifacts",
            "ocr_prerequisite",
            "independent_final_reviews",
            "visual_verification",
            "page_layout",
            "machine_verification",
            "audit_submission",
            "reports",
        },
        label="analysis-37 acceptance projection",
    )
    _require(
        projection.get("profile") == "analysis-37"
        and projection.get("result") == "PASS"
        and projection.get("acceptance_passed") is True
        and projection.get("terminal_status") == "VERIFIED"
        and projection.get("quality_tier") == "high"
        and projection.get("template") == "faithfulbook"
        and SHA256_RE.fullmatch(str(projection.get("analysis_attestation_sha256") or "").lower()) is not None
        and projection.get("runtime_identity") == runtime
        and projection.get("source") == source,
        "analysis-37 acceptance projection identity is invalid",
    )
    projected_service = _require_exact_fields(
        projection.get("service_binding"),
        required={"verified", "pid", "process_image_filename", "process_image_sha256", "listener_port", "listener_pid", "listener_pid_verified", "listener_image_filename", "listener_image_sha256"},
        label="projected candidate service binding",
    )
    _require(
        projected_service.get("verified") is True
        and int(projected_service.get("pid") or 0) > 0
        and projected_service.get("process_image_filename") == "LaTeXStruct.exe"
        and str(projected_service.get("process_image_sha256") or "").lower()
        == str(runtime.get("executable_sha256") or "").lower()
        and 0 < int(projected_service.get("listener_port") or 0) <= 65535
        and int(projected_service.get("listener_pid") or 0) > 0
        and projected_service.get("listener_pid_verified") is True
        and projected_service.get("listener_image_filename") == "LaTeXStruct.exe"
        and str(projected_service.get("listener_image_sha256") or "").lower()
        == str(runtime.get("executable_sha256") or "").lower(),
        "projected service process is not bound to the tested executable bytes",
    )
    projected_snapshot = _require_exact_fields(
        projection.get("snapshot_binding"),
        required={
            "snapshot_hash",
            "prompt_version",
            "response_schema_hash",
            "evidence_hashes",
            "model_bindings",
            "model_bindings_sha256",
            "transport_contracts_sha256",
            "analysis_configuration",
            "analysis_configuration_sha256",
            "release_model_policy",
            "transport_invocation_count",
            "transport_closure",
            "all_transport_bindings_verified",
        },
        label="projected analysis snapshot binding",
    )
    projected_snapshot_hashes = _require_exact_fields(
        projected_snapshot.get("evidence_hashes"),
        required=set(ANALYSIS_EVIDENCE_HASH_FIELDS),
        label="projected analysis snapshot evidence hashes",
    )
    _require(
        SHA256_RE.fullmatch(
            str(projected_snapshot.get("snapshot_hash") or "").lower()
        )
        is not None
        and bool(str(projected_snapshot.get("prompt_version") or "").strip())
        and str(projected_snapshot.get("response_schema_hash") or "").lower()
        == str(projected_snapshot_hashes.get("response_schema_hash") or "").lower()
        and all(
            SHA256_RE.fullmatch(str(value or "").lower()) is not None
            for value in projected_snapshot_hashes.values()
        )
        and SHA256_RE.fullmatch(
            str(projected_snapshot.get("model_bindings_sha256") or "").lower()
        )
        is not None
        and SHA256_RE.fullmatch(
            str(projected_snapshot.get("transport_contracts_sha256") or "").lower()
        )
        is not None
        and str(projected_snapshot.get("model_bindings_sha256") or "").lower()
        == _canonical_json_sha256(projected_snapshot.get("model_bindings"))
        and type(projected_snapshot.get("transport_invocation_count")) is int
        and int(projected_snapshot["transport_invocation_count"]) > 0
        and projected_snapshot.get("all_transport_bindings_verified") is True,
        "projected analysis snapshot/transport binding is incomplete",
    )
    _verify_analysis_transport_closure(
        projected_snapshot.get("transport_closure"),
        expected_invocations=int(projected_snapshot["transport_invocation_count"]),
        model_bindings=projected_snapshot.get("model_bindings"),
        expected_contracts_sha256=str(
            projected_snapshot.get("transport_contracts_sha256") or ""
        ),
    )
    projected_risk = _require_mapping(
        projection.get("page_risk_admission"),
        "projected analysis page-risk closure",
    )
    projected_configuration = _verify_analysis_configuration(
        projected_snapshot.get("analysis_configuration"),
        claimed_sha256=projected_snapshot.get("analysis_configuration_sha256"),
        expected_pages=37,
        admission=_require_mapping(
            projected_risk.get("admission"),
            "projected analysis page-risk admission",
        ),
        model_bindings=projected_snapshot.get("model_bindings"),
        expected_contracts_sha256=str(
            projected_snapshot.get("transport_contracts_sha256") or ""
        ),
        snapshot_config_sha256=str(
            projected_snapshot_hashes.get("analysis_config_hash") or ""
        ),
    )
    projected_model_policy = _verify_analysis_release_model_policy(
        projected_snapshot.get("release_model_policy"),
        model_bindings=projected_snapshot.get("model_bindings"),
        transport_contracts=projected_configuration.get("transport_contracts"),
    )
    selected = _require_exact_fields(
        projection.get("selected_range"),
        required={"start_page", "end_page", "expected_pages"},
        label="analysis-37 selected range",
    )
    _require(
        selected == {"start_page": 1, "end_page": 37, "expected_pages": 37},
        "analysis-37 projection does not cover pages 1-37",
    )
    _verify_analysis_page_risk_closure(
        projection.get("page_risk_admission"),
        expected_pages=37,
        source_sha256=str(source.get("sha256") or "").lower(),
        evidence_hashes=projected_snapshot_hashes,
        analysis_configuration=projected_configuration,
        final_candidate_sha256=str(
            _require_mapping(
                projection.get("compilation"),
                "projected analysis compilation",
            ).get("candidate_tex_sha256")
            or ""
        ).lower(),
    )
    execution = _require_exact_fields(
        projection.get("execution"),
        required={"real_execution", "test_double", "simulated", "api_client", "ui_driver", "workflow", "producer"},
        label="analysis-37 execution",
    )
    _require(
        execution.get("real_execution") is True
        and execution.get("test_double") is False
        and execution.get("simulated") is False
        and execution.get("api_client") == "LocalHttpApi"
        and execution.get("ui_driver") == "PlaywrightUiDriver"
        and execution.get("workflow") == "OCR_ANALYSIS_REVIEW",
        "analysis-37 projection is not a real combined workflow",
    )
    models = _require_exact_fields(
        projection.get("models"),
        required={"calls_total", "roles"},
        label="projected analysis/review model evidence",
    )
    model_roles = models.get("roles")
    _require(isinstance(model_roles, list) and bool(model_roles), "projected model roles are missing")
    projected_calls = 0
    projected_role_names: set[str] = set()
    for index, role_value in enumerate(model_roles, 1):
        role = _require_exact_fields(
            role_value,
            required={"role", "model_id", "backend", "calls"},
            label=f"projected model role {index}",
        )
        role_name = str(role.get("role") or "")
        calls = int(role.get("calls") or 0)
        _require(
            role_name in {"structure", "analysis", "review", "visual_review"}
            and role.get("model_id")
            == projected_model_policy.get("declared_model_id")
            and role.get("backend") == "codex_cli"
            and calls > 0,
            f"projected model role {index} is invalid",
        )
        projected_calls += calls
        projected_role_names.add(role_name)
    _require(
        int(models.get("calls_total") or 0) == projected_calls
        and int(projected_snapshot.get("transport_invocation_count") or 0)
        == projected_calls
        and "analysis" in projected_role_names
        and "visual_review" in projected_role_names,
        "projected analysis/review model call ledger is incomplete",
    )
    compilation = _require_exact_fields(
        projection.get("compilation"),
        required={"status", "successful_passes", "pass_exit_codes", "compile_log_sha256", "candidate_tex_sha256", "candidate_pdf_sha256"},
        label="analysis-37 compilation",
    )
    _require(
        compilation.get("status") == "COMPILED"
        and int(compilation.get("successful_passes") or 0) >= 2
        and isinstance(compilation.get("pass_exit_codes"), list)
        and len(compilation["pass_exit_codes"]) >= 2
        and all(code == 0 for code in compilation["pass_exit_codes"]),
        "analysis-37 projection lacks a real double-pass final compilation",
    )
    for field in ("compile_log_sha256", "candidate_tex_sha256", "candidate_pdf_sha256"):
        _require(SHA256_RE.fullmatch(str(compilation.get(field) or "").lower()) is not None, f"analysis-37 projection lacks {field}")
    artifacts = _require_exact_fields(
        projection.get("artifacts"),
        required=set(ANALYSIS_ARTIFACT_SPECS),
        label="analysis-37 real artifact bindings",
    )
    for role, (filename, digest_field) in ANALYSIS_ARTIFACT_SPECS.items():
        record = _require_exact_fields(artifacts.get(role), required={"filename", "bytes", "sha256"}, label=f"projected {filename}")
        _require(
            record.get("filename") == filename
            and isinstance(record.get("bytes"), int)
            and not isinstance(record.get("bytes"), bool)
            and int(record.get("bytes")) > 0
            and str(record.get("sha256") or "").lower() == str(compilation.get(digest_field) or "").lower(),
            f"projected real artifact binding is invalid: {filename}",
        )
    ocr = _require_exact_fields(
        projection.get("ocr_prerequisite"),
        required={"profile", "attestation_filename", "attestation_sha256", "result", "acceptance_passed", "successful_pages", "source_sha256", "run_id", "baseline_manifest_sha256", "runtime_identity", "selected_range"},
        label="projected OCR prerequisite",
    )
    _require(
        ocr.get("profile") == "ocr-37"
        and ocr.get("attestation_filename") == "ocr-prerequisite/acceptance-attestation.json"
        and SHA256_RE.fullmatch(str(ocr.get("attestation_sha256") or "").lower()) is not None
        and ocr.get("result") == "PASS"
        and ocr.get("acceptance_passed") is True
        and int(ocr.get("successful_pages") or 0) == 37
        and str(ocr.get("source_sha256") or "").lower() == RAMSEY_37_SOURCE_SHA256
        and re.fullmatch(r"[0-9a-f]{16,64}", str(ocr.get("run_id") or ""))
        is not None
        and SHA256_RE.fullmatch(
            str(ocr.get("baseline_manifest_sha256") or "").lower()
        )
        is not None,
        "projected OCR prerequisite is not a fixed-source 37-page PASS",
    )
    _require(
        ocr.get("runtime_identity") == runtime
        and ocr.get("selected_range") == selected,
        "projected OCR prerequisite is not bound to the exact runtime/range",
    )
    reviews = projection.get("independent_final_reviews")
    _require(isinstance(reviews, list) and len(reviews) == 2, "analysis-37 projection lacks two independent final reviews")
    candidate_sha = str(compilation.get("candidate_tex_sha256") or "").lower()
    review_ids: set[str] = set()
    context_ids: set[str] = set()
    context_hashes: set[str] = set()
    for index, review_value in enumerate(reviews, 1):
        review = _require_exact_fields(
            review_value,
            required={
                "pass_number",
                "review_id",
                "context_id",
                "context_sha256",
                "independent",
                "result",
                "candidate_tex_sha256",
                "pages_checked",
                "expected_page_ids",
                "checked_page_ids",
                "checked_page_ids_sha256",
                "model_id",
                "backend",
                "calls",
            },
            label=f"projected final review {index}",
        )
        context_id = str(review.get("context_id") or "")
        context_sha = str(review.get("context_sha256") or "").lower()
        review_id = str(review.get("review_id") or "")
        expected_page_ids = review.get("expected_page_ids")
        checked_page_ids = review.get("checked_page_ids")
        _require(
            review_id and review_id not in review_ids
            and context_id and context_id not in context_ids
            and SHA256_RE.fullmatch(context_sha) is not None and context_sha not in context_hashes
            and review.get("pass_number") == index
            and review.get("independent") is True
            and review.get("result") == "PASS"
            and str(review.get("candidate_tex_sha256") or "").lower() == candidate_sha
            and int(review.get("pages_checked") or 0) == 37
            and isinstance(expected_page_ids, list)
            and isinstance(checked_page_ids, list)
            and len(expected_page_ids) == 37
            and len(set(expected_page_ids)) == 37
            and checked_page_ids == expected_page_ids
            and str(review.get("checked_page_ids_sha256") or "").lower()
            == page_id_sequence_sha256(checked_page_ids)
            and context_sha == review_context_sha256(
                pass_number=index,
                context_id=context_id,
                candidate_tex_sha256=candidate_sha,
                checked_page_ids=checked_page_ids,
            )
            and int(review.get("calls") or 0) == 37
            and bool(str(review.get("model_id") or "").strip())
            and bool(str(review.get("backend") or "").strip()),
            f"projected final review {index} is not an independent full-page PASS",
        )
        review_ids.add(review_id)
        context_ids.add(context_id)
        context_hashes.add(context_sha)
    visual = _require_exact_fields(
        projection.get("visual_verification"),
        required={"passed", "expected_pages", "pages_checked", "independent_review_passes", "model_calls", "page_id_set_sha256", "candidate_tex_sha256", "candidate_pdf_sha256", "render_compare_closed_loop", "closed_loop_evidence"},
        label="projected visual verification",
    )
    projected_closed_loop = verify_render_compare_closed_loop(
        visual.get("closed_loop_evidence")
    )
    _require(
        visual.get("passed") is True
        and int(visual.get("expected_pages") or 0) == 37
        and int(visual.get("pages_checked") or 0) == 37
        and int(visual.get("independent_review_passes") or 0) == 2
        and int(visual.get("model_calls") or 0) == 74
        and str(visual.get("page_id_set_sha256") or "").lower()
        == page_id_sequence_sha256(reviews[0]["expected_page_ids"])
        and all(
            review["expected_page_ids"] == reviews[0]["expected_page_ids"]
            for review in reviews
        )
        and str(visual.get("candidate_tex_sha256") or "").lower() == candidate_sha
        and str(visual.get("candidate_pdf_sha256") or "").lower() == str(compilation.get("candidate_pdf_sha256") or "").lower()
        and visual.get("render_compare_closed_loop") is True,
        "projected visual verification is not a complete 37-page closed loop",
    )
    _require(
        projected_closed_loop.get("final_review_context_sha256s")
        == [str(review["context_sha256"]).lower() for review in reviews]
        and projected_closed_loop.get("final_candidate_tex_sha256") == candidate_sha
        and projected_closed_loop.get("final_candidate_pdf_sha256")
        == str(compilation.get("candidate_pdf_sha256") or "").lower(),
        "projected render/compare closed-loop evidence is inconsistent",
    )
    page_layout = _require_exact_fields(
        projection.get("page_layout"),
        required={"source_page_count", "candidate_page_count", "minimum_candidate_pages", "maximum_candidate_pages", "page_growth", "candidate_only_pages", "candidate_mapping_sha256", "candidate_mapping", "no_abnormal_page_inflation", "active_tableofcontents_count", "template"},
        label="projected final page-layout evidence",
    )
    projected_candidate_pages = int(page_layout.get("candidate_page_count") or 0)
    projected_candidate_only = page_layout.get("candidate_only_pages")
    _require(
        int(page_layout.get("source_page_count") or 0) == 37
        and MIN_ANALYSIS_37_CANDIDATE_PAGES
        <= projected_candidate_pages
        <= MAX_ANALYSIS_37_CANDIDATE_PAGES
        and int(page_layout.get("minimum_candidate_pages") or 0)
        == MIN_ANALYSIS_37_CANDIDATE_PAGES
        and int(page_layout.get("maximum_candidate_pages") or 0)
        == MAX_ANALYSIS_37_CANDIDATE_PAGES
        and int(page_layout.get("page_growth") or 0) == projected_candidate_pages - 37
        and int(page_layout.get("page_growth") or 0) >= -5
        and int(page_layout.get("page_growth") or 0) <= 5
        and isinstance(projected_candidate_only, list)
        and len(projected_candidate_only) == len(set(projected_candidate_only))
        and all(isinstance(page, int) and 1 <= page <= projected_candidate_pages for page in projected_candidate_only)
        and page_layout.get("no_abnormal_page_inflation") is True
        and int(page_layout.get("active_tableofcontents_count") or 0) == 1
        and page_layout.get("template") == "faithfulbook",
        "projected final PDF page count/mapping/automatic TOC gate is invalid",
    )
    projected_mapping = verify_candidate_page_mapping(
        page_layout.get("candidate_mapping"),
        expected_source_pages=37,
        expected_candidate_pages=projected_candidate_pages,
        expected_candidate_tex_sha256=candidate_sha,
        expected_candidate_pdf_sha256=str(
            compilation.get("candidate_pdf_sha256") or ""
        ).lower(),
    )
    _require(
        projected_candidate_only == projected_mapping["candidate_only_pages"]
        and str(page_layout.get("candidate_mapping_sha256") or "").lower()
        == projected_mapping["mapping_sha256"],
        "projected final page layout differs from its recomputed mapping",
    )
    machine = _require_exact_fields(
        projection.get("machine_verification"),
        required={"passed", "candidate_tex_sha256", "pages_checked", "silent_omissions", "text_loss", "unauthorized_math_changes", "unclosed_formal_environments", "open_critical_issues", "open_high_issues", "regressions", "verification_json_sha256"},
        label="projected machine verification",
    )
    _require(
        machine.get("passed") is True
        and str(machine.get("candidate_tex_sha256") or "").lower() == candidate_sha
        and int(machine.get("pages_checked") or 0) == 37
        and all(int(machine.get(field) or 0) == 0 for field in ("silent_omissions", "text_loss", "unauthorized_math_changes", "unclosed_formal_environments", "open_critical_issues", "open_high_issues", "regressions"))
        and SHA256_RE.fullmatch(str(machine.get("verification_json_sha256") or "").lower()) is not None,
        "projected machine verification is not a zero-blocker 37-page PASS",
    )
    audit = _require_exact_fields(
        projection.get("audit_submission"),
        required={"filename", "bytes", "sha256", "packaging_status", "audit_package_status", "verification_status", "published_to_github"},
        label="projected AI audit submission",
    )
    _require(
        audit.get("filename") == "analysis-audit-submission.zip"
        and isinstance(audit.get("bytes"), int)
        and not isinstance(audit.get("bytes"), bool)
        and int(audit.get("bytes")) > 0
        and SHA256_RE.fullmatch(str(audit.get("sha256") or "").lower()) is not None
        and audit.get("packaging_status") == "SUCCESS"
        and audit.get("audit_package_status") == "VALID"
        and audit.get("verification_status") == "VERIFIED"
        and audit.get("published_to_github") is False,
        "projected AI audit package binding is invalid",
    )
    reports = _require_exact_fields(projection.get("reports"), required={"performance", "validation", "verification"}, label="projected report bindings")
    for name, expected_filename in (("performance", "analysis-performance.json"), ("validation", "analysis-validation-report.json"), ("verification", "analysis-machine-verification.json")):
        report = _require_exact_fields(reports.get(name), required={"filename", "sha256"}, label=f"projected {name} report")
        _require(report.get("filename") == expected_filename and SHA256_RE.fullmatch(str(report.get("sha256") or "").lower()) is not None, f"projected {name} report binding is invalid")
    _require(
        str(reports["verification"].get("sha256") or "").lower()
        == str(machine.get("verification_json_sha256") or "").lower(),
        "projected machine-verification report digest is inconsistent",
    )
    _verify_analysis_37_performance_claim(
        payload.get("performance_claim"),
        report_record=reports["performance"],
    )
    return payload


def verify_release_executable(
    *,
    manifest: Path,
    version: str,
    commit: str,
    executable: Path,
    portable: Path,
) -> dict[str, str]:
    """Bind release bytes to the executable used by the strict analysis-37 run."""

    payload = verify_release_attestation(
        manifest,
        version=version,
        commit=commit,
    )
    expected = str(payload.get("tested_executable_sha256") or "").lower()
    _require(SHA256_RE.fullmatch(expected) is not None, "attested executable SHA-256 is invalid")
    _require(executable.is_file(), "release executable is missing")
    actual = _sha256_file(executable)
    _require(
        actual == expected,
        "release executable SHA-256 differs from the analysis-37 tested executable",
    )
    _require(portable.is_file(), "release portable archive is missing")
    try:
        with zipfile.ZipFile(portable, "r") as archive:
            names = archive.namelist()
            _require(names.count("LaTeXStruct.exe") == 1, "portable archive must contain exactly one LaTeXStruct.exe")
            portable_bytes = archive.read("LaTeXStruct.exe")
    except KeyError as exc:
        raise ReleaseIntegrityError("portable archive is missing LaTeXStruct.exe") from exc
    portable_sha = _sha256_bytes(portable_bytes)
    _require(
        portable_sha == expected,
        "portable LaTeXStruct.exe SHA-256 differs from the analysis-37 tested executable",
    )
    _require(
        portable_bytes == executable.read_bytes(),
        "portable LaTeXStruct.exe bytes differ from the release executable",
    )
    return {
        "tested_executable_sha256": expected,
        "release_executable_sha256": actual,
        "portable_executable_sha256": portable_sha,
    }


def verify_candidate_release_assets(
    *,
    manifest: Path,
    version: str,
    commit: str,
    assets_manifest: Path,
    checksums: Path,
    assets_dir: Path,
) -> dict[str, Any]:
    """Verify the immutable candidate artifact selected by the attested run id.

    The tag workflow must download these files from the earlier
    ``workflow_dispatch`` run.  This verifier deliberately does not create or
    rewrite any release bytes: it binds the downloaded portable/setup assets to
    the strict analysis-37 attestation, re-computes every digest, and verifies the
    executable embedded in the portable archive.
    """

    attestation = verify_release_attestation(
        manifest,
        version=version,
        commit=commit,
    )
    runtime = attestation["runtime_identity"]
    tested_executable_sha = str(
        attestation.get("tested_executable_sha256") or ""
    ).lower()
    build_id = str(runtime.get("build_id") or "").strip()
    _require(
        GITHUB_RUN_ID_RE.fullmatch(build_id) is not None,
        "attested build id must be a numeric GitHub Actions run id",
    )

    asset_payload = dict(
        _require_exact_fields(
            _load_json(assets_manifest),
            required={"schema_version", "version", "commit", "build_id", "assets"},
            label="release asset manifest",
        )
    )
    normalized_commit = str(commit or "").strip().lower()
    _require(
        asset_payload.get("schema_version") == ASSET_MANIFEST_SCHEMA,
        "unsupported release asset manifest schema",
    )
    _require(asset_payload.get("version") == version, "release asset version mismatch")
    _require(
        str(asset_payload.get("commit") or "").lower() == normalized_commit,
        "candidate artifact commit differs from the analysis-37 tested commit",
    )
    _require(
        str(asset_payload.get("build_id") or "").strip() == build_id,
        "candidate artifact build id differs from the analysis-37 GitHub run id",
    )

    expected_names = {
        f"LaTeXStruct-portable-{version}.zip",
        f"LaTeXStruct-setup-{version}.exe",
    }
    _require(
        assets_manifest.name == "release-assets.json"
        and checksums.name == "SHA256SUMS.txt",
        "candidate metadata filenames are not canonical",
    )
    expected_artifact_files = expected_names | {
        assets_manifest.name,
        checksums.name,
    }
    actual_artifact_files = {
        path.name for path in assets_dir.iterdir() if path.is_file()
    }
    _require(
        actual_artifact_files == expected_artifact_files,
        "candidate artifact must contain exactly portable, setup, release-assets.json, "
        "and SHA256SUMS.txt",
    )
    raw_records = asset_payload.get("assets")
    _require(isinstance(raw_records, list), "release asset records must be a list")
    _require(
        len(raw_records) == len(expected_names),
        "candidate artifact must contain exactly the portable and setup assets",
    )
    records: list[dict[str, Any]] = []
    observed_names: set[str] = set()
    for index, raw_record in enumerate(raw_records):
        record = dict(
            _require_exact_fields(
                raw_record,
                required={"filename", "bytes", "sha256"},
                label=f"release asset record {index}",
            )
        )
        filename = str(record.get("filename") or "")
        _require(
            filename in expected_names and Path(filename).name == filename,
            f"unexpected release asset filename: {filename or '<missing>'}",
        )
        _require(filename not in observed_names, f"duplicate release asset name: {filename}")
        observed_names.add(filename)
        byte_count = record.get("bytes")
        _require(
            isinstance(byte_count, int) and not isinstance(byte_count, bool) and byte_count > 0,
            f"release asset byte count is invalid: {filename}",
        )
        digest = str(record.get("sha256") or "").lower()
        _require(
            SHA256_RE.fullmatch(digest) is not None,
            f"release asset SHA-256 is invalid: {filename}",
        )
        asset_path = assets_dir / filename
        _require(asset_path.is_file(), f"release asset is missing: {filename}")
        _require(
            asset_path.stat().st_size == byte_count,
            f"release asset byte count mismatch: {filename}",
        )
        _require(
            _sha256_file(asset_path) == digest,
            f"release asset digest mismatch: {filename}",
        )
        records.append(
            {"filename": filename, "bytes": byte_count, "sha256": digest}
        )
    _require(
        observed_names == expected_names,
        "candidate artifact is missing the portable or setup asset",
    )
    _require(
        records == sorted(records, key=lambda item: str(item["filename"]).casefold()),
        "release asset records are not in canonical order",
    )

    canonical_sums = "".join(
        f"{record['sha256']}  {record['filename']}\n" for record in records
    ).encode("utf-8")
    _require(checksums.is_file(), "candidate SHA256SUMS.txt is missing")
    _require(
        checksums.read_bytes() == canonical_sums,
        "candidate SHA256SUMS.txt does not match re-computed release assets",
    )

    portable = assets_dir / f"LaTeXStruct-portable-{version}.zip"
    expected_members = [
        "LaTeXStruct.exe",
        "LICENSE",
        "THIRD_PARTY_NOTICES.txt",
    ]
    try:
        with zipfile.ZipFile(portable, "r") as archive:
            members = archive.namelist()
            _require(
                members == expected_members,
                "portable archive must contain exactly one executable and the two "
                "root license files",
            )
            executable_bytes = archive.read("LaTeXStruct.exe")
    except (KeyError, zipfile.BadZipFile) as exc:
        raise ReleaseIntegrityError("candidate portable archive is invalid") from exc
    portable_executable_sha = _sha256_bytes(executable_bytes)
    _require(
        portable_executable_sha == tested_executable_sha,
        "portable LaTeXStruct.exe SHA-256 differs from the executable tested by "
        "the strict analysis-37 run",
    )
    return {
        "version": version,
        "commit": normalized_commit,
        "build_id": build_id,
        "tested_executable_sha256": tested_executable_sha,
        "portable_executable_sha256": portable_executable_sha,
        "assets": records,
    }


def _github_acceptance_artifact_names(version: str) -> tuple[str, str]:
    _require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None, "invalid version")
    return (
        f"LaTeXStruct-analysis-37-evidence-v{version}",
        f"LaTeXStruct-analysis-37-closure-v{version}",
    )


def _github_repository(value: object) -> str:
    repository = str(value or "").strip()
    _require(
        re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
            r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})",
            repository,
        )
        is not None,
        "invalid GitHub repository identity",
    )
    return repository


def _file_record(path: Path, *, filename: str | None = None) -> dict[str, Any]:
    _require(path.is_file(), f"trusted acceptance file is missing: {path.name}")
    return {
        "filename": filename or path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _validate_file_record(
    value: object,
    *,
    expected_filename: str,
    label: str,
) -> dict[str, Any]:
    record = dict(
        _require_exact_fields(
            value,
            required={"filename", "bytes", "sha256"},
            label=label,
        )
    )
    _require(record.get("filename") == expected_filename, f"{label} filename is invalid")
    byte_count = record.get("bytes")
    _require(
        isinstance(byte_count, int) and not isinstance(byte_count, bool) and byte_count > 0,
        f"{label} byte count is invalid",
    )
    digest = str(record.get("sha256") or "").lower()
    _require(SHA256_RE.fullmatch(digest) is not None, f"{label} SHA-256 is invalid")
    record["sha256"] = digest
    return record


def _github_acceptance_run_identity(
    *,
    run_id: object,
    run_attempt: object,
    workflow_path: object,
    runner_label: object,
) -> dict[str, Any]:
    normalized_run_id = str(run_id or "").strip()
    _require(
        GITHUB_RUN_ID_RE.fullmatch(normalized_run_id) is not None,
        "acceptance run id must be a numeric GitHub Actions run id",
    )
    _require(
        isinstance(run_attempt, int)
        and not isinstance(run_attempt, bool)
        and run_attempt == 1,
        "trusted acceptance requires GitHub run attempt 1",
    )
    normalized_workflow_path = str(workflow_path or "").strip()
    _require(
        normalized_workflow_path in GITHUB_ACCEPTANCE_WORKFLOWS,
        "trusted acceptance workflow path is invalid",
    )
    normalized_runner_label = str(runner_label or "").strip()
    _require(
        GITHUB_ACCEPTANCE_RUNNER_LABEL_RE.fullmatch(normalized_runner_label)
        is not None,
        "trusted acceptance runner label is invalid",
    )
    return {
        "workflow_path": normalized_workflow_path,
        "event": GITHUB_ACCEPTANCE_EVENT,
        "run_id": normalized_run_id,
        "run_attempt": 1,
        "runner_label": normalized_runner_label,
    }


def _validate_github_acceptance_reference(
    value: object,
    *,
    version: str,
    commit: str,
    repository: str,
) -> dict[str, Any]:
    reference = dict(
        _require_exact_fields(
            value,
            required={
                "schema_version",
                "repository",
                "version",
                "commit",
                "acceptance_run",
                "candidate_build",
                "artifacts",
                "files",
            },
            label="GitHub acceptance reference",
        )
    )
    normalized_commit = str(commit or "").strip().lower()
    _require(reference.get("schema_version") == GITHUB_ACCEPTANCE_REFERENCE_SCHEMA, "unsupported GitHub acceptance reference schema")
    _require(reference.get("repository") == repository, "GitHub acceptance repository mismatch")
    _require(reference.get("version") == version, "GitHub acceptance version mismatch")
    _require(str(reference.get("commit") or "").lower() == normalized_commit, "GitHub acceptance commit mismatch")
    run = dict(
        _require_exact_fields(
            reference.get("acceptance_run"),
            required={
                "workflow_path",
                "event",
                "run_id",
                "run_attempt",
                "runner_label",
            },
            label="GitHub acceptance run reference",
        )
    )
    expected_run = _github_acceptance_run_identity(
        run_id=run.get("run_id"),
        run_attempt=run.get("run_attempt"),
        workflow_path=run.get("workflow_path"),
        runner_label=run.get("runner_label"),
    )
    _require(run == expected_run, "GitHub acceptance run reference is invalid")
    candidate = dict(
        _require_exact_fields(
            reference.get("candidate_build"),
            required={"workflow_path", "run_id", "artifact_name"},
            label="candidate build reference",
        )
    )
    candidate_run_id = str(candidate.get("run_id") or "").strip()
    _require(
        candidate.get("workflow_path") == GITHUB_CANDIDATE_WORKFLOW
        and GITHUB_RUN_ID_RE.fullmatch(candidate_run_id) is not None
        and candidate.get("artifact_name") == f"LaTeXStruct-v{version}",
        "candidate build reference is invalid",
    )
    _require(
        (candidate_run_id == run["run_id"])
        == (run["workflow_path"] == GITHUB_CANDIDATE_WORKFLOW),
        "acceptance workflow mode does not match the candidate run identity",
    )
    payload_name, closure_name = _github_acceptance_artifact_names(version)
    artifacts = dict(
        _require_exact_fields(
            reference.get("artifacts"),
            required={"payload", "closure"},
            label="trusted GitHub artifact names",
        )
    )
    _require(
        artifacts == {"payload": payload_name, "closure": closure_name},
        "trusted GitHub artifact names are not canonical",
    )
    files = dict(
        _require_exact_fields(
            reference.get("files"),
            required={"release_attestation", "trusted_root"},
            label="trusted GitHub payload filenames",
        )
    )
    _require(
        files
        == {
            "release_attestation": "release-attestation.json",
            "trusted_root": "github-acceptance-root.json",
        },
        "trusted GitHub payload filenames are not canonical",
    )
    reference["acceptance_run"] = run
    reference["candidate_build"] = candidate
    reference["artifacts"] = artifacts
    reference["files"] = files
    return reference


def assemble_github_acceptance_payload(
    *,
    version: str,
    commit: str,
    repository: str,
    acceptance_run_id: str,
    acceptance_run_attempt: int,
    acceptance_workflow_path: str,
    runner_label: str,
    candidate_run_id: str,
    analysis_run_dir: Path,
    release_manifest: Path,
    assets_manifest: Path,
    checksums: Path,
    assets_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Create the public, hash-only payload emitted by the trusted acceptance run.

    Private source/candidate PDFs, page renders, and the full audit ZIP remain in
    ``analysis_run_dir``.  Only canonical JSON projections are written here.
    """

    normalized_commit = str(commit or "").strip().lower()
    _require(COMMIT_RE.fullmatch(normalized_commit) is not None, "invalid release commit")
    repository = _github_repository(repository)
    run = _github_acceptance_run_identity(
        run_id=acceptance_run_id,
        run_attempt=acceptance_run_attempt,
        workflow_path=acceptance_workflow_path,
        runner_label=runner_label,
    )
    normalized_candidate_run_id = str(candidate_run_id or "").strip()
    _require(
        GITHUB_RUN_ID_RE.fullmatch(normalized_candidate_run_id) is not None,
        "candidate build id must be a numeric GitHub Actions run id",
    )
    _require(
        (normalized_candidate_run_id == run["run_id"])
        == (run["workflow_path"] == GITHUB_CANDIDATE_WORKFLOW),
        "acceptance workflow mode does not match the candidate run identity",
    )
    _require(
        release_manifest.name == "release-attestation.json",
        "release attestation filename is not canonical",
    )
    release = verify_release_attestation(
        release_manifest, version=version, commit=normalized_commit
    )
    private = verify_analysis_attestation(
        analysis_run_dir,
        expected_pages=37,
        version=version,
        commit=normalized_commit,
    )
    _require(
        _sha256_file(analysis_run_dir / "analysis-attestation.json")
        == str(release["acceptance"].get("analysis_attestation_sha256") or "").lower(),
        "release projection differs from the private analysis attestation",
    )
    _require(
        str(release["runtime_identity"].get("build_id") or "")
        == normalized_candidate_run_id,
        "release projection is not bound to the selected candidate build run",
    )
    candidate = verify_candidate_release_assets(
        manifest=release_manifest,
        version=version,
        commit=normalized_commit,
        assets_manifest=assets_manifest,
        checksums=checksums,
        assets_dir=assets_dir,
    )
    _require(
        str(candidate.get("build_id") or "") == normalized_candidate_run_id,
        "candidate asset closure build id mismatch",
    )
    if output_dir.exists():
        _require(
            output_dir.is_dir() and not any(output_dir.iterdir()),
            "trusted acceptance payload directory must be empty",
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    payload_name, closure_name = _github_acceptance_artifact_names(version)
    reference = {
        "schema_version": GITHUB_ACCEPTANCE_REFERENCE_SCHEMA,
        "repository": repository,
        "version": version,
        "commit": normalized_commit,
        "acceptance_run": run,
        "candidate_build": {
            "workflow_path": GITHUB_CANDIDATE_WORKFLOW,
            "run_id": normalized_candidate_run_id,
            "artifact_name": f"LaTeXStruct-v{version}",
        },
        "artifacts": {"payload": payload_name, "closure": closure_name},
        "files": {
            "release_attestation": "release-attestation.json",
            "trusted_root": "github-acceptance-root.json",
        },
    }
    reference_path = output_dir / "github-acceptance-reference.json"
    release_path = output_dir / "release-attestation.json"
    _atomic_json(reference_path, reference)
    _atomic_write(release_path, release_manifest.read_bytes())
    audit = private["audit_submission"]
    audit_record = {
        "filename": str(audit["filename"]),
        "bytes": int(audit["bytes"]),
        "sha256": str(audit["sha256"]).lower(),
    }
    root = {
        "schema_version": GITHUB_ACCEPTANCE_ROOT_SCHEMA,
        "repository": repository,
        "version": version,
        "commit": normalized_commit,
        "acceptance_run": run,
        "candidate_build": {
            "workflow_path": GITHUB_CANDIDATE_WORKFLOW,
            "run_id": normalized_candidate_run_id,
            "artifact_name": f"LaTeXStruct-v{version}",
            "release_assets_manifest": _file_record(
                assets_manifest, filename="release-assets.json"
            ),
            "checksums": _file_record(checksums, filename="SHA256SUMS.txt"),
            "tested_executable_sha256": candidate["tested_executable_sha256"],
            "assets": candidate["assets"],
        },
        "acceptance": {
            "profile": "analysis-37",
            "source_sha256": str(private["source"]["sha256"]).lower(),
            "analysis_attestation_sha256": _sha256_file(
                analysis_run_dir / "analysis-attestation.json"
            ),
            "audit_package": audit_record,
            "artifacts": private["artifacts"],
            "reports": private["reports"],
        },
        "public_payload": {
            "reference": _file_record(reference_path),
            "release_attestation": _file_record(release_path),
            "source_pdf_uploaded": False,
            "candidate_pdf_uploaded": False,
            "page_images_uploaded": False,
            "audit_zip_uploaded": False,
        },
        "result": "PASS",
    }
    root_path = output_dir / "github-acceptance-root.json"
    _atomic_json(root_path, root)
    return {
        "reference": reference,
        "root": root,
        "payload_artifact_name": payload_name,
        "closure_artifact_name": closure_name,
    }


def _validate_artifact_digest(value: object, *, label: str) -> str:
    digest = str(value or "").strip().lower()
    _require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
        f"{label} digest must be a GitHub sha256 artifact digest",
    )
    return digest


def write_github_acceptance_closure(
    *,
    payload_dir: Path,
    repository: str,
    version: str,
    commit: str,
    acceptance_run_id: str,
    acceptance_run_attempt: int,
    acceptance_workflow_path: str,
    runner_label: str,
    candidate_run_id: str,
    payload_artifact_id: str,
    payload_artifact_digest: str,
    output: Path,
) -> dict[str, Any]:
    repository = _github_repository(repository)
    normalized_commit = str(commit or "").strip().lower()
    run = _github_acceptance_run_identity(
        run_id=acceptance_run_id,
        run_attempt=acceptance_run_attempt,
        workflow_path=acceptance_workflow_path,
        runner_label=runner_label,
    )
    reference_path = payload_dir / "github-acceptance-reference.json"
    root_path = payload_dir / "github-acceptance-root.json"
    release_path = payload_dir / "release-attestation.json"
    reference = _validate_github_acceptance_reference(
        _load_json(reference_path),
        version=version,
        commit=normalized_commit,
        repository=repository,
    )
    _require(reference["acceptance_run"] == run, "payload acceptance run identity mismatch")
    normalized_candidate_run_id = str(candidate_run_id or "").strip()
    _require(
        reference["candidate_build"]["run_id"] == normalized_candidate_run_id,
        "payload candidate build identity mismatch",
    )
    payload_name, _closure_name = _github_acceptance_artifact_names(version)
    artifact_id = str(payload_artifact_id or "").strip()
    _require(
        GITHUB_RUN_ID_RE.fullmatch(artifact_id) is not None,
        "payload artifact id must be numeric",
    )
    files = [
        _file_record(reference_path),
        _file_record(root_path),
        _file_record(release_path),
    ]
    files.sort(key=lambda item: str(item["filename"]))
    closure = {
        "schema_version": GITHUB_ACCEPTANCE_CLOSURE_SCHEMA,
        "repository": repository,
        "version": version,
        "commit": normalized_commit,
        "acceptance_run": run,
        "candidate_run_id": normalized_candidate_run_id,
        "payload_artifact": {
            "name": payload_name,
            "id": artifact_id,
            "digest": _validate_artifact_digest(
                payload_artifact_digest, label="payload artifact"
            ),
        },
        "payload_files": files,
        "result": "PASS",
    }
    _atomic_json(output, closure)
    return closure


def _read_github_artifact_zip(
    path: Path,
    *,
    expected_names: set[str],
    expected_digest: str,
    label: str,
) -> dict[str, bytes]:
    _require(path.is_file(), f"{label} archive is missing")
    _require(
        _sha256_file(path) == expected_digest.removeprefix("sha256:"),
        f"{label} archive digest differs from GitHub API metadata",
    )
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            _require(
                set(names) == expected_names and len(names) == len(expected_names),
                f"{label} archive members are not canonical",
            )
            payloads: dict[str, bytes] = {}
            for info in infos:
                mode = (info.external_attr >> 16) & 0xFFFF
                _require(
                    not info.is_dir()
                    and not (mode and stat.S_IFMT(mode) == stat.S_IFLNK)
                    and info.flag_bits & 0x1 == 0
                    and info.file_size <= 16 * 1024 * 1024,
                    f"{label} archive contains an unsafe member",
                )
                payloads[info.filename] = archive.read(info)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise ReleaseIntegrityError(f"cannot read {label} archive: {exc}") from exc
    return payloads


def _github_artifact_records(
    metadata: Mapping[str, Any],
    *,
    reference: Mapping[str, Any],
    commit: str,
) -> dict[str, dict[str, Any]]:
    raw_artifacts = metadata.get("artifacts")
    _require(isinstance(raw_artifacts, list), "GitHub artifact API response is invalid")
    expected_names = set(reference["artifacts"].values())
    if (
        reference["candidate_build"]["run_id"]
        == reference["acceptance_run"]["run_id"]
    ):
        expected_names.add(str(reference["candidate_build"]["artifact_name"]))
    _require(
        metadata.get("total_count") == len(expected_names)
        and len(raw_artifacts) == len(expected_names),
        "trusted acceptance run artifact inventory is not canonical",
    )
    result: dict[str, dict[str, Any]] = {}
    for value in raw_artifacts:
        _require(isinstance(value, Mapping), "GitHub artifact API record is invalid")
        name = str(value.get("name") or "")
        artifact_id = str(value.get("id") or "")
        digest = _validate_artifact_digest(
            value.get("digest"), label=f"GitHub artifact {name or '<missing>'}"
        )
        workflow_run = value.get("workflow_run")
        _require(isinstance(workflow_run, Mapping), "GitHub artifact lacks workflow run identity")
        _require(
            name in expected_names
            and name not in result
            and GITHUB_RUN_ID_RE.fullmatch(artifact_id) is not None
            and value.get("expired") is False
            and str(workflow_run.get("id") or "")
            == reference["acceptance_run"]["run_id"]
            and str(workflow_run.get("head_sha") or "").lower() == commit,
            "GitHub artifact is expired, duplicated, or detached from the acceptance run",
        )
        result[name] = {"id": artifact_id, "digest": digest}
    _require(set(result) == expected_names, "trusted acceptance artifacts are incomplete")
    return result


def verify_github_acceptance_trust(
    *,
    reference_manifest: Path,
    release_manifest: Path,
    run_metadata: Path,
    artifacts_metadata: Path,
    payload_archive: Path,
    closure_archive: Path,
    repository: str,
    version: str,
    commit: str,
) -> dict[str, Any]:
    """Verify a stable-release trust root using live GitHub API metadata."""

    repository = _github_repository(repository)
    normalized_commit = str(commit or "").strip().lower()
    release = verify_release_attestation(
        release_manifest, version=version, commit=normalized_commit
    )
    reference_bytes = reference_manifest.read_bytes()
    reference = _validate_github_acceptance_reference(
        _load_json_bytes(reference_bytes, label=reference_manifest.name),
        version=version,
        commit=normalized_commit,
        repository=repository,
    )
    _require(
        reference["candidate_build"]["run_id"]
        == str(release["runtime_identity"].get("build_id") or ""),
        "GitHub acceptance reference candidate run differs from the release runtime",
    )
    run_api = _load_json(run_metadata)
    api_repository = run_api.get("repository")
    _require(isinstance(api_repository, Mapping), "GitHub run lacks repository identity")
    _require(
        str(run_api.get("id") or "") == reference["acceptance_run"]["run_id"]
        and str(run_api.get("head_sha") or "").lower() == normalized_commit
        and run_api.get("event") == GITHUB_ACCEPTANCE_EVENT
        and run_api.get("status") == "completed"
        and run_api.get("conclusion") == "success"
        and run_api.get("path") == reference["acceptance_run"]["workflow_path"]
        and run_api.get("run_attempt") == 1
        and api_repository.get("full_name") == repository,
        "GitHub acceptance run is not a successful first attempt on the tested commit",
    )
    artifact_api = _load_json(artifacts_metadata)
    artifacts = _github_artifact_records(
        artifact_api, reference=reference, commit=normalized_commit
    )
    payload_name = reference["artifacts"]["payload"]
    closure_name = reference["artifacts"]["closure"]
    payloads = _read_github_artifact_zip(
        payload_archive,
        expected_names={
            "github-acceptance-reference.json",
            "github-acceptance-root.json",
            "release-attestation.json",
        },
        expected_digest=artifacts[payload_name]["digest"],
        label="trusted acceptance payload",
    )
    closures = _read_github_artifact_zip(
        closure_archive,
        expected_names={"github-acceptance-closure.json"},
        expected_digest=artifacts[closure_name]["digest"],
        label="trusted acceptance closure",
    )
    _require(
        payloads["github-acceptance-reference.json"] == reference_bytes,
        "committed GitHub acceptance reference differs from the trusted artifact",
    )
    release_bytes = release_manifest.read_bytes()
    _require(
        payloads["release-attestation.json"] == release_bytes,
        "committed release attestation differs from the trusted acceptance artifact",
    )
    closure = dict(
        _require_exact_fields(
            _load_json_bytes(
                closures["github-acceptance-closure.json"],
                label="github-acceptance-closure.json",
            ),
            required={
                "schema_version",
                "repository",
                "version",
                "commit",
                "acceptance_run",
                "candidate_run_id",
                "payload_artifact",
                "payload_files",
                "result",
            },
            label="GitHub acceptance closure",
        )
    )
    _require(
        closure.get("schema_version") == GITHUB_ACCEPTANCE_CLOSURE_SCHEMA
        and closure.get("repository") == repository
        and closure.get("version") == version
        and str(closure.get("commit") or "").lower() == normalized_commit
        and closure.get("acceptance_run") == reference["acceptance_run"]
        and str(closure.get("candidate_run_id") or "")
        == reference["candidate_build"]["run_id"]
        and closure.get("result") == "PASS",
        "GitHub acceptance closure identity is invalid",
    )
    payload_artifact = dict(
        _require_exact_fields(
            closure.get("payload_artifact"),
            required={"name", "id", "digest"},
            label="closed payload artifact",
        )
    )
    _require(
        payload_artifact
        == {
            "name": payload_name,
            "id": artifacts[payload_name]["id"],
            "digest": artifacts[payload_name]["digest"],
        },
        "closure does not bind the live GitHub payload artifact",
    )
    raw_file_records = closure.get("payload_files")
    _require(isinstance(raw_file_records, list) and len(raw_file_records) == 3, "closure payload file inventory is invalid")
    expected_payload_files = set(payloads)
    closed_files: dict[str, dict[str, Any]] = {}
    for value in raw_file_records:
        _require(isinstance(value, Mapping), "closure payload file record is invalid")
        filename = str(value.get("filename") or "")
        _require(filename in expected_payload_files and filename not in closed_files, "closure payload filename is invalid")
        record = _validate_file_record(
            value, expected_filename=filename, label=f"closed payload file {filename}"
        )
        _require(
            record["bytes"] == len(payloads[filename])
            and record["sha256"] == _sha256_bytes(payloads[filename]),
            f"closed payload file differs from artifact bytes: {filename}",
        )
        closed_files[filename] = record
    _require(set(closed_files) == expected_payload_files, "closure payload file inventory is incomplete")
    root = dict(
        _require_exact_fields(
            _load_json_bytes(
                payloads["github-acceptance-root.json"],
                label="github-acceptance-root.json",
            ),
            required={
                "schema_version",
                "repository",
                "version",
                "commit",
                "acceptance_run",
                "candidate_build",
                "acceptance",
                "public_payload",
                "result",
            },
            label="GitHub acceptance root",
        )
    )
    _require(
        root.get("schema_version") == GITHUB_ACCEPTANCE_ROOT_SCHEMA
        and root.get("repository") == repository
        and root.get("version") == version
        and str(root.get("commit") or "").lower() == normalized_commit
        and root.get("acceptance_run") == reference["acceptance_run"]
        and root.get("result") == "PASS",
        "GitHub acceptance root identity is invalid",
    )
    public_payload = dict(
        _require_exact_fields(
            root.get("public_payload"),
            required={
                "reference",
                "release_attestation",
                "source_pdf_uploaded",
                "candidate_pdf_uploaded",
                "page_images_uploaded",
                "audit_zip_uploaded",
            },
            label="GitHub acceptance publication policy",
        )
    )
    _require(
        public_payload.get("source_pdf_uploaded") is False
        and public_payload.get("candidate_pdf_uploaded") is False
        and public_payload.get("page_images_uploaded") is False
        and public_payload.get("audit_zip_uploaded") is False,
        "private acceptance evidence was marked for GitHub publication",
    )
    for key, filename in (
        ("reference", "github-acceptance-reference.json"),
        ("release_attestation", "release-attestation.json"),
    ):
        record = _validate_file_record(
            public_payload.get(key),
            expected_filename=filename,
            label=f"public payload {key}",
        )
        _require(
            record["bytes"] == len(payloads[filename])
            and record["sha256"] == _sha256_bytes(payloads[filename]),
            f"GitHub acceptance root does not bind {filename}",
        )
    candidate_root = dict(
        _require_exact_fields(
            root.get("candidate_build"),
            required={
                "workflow_path",
                "run_id",
                "artifact_name",
                "release_assets_manifest",
                "checksums",
                "tested_executable_sha256",
                "assets",
            },
            label="root candidate build closure",
        )
    )
    _require(
        candidate_root.get("workflow_path") == GITHUB_CANDIDATE_WORKFLOW
        and str(candidate_root.get("run_id") or "")
        == reference["candidate_build"]["run_id"]
        and candidate_root.get("artifact_name")
        == reference["candidate_build"]["artifact_name"]
        and str(candidate_root.get("tested_executable_sha256") or "").lower()
        == str(release["tested_executable_sha256"]).lower(),
        "trusted root candidate build closure is inconsistent",
    )
    _validate_file_record(
        candidate_root.get("release_assets_manifest"),
        expected_filename="release-assets.json",
        label="root release asset manifest",
    )
    _validate_file_record(
        candidate_root.get("checksums"),
        expected_filename="SHA256SUMS.txt",
        label="root candidate checksums",
    )
    _require(
        candidate_root.get("assets")
        == sorted(
            candidate_root.get("assets") or [],
            key=lambda item: str(item.get("filename") or "").casefold(),
        ),
        "trusted root candidate assets are not canonical",
    )
    acceptance_root = dict(
        _require_exact_fields(
            root.get("acceptance"),
            required={
                "profile",
                "source_sha256",
                "analysis_attestation_sha256",
                "audit_package",
                "artifacts",
                "reports",
            },
            label="root analysis-37 acceptance closure",
        )
    )
    projected = release["acceptance"]
    _require(
        acceptance_root.get("profile") == "analysis-37"
        and str(acceptance_root.get("source_sha256") or "").lower()
        == RAMSEY_37_SOURCE_SHA256
        and str(acceptance_root.get("analysis_attestation_sha256") or "").lower()
        == str(projected.get("analysis_attestation_sha256") or "").lower()
        and acceptance_root.get("artifacts") == projected.get("artifacts")
        and acceptance_root.get("reports") == projected.get("reports"),
        "trusted root does not close over the release analysis-37 projection",
    )
    audit = _validate_file_record(
        acceptance_root.get("audit_package"),
        expected_filename="analysis-audit-submission.zip",
        label="private audit package root",
    )
    projected_audit = projected.get("audit_submission") or {}
    _require(
        audit["bytes"] == projected_audit.get("bytes")
        and audit["sha256"] == str(projected_audit.get("sha256") or "").lower(),
        "trusted root audit package digest differs from the release projection",
    )
    return {
        "repository": repository,
        "version": version,
        "commit": normalized_commit,
        "acceptance_run_id": reference["acceptance_run"]["run_id"],
        "candidate_run_id": reference["candidate_build"]["run_id"],
        "payload_artifact_id": artifacts[payload_name]["id"],
        "closure_artifact_id": artifacts[closure_name]["id"],
        "tested_executable_sha256": release["tested_executable_sha256"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    portable = subparsers.add_parser("build-portable")
    portable.add_argument("--executable", type=Path, required=True)
    portable.add_argument("--license", dest="license_file", type=Path, required=True)
    portable.add_argument("--notices", dest="notices_file", type=Path, required=True)
    portable.add_argument("--output", type=Path, required=True)

    assets = subparsers.add_parser("record-assets")
    assets.add_argument("--version", required=True)
    assets.add_argument("--commit", required=True)
    assets.add_argument("--build-id", required=True)
    assets.add_argument("--output", type=Path, required=True)
    assets.add_argument("--checksums-output", type=Path, required=True)
    assets.add_argument("assets", nargs="+", type=Path)

    notes = subparsers.add_parser("verify-release-notes")
    notes.add_argument("--changelog", type=Path, required=True)
    notes.add_argument("--readme", type=Path, required=True)
    notes.add_argument("--version", required=True)

    assemble = subparsers.add_parser("assemble-attestations")
    assemble.add_argument("--version", required=True)
    assemble.add_argument("--commit", required=True)
    assemble.add_argument("--analysis-run-37", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify-attestation")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--commit", required=True)

    release_executable = subparsers.add_parser("verify-release-executable")
    release_executable.add_argument("--manifest", type=Path, required=True)
    release_executable.add_argument("--version", required=True)
    release_executable.add_argument("--commit", required=True)
    release_executable.add_argument("--executable", type=Path, required=True)
    release_executable.add_argument("--portable", type=Path, required=True)

    candidate_assets = subparsers.add_parser("verify-candidate-assets")
    candidate_assets.add_argument("--manifest", type=Path, required=True)
    candidate_assets.add_argument("--version", required=True)
    candidate_assets.add_argument("--commit", required=True)
    candidate_assets.add_argument("--assets-manifest", type=Path, required=True)
    candidate_assets.add_argument("--checksums", type=Path, required=True)
    candidate_assets.add_argument("--assets-dir", type=Path, required=True)

    github_payload = subparsers.add_parser("assemble-github-acceptance")
    github_payload.add_argument("--version", required=True)
    github_payload.add_argument("--commit", required=True)
    github_payload.add_argument("--repository", required=True)
    github_payload.add_argument("--acceptance-run-id", required=True)
    github_payload.add_argument("--acceptance-run-attempt", type=int, required=True)
    github_payload.add_argument("--acceptance-workflow-path", required=True)
    github_payload.add_argument("--runner-label", required=True)
    github_payload.add_argument("--candidate-run-id", required=True)
    github_payload.add_argument("--analysis-run-37", type=Path, required=True)
    github_payload.add_argument("--release-manifest", type=Path, required=True)
    github_payload.add_argument("--assets-manifest", type=Path, required=True)
    github_payload.add_argument("--checksums", type=Path, required=True)
    github_payload.add_argument("--assets-dir", type=Path, required=True)
    github_payload.add_argument("--output-dir", type=Path, required=True)

    github_closure = subparsers.add_parser("write-github-acceptance-closure")
    github_closure.add_argument("--payload-dir", type=Path, required=True)
    github_closure.add_argument("--repository", required=True)
    github_closure.add_argument("--version", required=True)
    github_closure.add_argument("--commit", required=True)
    github_closure.add_argument("--acceptance-run-id", required=True)
    github_closure.add_argument("--acceptance-run-attempt", type=int, required=True)
    github_closure.add_argument("--acceptance-workflow-path", required=True)
    github_closure.add_argument("--runner-label", required=True)
    github_closure.add_argument("--candidate-run-id", required=True)
    github_closure.add_argument("--payload-artifact-id", required=True)
    github_closure.add_argument("--payload-artifact-digest", required=True)
    github_closure.add_argument("--output", type=Path, required=True)

    github_verify = subparsers.add_parser("verify-github-acceptance")
    github_verify.add_argument("--reference-manifest", type=Path, required=True)
    github_verify.add_argument("--release-manifest", type=Path, required=True)
    github_verify.add_argument("--run-metadata", type=Path, required=True)
    github_verify.add_argument("--artifacts-metadata", type=Path, required=True)
    github_verify.add_argument("--payload-archive", type=Path, required=True)
    github_verify.add_argument("--closure-archive", type=Path, required=True)
    github_verify.add_argument("--repository", required=True)
    github_verify.add_argument("--version", required=True)
    github_verify.add_argument("--commit", required=True)

    schema = subparsers.add_parser(
        "analysis-schema",
        help="write the strict contract for a real analysis acceptance producer",
    )
    schema.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build-portable":
            build_portable_archive(
                executable=args.executable,
                license_file=args.license_file,
                notices_file=args.notices_file,
                output=args.output,
            )
        elif args.command == "record-assets":
            write_asset_manifest(
                assets=args.assets,
                version=args.version,
                commit=args.commit,
                build_id=args.build_id,
                output=args.output,
                checksums_output=args.checksums_output,
            )
        elif args.command == "verify-release-notes":
            verify_release_notes(
                args.changelog,
                args.version,
                readme=args.readme,
            )
        elif args.command == "assemble-attestations":
            assemble_release_attestation(
                version=args.version,
                commit=args.commit,
                run_dirs={"analysis-37": args.analysis_run_37},
                output=args.output,
            )
        elif args.command == "analysis-schema":
            schema = analysis_attestation_json_schema()
            encoded = (
                json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            if args.output is None:
                sys.stdout.buffer.write(encoded)
            else:
                _atomic_write(args.output, encoded)
        elif args.command == "verify-release-executable":
            verify_release_executable(
                manifest=args.manifest,
                version=args.version,
                commit=args.commit,
                executable=args.executable,
                portable=args.portable,
            )
        elif args.command == "verify-candidate-assets":
            verify_candidate_release_assets(
                manifest=args.manifest,
                version=args.version,
                commit=args.commit,
                assets_manifest=args.assets_manifest,
                checksums=args.checksums,
                assets_dir=args.assets_dir,
            )
        elif args.command == "assemble-github-acceptance":
            assemble_github_acceptance_payload(
                version=args.version,
                commit=args.commit,
                repository=args.repository,
                acceptance_run_id=args.acceptance_run_id,
                acceptance_run_attempt=args.acceptance_run_attempt,
                acceptance_workflow_path=args.acceptance_workflow_path,
                runner_label=args.runner_label,
                candidate_run_id=args.candidate_run_id,
                analysis_run_dir=args.analysis_run_37,
                release_manifest=args.release_manifest,
                assets_manifest=args.assets_manifest,
                checksums=args.checksums,
                assets_dir=args.assets_dir,
                output_dir=args.output_dir,
            )
        elif args.command == "write-github-acceptance-closure":
            write_github_acceptance_closure(
                payload_dir=args.payload_dir,
                repository=args.repository,
                version=args.version,
                commit=args.commit,
                acceptance_run_id=args.acceptance_run_id,
                acceptance_run_attempt=args.acceptance_run_attempt,
                acceptance_workflow_path=args.acceptance_workflow_path,
                runner_label=args.runner_label,
                candidate_run_id=args.candidate_run_id,
                payload_artifact_id=args.payload_artifact_id,
                payload_artifact_digest=args.payload_artifact_digest,
                output=args.output,
            )
        elif args.command == "verify-github-acceptance":
            verify_github_acceptance_trust(
                reference_manifest=args.reference_manifest,
                release_manifest=args.release_manifest,
                run_metadata=args.run_metadata,
                artifacts_metadata=args.artifacts_metadata,
                payload_archive=args.payload_archive,
                closure_archive=args.closure_archive,
                repository=args.repository,
                version=args.version,
                commit=args.commit,
            )
        else:
            verify_release_attestation(
                args.manifest,
                version=args.version,
                commit=args.commit,
            )
    except (OSError, ValueError, ReleaseIntegrityError, zipfile.BadZipFile) as exc:
        print(f"release integrity failure: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

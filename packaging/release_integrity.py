#!/usr/bin/env python3
"""Fail-closed release attestation and Windows asset integrity utilities."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence


RELEASE_ATTESTATION_SCHEMA = "latexstruct-release-acceptance/2"
RUN_ATTESTATION_SCHEMA = "latexstruct-v2-ocr-acceptance-attestation/1"
ANALYSIS_ATTESTATION_SCHEMA = "latexstruct-v2-analysis-acceptance-attestation/2"
ANALYSIS_PERFORMANCE_SCHEMA = "latexstruct-v2-analysis-performance/1"
ANALYSIS_VALIDATION_SCHEMA = "latexstruct-v2-analysis-validation/1"
ANALYSIS_MACHINE_VERIFICATION_SCHEMA = "latexstruct-v2-analysis-machine-verification/1"
ASSET_MANIFEST_SCHEMA = "latexstruct-release-assets/1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
GITHUB_RUN_ID_RE = re.compile(r"[1-9][0-9]*")
PROFILE_SPECS = {
    "ocr-17": ("ocr", 17),
    "ocr-600": ("ocr", 600),
    "analysis-17": ("analysis", 17),
    "analysis-600": ("analysis", 600),
}
ANALYSIS_ARTIFACT_SPECS = {
    "candidate_tex": ("candidate.tex", "candidate_tex_sha256"),
    "candidate_pdf": ("candidate.pdf", "candidate_pdf_sha256"),
    "compile_log": ("compile.log", "compile_log_sha256"),
}


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
            "sha256": sha,
            "total_pages": {"type": "integer", "minimum": 1},
        },
    }
    review = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "review_id",
            "context_id",
            "context_sha256",
            "independent",
            "result",
            "candidate_tex_sha256",
            "pages_checked",
            "model_id",
            "backend",
            "calls",
        ],
        "properties": {
            "review_id": nonempty,
            "context_id": nonempty,
            "context_sha256": sha,
            "independent": {"const": True},
            "result": {"const": "PASS"},
            "candidate_tex_sha256": sha,
            "pages_checked": {"type": "integer", "minimum": 1},
            "model_id": nonempty,
            "backend": nonempty,
            "calls": {"type": "integer", "minimum": 1},
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
            "generated_at",
            "execution",
            "runtime_identity",
            "source",
            "selected_range",
            "models",
            "compilation",
            "artifacts",
            "timing",
            "independent_final_reviews",
            "machine_verification",
            "reports",
        ],
        "properties": {
            "schema_version": {"const": ANALYSIS_ATTESTATION_SCHEMA},
            "profile_kind": {"const": "analysis"},
            "profile": {"enum": ["analysis-17", "analysis-600"]},
            "result": {"const": "PASS"},
            "acceptance_passed": {"const": True},
            "terminal_status": {"const": "VERIFIED"},
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
            "source": source,
            "selected_range": {
                "type": "object",
                "additionalProperties": False,
                "required": ["start_page", "end_page", "expected_pages"],
                "properties": {
                    "start_page": {"const": 1},
                    "end_page": {"type": "integer", "minimum": 1},
                    "expected_pages": {"type": "integer", "minimum": 1},
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
            "independent_final_reviews": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": review,
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


def verify_release_notes(changelog: Path, version: str) -> None:
    try:
        text = changelog.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseIntegrityError(f"cannot read CHANGELOG: {exc}") from exc
    escaped = re.escape(version)
    match = re.search(
        rf"(?ms)^## v{escaped}(?:（[^\r\n]+\)|[^\r\n]*)\r?\n(?P<body>.*?)(?=^## |\Z)",
        text,
    )
    _require(match is not None and bool(match.group("body").strip()), f"CHANGELOG missing v{version}")
    body = match.group("body")
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

    _require(expected_pages in {17, 600}, "analysis profile must cover 17 or 600 pages")
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
            "generated_at",
            "execution",
            "runtime_identity",
            "source",
            "selected_range",
            "models",
            "compilation",
            "artifacts",
            "timing",
            "independent_final_reviews",
            "machine_verification",
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

    source = _require_exact_fields(
        root.get("source"),
        required={"filename", "sha256", "total_pages"},
        label="analysis source evidence",
    )
    source_name = _safe_relative_member(source.get("filename"))
    _require(source_name.suffix.lower() == ".pdf", "analysis source must be a PDF")
    _require(
        SHA256_RE.fullmatch(str(source.get("sha256") or "").lower()) is not None,
        "analysis source PDF SHA-256 is missing",
    )
    _require(int(source.get("total_pages") or 0) >= expected_pages, "analysis source PDF page count is too small")
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
        _require(bool(str(role.get("model_id") or "").strip()), f"analysis model id {index} is missing")
        _require(bool(str(role.get("backend") or "").strip()), f"analysis model backend {index} is missing")
        calls = int(role.get("calls") or 0)
        _require(calls > 0, f"analysis model role {index} has no real calls")
        role_calls += calls
        if role.get("role") in {"review", "visual_review"}:
            declared_review_calls += calls
            review_model_pairs.add(
                (str(role.get("model_id")), str(role.get("backend")))
            )
    _require(int(models.get("calls_total") or 0) == role_calls > 0, "analysis model call total is invalid")

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
                "review_id",
                "context_id",
                "context_sha256",
                "independent",
                "result",
                "candidate_tex_sha256",
                "pages_checked",
                "model_id",
                "backend",
                "calls",
            },
            label=f"independent final review {index}",
        )
        review_id = str(review.get("review_id") or "").strip()
        context_id = str(review.get("context_id") or "").strip()
        context_sha = str(review.get("context_sha256") or "").lower()
        _require(bool(review_id) and review_id not in review_ids, "final-review ids must be distinct")
        _require(bool(context_id) and context_id not in context_ids, "final reviews must use distinct context ids")
        _require(SHA256_RE.fullmatch(context_sha) is not None and context_sha not in context_hashes, "final reviews must use distinct context hashes")
        review_ids.add(review_id)
        context_ids.add(context_id)
        context_hashes.add(context_sha)
        _require(review.get("independent") is True, f"final review {index} is not independent")
        _require(review.get("result") == "PASS", f"final review {index} did not PASS")
        _require(str(review.get("candidate_tex_sha256") or "").lower() == candidate_sha, f"final review {index} checked a different candidate")
        _require(int(review.get("pages_checked") or 0) == expected_pages, f"final review {index} page coverage mismatch")
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
    if expected_pages == 600:
        thresholds = performance.get("thresholds")
        _require(isinstance(thresholds, Mapping), "analysis-600 time thresholds are missing")
        maximum = float(thresholds.get("maximum_wall_time_seconds") or 0)
        _require(0 < maximum <= 10800, "analysis-600 wall-time threshold exceeds 10800 seconds")
        _require(performance.get("target_met") is True, "analysis-600 time target was not met")
        _require(float(timing.get("wall_time_seconds") or 0) <= maximum, "analysis-600 measured wall time exceeds its target")
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
    actual_profiles = set(run_dirs)
    required_profiles = set(PROFILE_SPECS)
    missing = sorted(required_profiles - actual_profiles)
    extra = sorted(actual_profiles - required_profiles)
    _require(
        not missing and not extra,
        "release requires exactly four real profiles "
        "(ocr-17, ocr-600, analysis-17, analysis-600); "
        f"missing={missing or 'none'}, unexpected={extra or 'none'}. "
        "The OCR acceptance runner cannot create analysis attestations; use "
        "tools/v2_analysis_acceptance.py and the analysis-schema contract.",
    )

    verified_runs: dict[str, dict[str, Any]] = {}
    for profile, (kind, expected_pages) in PROFILE_SPECS.items():
        source_dir = run_dirs[profile]
        if kind == "ocr":
            verified = verify_run_attestation(
                source_dir,
                expected_pages=expected_pages,
                version=version,
                commit=normalized_commit,
            )
        else:
            verified = verify_analysis_attestation(
                source_dir,
                expected_pages=expected_pages,
                version=version,
                commit=normalized_commit,
            )
        verified_runs[profile] = verified

    runtime_identities = [
        verified_runs[profile]["runtime_identity"] for profile in PROFILE_SPECS
    ]
    _require(
        all(identity == runtime_identities[0] for identity in runtime_identities[1:]),
        "all four profiles must test the same commit/build_id/executable SHA",
    )
    for pages in (17, 600):
        ocr = verified_runs[f"ocr-{pages}"]
        analysis = verified_runs[f"analysis-{pages}"]
        _require(
            analysis["source"] == ocr["source"],
            f"analysis-{pages} is not bound to the ocr-{pages} source PDF SHA",
        )
        _require(
            analysis["selected_range"] == ocr["selected_range"],
            f"analysis-{pages} selected range differs from ocr-{pages}",
        )
    records: dict[str, Any] = {}
    filenames_by_kind = {
        "ocr": (
            "acceptance-attestation.json",
            "performance.json",
            "validation-report.json",
        ),
        "analysis": (
            "analysis-attestation.json",
            "analysis-performance.json",
            "analysis-validation-report.json",
            "analysis-machine-verification.json",
            *(filename for filename, _field in ANALYSIS_ARTIFACT_SPECS.values()),
        ),
    }
    attestation_filename = {
        "ocr": "acceptance-attestation.json",
        "analysis": "analysis-attestation.json",
    }
    for profile, (kind, _expected_pages) in PROFILE_SPECS.items():
        source_dir = run_dirs[profile]
        destination = output.parent / profile
        destination.mkdir(parents=True, exist_ok=True)
        for filename in filenames_by_kind[kind]:
            _atomic_write(destination / filename, (source_dir / filename).read_bytes())
        relative = Path(profile) / attestation_filename[kind]
        records[profile] = {
            "profile_kind": kind,
            "path": relative.as_posix(),
            "sha256": _sha256_file(output.parent / relative),
        }
    payload = {
        "schema_version": RELEASE_ATTESTATION_SCHEMA,
        "version": version,
        "commit": normalized_commit,
        "required_profiles": list(PROFILE_SPECS),
        "runtime_identity": dict(runtime_identities[0]),
        "tested_executable_sha256": str(
            runtime_identities[0]["executable_sha256"]
        ).lower(),
        "sources": {
            "17": dict(verified_runs["ocr-17"]["source"]),
            "600": dict(verified_runs["ocr-600"]["source"]),
        },
        "verification": {
            "profile_count": 4,
            "all_profiles_passed": True,
            "analysis_terminal_status": "VERIFIED",
        },
        "runs": records,
    }
    _atomic_json(output, payload)
    return payload


def verify_release_attestation(
    manifest: Path,
    *,
    version: str,
    commit: str,
) -> dict[str, Any]:
    payload = _load_json(manifest)
    run_probe = payload.get("runs")
    missing_analysis = [
        profile
        for profile in ("analysis-17", "analysis-600")
        if not isinstance(run_probe, Mapping) or profile not in run_probe
    ]
    _require(
        not missing_analysis,
        "missing required real analysis attestations: "
        f"{', '.join(missing_analysis)}. OCR evidence cannot substitute for them; "
        "generate them with tools/v2_analysis_acceptance.py using the "
        "analysis-schema contract.",
    )
    payload = dict(
        _require_exact_fields(
            payload,
            required={
                "schema_version",
                "version",
                "commit",
                "required_profiles",
                "runtime_identity",
                "tested_executable_sha256",
                "sources",
                "verification",
                "runs",
            },
            label="release attestation",
        )
    )
    normalized_commit = str(commit or "").strip().lower()
    _require(COMMIT_RE.fullmatch(normalized_commit) is not None, "invalid release commit")
    _require(payload.get("schema_version") == RELEASE_ATTESTATION_SCHEMA, "unsupported release attestation schema")
    _require(payload.get("version") == version, "release attestation version mismatch")
    _require(str(payload.get("commit") or "").lower() == normalized_commit, "release attestation commit mismatch")
    _require(
        payload.get("required_profiles") == list(PROFILE_SPECS),
        "release attestation required-profile summary is invalid",
    )
    runs = payload.get("runs")
    _require(
        isinstance(runs, Mapping) and set(runs) == set(PROFILE_SPECS),
        "release attestation must contain exactly ocr-17, ocr-600, "
        "analysis-17, and analysis-600; missing analysis evidence keeps the gate closed",
    )
    verified_runs: dict[str, dict[str, Any]] = {}
    for profile, (kind, expected_pages) in PROFILE_SPECS.items():
        record = runs.get(profile)
        record = _require_exact_fields(
            record,
            required={"profile_kind", "path", "sha256"},
            label=f"{profile} release record",
        )
        _require(record.get("profile_kind") == kind, f"{profile} kind mismatch")
        relative = _safe_relative_member(record.get("path"))
        filename = (
            "acceptance-attestation.json"
            if kind == "ocr"
            else "analysis-attestation.json"
        )
        expected_relative = Path(profile) / filename
        _require(relative == expected_relative, f"unexpected {profile} attestation path")
        path = manifest.parent / relative
        digest = str(record.get("sha256") or "").lower()
        _require(SHA256_RE.fullmatch(digest) is not None, f"{profile} attestation SHA-256 is invalid")
        _require(path.is_file() and _sha256_file(path) == digest, f"{profile} attestation digest mismatch")
        if kind == "ocr":
            verified = verify_run_attestation(
                path.parent,
                expected_pages=expected_pages,
                version=version,
                commit=normalized_commit,
            )
        else:
            verified = verify_analysis_attestation(
                path.parent,
                expected_pages=expected_pages,
                version=version,
                commit=normalized_commit,
            )
        verified_runs[profile] = verified
    runtime_identities = [
        verified_runs[profile]["runtime_identity"] for profile in PROFILE_SPECS
    ]
    _require(
        all(identity == runtime_identities[0] for identity in runtime_identities[1:]),
        "all four profiles must test the same commit/build_id/executable SHA",
    )
    _require(
        payload.get("runtime_identity") == runtime_identities[0],
        "release runtime-identity summary differs from verified profiles",
    )
    _require(
        str(payload.get("tested_executable_sha256") or "").lower()
        == str(runtime_identities[0].get("executable_sha256") or "").lower(),
        "release tested-executable summary differs from verified profiles",
    )
    for pages in (17, 600):
        ocr = verified_runs[f"ocr-{pages}"]
        analysis = verified_runs[f"analysis-{pages}"]
        _require(
            analysis["source"] == ocr["source"],
            f"analysis-{pages} is not bound to the ocr-{pages} source PDF SHA",
        )
        _require(
            analysis["selected_range"] == ocr["selected_range"],
            f"analysis-{pages} selected range differs from ocr-{pages}",
        )
    _require(
        payload.get("sources")
        == {
            "17": verified_runs["ocr-17"]["source"],
            "600": verified_runs["ocr-600"]["source"],
        },
        "release source-PDF summary differs from verified profiles",
    )
    _require(
        payload.get("verification")
        == {
            "profile_count": 4,
            "all_profiles_passed": True,
            "analysis_terminal_status": "VERIFIED",
        },
        "release verification summary is not a four-profile VERIFIED PASS",
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
    """Bind the bytes being released to the executable used by all four profiles."""

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
        "release executable SHA-256 differs from the executable tested by all four profiles",
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
        "portable LaTeXStruct.exe SHA-256 differs from the executable tested by all four profiles",
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
    the four-profile attestation, re-computes every digest, and verifies the
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
        "candidate artifact commit differs from the four-profile tested commit",
    )
    _require(
        str(asset_payload.get("build_id") or "").strip() == build_id,
        "candidate artifact build id differs from the four-profile GitHub run id",
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
        "all four profiles",
    )
    return {
        "version": version,
        "commit": normalized_commit,
        "build_id": build_id,
        "tested_executable_sha256": tested_executable_sha,
        "portable_executable_sha256": portable_executable_sha,
        "assets": records,
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
    notes.add_argument("--version", required=True)

    assemble = subparsers.add_parser("assemble-attestations")
    assemble.add_argument("--version", required=True)
    assemble.add_argument("--commit", required=True)
    assemble.add_argument("--run-17", type=Path, required=True)
    assemble.add_argument("--run-600", type=Path, required=True)
    assemble.add_argument("--analysis-run-17", type=Path, required=True)
    assemble.add_argument("--analysis-run-600", type=Path, required=True)
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
            verify_release_notes(args.changelog, args.version)
        elif args.command == "assemble-attestations":
            assemble_release_attestation(
                version=args.version,
                commit=args.commit,
                run_dirs={
                    "ocr-17": args.run_17,
                    "ocr-600": args.run_600,
                    "analysis-17": args.analysis_run_17,
                    "analysis-600": args.analysis_run_600,
                },
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

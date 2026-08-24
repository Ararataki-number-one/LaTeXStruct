#!/usr/bin/env python3
"""Fail-closed release attestation and Windows asset integrity utilities."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


RELEASE_ATTESTATION_SCHEMA = "latexstruct-release-acceptance/4"
RUN_ATTESTATION_SCHEMA = "latexstruct-v2-ocr-acceptance-attestation/2"
ANALYSIS_ATTESTATION_SCHEMA = "latexstruct-v2-analysis-acceptance-attestation/4"
ANALYSIS_PERFORMANCE_SCHEMA = "latexstruct-v2-analysis-performance/1"
ANALYSIS_VALIDATION_SCHEMA = "latexstruct-v2-analysis-validation/1"
ANALYSIS_MACHINE_VERIFICATION_SCHEMA = "latexstruct-v2-analysis-machine-verification/1"
ASSET_MANIFEST_SCHEMA = "latexstruct-release-assets/1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
GITHUB_RUN_ID_RE = re.compile(r"[1-9][0-9]*")
RAMSEY_37_SOURCE_SHA256 = (
    "29074289719d99d7fc89f528cc0b140c27be679ea5d2477fe517eff741e7757c"
)
PROFILE_SPECS = {"analysis-37": ("analysis", 37)}
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
    baseline_pdf = descriptors.get("BASELINE_PDF")
    page_map = descriptors.get("PAGE_MAP")
    _require(
        isinstance(baseline_pdf, Mapping) and isinstance(page_map, Mapping),
        "OCR compiled baseline lacks PDF/page-map artifacts",
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
            "quality_tier",
            "template",
            "generated_at",
            "execution",
            "runtime_identity",
            "service_binding",
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
                },
            },
            "page_layout": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source_page_count",
                    "candidate_page_count",
                    "maximum_candidate_pages",
                    "page_growth",
                    "candidate_only_pages",
                    "candidate_mapping_sha256",
                    "no_abnormal_page_inflation",
                    "active_tableofcontents_count",
                    "template",
                ],
                "properties": {
                    "source_page_count": {"const": 37},
                    "candidate_page_count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 42,
                    },
                    "maximum_candidate_pages": {"const": 42},
                    "page_growth": {"type": "integer", "maximum": 5},
                    "candidate_only_pages": {
                        "type": "array",
                        "maxItems": 5,
                        "uniqueItems": True,
                        "items": {"type": "integer", "minimum": 1, "maximum": 42},
                    },
                    "candidate_mapping_sha256": sha,
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
        SHA256_RE.fullmatch(str(visual.get("page_id_set_sha256") or "").lower())
        is not None,
        "visual page-id coverage digest is missing",
    )
    _require(
        str(visual.get("candidate_tex_sha256") or "").lower() == candidate_sha
        and str(visual.get("candidate_pdf_sha256") or "").lower()
        == str(compilation.get("candidate_pdf_sha256") or "").lower(),
        "visual verification checked different candidate bytes",
    )
    _require(
        visual.get("render_compare_closed_loop") is True,
        "compile-render-compare-fix-recompile loop was not attested",
    )

    page_layout = _require_exact_fields(
        root.get("page_layout"),
        required={
            "source_page_count",
            "candidate_page_count",
            "maximum_candidate_pages",
            "page_growth",
            "candidate_only_pages",
            "candidate_mapping_sha256",
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
        and 0 < candidate_page_count <= 42
        and int(page_layout.get("maximum_candidate_pages") or 0) == 42
        and int(page_layout.get("page_growth") or 0) == candidate_page_count - 37
        and int(page_layout.get("page_growth") or 0) <= 5,
        "analysis-37 final PDF has abnormal page inflation",
    )
    _require(
        _pdf_page_count(run_dir / "candidate.pdf") == candidate_page_count,
        "analysis-37 candidate PDF page count differs from the declared layout evidence",
    )
    _require(
        isinstance(candidate_only_pages, list)
        and len(candidate_only_pages) <= 5
        and len(candidate_only_pages) == len(set(candidate_only_pages))
        and all(
            isinstance(page, int) and 1 <= page <= candidate_page_count
            for page in candidate_only_pages
        )
        and SHA256_RE.fullmatch(
            str(page_layout.get("candidate_mapping_sha256") or "").lower()
        )
        is not None,
        "analysis-37 candidate-only page mapping is invalid",
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
    selected = _require_exact_fields(
        projection.get("selected_range"),
        required={"start_page", "end_page", "expected_pages"},
        label="analysis-37 selected range",
    )
    _require(
        selected == {"start_page": 1, "end_page": 37, "expected_pages": 37},
        "analysis-37 projection does not cover pages 1-37",
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
            and bool(str(role.get("model_id") or "").strip())
            and bool(str(role.get("backend") or "").strip())
            and calls > 0,
            f"projected model role {index} is invalid",
        )
        projected_calls += calls
        projected_role_names.add(role_name)
    _require(
        int(models.get("calls_total") or 0) == projected_calls
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
        review = _require_exact_fields(review_value, required={"review_id", "context_id", "context_sha256", "independent", "result", "candidate_tex_sha256", "pages_checked", "model_id", "backend", "calls"}, label=f"projected final review {index}")
        context_id = str(review.get("context_id") or "")
        context_sha = str(review.get("context_sha256") or "").lower()
        review_id = str(review.get("review_id") or "")
        _require(
            review_id and review_id not in review_ids
            and context_id and context_id not in context_ids
            and SHA256_RE.fullmatch(context_sha) is not None and context_sha not in context_hashes
            and review.get("independent") is True
            and review.get("result") == "PASS"
            and str(review.get("candidate_tex_sha256") or "").lower() == candidate_sha
            and int(review.get("pages_checked") or 0) == 37
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
        required={"passed", "expected_pages", "pages_checked", "independent_review_passes", "model_calls", "page_id_set_sha256", "candidate_tex_sha256", "candidate_pdf_sha256", "render_compare_closed_loop"},
        label="projected visual verification",
    )
    _require(
        visual.get("passed") is True
        and int(visual.get("expected_pages") or 0) == 37
        and int(visual.get("pages_checked") or 0) == 37
        and int(visual.get("independent_review_passes") or 0) == 2
        and int(visual.get("model_calls") or 0) == 74
        and SHA256_RE.fullmatch(str(visual.get("page_id_set_sha256") or "").lower()) is not None
        and str(visual.get("candidate_tex_sha256") or "").lower() == candidate_sha
        and str(visual.get("candidate_pdf_sha256") or "").lower() == str(compilation.get("candidate_pdf_sha256") or "").lower()
        and visual.get("render_compare_closed_loop") is True,
        "projected visual verification is not a complete 37-page closed loop",
    )
    page_layout = _require_exact_fields(
        projection.get("page_layout"),
        required={"source_page_count", "candidate_page_count", "maximum_candidate_pages", "page_growth", "candidate_only_pages", "candidate_mapping_sha256", "no_abnormal_page_inflation", "active_tableofcontents_count", "template"},
        label="projected final page-layout evidence",
    )
    projected_candidate_pages = int(page_layout.get("candidate_page_count") or 0)
    projected_candidate_only = page_layout.get("candidate_only_pages")
    _require(
        int(page_layout.get("source_page_count") or 0) == 37
        and 0 < projected_candidate_pages <= 42
        and int(page_layout.get("maximum_candidate_pages") or 0) == 42
        and int(page_layout.get("page_growth") or 0) == projected_candidate_pages - 37
        and int(page_layout.get("page_growth") or 0) <= 5
        and isinstance(projected_candidate_only, list)
        and len(projected_candidate_only) <= 5
        and len(projected_candidate_only) == len(set(projected_candidate_only))
        and all(isinstance(page, int) and 1 <= page <= projected_candidate_pages for page in projected_candidate_only)
        and SHA256_RE.fullmatch(str(page_layout.get("candidate_mapping_sha256") or "").lower()) is not None
        and page_layout.get("no_abnormal_page_inflation") is True
        and int(page_layout.get("active_tableofcontents_count") or 0) == 1
        and page_layout.get("template") == "faithfulbook",
        "projected final PDF page count/mapping/automatic TOC gate is invalid",
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

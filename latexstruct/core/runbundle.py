# -*- coding: utf-8 -*-
"""Deterministic audit artifacts for every exported project run bundle.

The normal project archive remains the transport container.  This module adds
small, machine-readable evidence files without changing any TeX, PDF, image,
or class resource already present in that archive.  ``SHA256SUMS`` covers every
member except itself, avoiding a circular digest while making the rest of the
bundle independently recomputable.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from collections.abc import Mapping

from .preview import preview_artifact_path


RUN_MANIFEST_NAME = "LATEXSTRUCT-RUN.json"
REPORT_JSON_NAME = "LATEXSTRUCT-REPORT.json"
ISSUES_CSV_NAME = "LATEXSTRUCT-ISSUES.csv"
VERIFICATION_JSON_NAME = "LATEXSTRUCT-VERIFICATION.json"
DECISIONS_JSON_NAME = "LATEXSTRUCT-DECISIONS.json"
SHA256SUMS_NAME = "SHA256SUMS"

RUN_BUNDLE_NAMES = frozenset({
    RUN_MANIFEST_NAME,
    REPORT_JSON_NAME,
    ISSUES_CSV_NAME,
    VERIFICATION_JSON_NAME,
    DECISIONS_JSON_NAME,
    SHA256SUMS_NAME,
})

PREVIEW_STATES = frozenset({
    "COMPILED",
    "PARTIAL_COMPILED",
    "SOURCE_PREVIEW",
})

TERMINAL_STATES = frozenset({
    "SUCCESS",
    "UNVERIFIED",
    "FAILED",
    "PARTIAL",
    "CANCELLED",
})
WINDOWS_DEVICE_STEMS = frozenset({
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
})


def _portable_archive_path(name: str, *, is_directory: bool) -> tuple[str, ...]:
    """Return a Windows-safe, case-insensitive namespace key for a ZIP member.

    ZIP member names normally use ``/`` even on Windows, but some producers
    store backslashes. Treat both as separators so an archive cannot hide a
    collision that appears only after extraction. Windows also aliases a final
    dot or space away from each path component; reject those names instead of
    silently rewriting them.
    """
    raw = str(name or "").replace("\\", "/")
    if is_directory:
        if not raw.endswith("/"):
            raise ValueError("ZIP directory entry has no trailing slash")
        raw = raw[:-1]
    if not raw or raw.startswith("/"):
        raise ValueError("project archive contains an unsafe empty or absolute path")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("project archive contains an unsafe path component")
    if any(":" in part or "\x00" in part for part in parts):
        raise ValueError("project archive contains a Windows-unsafe path component")
    if any(part.endswith((".", " ")) for part in parts):
        raise ValueError(
            "project archive member has a Windows-unsafe trailing dot or space"
        )
    if any(
        part.split(".", 1)[0].rstrip(" .").casefold() in WINDOWS_DEVICE_STEMS
        for part in parts
    ):
        raise ValueError("project archive member uses a reserved Windows device name")
    return tuple(part.casefold() for part in parts)


def validate_archive_namespace(
    entries: list[tuple[str, bool]],
    *,
    additions: tuple[str, ...] = (),
) -> None:
    """Reject cross-platform duplicate and file/directory archive collisions."""
    canonical: list[tuple[str, tuple[str, ...], bool]] = []
    for name, is_directory in entries:
        canonical.append(
            (name, _portable_archive_path(name, is_directory=is_directory), is_directory)
        )
    canonical.extend(
        (name, _portable_archive_path(name, is_directory=False), False)
        for name in additions
    )

    seen: dict[tuple[str, ...], tuple[str, bool]] = {}
    for name, path, is_directory in canonical:
        previous = seen.get(path)
        if previous is not None:
            raise ValueError(
                "project archive contains cross-platform duplicate member names: "
                f"{previous[0]}, {name}"
            )
        seen[path] = (name, is_directory)

    for name, path, _is_directory in canonical:
        for length in range(1, len(path)):
            ancestor = seen.get(path[:length])
            if ancestor is not None and not ancestor[1]:
                raise ValueError(
                    "project archive contains a file/directory path collision: "
                    f"{ancestor[0]}, {name}"
                )


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def preview_state_from_verification(verification: Mapping | None) -> str:
    """Return the honest preview tier established by recorded compile evidence."""
    verification = verification if isinstance(verification, Mapping) else {}
    compiled = verification.get("compile_after")
    if not isinstance(compiled, Mapping) or not compiled.get("available"):
        return "SOURCE_PREVIEW"
    explicit = str(compiled.get("preview_status") or "")
    if explicit == "SOURCE_PREVIEW":
        return "SOURCE_PREVIEW"
    # v1.2.4 and older recorded compile success but did not preserve the PDF.
    # Such projects remain exportable, while their package preview honestly
    # falls back to source until a hash-bound artifact exists.
    evidence = verification.get("preview_artifact")
    if not isinstance(evidence, Mapping) or not evidence:
        return "SOURCE_PREVIEW"
    evidence_status = str(evidence.get("status") or "")
    if (
        compiled.get("ok") is True
        and explicit in {"", "COMPILED"}
        and evidence_status == "COMPILED"
    ):
        return "COMPILED"
    if (
        compiled.get("ok") is not True
        and explicit == "PARTIAL_COMPILED"
        and evidence_status == "PARTIAL_COMPILED"
    ):
        return "PARTIAL_COMPILED"
    return "SOURCE_PREVIEW"


def normalize_terminal_status(value: object, *, verified: bool = False) -> str:
    """Map API/job vocabulary onto the stable run-bundle terminal contract."""
    status = str(value or "").strip().upper()
    aliases = {
        "DONE": "SUCCESS" if verified else "UNVERIFIED",
        "COMMITTED": "SUCCESS" if verified else "UNVERIFIED",
        "BLOCKED": "UNVERIFIED",
        "SOURCE": "UNVERIFIED",
        "ERROR": "FAILED",
    }
    normalized = aliases.get(status, status)
    if verified:
        return "SUCCESS"
    return normalized if normalized in TERMINAL_STATES else "UNVERIFIED"


def _issue_rows(info: Mapping) -> list[dict[str, object]]:
    verification = info.get("verification")
    verification = verification if isinstance(verification, Mapping) else {}
    rows: list[dict[str, object]] = []

    failures = info.get("failures")
    if not isinstance(failures, list):
        failures = verification.get("failures")
    if isinstance(failures, list):
        for index, item in enumerate(failures, 1):
            if not isinstance(item, Mapping):
                continue
            rows.append({
                "issue_id": f"BLOCKER-{index:03d}",
                "severity": "blocker",
                "category": str(item.get("id") or "verification"),
                "status": "open",
                "candidate_id": "",
                "line": "",
                "message": str(item.get("summary") or item.get("label") or ""),
                "next_action": str(item.get("action") or ""),
            })

    ambiguous = info.get("ambiguous")
    if isinstance(ambiguous, list):
        for index, item in enumerate(ambiguous, 1):
            if not isinstance(item, Mapping):
                continue
            rows.append({
                "issue_id": f"AMBIGUOUS-{index:03d}",
                "severity": "review",
                "category": "structure",
                "status": "open",
                "candidate_id": str(item.get("candidate_id") or ""),
                "line": item.get("line") or "",
                "message": str(item.get("reason") or ""),
                "next_action": "人工核对源页面后重新分析",
            })

    rejected = info.get("rejected")
    if isinstance(rejected, list):
        for index, item in enumerate(rejected, 1):
            if not isinstance(item, Mapping):
                continue
            rows.append({
                "issue_id": f"REJECTED-{index:03d}",
                "severity": "diagnostic",
                "category": "patch",
                "status": "preserved",
                "candidate_id": str(item.get("candidate_id") or ""),
                "line": "",
                "message": str(item.get("error") or item.get("reason") or ""),
                "next_action": "原文已保留；需要时查看 Markdown 报告",
            })
    if (
        verification.get("safe_to_export") is not True
        and not any(row["severity"] == "blocker" for row in rows)
    ):
        rows.insert(0, {
            "issue_id": "BLOCKER-001",
            "severity": "blocker",
            "category": "verification",
            "status": "open",
            "candidate_id": "",
            "line": "",
            "message": "没有与当前工件绑定的完整通过记录",
            "next_action": "重新分析并通过全部机器检查后再作为已验证成品交付",
        })
    return rows


def _issues_csv_bytes(rows: list[dict[str, object]]) -> bytes:
    columns = (
        "issue_id",
        "severity",
        "category",
        "status",
        "candidate_id",
        "line",
        "message",
        "next_action",
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _identity_from_provenance(provenance: Mapping, prefix: str) -> dict[str, str]:
    return {
        "app_version": str(provenance.get(f"{prefix}_app_version") or "unknown"),
        "build_id": str(provenance.get(f"{prefix}_build_id") or "unknown"),
        "commit": str(provenance.get(f"{prefix}_commit") or "unknown"),
    }


def _valid_digest(value: object) -> str:
    digest = str(value or "").strip().lower()
    return digest if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest) else "unknown"


def _bound_preview_artifact(
    *,
    preview_state: str,
    verification: Mapping,
    base_files: Mapping[str, bytes],
    main_path: str,
) -> tuple[str, bool]:
    """Resolve a preview only when its recorded digest binds it to the archive."""
    if preview_state == "SOURCE_PREVIEW":
        return main_path, False

    digest = _valid_digest(
        verification.get("preview_artifact", {}).get("sha256")
        if isinstance(verification.get("preview_artifact"), Mapping)
        else None
    )
    evidence = verification.get("preview_artifact")
    if not isinstance(evidence, Mapping) or not evidence or digest == "unknown":
        raise ValueError("compiled preview has no hash-bound artifact evidence")
    expected_name = preview_artifact_path(preview_state, digest)
    filename = str(evidence.get("filename") or "")
    if evidence.get("status") != preview_state:
        raise ValueError("compiled preview evidence conflicts with its preview state")
    if filename != expected_name:
        raise ValueError("compiled preview filename conflicts with its preview state")
    payload = base_files.get(filename)
    if payload is None:
        raise ValueError("compiled preview artifact is missing from the project archive")
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("compiled preview artifact does not match its recorded digest")
    recorded_bytes = evidence.get("bytes")
    if recorded_bytes is not None and recorded_bytes != len(payload):
        raise ValueError("compiled preview artifact does not match its recorded size")
    return filename, True


def _lineage_records(
    base_files: Mapping[str, bytes],
    provenance: Mapping,
    main_path: str,
) -> list[dict[str, object]]:
    source_digest = _valid_digest(provenance.get("source_sha256"))
    raw_digest = _valid_digest(
        provenance.get("raw_bytes_sha256") or provenance.get("raw_sha256")
    )
    body_digest = _valid_digest(provenance.get("body_sha256"))
    source_path = "external-or-legacy-source"
    if source_digest != "unknown":
        for name, data in base_files.items():
            if hashlib.sha256(data).hexdigest() == source_digest:
                source_path = name
                break
    raw_path = str(provenance.get("raw_artifact_path") or "unknown")
    main_bytes_digest = (
        hashlib.sha256(base_files[main_path]).hexdigest()
        if main_path in base_files
        else "unknown"
    )
    source_id = f"sha256:{source_digest}"
    raw_id = f"sha256:{raw_digest}"
    body_id = f"sha256:{body_digest}"
    return [
        {
            "artifact_id": source_id,
            "role": "source-document",
            "path": source_path,
            "bytes_sha256": source_digest,
            "normalized_text_sha256": "not-applicable",
            "normalization_pipeline": "none",
            "parent_artifact_ids": [],
        },
        {
            "artifact_id": raw_id,
            "role": str(provenance.get("raw_artifact_role") or "analysis-input-tex"),
            "path": raw_path,
            "bytes_sha256": raw_digest,
            "normalized_text_sha256": _valid_digest(
                provenance.get("raw_normalized_text_sha256")
            ),
            "normalization_pipeline": str(
                provenance.get("raw_normalization_pipeline") or "unknown"
            ),
            "parent_artifact_ids": [source_id],
        },
        {
            "artifact_id": body_id,
            "role": "unstamped-result-tex",
            "path": f"{main_path}#without-provenance",
            "bytes_sha256": body_digest,
            "normalized_text_sha256": "unknown",
            "normalization_pipeline": "none",
            "parent_artifact_ids": [raw_id],
        },
        {
            "artifact_id": f"sha256:{main_bytes_digest}",
            "role": "exported-main-tex",
            "path": main_path,
            "bytes_sha256": main_bytes_digest,
            "normalized_text_sha256": "unknown",
            "normalization_pipeline": "provenance-comment-stamp",
            "parent_artifact_ids": [body_id],
        },
    ]


def build_run_bundle_artifacts(
    *,
    base_files: Mapping[str, bytes],
    info: Mapping | None,
    provenance: Mapping | None,
    terminal_status: str,
    attempt: str,
    main_path: str,
) -> dict[str, bytes]:
    """Build deterministic audit files for an already assembled archive."""
    info = info if isinstance(info, Mapping) else {}
    provenance = provenance if isinstance(provenance, Mapping) else {}
    verification = info.get("verification")
    verification = verification if isinstance(verification, Mapping) else {}
    safe = verification.get("safe_to_export") is True
    terminal_status = normalize_terminal_status(terminal_status, verified=safe)
    preview_state = preview_state_from_verification(verification)
    preview_artifact, compiled_pdf_included = _bound_preview_artifact(
        preview_state=preview_state,
        verification=verification,
        base_files=base_files,
        main_path=main_path,
    )
    issues = _issue_rows(info)
    blockers = [row for row in issues if row["severity"] == "blocker"]

    decisions_payload = {
        "schema": "latexstruct-decisions-export-v1",
        "items": info.get("items") if isinstance(info.get("items"), list) else [],
        "applied": info.get("applied") if isinstance(info.get("applied"), list) else [],
        "rejected": info.get("rejected") if isinstance(info.get("rejected"), list) else [],
        "ambiguous": info.get("ambiguous") if isinstance(info.get("ambiguous"), list) else [],
        "ai_notes": info.get("ai_notes") if isinstance(info.get("ai_notes"), list) else [],
        "review": info.get("review") if isinstance(info.get("review"), Mapping) else {},
    }
    report_payload = {
        "schema": "latexstruct-audit-report-v1",
        "verification_status": "VERIFIED" if safe else "UNVERIFIED",
        "terminal_status": str(terminal_status or "unknown"),
        "attempt": str(attempt or "unknown"),
        "safe_to_export": safe,
        "preview_state": preview_state,
        "first_open": main_path if safe else "LATEXSTRUCT-REPORT.md",
        "why_unverified": [row["message"] for row in blockers],
        "blocker_count": len(blockers),
        "issue_count": len(issues),
        "checks": verification.get("checks")
        if isinstance(verification.get("checks"), list)
        else [],
        "structure": verification.get("structure_decisions")
        if isinstance(verification.get("structure_decisions"), Mapping)
        else {},
        "compile": {
            "summary": verification.get("compile")
            if isinstance(verification.get("compile"), Mapping)
            else {},
            "before": verification.get("compile_before")
            if isinstance(verification.get("compile_before"), Mapping)
            else {},
            "after": verification.get("compile_after")
            if isinstance(verification.get("compile_after"), Mapping)
            else {},
            "artifact": verification.get("preview_artifact")
            if isinstance(verification.get("preview_artifact"), Mapping)
            else {},
        },
    }
    run_payload = {
        "schema": "latexstruct-run-bundle-v1",
        "terminal_status": str(terminal_status or "unknown"),
        "verification_status": "VERIFIED" if safe else "UNVERIFIED",
        "attempt": str(attempt or "unknown"),
        "main_artifact": main_path,
        "preview": {
            "state": preview_state,
            "artifact": preview_artifact,
            "compiled_pdf_included": compiled_pdf_included,
        },
        "producer_identity": _identity_from_provenance(provenance, "producer"),
        "exporter_identity": _identity_from_provenance(provenance, "exporter"),
        "provenance_schema": str(provenance.get("schema_version") or "unknown"),
        "lineage": _lineage_records(base_files, provenance, main_path),
        "artifact_inventory": sorted({*base_files, *RUN_BUNDLE_NAMES}),
        "hash_manifest": SHA256SUMS_NAME,
        "hash_manifest_encoding": "UTF-8",
        "hash_manifest_format": "sha256, two spaces, filename, LF",
        "hash_manifest_scope": "every archive member except SHA256SUMS itself",
    }

    artifacts = {
        VERIFICATION_JSON_NAME: _json_bytes(verification),
        DECISIONS_JSON_NAME: _json_bytes(decisions_payload),
        REPORT_JSON_NAME: _json_bytes(report_payload),
        ISSUES_CSV_NAME: _issues_csv_bytes(issues),
        RUN_MANIFEST_NAME: _json_bytes(run_payload),
    }
    digested = {**base_files, **artifacts}
    if any("\n" in name or "\r" in name for name in digested):
        raise ValueError("project archive member names cannot contain CR or LF")
    artifacts[SHA256SUMS_NAME] = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        for name, data in sorted(digested.items())
    ).encode("utf-8")
    return artifacts


def append_run_bundle(
    archive_bytes: bytes,
    *,
    info: Mapping | None,
    provenance: Mapping | None,
    terminal_status: str,
    attempt: str,
    main_path: str,
) -> bytes:
    """Append one canonical audit set to a ZIP, rejecting ambiguous duplicates."""
    output = io.BytesIO(bytes(archive_bytes))
    with zipfile.ZipFile(output, "a", zipfile.ZIP_DEFLATED) as archive:
        member_info = archive.infolist()
        names = [member.filename for member in member_info]
        if len(names) != len(set(names)):
            raise ValueError("project archive contains duplicate member names")
        folded_names: dict[str, str] = {}
        for name in names:
            folded = name.casefold()
            if folded in folded_names:
                raise ValueError(
                    "project archive contains case-insensitive duplicate member names: "
                    f"{folded_names[folded]}, {name}"
                )
            folded_names[folded] = name
        reserved_folded = {name.casefold(): name for name in RUN_BUNDLE_NAMES}
        collisions = {
            original
            for folded, original in folded_names.items()
            if folded in reserved_folded
        }
        if collisions:
            raise ValueError(
                "project archive conflicts with reserved run-bundle files: "
                + ", ".join(sorted(collisions))
            )
        validate_archive_namespace(
            [(member.filename, member.is_dir()) for member in member_info],
            additions=tuple(sorted(RUN_BUNDLE_NAMES)),
        )
        base_files = {name: archive.read(name) for name in names}
        if main_path not in base_files:
            raise ValueError("project archive has no declared main artifact")
        artifacts = build_run_bundle_artifacts(
            base_files=base_files,
            info=info,
            provenance=provenance,
            terminal_status=terminal_status,
            attempt=attempt,
            main_path=main_path,
        )
        for name, data in artifacts.items():
            archive.writestr(name, data)
    return output.getvalue()

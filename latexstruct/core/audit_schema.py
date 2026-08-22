# -*- coding: utf-8 -*-
"""Typed contracts for deterministic external-AI audit submission bundles."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

AUDIT_SUBMISSION_SCHEMA_VERSION = "latexstruct-audit-submission-v1"
AUDIT_SNAPSHOT_SCHEMA_VERSION = "latexstruct-run-snapshot-v1"


class AuditWorkflow(str, Enum):
    ANALYSIS_REVIEW_ONLY = "ANALYSIS_REVIEW_ONLY"
    OCR_ONLY = "OCR_ONLY"
    OCR_ANALYSIS_REVIEW = "OCR_ANALYSIS_REVIEW"
    TEMPLATE_CONVERSION = "TEMPLATE_CONVERSION"
    MULTIFILE_PROJECT = "MULTIFILE_PROJECT"


class AuditProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"


class AuditTerminalStatus(str, Enum):
    SUCCESS = "SUCCESS"
    UNVERIFIED = "UNVERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


class AuditPreviewStatus(str, Enum):
    COMPILED = "COMPILED"
    PARTIAL_COMPILED = "PARTIAL_COMPILED"
    SOURCE_PREVIEW = "SOURCE_PREVIEW"


@dataclass(frozen=True)
class AuditSubmissionRequest:
    profile: AuditProfile = AuditProfile.STANDARD
    audit_focus: str = ""
    include_source: bool = True
    include_compile_logs: bool = True
    include_verification: bool = True
    include_evidence: bool = False
    sanitize: bool = True
    reviewed_candidate_ids: tuple[str, ...] = ()
    force: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "AuditSubmissionRequest":
        data = dict(value or {})
        try:
            profile = AuditProfile(str(data.get("profile") or AuditProfile.STANDARD.value))
        except ValueError as exc:
            raise ValueError("审计深度必须是 quick、standard 或 full") from exc
        focus = str(data.get("audit_focus") or data.get("focus") or "").strip()
        if len(focus) > 4000:
            raise ValueError("审计重点过长，请控制在 4000 字以内")
        reviewed = tuple(sorted({
            str(item).strip()
            for item in (data.get("reviewed_candidate_ids") or [])
            if str(item).strip()
        }))
        return cls(
            profile=profile,
            audit_focus=focus,
            include_source=bool(data.get("include_source", True)),
            include_compile_logs=bool(data.get("include_compile_logs", True)),
            include_verification=bool(data.get("include_verification", True)),
            include_evidence=bool(data.get("include_evidence", profile is AuditProfile.FULL)),
            sanitize=bool(data.get("sanitize", True)),
            reviewed_candidate_ids=reviewed,
            force=bool(data.get("force", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "audit_focus": self.audit_focus,
            "include_source": self.include_source,
            "include_compile_logs": self.include_compile_logs,
            "include_verification": self.include_verification,
            "include_evidence": self.include_evidence,
            "sanitize": self.sanitize,
            "reviewed_candidate_ids": list(self.reviewed_candidate_ids),
            "force": self.force,
        }


@dataclass(frozen=True)
class AuditArtifact:
    artifact_id: str
    artifact_role: str
    path: str
    bytes_sha256: str
    size_bytes: int
    media_type: str = "application/octet-stream"
    parents: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    alias_roles: tuple[str, ...] = ()
    source_sha256: str = ""
    status: str = "available"
    preview_status: AuditPreviewStatus | None = None
    sanitized: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "artifact_role": self.artifact_role,
            "path": self.path,
            "bytes_sha256": self.bytes_sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "parents": list(self.parents),
            "aliases": list(self.aliases),
            "alias_roles": list(self.alias_roles),
            "status": self.status,
            "sanitized": self.sanitized,
        }
        if self.source_sha256:
            result["source_sha256"] = self.source_sha256
        if self.preview_status is not None:
            result["preview_status"] = self.preview_status.value
        if self.metadata:
            result["metadata"] = dict(self.metadata)
        return result


@dataclass(frozen=True)
class RunSnapshot:
    snapshot_id: str
    project_id: str
    project_name: str
    workflow_type: AuditWorkflow
    terminal_status: AuditTerminalStatus
    verification_status: str
    generated_at_utc: str
    project_fingerprint: str
    reviewed_candidate_ids_sha256: str
    runtime: Mapping[str, Any]
    template: str = ""
    page_range: tuple[int, ...] = ()
    blockers: tuple[Mapping[str, Any], ...] = ()
    artifacts: tuple[AuditArtifact, ...] = ()
    missing_artifacts: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False)
    schema_version: str = AUDIT_SNAPSHOT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "project": {"id": self.project_id, "name": self.project_name},
            "workflow": {
                "type": self.workflow_type.value,
                "status": self.terminal_status.value,
                "verification_status": self.verification_status,
                "template": self.template,
            },
            "generated_at_utc": self.generated_at_utc,
            "project_fingerprint": self.project_fingerprint,
            "reviewed_candidate_ids_sha256": self.reviewed_candidate_ids_sha256,
            "runtime": dict(self.runtime),
            "page_range": list(self.page_range),
            "blockers": [dict(item) for item in self.blockers],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "missing_artifacts": [dict(item) for item in self.missing_artifacts],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AuditSubmissionManifest:
    submission_id: str
    snapshot: RunSnapshot
    profile: AuditProfile
    control_files: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    package_filename: str = ""
    schema_version: str = AUDIT_SUBMISSION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.snapshot.to_dict(),
            "schema_version": self.schema_version,
            "submission_id": self.submission_id,
            "profile": self.profile.value,
            "package_filename": self.package_filename,
            "control_files": {key: dict(value) for key, value in self.control_files.items()},
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class AuditSubmissionResult:
    submission_id: str
    manifest: AuditSubmissionManifest
    prompt_short: str
    prompt_full: str
    readme: str
    package_path: str = ""
    package_sha256: str = ""
    lightweight_only: bool = False
    stale: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        snapshot = self.manifest.snapshot
        return {
            "ok": True,
            "submission_id": self.submission_id,
            "status": snapshot.terminal_status.value,
            "verification_status": snapshot.verification_status,
            "workflow_type": snapshot.workflow_type.value,
            "profile": self.manifest.profile.value,
            "generated_at_utc": snapshot.generated_at_utc,
            "package_filename": self.manifest.package_filename,
            "package_sha256": self.package_sha256,
            "prompt_short": self.prompt_short,
            "warnings": list(self.manifest.warnings),
            "stale": self.stale,
            "lightweight_only": self.lightweight_only,
            "project_fingerprint": snapshot.project_fingerprint,
            "reviewed_candidate_ids_sha256": snapshot.reviewed_candidate_ids_sha256,
            "reviewed_candidate_ids": list(snapshot.metadata.get("reviewed_candidate_ids") or []),
        }

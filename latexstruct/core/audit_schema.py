# -*- coding: utf-8 -*-
"""Immutable data contract for AI audit submissions.

The host application assigns every artifact role, preview status and parent
relationship before this module sees a run.  In particular, none of these
values are inferred by a language model or by the prompt renderer.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .preview import PREVIEW_STATUSES


SCHEMA_VERSION = "latexstruct-ai-audit-submission-v1"


class AuditWorkflow(str, Enum):
    ANALYSIS_REVIEW_ONLY = "ANALYSIS_REVIEW_ONLY"
    OCR_ONLY = "OCR_ONLY"
    OCR_ANALYSIS_REVIEW = "OCR_ANALYSIS_REVIEW"
    TEMPLATE_CONVERSION = "TEMPLATE_CONVERSION"
    MULTIFILE_PROJECT = "MULTIFILE_PROJECT"


class TerminalStatus(str, Enum):
    SUCCESS = "SUCCESS"
    UNVERIFIED = "UNVERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


class AuditDepth(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"


# Roles are strings (instead of a closed Enum) so later versions can add
# evidence types without silently misclassifying them.  These constants are the
# built-in contract used by the package planner and by the server integration.
class ArtifactRole:
    SOURCE_TEX = "SOURCE_TEX"
    SOURCE_PDF = "SOURCE_PDF"
    SOURCE_IMAGE = "SOURCE_IMAGE"
    STAGE_SOURCE_TEX = "STAGE_SOURCE_TEX"
    RAW_OCR_TEX = "RAW_OCR_TEX"
    AI_ANALYZED_TEX = "AI_ANALYZED_TEX"
    RULE_ANALYZED_TEX = "RULE_ANALYZED_TEX"
    AI_REVIEWED_TEX = "AI_REVIEWED_TEX"
    CURRENT_TEX = "CURRENT_TEX"
    CURRENT_PREVIEW = "CURRENT_PREVIEW"
    RAW_OCR_PREVIEW = "RAW_OCR_PREVIEW"
    REPORT = "REPORT"
    VERIFICATION = "VERIFICATION"
    DECISIONS = "DECISIONS"
    RAW_TO_CURRENT_DIFF = "RAW_TO_CURRENT_DIFF"
    COMPILE_CURRENT_LOG = "COMPILE_CURRENT_LOG"
    COMPILE_RAW_LOG = "COMPILE_RAW_LOG"
    ERROR_LOG = "ERROR_LOG"
    OUTLINE = "OUTLINE"
    PAGE_IMAGE = "PAGE_IMAGE"
    FORMULA_CROP = "FORMULA_CROP"
    PROJECT_FILE = "PROJECT_FILE"
    EVIDENCE = "EVIDENCE"
    README = "README"
    PROMPT_SHORT = "PROMPT_SHORT"
    PROMPT_FULL = "PROMPT_FULL"
    SUBMISSION_MANIFEST = "SUBMISSION_MANIFEST"
    SHA256SUMS = "SHA256SUMS"


_ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


def normalize_artifact_role(value: object) -> str:
    role = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not _ROLE_RE.fullmatch(role):
        raise ValueError(f"invalid audit artifact role: {value!r}")
    return role


def _freeze(value: Any) -> Any:
    """Deep-copy JSON-like state into immutable containers."""
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    return value


def thaw_json(value: Any) -> Any:
    """Return a JSON-serializable copy of recursively frozen state."""
    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _enum_value(enum_type: type[Enum], value: object, label: str) -> Enum:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise ValueError(f"invalid {label}: {value!r}; expected one of {allowed}") from exc


@dataclass(frozen=True, slots=True)
class AuditArtifact:
    """One host-classified, byte-immutable run artifact.

    ``path`` is the requested portable path in the audit package, never a local
    source path.  A same-name collision is resolved later without overwriting;
    the original request remains immutable in the snapshot.
    """

    artifact_role: str
    path: str
    data: bytes = field(repr=False)
    media_type: str = "application/octet-stream"
    parent_artifact_ids: tuple[str, ...] = ()
    preview_status: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)
    artifact_id: str = field(init=False)
    bytes_sha256: str = field(init=False)
    byte_count: int = field(init=False)

    def __post_init__(self) -> None:
        role = normalize_artifact_role(self.artifact_role)
        data = bytes(self.data)
        digest = hashlib.sha256(data).hexdigest()
        preview_status = self.preview_status
        if preview_status is not None:
            preview_status = str(preview_status).strip().upper()
            if preview_status not in PREVIEW_STATUSES:
                raise ValueError(f"invalid preview status: {self.preview_status!r}")
            if role not in {ArtifactRole.CURRENT_PREVIEW, ArtifactRole.RAW_OCR_PREVIEW}:
                raise ValueError("preview_status is allowed only on a preview artifact role")
        elif role in {ArtifactRole.CURRENT_PREVIEW, ArtifactRole.RAW_OCR_PREVIEW}:
            raise ValueError("preview artifacts require an explicit preview_status")
        parents = tuple(str(item) for item in self.parent_artifact_ids)
        if any(not item for item in parents):
            raise ValueError("parent artifact ids cannot be empty")
        if not str(self.path or "").strip():
            raise ValueError("audit artifact package path cannot be empty")
        object.__setattr__(self, "artifact_role", role)
        object.__setattr__(self, "path", str(self.path))
        object.__setattr__(self, "data", data)
        object.__setattr__(self, "media_type", str(self.media_type or "application/octet-stream"))
        object.__setattr__(self, "parent_artifact_ids", parents)
        object.__setattr__(self, "preview_status", preview_status)
        object.__setattr__(self, "metadata", _freeze(dict(self.metadata or {})))
        object.__setattr__(self, "bytes_sha256", digest)
        object.__setattr__(self, "byte_count", len(data))
        # Logical identity and payload identity are deliberately different.
        # Equal bytes at source/analyzed/reviewed/current stages are common and
        # must remain separate lineage nodes even though the ZIP stores their
        # payload only once and records the other nodes as aliases.
        logical_identity = {
            "artifact_role": role,
            "path": str(self.path),
            "bytes_sha256": digest,
            "parent_artifact_ids": list(parents),
            "preview_status": preview_status,
        }
        logical_digest = hashlib.sha256(_canonical_json(logical_identity)).hexdigest()
        object.__setattr__(self, "artifact_id", f"artifact:{logical_digest}")


@dataclass(frozen=True, slots=True)
class RunSnapshot:
    """Deeply immutable capture of one terminal run.

    Verification is deliberately derived only from the captured machine record:
    ``terminal_status=SUCCESS`` by itself never creates a VERIFIED claim.
    """

    project_id: str
    run_id: str
    workflow: AuditWorkflow
    terminal_status: TerminalStatus
    captured_at: str
    artifacts: tuple[AuditArtifact, ...]
    machine_verification: Mapping[str, object] = field(default_factory=dict, repr=False)
    blockers: tuple[str, ...] = ()
    model: str = "unknown"
    app_version: str = "unknown"
    template: str = "none"
    page_range: str = "all"
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)
    snapshot_id: str = field(init=False)
    current_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        workflow = _enum_value(AuditWorkflow, self.workflow, "audit workflow")
        terminal = _enum_value(TerminalStatus, self.terminal_status, "terminal status")
        artifacts = tuple(self.artifacts)
        if any(not isinstance(item, AuditArtifact) for item in artifacts):
            raise TypeError("RunSnapshot.artifacts must contain AuditArtifact values")
        verification = _freeze(dict(self.machine_verification or {}))
        blockers = tuple(str(item) for item in self.blockers if str(item).strip())
        metadata = _freeze(dict(self.metadata or {}))
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "terminal_status", terminal)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "machine_verification", verification)
        object.__setattr__(self, "blockers", blockers)
        object.__setattr__(self, "metadata", metadata)

        identity = {
            "project_id": str(self.project_id),
            "run_id": str(self.run_id),
            "workflow": workflow.value,
            "terminal_status": terminal.value,
            "captured_at": str(self.captured_at),
            "verification": thaw_json(verification),
            "blockers": list(blockers),
            "model": str(self.model),
            "app_version": str(self.app_version),
            "template": str(self.template),
            "page_range": str(self.page_range),
            "metadata": thaw_json(metadata),
            "artifacts": [
                {
                    "role": item.artifact_role,
                    "path": item.path,
                    "sha256": item.bytes_sha256,
                    "parents": list(item.parent_artifact_ids),
                    "preview_status": item.preview_status,
                }
                for item in artifacts
            ],
        }
        snapshot_digest = hashlib.sha256(_canonical_json(identity)).hexdigest()
        current_roles = {
            ArtifactRole.CURRENT_TEX,
            ArtifactRole.CURRENT_PREVIEW,
            ArtifactRole.DECISIONS,
            ArtifactRole.VERIFICATION,
        }
        current = [
            (item.artifact_role, item.bytes_sha256)
            for item in artifacts
            if item.artifact_role in current_roles
        ]
        current_digest = hashlib.sha256(_canonical_json(sorted(current))).hexdigest()
        object.__setattr__(self, "snapshot_id", f"snapshot-{snapshot_digest[:24]}")
        object.__setattr__(self, "current_fingerprint", current_digest)

    @property
    def verification_status(self) -> str:
        # Identity comparison is intentional: truthy strings and terminal success
        # cannot promote an unverified run.
        return (
            "VERIFIED"
            if self.machine_verification.get("safe_to_export") is True
            else "UNVERIFIED"
        )


@dataclass(frozen=True, slots=True)
class AuditSubmissionRequest:
    depth: AuditDepth = AuditDepth.STANDARD
    audit_focus: str = ""
    include_source_files: bool = True
    include_compile_logs: bool = True
    include_verification: bool = True
    include_page_images: bool | None = None
    include_formula_crops: bool | None = None
    sanitize_sensitive: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "depth", _enum_value(AuditDepth, self.depth, "audit depth"))
        object.__setattr__(self, "audit_focus", str(self.audit_focus or "").strip())

    @property
    def effective_page_images(self) -> bool:
        if self.include_page_images is not None:
            return bool(self.include_page_images)
        return self.depth is AuditDepth.FULL

    @property
    def effective_formula_crops(self) -> bool:
        if self.include_formula_crops is not None:
            return bool(self.include_formula_crops)
        return self.depth is AuditDepth.FULL


@dataclass(frozen=True, slots=True)
class AuditManifestArtifact:
    artifact_id: str
    artifact_role: str
    path: str
    bytes_sha256: str | None
    byte_count: int | None
    media_type: str
    parent_artifact_ids: tuple[str, ...] = ()
    preview_status: str | None = None
    aliases: tuple[Mapping[str, object], ...] = ()
    source_bytes_sha256: str | None = None
    redacted: bool = False
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "aliases", tuple(_freeze(dict(item)) for item in self.aliases))
        object.__setattr__(self, "metadata", _freeze(dict(self.metadata or {})))

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "artifact_id": self.artifact_id,
            "artifact_role": self.artifact_role,
            "path": self.path,
            "bytes_sha256": self.bytes_sha256,
            "byte_count": self.byte_count,
            "media_type": self.media_type,
            "parent_artifact_ids": list(self.parent_artifact_ids),
            "preview_status": self.preview_status,
            "aliases": thaw_json(self.aliases),
            "redacted": self.redacted,
            "metadata": thaw_json(self.metadata),
        }
        if self.source_bytes_sha256 and self.source_bytes_sha256 != self.bytes_sha256:
            result["source_bytes_sha256"] = self.source_bytes_sha256
        return result


@dataclass(frozen=True, slots=True)
class AuditSubmissionManifest:
    submission_id: str
    snapshot_id: str
    snapshot_fingerprint: str
    generated_at: str
    workflow: AuditWorkflow
    terminal_status: TerminalStatus
    verification_status: str
    depth: AuditDepth
    audit_focus: str
    project_id: str
    run_id: str
    model: str
    app_version: str
    template: str
    page_range: str
    blockers: tuple[str, ...]
    missing_expected_roles: tuple[str, ...]
    unavailable_parent_artifact_ids: tuple[str, ...]
    artifacts: tuple[AuditManifestArtifact, ...]
    privacy: Mapping[str, object]
    schema: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.verification_status not in {"VERIFIED", "UNVERIFIED"}:
            raise ValueError("verification_status must be copied from machine verification")
        object.__setattr__(self, "privacy", _freeze(dict(self.privacy or {})))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "submission_id": self.submission_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "generated_at": self.generated_at,
            "workflow": self.workflow.value,
            "terminal_status": self.terminal_status.value,
            "verification_status": self.verification_status,
            "depth": self.depth.value,
            "audit_focus": self.audit_focus,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "model": self.model,
            "app_version": self.app_version,
            "template": self.template,
            "page_range": self.page_range,
            "blockers": list(self.blockers),
            "missing_expected_roles": list(self.missing_expected_roles),
            "unavailable_parent_artifact_ids": list(
                self.unavailable_parent_artifact_ids
            ),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "privacy": thaw_json(self.privacy),
            "authority": {
                "artifact_roles": [
                    "submission_manifest.json.artifacts[].artifact_role",
                    "submission_manifest.json.artifacts[].aliases[].artifact_role",
                ],
                "verification": "captured_machine_verification_only",
                "lineage": [
                    "submission_manifest.json.artifacts[].parent_artifact_ids",
                    "submission_manifest.json.artifacts[].aliases[].parent_artifact_ids",
                ],
                "physical_payload": (
                    "submission_manifest.json.artifacts[].path; aliases reuse their "
                    "containing artifact payload"
                ),
            },
        }


@dataclass(frozen=True, slots=True)
class AuditSubmissionResult:
    submission_id: str
    snapshot_id: str
    snapshot_fingerprint: str
    generated_at: str
    manifest: AuditSubmissionManifest
    files: Mapping[str, bytes] = field(repr=False)
    zip_bytes: bytes = field(default=b"", repr=False)
    zip_sha256: str = ""
    zip_path: str | None = None

    def __post_init__(self) -> None:
        frozen_files = MappingProxyType({str(name): bytes(data) for name, data in self.files.items()})
        object.__setattr__(self, "files", frozen_files)
        object.__setattr__(self, "zip_bytes", bytes(self.zip_bytes))

    def is_stale(self, current_fingerprint: str) -> bool:
        return self.snapshot_fingerprint != str(current_fingerprint or "")


def artifacts_by_role(
    artifacts: Iterable[AuditArtifact], role: str
) -> tuple[AuditArtifact, ...]:
    normalized = normalize_artifact_role(role)
    return tuple(item for item in artifacts if item.artifact_role == normalized)

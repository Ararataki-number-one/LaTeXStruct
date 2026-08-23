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


SCHEMA_VERSION = "latexstruct-ai-audit-submission-v2"


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


class VerificationStatus(str, Enum):
    """Machine-verification state captured before audit packaging."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    NOT_RUN = "NOT_RUN"


class PackagingStatus(str, Enum):
    """Whether the host completed the audit-package construction process."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class AuditPackageStatus(str, Enum):
    """Independent validity of the produced audit material itself."""

    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"


class StageExecutionStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class BlockerSeverity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    UNKNOWN = "UNKNOWN"


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
    REPORT_JSON = "REPORT_JSON"
    ISSUES_CSV = "ISSUES_CSV"
    METRICS = "METRICS"
    TEMPLATE_MANIFEST = "TEMPLATE_MANIFEST"
    COMPILE_INPUT_MANIFEST = "COMPILE_INPUT_MANIFEST"
    RAW_COMPILE_INPUT_MANIFEST = "RAW_COMPILE_INPUT_MANIFEST"
    PACKAGING_INTEGRITY = "PACKAGING_INTEGRITY"
    PACKAGING_ERROR = "PACKAGING_ERROR"
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
class AuditStageExecution:
    """Host-recorded execution fact for one pipeline stage.

    Equal artifact bytes never determine this status.  ``canonical_artifact_id``
    and ``deduplicated`` describe storage only after the host has independently
    recorded that the stage ran.
    """

    status: StageExecutionStatus
    reason: str = ""
    checked: bool | None = None
    canonical_artifact_id: str | None = None
    deduplicated: bool = False
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        status = _enum_value(StageExecutionStatus, self.status, "stage execution status")
        canonical = str(self.canonical_artifact_id or "").strip() or None
        if self.deduplicated and not canonical:
            raise ValueError("deduplicated stage requires canonical_artifact_id")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason", str(self.reason or "").strip())
        object.__setattr__(self, "checked", None if self.checked is None else bool(self.checked))
        object.__setattr__(self, "canonical_artifact_id", canonical)
        object.__setattr__(self, "deduplicated", bool(self.deduplicated))
        object.__setattr__(self, "metadata", _freeze(dict(self.metadata or {})))

    @classmethod
    def from_value(cls, value: object) -> AuditStageExecution:
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            return cls(
                status=value.get("status", StageExecutionStatus.NOT_REQUESTED),
                reason=str(value.get("reason") or ""),
                checked=value.get("checked") if "checked" in value else None,
                canonical_artifact_id=value.get("canonical_artifact_id"),
                deduplicated=bool(value.get("deduplicated", False)),
                metadata=value.get("metadata") or {},
            )
        return cls(status=value)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "status": self.status.value,
            "reason": self.reason or None,
            "checked": self.checked,
            "canonical_artifact_id": self.canonical_artifact_id,
            "deduplicated": self.deduplicated,
        }
        if self.metadata:
            result["metadata"] = thaw_json(self.metadata)
        return result


@dataclass(frozen=True, slots=True)
class AuditBlocker:
    """Machine-readable blocker; legacy strings are losslessly wrapped."""

    id: str
    severity: BlockerSeverity
    module: str
    summary: str
    candidate_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    recommended_fix: str = ""
    acceptance: str = ""
    legacy: bool = False

    def __post_init__(self) -> None:
        blocker_id = str(self.id or "").strip()
        summary = str(self.summary or "").strip()
        if not blocker_id:
            raise ValueError("structured blocker id cannot be empty")
        if not summary:
            raise ValueError("structured blocker summary cannot be empty")
        object.__setattr__(self, "id", blocker_id)
        object.__setattr__(
            self,
            "severity",
            _enum_value(BlockerSeverity, self.severity, "blocker severity"),
        )
        object.__setattr__(self, "module", str(self.module or "unknown").strip() or "unknown")
        object.__setattr__(self, "summary", summary)
        object.__setattr__(
            self,
            "candidate_ids",
            tuple(str(item) for item in self.candidate_ids if str(item).strip()),
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(str(item) for item in self.evidence if str(item).strip()),
        )
        object.__setattr__(self, "recommended_fix", str(self.recommended_fix or "").strip())
        object.__setattr__(self, "acceptance", str(self.acceptance or "").strip())
        object.__setattr__(self, "legacy", bool(self.legacy))

    @classmethod
    def from_value(cls, value: object) -> AuditBlocker:
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            return cls(
                id=str(value.get("id") or ""),
                severity=value.get("severity", BlockerSeverity.UNKNOWN),
                module=str(value.get("module") or "unknown"),
                summary=str(value.get("summary") or ""),
                candidate_ids=tuple(value.get("candidate_ids") or ()),
                evidence=tuple(value.get("evidence") or ()),
                recommended_fix=str(value.get("recommended_fix") or ""),
                acceptance=str(value.get("acceptance") or ""),
                legacy=bool(value.get("legacy", False)),
            )
        text = str(value or "").strip()
        if text.startswith("{"):
            try:
                decoded = json.loads(text)
            except (TypeError, ValueError):
                decoded = None
            if isinstance(decoded, Mapping) and decoded.get("summary"):
                return cls.from_value(decoded)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        return cls(
            id=f"legacy-blocker-{digest}",
            severity=BlockerSeverity.UNKNOWN,
            module="legacy",
            summary=text,
            legacy=True,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "module": self.module,
            "summary": self.summary,
            "candidate_ids": list(self.candidate_ids),
            "evidence": list(self.evidence),
            "recommended_fix": self.recommended_fix or None,
            "acceptance": self.acceptance or None,
            "legacy": self.legacy,
        }

    def to_transport_text(self) -> str:
        """JSON text survives legacy snapshot/store code that accepts strings only."""
        return _canonical_json(self.to_dict()).decode("utf-8")


@dataclass(frozen=True, slots=True)
class SelectedPageRange:
    start: int | None = None
    end: int | None = None
    pages: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        pages = tuple(int(page) for page in self.pages)
        if any(page < 1 for page in pages) or len(set(pages)) != len(pages):
            raise ValueError("selected PDF pages must be unique positive integers")
        if pages != tuple(sorted(pages)):
            raise ValueError("selected PDF pages must be in ascending order")
        start = int(self.start) if self.start is not None else (pages[0] if pages else None)
        end = int(self.end) if self.end is not None else (pages[-1] if pages else None)
        if pages and (start != pages[0] or end != pages[-1]):
            raise ValueError("selected page range start/end must match pages")
        if start is not None and end is not None and (start < 1 or end < start):
            raise ValueError("invalid selected PDF page range")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)
        object.__setattr__(self, "pages", pages)

    @classmethod
    def from_value(cls, value: object) -> SelectedPageRange:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("selected_page_range must be a mapping")
        return cls(
            start=value.get("start"),
            end=value.get("end"),
            pages=tuple(value.get("pages") or ()),
        )

    def to_dict(self) -> dict[str, object]:
        return {"start": self.start, "end": self.end, "pages": list(self.pages)}


@dataclass(frozen=True, slots=True)
class SourcePdfInfo:
    page_count: int | None = None
    selected_page_range: SelectedPageRange = field(default_factory=SelectedPageRange)

    def __post_init__(self) -> None:
        page_count = None if self.page_count is None else int(self.page_count)
        if page_count is not None and page_count < 1:
            raise ValueError("source PDF page_count must be positive")
        selected = SelectedPageRange.from_value(self.selected_page_range)
        if page_count is not None and any(page > page_count for page in selected.pages):
            raise ValueError("selected PDF page exceeds source page_count")
        object.__setattr__(self, "page_count", page_count)
        object.__setattr__(self, "selected_page_range", selected)

    @classmethod
    def from_value(cls, value: object) -> SourcePdfInfo:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("source_pdf must be a mapping")
        return cls(
            page_count=value.get("page_count"),
            selected_page_range=SelectedPageRange.from_value(
                value.get("selected_page_range") or {}
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "page_count": self.page_count,
            "selected_page_range": self.selected_page_range.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class AuditProvenance:
    """Structured producer facts; empty mappings mean unknown, never inferred."""

    runtime: Mapping[str, object] = field(default_factory=dict)
    models: Mapping[str, object] = field(default_factory=dict)
    prompts: Mapping[str, object] = field(default_factory=dict)
    template: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        unknown_reason = "legacy run did not persist producer identity"
        runtime = {
            "app_version": None,
            "git_commit": None,
            "build_id": None,
            "dirty": None,
            "python_version": None,
            "platform": None,
            "started_at": None,
            "finished_at": None,
            "identity_status": "UNKNOWN",
            "reason": unknown_reason,
            **dict(self.runtime or {}),
        }
        models = dict(self.models or {})
        for name in ("ocr", "decision", "review"):
            supplied = models.get(name)
            if not isinstance(supplied, Mapping):
                supplied = {}
            models[name] = {
                "backend": None,
                "provider": None,
                "model": None,
                "status": "UNKNOWN",
                "reason": "legacy run did not persist model identity",
                **dict(supplied),
            }
        prompts = {
            "ocr_prompt_version": None,
            "decision_prompt_version": None,
            "review_prompt_version": None,
            "decision_schema_version": None,
            "review_schema_version": None,
            **dict(self.prompts or {}),
        }
        template = {
            "id": None,
            "version": None,
            "asset_manifest_sha256": None,
            **dict(self.template or {}),
        }
        object.__setattr__(self, "runtime", _freeze(runtime))
        object.__setattr__(self, "models", _freeze(models))
        object.__setattr__(self, "prompts", _freeze(prompts))
        object.__setattr__(self, "template", _freeze(template))

    @classmethod
    def from_value(cls, value: object) -> AuditProvenance:
        if isinstance(value, cls):
            return value
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise TypeError("provenance must be a mapping")
        return cls(
            runtime=value.get("runtime") or {},
            models=value.get("models") or {},
            prompts=value.get("prompts") or {},
            template=value.get("template") or {},
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "runtime": thaw_json(self.runtime),
            "models": thaw_json(self.models),
            "prompts": thaw_json(self.prompts),
            "template": thaw_json(self.template),
        }


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


_STANDARD_STAGE_NAMES = ("ocr", "analysis", "review", "template")
_STAGE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _logical_artifact_roles(artifacts: Iterable[AuditArtifact | AuditManifestArtifact]) -> set[str]:
    roles: set[str] = set()
    for artifact in artifacts:
        roles.add(artifact.artifact_role)
        for alias in getattr(artifact, "aliases", ()):
            role = str(alias.get("artifact_role") or "")
            if role:
                roles.add(role)
    return roles


def _legacy_stage_map(
    workflow: AuditWorkflow,
    terminal_status: TerminalStatus,
    artifacts: Iterable[AuditArtifact | AuditManifestArtifact],
) -> Mapping[str, AuditStageExecution]:
    """Conservative compatibility view for v1 snapshots with no stage map.

    Artifact presence can prove that an output exists.  Absence never proves a
    stage completed, and identical bytes never prove that review ran.
    """
    roles = _logical_artifact_roles(artifacts)
    completed_roles = {
        "ocr": {ArtifactRole.RAW_OCR_TEX},
        "analysis": {ArtifactRole.AI_ANALYZED_TEX, ArtifactRole.RULE_ANALYZED_TEX},
        "review": {ArtifactRole.AI_REVIEWED_TEX},
        "template": {ArtifactRole.TEMPLATE_MANIFEST},
    }
    requested = {
        AuditWorkflow.ANALYSIS_REVIEW_ONLY: {"analysis", "review"},
        AuditWorkflow.OCR_ONLY: {"ocr"},
        AuditWorkflow.OCR_ANALYSIS_REVIEW: {"ocr", "analysis", "review"},
        AuditWorkflow.TEMPLATE_CONVERSION: {"template"},
        AuditWorkflow.MULTIFILE_PROJECT: set(),
    }[workflow]
    result: dict[str, AuditStageExecution] = {}
    for name in _STANDARD_STAGE_NAMES:
        if roles.intersection(completed_roles[name]):
            result[name] = AuditStageExecution(
                StageExecutionStatus.COMPLETED,
                reason=(
                    "legacy manifest contains a host-classified stage output; "
                    "checked state was not persisted"
                ),
            )
        elif name not in requested:
            result[name] = AuditStageExecution(StageExecutionStatus.NOT_REQUESTED)
        elif terminal_status is TerminalStatus.CANCELLED:
            result[name] = AuditStageExecution(
                StageExecutionStatus.CANCELLED,
                reason="legacy run was cancelled before this stage produced an artifact",
            )
        else:
            result[name] = AuditStageExecution(
                StageExecutionStatus.SKIPPED,
                reason=(
                    "legacy run did not persist this stage execution and no "
                    "host-classified stage artifact exists"
                ),
            )
    return MappingProxyType(result)


def _normalize_stage_map(
    value: Mapping[str, object] | None,
    *,
    workflow: AuditWorkflow,
    terminal_status: TerminalStatus,
    artifacts: Iterable[AuditArtifact | AuditManifestArtifact],
) -> Mapping[str, AuditStageExecution]:
    if not value:
        return _legacy_stage_map(workflow, terminal_status, artifacts)
    result: dict[str, AuditStageExecution] = {}
    for raw_name, raw_execution in value.items():
        name = str(raw_name or "").strip().lower()
        if not _STAGE_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid audit stage name: {raw_name!r}")
        result[name] = AuditStageExecution.from_value(raw_execution)
    for name in _STANDARD_STAGE_NAMES:
        result.setdefault(
            name,
            AuditStageExecution(
                StageExecutionStatus.NOT_REQUESTED,
                reason="host stage map omitted this stage",
            ),
        )
    return MappingProxyType(result)


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
    blockers: tuple[str | AuditBlocker | Mapping[str, object], ...] = ()
    model: str = "unknown"
    app_version: str = "unknown"
    template: str = "none"
    page_range: str = "all"
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)
    stages: Mapping[str, AuditStageExecution | Mapping[str, object] | str] = field(
        default_factory=dict,
        repr=False,
    )
    source_pdf: SourcePdfInfo | Mapping[str, object] | None = None
    provenance: AuditProvenance | Mapping[str, object] | None = None
    snapshot_id: str = field(init=False)
    current_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        workflow = _enum_value(AuditWorkflow, self.workflow, "audit workflow")
        terminal = _enum_value(TerminalStatus, self.terminal_status, "terminal status")
        artifacts = tuple(self.artifacts)
        if any(not isinstance(item, AuditArtifact) for item in artifacts):
            raise TypeError("RunSnapshot.artifacts must contain AuditArtifact values")
        verification = _freeze(dict(self.machine_verification or {}))
        blockers = []
        for item in self.blockers:
            if isinstance(item, AuditBlocker | Mapping):
                blocker_text = AuditBlocker.from_value(item).to_transport_text()
            else:
                blocker_text = str(item or "").strip()
            if blocker_text:
                blockers.append(blocker_text)
        blocker_tuple = tuple(blockers)
        metadata = _freeze(dict(self.metadata or {}))
        stages = _normalize_stage_map(
            self.stages,
            workflow=workflow,
            terminal_status=terminal,
            artifacts=artifacts,
        )
        source_pdf = None if self.source_pdf is None else SourcePdfInfo.from_value(self.source_pdf)
        provenance = AuditProvenance.from_value(self.provenance)
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "terminal_status", terminal)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "machine_verification", verification)
        object.__setattr__(self, "blockers", blocker_tuple)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "stages", stages)
        object.__setattr__(self, "source_pdf", source_pdf)
        object.__setattr__(self, "provenance", provenance)

        identity = {
            "project_id": str(self.project_id),
            "run_id": str(self.run_id),
            "workflow": workflow.value,
            "terminal_status": terminal.value,
            "captured_at": str(self.captured_at),
            "verification": thaw_json(verification),
            "blockers": list(blocker_tuple),
            "model": str(self.model),
            "app_version": str(self.app_version),
            "template": str(self.template),
            "page_range": str(self.page_range),
            "metadata": thaw_json(metadata),
            "stages": {
                name: execution.to_dict() for name, execution in stages.items()
            },
            "source_pdf": source_pdf.to_dict() if source_pdf else None,
            "provenance": provenance.to_dict(),
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
    def verification_status(self) -> VerificationStatus:
        # Identity comparison is intentional: truthy strings and terminal success
        # cannot promote an unverified run.
        if not self.machine_verification:
            return VerificationStatus.NOT_RUN
        if self.machine_verification.get("safe_to_export") is True:
            return VerificationStatus.VERIFIED
        return VerificationStatus.UNVERIFIED

    @property
    def source_run_status(self) -> TerminalStatus:
        return self.terminal_status

    @property
    def structured_blockers(self) -> tuple[AuditBlocker, ...]:
        return tuple(AuditBlocker.from_value(item) for item in self.blockers)


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
        normalized_aliases = []
        for raw_alias in self.aliases:
            alias = dict(raw_alias)
            logical_path = str(
                alias.pop("logical_path", "")
                or alias.pop("path", "")
                or alias.get("requested_path", "")
            ).strip()
            if not logical_path:
                raise ValueError("deduplicated alias requires logical_path")
            requested = str(
                alias.pop("requested_logical_path", "")
                or alias.pop("requested_path", "")
            ).strip()
            alias.pop("canonical_artifact_id", None)
            alias.pop("canonical_path", None)
            alias.pop("deduplicated", None)
            alias.pop("bytes_sha256", None)
            alias.update({
                "logical_path": logical_path,
                "canonical_artifact_id": self.artifact_id,
                "canonical_path": self.path,
                "deduplicated": True,
                "bytes_sha256": self.bytes_sha256,
            })
            if requested and requested != logical_path:
                alias["requested_logical_path"] = requested
            normalized_aliases.append(_freeze(alias))
        object.__setattr__(self, "aliases", tuple(normalized_aliases))
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
    verification_status: VerificationStatus | str
    depth: AuditDepth
    audit_focus: str
    project_id: str
    run_id: str
    model: str
    app_version: str
    template: str
    page_range: str
    blockers: tuple[AuditBlocker | Mapping[str, object] | str, ...]
    missing_expected_roles: tuple[str, ...]
    unavailable_parent_artifact_ids: tuple[str, ...]
    artifacts: tuple[AuditManifestArtifact, ...]
    privacy: Mapping[str, object]
    missing_expected_role_details: tuple[Mapping[str, object], ...] = ()
    packaging_status: PackagingStatus | str = PackagingStatus.SUCCESS
    audit_package_status: AuditPackageStatus | str = AuditPackageStatus.VALID
    stages: Mapping[str, AuditStageExecution | Mapping[str, object] | str] = field(
        default_factory=dict
    )
    source_pdf: SourcePdfInfo | Mapping[str, object] | None = None
    provenance: AuditProvenance | Mapping[str, object] | None = None
    schema: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        workflow = _enum_value(AuditWorkflow, self.workflow, "audit workflow")
        terminal = _enum_value(TerminalStatus, self.terminal_status, "terminal status")
        verification = _enum_value(
            VerificationStatus,
            self.verification_status,
            "verification status",
        )
        depth = _enum_value(AuditDepth, self.depth, "audit depth")
        packaging = _enum_value(PackagingStatus, self.packaging_status, "packaging status")
        package = _enum_value(
            AuditPackageStatus,
            self.audit_package_status,
            "audit package status",
        )
        # A failed packager can never emit a VALID package.  A partial packager
        # can at best emit an INCOMPLETE package.  This is a fail-closed status
        # relationship, independent of source verification.
        if packaging is PackagingStatus.FAILED:
            package = AuditPackageStatus.INVALID
        elif packaging is PackagingStatus.PARTIAL and package is AuditPackageStatus.VALID:
            package = AuditPackageStatus.INCOMPLETE
        artifacts = tuple(self.artifacts)
        if any(not isinstance(item, AuditManifestArtifact) for item in artifacts):
            raise TypeError("AuditSubmissionManifest.artifacts must contain manifest artifacts")
        blockers = tuple(AuditBlocker.from_value(item) for item in self.blockers)
        stages = _normalize_stage_map(
            self.stages,
            workflow=workflow,
            terminal_status=terminal,
            artifacts=artifacts,
        )
        source_pdf = None if self.source_pdf is None else SourcePdfInfo.from_value(self.source_pdf)
        provenance = AuditProvenance.from_value(self.provenance)
        object.__setattr__(self, "workflow", workflow)
        object.__setattr__(self, "terminal_status", terminal)
        object.__setattr__(self, "verification_status", verification)
        object.__setattr__(self, "depth", depth)
        object.__setattr__(self, "packaging_status", packaging)
        object.__setattr__(self, "audit_package_status", package)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "blockers", blockers)
        object.__setattr__(self, "stages", stages)
        object.__setattr__(self, "source_pdf", source_pdf)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(
            self,
            "missing_expected_roles",
            tuple(str(role) for role in self.missing_expected_roles),
        )
        object.__setattr__(
            self,
            "missing_expected_role_details",
            tuple(_freeze(dict(item)) for item in self.missing_expected_role_details),
        )
        object.__setattr__(
            self,
            "unavailable_parent_artifact_ids",
            tuple(str(item) for item in self.unavailable_parent_artifact_ids),
        )
        object.__setattr__(self, "privacy", _freeze(dict(self.privacy or {})))

    @property
    def source_run_status(self) -> TerminalStatus:
        """Preferred v2 name; ``terminal_status`` remains the compatibility alias."""
        return self.terminal_status

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "submission_id": self.submission_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "generated_at": self.generated_at,
            "workflow": self.workflow.value,
            "source_run_status": self.source_run_status.value,
            "terminal_status": self.terminal_status.value,
            "verification_status": self.verification_status.value,
            "packaging_status": self.packaging_status.value,
            "audit_package_status": self.audit_package_status.value,
            "depth": self.depth.value,
            "audit_focus": self.audit_focus,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "model": self.model,
            "app_version": self.app_version,
            "template": self.template,
            "page_range": self.page_range,
            "stages": {
                name: execution.to_dict() for name, execution in self.stages.items()
            },
            "blockers": [item.to_dict() for item in self.blockers],
            "missing_expected_roles": list(self.missing_expected_roles),
            "missing_expected_role_details": thaw_json(
                self.missing_expected_role_details
            ),
            "unavailable_parent_artifact_ids": list(
                self.unavailable_parent_artifact_ids
            ),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "privacy": thaw_json(self.privacy),
            "source_pdf": self.source_pdf.to_dict() if self.source_pdf else None,
            "provenance": self.provenance.to_dict(),
            "authority": {
                "artifact_roles": [
                    "submission_manifest.json.artifacts[].artifact_role",
                    "submission_manifest.json.artifacts[].aliases[].artifact_role",
                ],
                "source_run_status": "captured_terminal_run_state_only",
                "verification": "captured_machine_verification_only",
                "packaging": "post-copy_packaging_integrity_results_only",
                "stages": "host-recorded_execution_map; never inferred from byte equality",
                "lineage": [
                    "submission_manifest.json.artifacts[].parent_artifact_ids",
                    "submission_manifest.json.artifacts[].aliases[].parent_artifact_ids",
                ],
                "physical_payload": (
                    "submission_manifest.json.artifacts[].path only; alias logical_path is "
                    "not a ZIP member and alias canonical_path names the reused payload"
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

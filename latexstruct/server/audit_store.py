# -*- coding: utf-8 -*-
"""Crash-safe persistence for immutable AI-audit run snapshots.

The store is scoped to one existing project directory.  Snapshot descriptors
contain only portable package paths and content-addressed blob references;
neither descriptor nor public summary serializes the host project's absolute
directory.  Submission directories are immutable commits, while a tiny atomic
pointer selects the latest one and independent sidecars record staleness.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import shutil
import stat
import threading
import unicodedata
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..core.audit_schema import (
    AuditArtifact,
    AuditSubmissionRequest,
    AuditWorkflow,
    RunSnapshot,
    TerminalStatus,
    thaw_json,
)
from ..core.audit_submission import (
    FULL_PROMPT_PATH,
    MANIFEST_PATH,
    README_PATH,
    SHORT_PROMPT_PATH,
    build_audit_submission,
    build_lightweight_audit_files,
)


SNAPSHOT_STORAGE_SCHEMA = "latexstruct-audit-snapshot-store-v1"
SUBMISSION_STORAGE_SCHEMA = "latexstruct-audit-submission-store-v1"
LATEST_POINTER_SCHEMA = "latexstruct-audit-latest-pointer-v1"
STALE_RECORD_SCHEMA = "latexstruct-audit-stale-record-v1"
SAVED_DOWNLOAD_RECORD_SCHEMA = "latexstruct-audit-saved-download-v1"

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_ABSOLUTE_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/][^\r\n\t\"']+")
_UNC_RE = re.compile(r"\\\\[^\\\s]+\\[^\r\n\t\"']+")
_POSIX_HOME_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])/(?:Users|home|root|tmp|private(?:/tmp)?|var|workspace(?:s)?|"
    r"mnt|opt|data|srv|etc|usr|Applications|Volumes|Library|System|media|run)"
    r"(?:/[^\r\n\t\"' ]*)?"
)
_SENSITIVE_KEYS = frozenset({
    "api_key", "authorization", "codex_token", "codex_login", "codex_auth",
    "codex_session", "codex_account", "chatgpt_account", "access_token",
    "refresh_token", "id_token", "account_id", "local_path", "absolute_path",
    "source_path", "email", "account", "account_email",
})
_WINDOWS_DEVICE_STEMS = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
})
_CONTROL_FILES = (README_PATH, SHORT_PROMPT_PATH, FULL_PROMPT_PATH, MANIFEST_PATH)
_MINIMAL_FAILURE_CONTROL_FILES = (README_PATH, MANIFEST_PATH)
_MINIMAL_FAILURE_MEMBERS = frozenset({
    README_PATH,
    MANIFEST_PATH,
    "audit/packaging-error.json",
    "audit/packaging-integrity.json",
    "audit/error.log",
})
_SHA256SUMS_PATH = "audit/SHA256SUMS"
_COMMIT_LOCKS_GUARD = threading.Lock()
_COMMIT_LOCKS: dict[str, threading.RLock] = {}


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _descriptor_sha256(descriptor: Mapping[str, object]) -> str:
    payload = dict(descriptor)
    payload.pop("descriptor_sha256", None)
    return _sha256(_json_bytes(payload))


def _safe_id(value: str, label: str) -> str:
    value = str(value or "")
    if not _SAFE_ID_RE.fullmatch(value):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def _portable_path(value: str) -> str:
    raw = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if (
        not raw
        or raw.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part or "\x00" in part for part in path.parts)
        or any("\r" in part or "\n" in part for part in path.parts)
    ):
        raise ValueError(f"snapshot artifact path is not portable: {value!r}")
    return path.as_posix()


def _strict_archive_path(value: object) -> str:
    """Validate one ZIP/member path without applying a lossy normalization."""
    raw = str(value or "")
    if "\\" in raw:
        raise ValueError(f"audit ZIP member uses a non-portable separator: {raw!r}")
    portable = _portable_path(raw)
    if portable != raw:
        raise ValueError(f"audit ZIP member path is not canonical: {raw!r}")
    for part in PurePosixPath(portable).parts:
        if part != part.rstrip(" ."):
            raise ValueError(f"audit ZIP member has an unsafe trailing character: {raw!r}")
        stem = part.rstrip(" .").split(".", 1)[0].casefold()
        if stem in _WINDOWS_DEVICE_STEMS:
            raise ValueError(f"audit ZIP member uses a reserved Windows device: {raw!r}")
    return portable


def _archive_collision_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _validate_file_namespace(files: Mapping[str, bytes]) -> dict[str, bytes]:
    normalized: dict[str, bytes] = {}
    collision_keys: dict[str, str] = {}
    for raw_name, raw_data in files.items():
        name = _strict_archive_path(raw_name)
        key = _archive_collision_key(name)
        previous = collision_keys.get(key)
        if previous is not None:
            raise ValueError(
                f"audit ZIP member has a case-insensitive collision: {previous!r} and {name!r}"
            )
        collision_keys[key] = name
        normalized[name] = bytes(raw_data)
    return normalized


def _is_minimal_failure_status(packaging_status: object, package_status: object) -> bool:
    return (
        str(getattr(packaging_status, "value", packaging_status) or "").upper()
        == "FAILED"
        or str(getattr(package_status, "value", package_status) or "").upper()
        == "INVALID"
    )


def _required_control_files(packaging_status: object, package_status: object) -> tuple[str, ...]:
    if _is_minimal_failure_status(packaging_status, package_status):
        return _MINIMAL_FAILURE_CONTROL_FILES
    return _CONTROL_FILES


def _manifest_identity_expectations(result: object) -> dict[str, str]:
    manifest = result.manifest
    return {
        "submission_id": str(result.submission_id),
        "snapshot_id": str(result.snapshot_id),
        "snapshot_fingerprint": str(result.snapshot_fingerprint),
        "generated_at": str(result.generated_at),
        "workflow": str(manifest.workflow.value),
        "source_run_status": str(manifest.source_run_status.value),
        "terminal_status": str(manifest.terminal_status.value),
        "verification_status": str(manifest.verification_status.value),
        "packaging_status": str(manifest.packaging_status.value),
        "audit_package_status": str(manifest.audit_package_status.value),
        "depth": str(manifest.depth.value),
    }


def _validate_manifest_and_sums(
    files: Mapping[str, bytes],
    *,
    require_sha256sums: bool,
    expected_identity: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Bind physical members, the manifest and SHA256SUMS to the same bytes."""
    try:
        manifest = json.loads(files[MANIFEST_PATH].decode("utf-8-sig"))
    except KeyError:
        raise ValueError("audit ZIP is missing submission_manifest.json") from None
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise ValueError("audit ZIP submission_manifest.json is unreadable") from None
    if not isinstance(manifest, dict):
        raise ValueError("audit ZIP submission_manifest.json must contain an object")

    if expected_identity is not None:
        for field_name, expected in expected_identity.items():
            actual = manifest.get(field_name)
            # source_run_status was introduced after terminal_status and is the
            # only identity field old manifests may legitimately omit.
            if field_name == "source_run_status" and actual is None:
                actual = manifest.get("terminal_status")
            if str(actual or "") != str(expected):
                raise ValueError(
                    f"audit ZIP manifest {field_name} conflicts with its submission result"
                )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("audit ZIP manifest has no physical artifact declaration list")
    declared: dict[str, Mapping[str, object]] = {}
    declared_keys: dict[str, str] = {}
    alias_rows: list[Mapping[str, object]] = []
    for raw_record in artifacts:
        if not isinstance(raw_record, Mapping):
            raise ValueError("audit ZIP manifest contains a malformed artifact declaration")
        path = _strict_archive_path(raw_record.get("path"))
        key = _archive_collision_key(path)
        if key in declared_keys:
            raise ValueError("audit ZIP manifest declares a duplicate or case-colliding path")
        declared_keys[key] = path
        declared[path] = raw_record
        aliases = raw_record.get("aliases")
        if aliases is None:
            aliases = ()
        if not isinstance(aliases, (list, tuple)):
            raise ValueError("audit ZIP manifest artifact aliases must be a list")
        for alias in aliases:
            if not isinstance(alias, Mapping):
                raise ValueError("audit ZIP manifest contains a malformed alias")
            if "path" in alias or "physical_path" in alias:
                raise ValueError("audit ZIP alias must not claim a physical path")
            alias_rows.append(alias)

    if set(declared) != set(files):
        missing = sorted(set(declared) - set(files))
        undeclared = sorted(set(files) - set(declared))
        raise ValueError(
            "audit ZIP actual members conflict with manifest declarations "
            f"(missing={missing}, undeclared={undeclared})"
        )

    for path, record in declared.items():
        role = str(record.get("artifact_role") or "")
        # The manifest and checksum file are self-referential controls.  Their
        # records intentionally use placeholder byte metadata; all other
        # physical artifacts must bind directly to their declared bytes.
        if role in {"SUBMISSION_MANIFEST", "SHA256SUMS"}:
            continue
        digest = str(record.get("bytes_sha256") or "")
        byte_count = record.get("byte_count")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"audit ZIP manifest has an invalid SHA-256 for {path}")
        if byte_count != len(files[path]) or not hmac.compare_digest(
            digest, _sha256(files[path])
        ):
            raise ValueError(f"audit ZIP member failed its manifest hash/size check: {path}")

    member_keys = {_archive_collision_key(name): name for name in files}
    for alias in alias_rows:
        logical_path = _strict_archive_path(alias.get("logical_path"))
        canonical_path = _strict_archive_path(alias.get("canonical_path"))
        if _archive_collision_key(logical_path) in member_keys:
            raise ValueError("audit ZIP alias logical_path incorrectly names a physical member")
        if canonical_path not in declared:
            raise ValueError("audit ZIP alias canonical_path does not name a physical member")
        if alias.get("deduplicated") is not True:
            raise ValueError("audit ZIP alias is not marked as deduplicated")

    minimal_failure = _is_minimal_failure_status(
        manifest.get("packaging_status"), manifest.get("audit_package_status")
    )
    required_controls = _required_control_files(
        manifest.get("packaging_status"), manifest.get("audit_package_status")
    )
    missing_controls = [name for name in required_controls if name not in files]
    if missing_controls:
        raise ValueError(f"audit ZIP is missing required control files: {missing_controls}")
    if minimal_failure:
        missing_failure = sorted(_MINIMAL_FAILURE_MEMBERS - set(files))
        if missing_failure:
            raise ValueError(
                f"minimal failure audit ZIP is missing failure evidence: {missing_failure}"
            )

    if _SHA256SUMS_PATH not in files:
        if require_sha256sums and not minimal_failure:
            raise ValueError("audit ZIP is missing audit/SHA256SUMS")
        return manifest
    try:
        text = files[_SHA256SUMS_PATH].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("audit ZIP SHA256SUMS is not UTF-8") from None
    sums: dict[str, str] = {}
    sum_keys: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError("audit ZIP SHA256SUMS contains a malformed line")
        digest, raw_path = match.groups()
        path = _strict_archive_path(raw_path)
        key = _archive_collision_key(path)
        if key in sum_keys:
            raise ValueError("audit ZIP SHA256SUMS contains a duplicate path")
        sum_keys[key] = path
        sums[path] = digest
    expected_sum_paths = set(files) - {_SHA256SUMS_PATH}
    if set(sums) != expected_sum_paths:
        raise ValueError("audit ZIP SHA256SUMS does not cover every non-self physical member")
    for path, expected_digest in sums.items():
        if not hmac.compare_digest(expected_digest, _sha256(files[path])):
            raise ValueError(f"audit ZIP SHA256SUMS failed verification: {path}")
    return manifest


def _validate_audit_zip(
    data: bytes,
    *,
    expected_files: Mapping[str, bytes] | None = None,
    expected_controls: Mapping[str, bytes] | None = None,
    expected_identity: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Read every member and validate namespace, manifest and checksums."""
    if not data:
        raise ValueError("generated audit ZIP is empty")
    extracted: dict[str, bytes] = {}
    collision_keys: dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            for info in archive.infolist():
                if info.is_dir():
                    raise ValueError("audit ZIP contains an undeclared directory member")
                if info.flag_bits & 0x1:
                    raise ValueError("audit ZIP contains an encrypted member")
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in {0, stat.S_IFREG}:
                    raise ValueError("audit ZIP contains a non-regular member")
                name = _strict_archive_path(info.filename)
                key = _archive_collision_key(name)
                if key in collision_keys:
                    raise ValueError(
                        "audit ZIP contains duplicate or case-insensitively colliding members"
                    )
                collision_keys[key] = name
                if expected_files is not None and name in expected_files:
                    if info.file_size != len(expected_files[name]):
                        raise ValueError(f"audit ZIP member size conflicts with generated bytes: {name}")
                with archive.open(info, "r") as handle:
                    extracted[name] = handle.read()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        raise ValueError("generated audit ZIP is unreadable") from exc

    extracted = _validate_file_namespace(extracted)
    if expected_files is not None:
        normalized_expected = _validate_file_namespace(expected_files)
        if set(extracted) != set(normalized_expected):
            raise ValueError("audit ZIP members do not match generated submission files")
        for name, expected in normalized_expected.items():
            if not hmac.compare_digest(extracted[name], expected):
                raise ValueError(f"audit ZIP member bytes changed during packaging: {name}")
    if expected_controls is not None:
        normalized_controls = _validate_file_namespace(expected_controls)
        for name, expected in normalized_controls.items():
            actual = extracted.get(name)
            if actual is None or not hmac.compare_digest(actual, expected):
                raise ValueError(
                    f"audit ZIP control differs from its committed copy: {name}"
                )
    return _validate_manifest_and_sums(
        extracted,
        require_sha256sums=True,
        expected_identity=expected_identity,
    )


def _redact_descriptor_text(value: str) -> str:
    value = _WINDOWS_ABSOLUTE_RE.sub("<LOCAL_PATH>", str(value))
    value = _UNC_RE.sub("<LOCAL_PATH>", value)
    return _POSIX_HOME_RE.sub("<LOCAL_PATH>", value)


def _is_sensitive_descriptor_key(value: object) -> bool:
    name = str(value).casefold()
    normalized = re.sub(r"[^a-z0-9]", "", name)
    return (
        normalized.endswith("apikey")
        or name in _SENSITIVE_KEYS
        or (
            normalized.startswith(("codex", "chatgpt"))
            and normalized.endswith(
                ("token", "email", "accountid", "userid", "login", "auth", "session", "account")
            )
        )
    )


def _safe_descriptor_value(value: Any) -> Any:
    """Remove location/credential fields while retaining machine booleans/results."""
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            name = str(key)
            if _is_sensitive_descriptor_key(name):
                result[name] = "<REDACTED>"
            else:
                result[name] = _safe_descriptor_value(item)
        return result
    if isinstance(value, (tuple, list)):
        return [_safe_descriptor_value(item) for item in value]
    if isinstance(value, str):
        return _redact_descriptor_text(value)
    return value


def _contains_local_absolute_path(value: Any) -> bool:
    """Inspect decoded values so JSON escaping cannot imitate a UNC path."""
    if isinstance(value, Mapping):
        return any(_contains_local_absolute_path(item) for item in value.values())
    if isinstance(value, (tuple, list)):
        return any(_contains_local_absolute_path(item) for item in value)
    if isinstance(value, str):
        return bool(
            _WINDOWS_ABSOLUTE_RE.search(value)
            or _UNC_RE.search(value)
            or _POSIX_HOME_RE.search(value)
        )
    return False


def _bounded_status_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 5:
        return "<TRUNCATED>"
    if isinstance(value, Mapping):
        return {
            str(key): _bounded_status_value(item, depth=depth + 1)
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (tuple, list)):
        return [
            _bounded_status_value(item, depth=depth + 1) for item in value[:100]
        ]
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:2000]


def _machine_verification_summary(value: Mapping[str, object]) -> dict[str, object]:
    """Keep only bounded status facts; the full record is a hashed artifact blob."""
    result: dict[str, object] = {
        # Identity comparison in RunSnapshot means only a literal boolean can
        # produce VERIFIED after this descriptor is loaded.
        "safe_to_export": value.get("safe_to_export") is True,
    }
    for key in (
        "export_blocked",
        "preview_state",
        "raw_preview_state",
        "audit_terminal_status",
    ):
        if key in value:
            result[key] = _safe_descriptor_value(value.get(key))
    for key in ("checks", "failures"):
        items = value.get(key)
        if isinstance(items, (list, tuple)):
            result[key] = _safe_descriptor_value(
                _bounded_status_value(list(items)[:100])
            )
    for key in ("compile_before", "compile_after", "compile"):
        record = value.get(key)
        if not isinstance(record, Mapping):
            continue
        result[key] = _safe_descriptor_value(_bounded_status_value({
            name: record.get(name)
            for name in (
                "available", "ok", "pages", "errors", "preview_status",
                "process_status", "return_code", "fatal_line", "timed_out",
                "checked", "unverified", "engine", "passes_attempted",
                "exit_code", "page_count", "pdf_sha256",
                "compile_input_sha256", "fatal_error", "log_path",
            )
            if name in record
        }))
    for key in ("preview_artifact", "raw_preview_artifact"):
        record = value.get(key)
        if not isinstance(record, Mapping):
            continue
        result[key] = _safe_descriptor_value(_bounded_status_value({
            name: record.get(name)
            for name in (
                "status", "filename", "sha256", "bytes", "engine",
                "passes_attempted", "exit_code", "page_count", "pdf_sha256",
                "compile_input_sha256", "fatal_line", "fatal_error", "log_path",
                "tex_sha256", "tex_lf_normalized_sha256",
            )
            if name in record
        }))
    return result


def _relative_blob_path(digest: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid blob digest")
    return f"blobs/{digest[:2]}/{digest}.blob"


@dataclass(frozen=True, slots=True)
class StoredAuditSubmission:
    submission_id: str
    snapshot_id: str
    snapshot_fingerprint: str
    generated_at: str
    workflow: str
    terminal_status: str
    verification_status: str
    packaging_status: str
    audit_package_status: str
    depth: str
    state: str
    relative_directory: str
    zip_relative_path: str | None = None
    zip_sha256: str = ""
    zip_bytes: int = 0
    stale: bool = False
    stale_reason: str = ""
    stale_at: str = ""
    current_fingerprint: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "submission_id": self.submission_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "generated_at": self.generated_at,
            "workflow": self.workflow,
            "terminal_status": self.terminal_status,
            "verification_status": self.verification_status,
            "packaging_status": self.packaging_status,
            "audit_package_status": self.audit_package_status,
            "depth": self.depth,
            "state": self.state,
            "relative_directory": self.relative_directory,
            "zip_relative_path": self.zip_relative_path,
            "zip_sha256": self.zip_sha256,
            "zip_bytes": self.zip_bytes,
            "stale": self.stale,
            "stale_reason": self.stale_reason,
            "stale_at": self.stale_at,
            "current_fingerprint": self.current_fingerprint,
        }


class AuditSubmissionStore:
    """One-project repository for snapshots, generated controls and ZIPs."""

    def __init__(self, project_directory: str | os.PathLike[str]):
        project = Path(project_directory).resolve()
        if not project.is_dir():
            raise ValueError("audit submission store requires an existing project directory")
        self._project_directory = project
        self._root = project / "audit-submissions"
        root_key = os.path.normcase(str(self._root))
        with _COMMIT_LOCKS_GUARD:
            self._commit_lock = _COMMIT_LOCKS.setdefault(root_key, threading.RLock())
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        """Local root for host operations; never include this value in API JSON."""
        return self._root

    def _atomic_write(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _write_immutable(self, path: Path, data: bytes) -> None:
        """Create once, permit byte-identical retries, reject replacement."""
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.is_file() and path.read_bytes() == data:
                return
            raise FileExistsError(f"immutable audit record already exists: {path.name}")
        temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if not path.is_file() or path.read_bytes() != data:
                    raise FileExistsError(
                        f"immutable audit record raced with different bytes: {path.name}"
                    ) from None
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _blob_write(self, data: bytes) -> str:
        digest = _sha256(data)
        relative = _relative_blob_path(digest)
        target = self._root / PurePosixPath(relative)
        self._write_immutable(target, data)
        if target.stat().st_size != len(data) or _sha256(target.read_bytes()) != digest:
            raise OSError("content-addressed audit blob failed its post-write check")
        return relative

    def save_snapshot(self, snapshot: RunSnapshot) -> str:
        """Persist a deep snapshot; an existing snapshot ID can never be replaced."""
        if not isinstance(snapshot, RunSnapshot):
            raise TypeError("save_snapshot requires RunSnapshot")
        snapshot_id = _safe_id(snapshot.snapshot_id, "snapshot id")
        artifact_rows = []
        for item in snapshot.artifacts:
            portable = _portable_path(item.path)
            blob = self._blob_write(item.data)
            artifact_rows.append({
                "artifact_id": item.artifact_id,
                "artifact_role": item.artifact_role,
                "path": portable,
                "blob": blob,
                "bytes_sha256": item.bytes_sha256,
                "byte_count": item.byte_count,
                "media_type": item.media_type,
                "parent_artifact_ids": list(item.parent_artifact_ids),
                "preview_status": item.preview_status,
                "metadata": _safe_descriptor_value(thaw_json(item.metadata)),
            })
        descriptor = {
            "schema": SNAPSHOT_STORAGE_SCHEMA,
            "snapshot_id": snapshot_id,
            "current_fingerprint": snapshot.current_fingerprint,
            "project_id": _redact_descriptor_text(str(snapshot.project_id)),
            "run_id": _redact_descriptor_text(str(snapshot.run_id)),
            "workflow": snapshot.workflow.value,
            "terminal_status": snapshot.terminal_status.value,
            "captured_at": str(snapshot.captured_at),
            "machine_verification": _machine_verification_summary(
                thaw_json(snapshot.machine_verification)
            ),
            "blockers": _safe_descriptor_value(list(snapshot.blockers)),
            "model": _redact_descriptor_text(str(snapshot.model)),
            "app_version": str(snapshot.app_version),
            "template": _redact_descriptor_text(str(snapshot.template)),
            "page_range": _redact_descriptor_text(str(snapshot.page_range)),
            "metadata": _safe_descriptor_value(thaw_json(snapshot.metadata)),
            "stages": _safe_descriptor_value({
                name: execution.to_dict()
                for name, execution in snapshot.stages.items()
            }),
            "source_pdf": _safe_descriptor_value(
                snapshot.source_pdf.to_dict() if snapshot.source_pdf else None
            ),
            "provenance": _safe_descriptor_value(snapshot.provenance.to_dict()),
            "artifacts": artifact_rows,
        }
        descriptor["descriptor_sha256"] = _descriptor_sha256(descriptor)
        encoded = _json_bytes(descriptor)
        # Verify the serialized descriptor itself has no host absolute location.
        if _contains_local_absolute_path(descriptor):
            raise ValueError("snapshot descriptor contains a local absolute path")
        self._write_immutable(self._root / "snapshots" / f"{snapshot_id}.json", encoded)
        return snapshot_id

    def load_snapshot(self, snapshot_id: str) -> RunSnapshot:
        snapshot_id = _safe_id(snapshot_id, "snapshot id")
        descriptor_path = self._root / "snapshots" / f"{snapshot_id}.json"
        try:
            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise KeyError(f"unknown audit snapshot: {snapshot_id}") from None
        if descriptor.get("schema") != SNAPSHOT_STORAGE_SCHEMA:
            raise ValueError("unsupported audit snapshot descriptor schema")
        if descriptor.get("snapshot_id") != snapshot_id:
            raise ValueError("audit snapshot descriptor ID does not match its immutable key")
        recorded_descriptor_hash = str(descriptor.get("descriptor_sha256") or "")
        if not hmac.compare_digest(recorded_descriptor_hash, _descriptor_sha256(descriptor)):
            raise ValueError("audit snapshot descriptor failed its integrity check")
        artifacts = []
        for row in descriptor.get("artifacts") or []:
            digest = str(row.get("bytes_sha256") or "")
            expected_blob = _relative_blob_path(digest)
            if row.get("blob") != expected_blob:
                raise ValueError("snapshot artifact blob reference conflicts with its SHA-256")
            blob_path = self._root / PurePosixPath(expected_blob)
            try:
                data = blob_path.read_bytes()
            except FileNotFoundError:
                raise ValueError("snapshot artifact blob is missing") from None
            if _sha256(data) != digest or len(data) != row.get("byte_count"):
                raise ValueError("snapshot artifact blob failed its hash/size check")
            artifact = AuditArtifact(
                artifact_role=row.get("artifact_role"),
                path=_portable_path(row.get("path")),
                data=data,
                media_type=row.get("media_type") or "application/octet-stream",
                parent_artifact_ids=tuple(row.get("parent_artifact_ids") or ()),
                preview_status=row.get("preview_status"),
                metadata=row.get("metadata") or {},
            )
            if row.get("artifact_id") != artifact.artifact_id:
                raise ValueError("snapshot logical artifact ID failed verification")
            artifacts.append(artifact)
        snapshot = RunSnapshot(
            project_id=descriptor.get("project_id") or "unknown",
            run_id=descriptor.get("run_id") or "unknown",
            workflow=AuditWorkflow(descriptor.get("workflow")),
            terminal_status=TerminalStatus(descriptor.get("terminal_status")),
            captured_at=descriptor.get("captured_at") or "unknown",
            artifacts=tuple(artifacts),
            machine_verification=descriptor.get("machine_verification") or {},
            blockers=tuple(descriptor.get("blockers") or ()),
            model=descriptor.get("model") or "unknown",
            app_version=descriptor.get("app_version") or "unknown",
            template=descriptor.get("template") or "none",
            page_range=descriptor.get("page_range") or "all",
            metadata=descriptor.get("metadata") or {},
            stages=descriptor.get("stages") or {},
            source_pdf=descriptor.get("source_pdf"),
            provenance=descriptor.get("provenance") or {},
        )
        if snapshot.current_fingerprint != descriptor.get("current_fingerprint"):
            raise ValueError("stored snapshot current-artifact fingerprint is inconsistent")
        # Descriptor privacy cleaning may redact non-artifact metadata, so the
        # original content identity is the immutable ID recorded by save_snapshot.
        object.__setattr__(snapshot, "snapshot_id", snapshot_id)
        return snapshot

    def _commit_submission(
        self,
        result,
        *,
        zip_filename: str | None,
        force_latest: bool = False,
    ) -> StoredAuditSubmission:
        submission_id = _safe_id(result.submission_id, "submission id")
        files = _validate_file_namespace(result.files)
        expected_identity = _manifest_identity_expectations(result)
        _validate_manifest_and_sums(
            files,
            require_sha256sums=zip_filename is not None,
            expected_identity=expected_identity,
        )
        control_files = _required_control_files(
            result.manifest.packaging_status,
            result.manifest.audit_package_status,
        )
        zip_digest = ""
        if zip_filename is not None:
            _validate_audit_zip(
                result.zip_bytes,
                expected_files=files,
                expected_identity=expected_identity,
            )
            zip_digest = _sha256(result.zip_bytes)
            if not hmac.compare_digest(zip_digest, str(result.zip_sha256 or "")):
                raise ValueError("generated audit ZIP SHA-256 conflicts with its result")
        relative_directory = f"submissions/{submission_id}"
        target = self._root / "submissions" / submission_id
        if target.exists():
            raise FileExistsError(f"audit submission already exists: {submission_id}")
        target.parent.mkdir(parents=True, exist_ok=True)
        stage = self._root / f".submission-{submission_id}-{uuid.uuid4().hex}.tmp"
        stage.mkdir(parents=True, exist_ok=False)
        try:
            for name in control_files:
                data = files.get(name)
                if data is None:
                    raise ValueError(f"generated audit submission is missing {name}")
                path = stage / PurePosixPath(name)
                self._atomic_write(path, data)
            zip_relative_path = None
            if zip_filename is not None:
                safe_name = self._safe_zip_filename(zip_filename)
                zip_path = stage / safe_name
                self._atomic_write(zip_path, result.zip_bytes)
                zip_relative_path = f"{relative_directory}/{safe_name}"
            descriptor = {
                "schema": SUBMISSION_STORAGE_SCHEMA,
                "submission_id": submission_id,
                "snapshot_id": result.snapshot_id,
                "snapshot_fingerprint": result.snapshot_fingerprint,
                "generated_at": result.generated_at,
                "workflow": result.manifest.workflow.value,
                "terminal_status": result.manifest.terminal_status.value,
                "verification_status": result.manifest.verification_status.value,
                "packaging_status": result.manifest.packaging_status.value,
                "audit_package_status": result.manifest.audit_package_status.value,
                "depth": result.manifest.depth.value,
                "state": "READY" if zip_filename is not None else "LIGHTWEIGHT",
                "relative_directory": relative_directory,
                "zip_relative_path": zip_relative_path,
                "zip_sha256": zip_digest if zip_filename is not None else "",
                "zip_bytes": len(result.zip_bytes) if zip_filename is not None else 0,
                "control_files": list(control_files),
                "control_sha256": {
                    name: _sha256(files[name]) for name in control_files
                },
                "control_bytes": {
                    name: len(files[name]) for name in control_files
                },
            }
            descriptor["descriptor_sha256"] = _descriptor_sha256(descriptor)
            self._atomic_write(stage / "submission.json", _json_bytes(descriptor))
            # The directory becomes visible as a complete immutable unit.
            os.replace(stage, target)
        finally:
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
        with self._commit_lock:
            if force_latest:
                # A terminal run is the host authority for "current".  Do not
                # read the old pointer here: it may refer to a damaged historic
                # control set, and that must not prevent recovery by a new run.
                self._mark_other_snapshot_submissions_stale_locked(
                    current_snapshot_id=result.snapshot_id,
                    current_fingerprint=result.snapshot_fingerprint,
                    reason="项目产生了新的终态运行快照",
                )
                self._atomic_write(
                    self._root / "latest.json",
                    _json_bytes({
                        "schema": LATEST_POINTER_SCHEMA,
                        "submission_id": submission_id,
                    }),
                )
            else:
                current = self.latest()
                if current is None or current.snapshot_id == result.snapshot_id:
                    self._atomic_write(
                        self._root / "latest.json",
                        _json_bytes({
                            "schema": LATEST_POINTER_SCHEMA,
                            "submission_id": submission_id,
                        }),
                    )
                else:
                    # A ZIP built from an older snapshot may finish after a new
                    # terminal run.  It remains downloadable history, but the
                    # POST result must already say stale before leaving storage.
                    self.mark_stale(
                        submission_id,
                        "生成期间项目产生了新的终态运行快照",
                        current_fingerprint=current.snapshot_fingerprint,
                    )
        return self.get_submission(submission_id)

    def _mark_other_snapshot_submissions_stale_locked(
        self,
        *,
        current_snapshot_id: str,
        current_fingerprint: str,
        reason: str,
    ) -> tuple[str, ...]:
        """Stale all intact historic descriptors before force-latest publish.

        The caller holds ``_commit_lock``.  This recovery path deliberately
        does not validate historic control files: a damaged old prompt must not
        block a new terminal commit.  Ordinary reads still validate those files
        and fail closed.  A damaged immutable descriptor is skipped because it
        cannot safely identify the snapshot it belongs to.
        """
        marked = []
        directory = self._root / "submissions"
        if not directory.is_dir():
            return ()
        for child in sorted(directory.iterdir(), key=lambda path: path.name):
            if not child.is_dir() or not _SAFE_ID_RE.fullmatch(child.name):
                continue
            try:
                descriptor = self._submission_descriptor_without_controls(child.name)
            except (KeyError, OSError, TypeError, ValueError):
                continue
            if descriptor.get("snapshot_id") == current_snapshot_id:
                continue
            stale_path = self._root / "stale" / f"{child.name}.json"
            if stale_path.is_file():
                continue
            self._write_stale_record(
                submission_id=child.name,
                snapshot_fingerprint=str(descriptor.get("snapshot_fingerprint") or ""),
                current_fingerprint=current_fingerprint,
                reason=reason,
            )
            marked.append(child.name)
        return tuple(marked)

    @staticmethod
    def _safe_zip_filename(filename: str) -> str:
        raw = str(filename or "LaTeXStruct-AI-audit.zip").replace("\\", "/")
        if "/" in raw or raw in {"", ".", ".."}:
            raise ValueError("audit ZIP filename must not contain a directory")
        cleaned = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff._ -]+", "_", raw).strip(" .")
        if not cleaned.casefold().endswith(".zip"):
            cleaned += ".zip"
        if not cleaned or cleaned.casefold() == ".zip":
            raise ValueError("invalid audit ZIP filename")
        if cleaned.split(".", 1)[0].rstrip(" .").casefold() in _WINDOWS_DEVICE_STEMS:
            raise ValueError("audit ZIP filename uses a reserved Windows device name")
        return cleaned

    def create_lightweight(
        self,
        snapshot: RunSnapshot,
        *,
        audit_focus: str = "",
    ) -> StoredAuditSubmission:
        """Persist a terminal snapshot and atomically commit its four controls."""
        # Acquire before snapshot/control generation so once a new terminal
        # publish begins, an older ZIP cannot commit as current in the middle.
        with self._commit_lock:
            self.save_snapshot(snapshot)
            result = build_lightweight_audit_files(snapshot, audit_focus=audit_focus)
            return self._commit_submission(
                result,
                zip_filename=None,
                force_latest=True,
            )

    # Explicitly named alias for call sites at the terminal transition.
    persist_terminal_snapshot = create_lightweight

    def generate_zip(
        self,
        snapshot_id: str,
        request: AuditSubmissionRequest | None = None,
        *,
        filename: str = "LaTeXStruct-AI-audit.zip",
        current_fingerprint: str = "",
        stale_reason: str = "current TeX/PDF/decisions/verification changed",
    ) -> StoredAuditSubmission:
        """Generate a new immutable submission; an older same-name ZIP survives."""
        snapshot = self.load_snapshot(snapshot_id)
        result = build_audit_submission(snapshot, request)
        stored = self._commit_submission(result, zip_filename=filename)
        if current_fingerprint and current_fingerprint != snapshot.current_fingerprint:
            stored = self.mark_stale(
                stored.submission_id,
                stale_reason,
                current_fingerprint=current_fingerprint,
            )
        return stored

    # A descriptive alias for FastAPI integration.
    generate_submission_zip = generate_zip

    def _submission_descriptor_without_controls(
        self,
        submission_id: str,
    ) -> dict[str, object]:
        """Read an immutable descriptor without trusting mutable controls.

        Only force-latest recovery/staleness code should use this path.  Public
        reads go through ``_submission_descriptor`` and therefore fail closed
        if any committed control file is missing or has changed.
        """
        submission_id = _safe_id(submission_id, "submission id")
        path = self._root / "submissions" / submission_id / "submission.json"
        try:
            descriptor = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise KeyError(f"unknown audit submission: {submission_id}") from None
        if descriptor.get("schema") != SUBMISSION_STORAGE_SCHEMA:
            raise ValueError("unsupported audit submission descriptor schema")
        if descriptor.get("submission_id") != submission_id:
            raise ValueError("audit submission descriptor ID mismatch")
        recorded_hash = str(descriptor.get("descriptor_sha256") or "")
        if not hmac.compare_digest(recorded_hash, _descriptor_sha256(descriptor)):
            raise ValueError("audit submission descriptor failed its integrity check")
        return descriptor

    def _submission_descriptor(self, submission_id: str) -> dict[str, object]:
        descriptor = self._submission_descriptor_without_controls(submission_id)
        control_hashes = descriptor.get("control_sha256")
        control_sizes = descriptor.get("control_bytes")
        if not isinstance(control_hashes, dict) or not isinstance(control_sizes, dict):
            raise ValueError("audit submission has no complete control-file commit record")
        expected_controls = _required_control_files(
            descriptor.get("packaging_status") or "SUCCESS",
            descriptor.get("audit_package_status") or "VALID",
        )
        recorded_controls = descriptor.get("control_files")
        if recorded_controls is None:
            # v1 descriptors predate the explicit list and always committed the
            # four normal controls.
            control_files = _CONTROL_FILES
        elif isinstance(recorded_controls, list):
            control_files = tuple(str(name) for name in recorded_controls)
        else:
            raise ValueError("audit submission has an invalid control-file list")
        if control_files != expected_controls:
            raise ValueError("audit submission control-file set conflicts with package status")
        if set(control_hashes) != set(control_files) or set(control_sizes) != set(control_files):
            raise ValueError("audit submission control-file commit record is ambiguous")
        directory = self._root / "submissions" / submission_id
        for name in control_files:
            expected_hash = str(control_hashes.get(name) or "")
            expected_size = control_sizes.get(name)
            path = directory / PurePosixPath(name)
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                raise ValueError(f"audit submission control file is missing: {name}") from None
            if len(data) != expected_size or not hmac.compare_digest(
                _sha256(data), expected_hash
            ):
                raise ValueError(f"audit submission control file failed verification: {name}")
        return descriptor

    def get_submission(self, submission_id: str) -> StoredAuditSubmission:
        descriptor = self._submission_descriptor(submission_id)
        stale_path = self._root / "stale" / f"{submission_id}.json"
        stale = {}
        if stale_path.is_file():
            stale = json.loads(stale_path.read_text(encoding="utf-8"))
            if stale.get("schema") != STALE_RECORD_SCHEMA:
                raise ValueError("unsupported audit stale record schema")
        return StoredAuditSubmission(
            submission_id=str(descriptor["submission_id"]),
            snapshot_id=str(descriptor["snapshot_id"]),
            snapshot_fingerprint=str(descriptor["snapshot_fingerprint"]),
            generated_at=str(descriptor["generated_at"]),
            workflow=str(descriptor["workflow"]),
            terminal_status=str(descriptor["terminal_status"]),
            verification_status=str(descriptor["verification_status"]),
            packaging_status=str(descriptor.get("packaging_status") or "SUCCESS"),
            audit_package_status=str(
                descriptor.get("audit_package_status") or "VALID"
            ),
            depth=str(descriptor["depth"]),
            state=str(descriptor["state"]),
            relative_directory=str(descriptor["relative_directory"]),
            zip_relative_path=(
                str(descriptor["zip_relative_path"])
                if descriptor.get("zip_relative_path")
                else None
            ),
            zip_sha256=str(descriptor.get("zip_sha256") or ""),
            zip_bytes=int(descriptor.get("zip_bytes") or 0),
            stale=bool(stale),
            stale_reason=str(stale.get("reason") or ""),
            stale_at=str(stale.get("marked_at") or ""),
            current_fingerprint=str(stale.get("current_fingerprint") or ""),
        )

    def latest(self) -> StoredAuditSubmission | None:
        path = self._root / "latest.json"
        try:
            pointer = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        if pointer.get("schema") != LATEST_POINTER_SCHEMA:
            raise ValueError("unsupported latest-audit pointer schema")
        return self.get_submission(str(pointer.get("submission_id") or ""))

    def record_saved_download(self, submission_id: str, filename: str) -> None:
        """Remember the exact collision-safe filename written to Downloads.

        The immutable submission descriptor continues to describe the canonical
        archive stored inside the project.  This small sidecar records only the
        basename of the user-facing copy, never its absolute host path.
        """
        submission = self.get_submission(submission_id)
        if not submission.zip_relative_path or not submission.zip_sha256:
            raise ValueError("audit submission has no ZIP to record as downloaded")
        raw_name = str(filename or "").strip()
        from .downloads import safe_download_filename

        safe_name = safe_download_filename(raw_name, default="LaTeXStruct-AI-audit.zip")
        if safe_name != raw_name or not safe_name.casefold().endswith(".zip"):
            raise ValueError("saved audit ZIP filename is not a safe basename")
        record = {
            "schema": SAVED_DOWNLOAD_RECORD_SCHEMA,
            "submission_id": submission.submission_id,
            "snapshot_id": submission.snapshot_id,
            "zip_sha256": submission.zip_sha256,
            "saved_filename": safe_name,
            "recorded_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
        }
        self._atomic_write(
            self._root / "saved-downloads" / f"{submission.submission_id}.json",
            _json_bytes(record),
        )

    def saved_download_filename(self, submission_id: str) -> str:
        """Return the verified user-facing basename, or ``""`` when absent."""
        submission = self.get_submission(submission_id)
        path = self._root / "saved-downloads" / f"{submission.submission_id}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ""
        if record.get("schema") != SAVED_DOWNLOAD_RECORD_SCHEMA:
            raise ValueError("unsupported audit saved-download record schema")
        if (
            record.get("submission_id") != submission.submission_id
            or record.get("snapshot_id") != submission.snapshot_id
            or not hmac.compare_digest(
                str(record.get("zip_sha256") or ""), submission.zip_sha256
            )
        ):
            raise ValueError("audit saved-download record conflicts with submission")
        raw_name = str(record.get("saved_filename") or "")
        from .downloads import safe_download_filename

        safe_name = safe_download_filename(raw_name, default="LaTeXStruct-AI-audit.zip")
        if safe_name != raw_name or not safe_name.casefold().endswith(".zip"):
            raise ValueError("audit saved-download record has an unsafe filename")
        return safe_name

    def submission_freshness(
        self,
        submission_id: str,
        *,
        stale_reason: str = "生成期间项目产生了新的终态运行快照",
    ) -> tuple[StoredAuditSubmission, StoredAuditSubmission | None]:
        """Atomically classify one submission against the current pointer.

        Callers use this immediately before publishing an API response.  A
        terminal commit and this classification share ``_commit_lock``, so the
        returned submission/latest pair cannot straddle two pointer states.
        Ordinary verified reads remain fail-closed because both records still
        pass through :meth:`get_submission` / :meth:`latest`.
        """
        with self._commit_lock:
            stored = self.get_submission(submission_id)
            newest = self.latest()
            if newest is not None and newest.snapshot_id != stored.snapshot_id:
                stored = self.mark_stale(
                    stored.submission_id,
                    stale_reason,
                    current_fingerprint=newest.snapshot_fingerprint,
                )
            return stored, newest

    def mark_stale(
        self,
        submission_id: str,
        reason: str,
        *,
        current_fingerprint: str = "",
        marked_at: str | None = None,
    ) -> StoredAuditSubmission:
        """Attach an explicit reason without mutating immutable submission files."""
        existing = self.get_submission(submission_id)
        self._write_stale_record(
            submission_id=existing.submission_id,
            snapshot_fingerprint=existing.snapshot_fingerprint,
            current_fingerprint=current_fingerprint,
            reason=reason,
            marked_at=marked_at,
        )
        return self.get_submission(existing.submission_id)

    def _write_stale_record(
        self,
        *,
        submission_id: str,
        snapshot_fingerprint: str,
        current_fingerprint: str,
        reason: str,
        marked_at: str | None = None,
    ) -> None:
        """Atomically write a stale sidecar from already-verified identity facts."""
        submission_id = _safe_id(submission_id, "submission id")
        reason = _redact_descriptor_text(str(reason or "").strip())
        if not reason:
            raise ValueError("stale audit submission requires an explicit reason")
        record = {
            "schema": STALE_RECORD_SCHEMA,
            "submission_id": submission_id,
            "snapshot_fingerprint": str(snapshot_fingerprint or ""),
            "current_fingerprint": str(current_fingerprint or ""),
            "reason": reason,
            "marked_at": marked_at or datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
        }
        self._atomic_write(
            self._root / "stale" / f"{submission_id}.json",
            _json_bytes(record),
        )

    def mark_outdated_submissions(
        self,
        current_fingerprint: str,
        reason: str,
    ) -> tuple[str, ...]:
        """Mark every committed submission not matching current project bytes."""
        current_fingerprint = str(current_fingerprint or "")
        if not current_fingerprint:
            raise ValueError("current fingerprint is required for stale evaluation")
        marked = []
        directory = self._root / "submissions"
        if not directory.is_dir():
            return ()
        with self._commit_lock:
            for child in sorted(directory.iterdir(), key=lambda path: path.name):
                if not child.is_dir() or not _SAFE_ID_RE.fullmatch(child.name):
                    continue
                try:
                    submission = self.get_submission(child.name)
                except (KeyError, OSError, TypeError, ValueError):
                    # A corrupt historic commit remains fail-closed when read,
                    # downloaded or listed.  It must not, however, prevent an
                    # intact current run from being evaluated or regenerated.
                    continue
                if submission.snapshot_fingerprint != current_fingerprint:
                    self.mark_stale(
                        submission.submission_id,
                        reason,
                        current_fingerprint=current_fingerprint,
                    )
                    marked.append(submission.submission_id)
        return tuple(marked)

    def download_path(self, submission_id: str) -> Path:
        """Resolve a verified local ZIP path for FileResponse/streaming only."""
        submission = self.get_submission(submission_id)
        if not submission.zip_relative_path:
            raise KeyError("audit submission has no ZIP yet")
        relative = _portable_path(submission.zip_relative_path)
        target = (self._root / PurePosixPath(relative)).resolve()
        try:
            target.relative_to(self._root.resolve())
        except ValueError:
            raise ValueError("audit ZIP path escapes its store") from None
        data = target.read_bytes()
        if _sha256(data) != submission.zip_sha256 or len(data) != submission.zip_bytes:
            raise ValueError("stored audit ZIP failed its hash/size check")
        _validate_audit_zip(
            data,
            expected_controls={
                name: (target.parent / PurePosixPath(name)).read_bytes()
                for name in _required_control_files(
                    submission.packaging_status,
                    submission.audit_package_status,
                )
            },
            expected_identity={
                "submission_id": submission.submission_id,
                "snapshot_id": submission.snapshot_id,
                "snapshot_fingerprint": submission.snapshot_fingerprint,
                "generated_at": submission.generated_at,
                "workflow": submission.workflow,
                "source_run_status": submission.terminal_status,
                "terminal_status": submission.terminal_status,
                "verification_status": submission.verification_status,
                "packaging_status": submission.packaging_status,
                "audit_package_status": submission.audit_package_status,
                "depth": submission.depth,
            },
        )
        return target

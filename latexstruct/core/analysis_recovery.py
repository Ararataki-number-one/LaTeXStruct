# -*- coding: utf-8 -*-
"""Crash-safe active-run storage for production analysis.

The store deliberately has no dependency on the analysis orchestrator.  It is
the durable boundary that can be called immediately before the first model
invocation and after each fully committed macro round.  Every directory is
write-once, every manifest is exact (rather than an allow-list), and recovery
uses only hash-valid candidates and checkpoints.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import threading
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping, Sequence


FROZEN_INPUT_SCHEMA = "latexstruct-analysis-frozen-inputs-v2"
_LEGACY_FROZEN_INPUT_SCHEMA = "latexstruct-analysis-frozen-inputs-v1"
CHECKPOINT_SCHEMA = "latexstruct-analysis-active-checkpoint-v1"
COMPILE_INPUT_SCHEMA = "latexstruct-compile-input-set-v1"
PROVISIONAL_IDENTITY_SCHEMA = "latexstruct-analysis-provisional-identity-v1"

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_PORTABLE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CANDIDATE_ID_RE = re.compile(r"cand-r(?P<round>\d{4})-(?P<prefix>[0-9a-f]{12})")
_CHECKPOINT_ID_RE = re.compile(
    r"checkpoint-(?P<sequence>\d{8})-(?P<digest>[0-9a-f]{16})"
)

_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
    | {f"COM{number}" for number in "¹²³"}
    | {f"LPT{number}" for number in "¹²³"}
)
_WINDOWS_FORBIDDEN_CHARS = frozenset('<>:"\\|?*')

_INPUT_ARTIFACT_PATHS = {
    "snapshot": "snapshot.json",
    "source_pdf": "source.pdf",
    "raw_ocr_tex": "raw_ocr.tex",
    "baseline_tex": "baseline.tex",
    "baseline_pdf": "baseline.pdf",
    "baseline_compile_log": "baseline_compile.log",
    "compile_input_manifest": "compile_input_manifest.json",
    "page_map": "page_map.json",
}
_INPUT_METADATA = "frozen_inputs.json"
_HASH_MANIFEST = "SHA256SUMS"
_PROVISIONAL_IDENTITY_FILE = "provisional_run_identity.json"

_STATE_FILES = {
    "run_state": "run_state.json",
    "issue_ledger": "issue_ledger.json",
    "task_ledger": "task_ledger.json",
    "budget_ledger": "budget_ledger.json",
    "invocation_ledger": "invocation_ledger.json",
    "compile_history": "compile_history.json",
    "candidate_page_map": "candidate_page_map.json",
    "rollback_history": "rollback_history.json",
}
_CHECKPOINT_METADATA = "checkpoint.json"

_CANDIDATE_FILES = frozenset(
    {
        "candidate.tex",
        "compile.log",
        "patch.json",
        "candidate.diff",
        "issue_ledger.json",
        "quality_vector.json",
        "review.json",
        "candidate.json",
        _HASH_MANIFEST,
    }
)
_REJECTED_DISPOSITION = "REJECTED_ROLLED_BACK"

_CANDIDATE_METADATA_FIELDS = frozenset({
    "candidate_id",
    "parent_candidate_id",
    "round_index",
    "tex_sha256",
    "pdf_sha256",
    "quality",
    "disposition",
    "reason",
    "artifact_directory",
})
_QUALITY_VECTOR_COUNT_FIELDS = frozenset({
    "silent_page_omissions",
    "silent_text_losses",
    "unauthorized_math_changes",
    "open_critical",
    "open_high",
    "formal_errors",
    "structure_reference_errors",
    "footnote_figure_equation_errors",
    "severe_visual_errors",
    "ordinary_layout_errors",
})
_QUALITY_VECTOR_FIELDS = frozenset({"fully_compiled", *_QUALITY_VECTOR_COUNT_FIELDS})


class AnalysisRecoveryError(ValueError):
    """Base class for fail-closed active-run storage errors."""


class ImmutableEvidenceError(AnalysisRecoveryError):
    """An existing write-once artifact differs from the requested bytes."""


class RecoveryValidationError(AnalysisRecoveryError):
    """Frozen evidence or an explicit recovery expectation is invalid."""


class ActiveRunLockError(AnalysisRecoveryError):
    """The active-run directory is already owned by another process."""


class _InvalidArtifact(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class CompileExtraBinding:
    logical_path: str
    stored_path: str
    sha256: str
    byte_count: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class FrozenAnalysisInputs:
    directory: Path
    run_id: str
    project_id: str
    candidate_storage_name: str
    snapshot_hash: str
    compile_input_manifest_hash: str
    page_map_sha256: str
    source_pdf_sha256: str
    raw_ocr_tex_sha256: str
    baseline_tex_sha256: str
    baseline_pdf_sha256: str
    baseline_compile_log_sha256: str
    compile_extras: tuple[CompileExtraBinding, ...]
    snapshot_bytes: bytes
    source_pdf_bytes: bytes
    raw_ocr_tex_bytes: bytes
    baseline_tex_bytes: bytes
    baseline_pdf_bytes: bytes
    baseline_compile_log_bytes: bytes
    compile_input_manifest_bytes: bytes
    page_map_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProvisionalRunIdentity:
    """Host-owned identity staged before immutable inputs can be frozen.

    This record is deliberately not part of ``inputs/`` and is not immutable
    evidence.  Its only mutable transition is from an unbound ``snapshot_hash``
    to one exact digest.
    """

    run_id: str
    project_id: str
    started_at: str
    snapshot_hash: str | None


@dataclass(frozen=True, slots=True)
class CheckpointCandidateBinding:
    candidate_id: str
    candidate_hash: str
    pdf_sha256: str
    manifest_sha256: str
    round_index: int
    disposition: str
    directory: Path
    candidate_tex_bytes: bytes
    candidate_pdf_bytes: bytes | None
    compile_log_bytes: bytes
    issue_ledger_bytes: bytes


@dataclass(frozen=True, slots=True)
class CommittedAnalysisCheckpoint:
    checkpoint_id: str
    sequence: int
    run_id: str
    project_id: str
    snapshot_hash: str
    frozen_compile_input_manifest_hash: str
    compile_input_hash: str
    best_compile_input_hash: str
    round_index: int
    directory: Path
    current_candidate: CheckpointCandidateBinding
    best_candidate: CheckpointCandidateBinding
    run_state: Any
    issue_ledger: Any
    task_ledger: Any
    budget_ledger: Any
    invocation_ledger: Any
    compile_history: Any
    candidate_page_map: Any
    rollback_history: Any


@dataclass(frozen=True, slots=True)
class RecoveryRejection:
    artifact: str
    code: str
    message: str
    sequence: int | None = None


@dataclass(frozen=True, slots=True)
class RecoveryScanResult:
    frozen_inputs: FrozenAnalysisInputs
    checkpoint: CommittedAnalysisCheckpoint | None
    rejected: tuple[RecoveryRejection, ...]
    latest_pointer: str | None
    latest_pointer_valid: bool


CheckpointSemanticValidator = Callable[[CommittedAnalysisCheckpoint], bool | None]


@dataclass(frozen=True, slots=True)
class _VerifiedDirectory:
    """One coherent, hash-verified byte snapshot of an artifact directory."""

    payloads: Mapping[str, bytes]
    hashes: Mapping[str, str]
    directories: frozenset[str]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _pretty_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _json_copy(value: Any, *, label: str) -> Any:
    try:
        return json.loads(_pretty_json_bytes(value))
    except (TypeError, ValueError) as exc:
        raise RecoveryValidationError(f"{label} is not finite JSON data") from exc


def _require_digest(value: object, *, label: str) -> str:
    digest = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(digest):
        raise RecoveryValidationError(f"{label} is not a SHA-256 digest")
    return digest


def _artifact_digest(value: object, *, label: str) -> str:
    digest = str(value or "")
    if not _DIGEST_RE.fullmatch(digest):
        raise _InvalidArtifact("invalid_digest", f"{label} is not a SHA-256 digest")
    return digest


def _portable_id(value: object, *, label: str) -> str:
    identifier = str(value or "")
    if not _PORTABLE_ID_RE.fullmatch(identifier):
        raise RecoveryValidationError(f"{label} is not a portable identifier")
    return identifier


def _portable_storage_name(value: object, *, label: str) -> str:
    """Validate one portable directory component, including Windows aliases."""

    name = _portable_id(value, label=label)
    if name.endswith((".", " ")):
        raise RecoveryValidationError(f"{label} has a non-portable trailing character")
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise RecoveryValidationError(f"{label} uses a reserved filename")
    return name


def _artifact_portable_id(value: object, *, label: str) -> str:
    identifier = str(value or "")
    if not _PORTABLE_ID_RE.fullmatch(identifier):
        raise _InvalidArtifact("unsafe_identity", f"{label} is not portable")
    return identifier


def _safe_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RecoveryValidationError(f"{label} is not a safe POSIX relative path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RecoveryValidationError(f"{label} contains a control character")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RecoveryValidationError(f"{label} is not a canonical relative path")
    for part in path.parts:
        if any(character in _WINDOWS_FORBIDDEN_CHARS for character in part) or part.endswith(
            (".", " ")
        ):
            raise RecoveryValidationError(f"{label} is unsafe on portable filesystems")
        stem = part.split(".", 1)[0].rstrip(" ").upper()
        if stem in _WINDOWS_RESERVED:
            raise RecoveryValidationError(f"{label} uses a reserved filename")
    return value


def _artifact_relative_path(value: object, *, label: str) -> str:
    try:
        return _safe_relative_path(value, label=label)
    except RecoveryValidationError as exc:
        raise _InvalidArtifact("unsafe_path", str(exc)) from exc


def _as_bytes(value: bytes | bytearray | memoryview | str, *, label: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise RecoveryValidationError(f"{label} must be text or bytes")


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(item_stat: os.stat_result) -> bool:
    """Reject symlinks and Windows reparse points such as junctions.

    A directory junction is reported as ``S_IFDIR`` rather than ``S_IFLNK``
    on Windows, so checking only ``stat.S_ISLNK`` permits an artifact path to
    escape its lexical run root.  All reparse points are rejected fail-closed;
    immutable analysis evidence must live in ordinary filesystem objects.
    """

    if stat.S_ISLNK(item_stat.st_mode):
        return True
    if os.name != "nt":
        return False
    attributes = int(getattr(item_stat, "st_file_attributes", 0) or 0)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _assert_no_symlink_chain(path: Path) -> None:
    absolute = _absolute_path(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            item_stat = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RecoveryValidationError(f"cannot inspect storage path: {current}") from exc
        if _is_link_or_reparse(item_stat):
            raise RecoveryValidationError(
                f"link or reparse point is forbidden in storage path: {current}"
            )


def assert_plain_storage_path(path: str | Path) -> None:
    """Reject any existing symlink or Windows reparse point in a path chain."""

    _assert_no_symlink_chain(_absolute_path(path))


def path_is_link_or_reparse(path: str | Path) -> bool:
    """Return whether one existing path is a symlink or Windows reparse point."""

    try:
        return _is_link_or_reparse(os.lstat(_absolute_path(path)))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RecoveryValidationError(f"cannot inspect storage path: {path}") from exc


def _ensure_directory(path: Path) -> None:
    _assert_no_symlink_chain(path)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise RecoveryValidationError(f"cannot create storage directory: {path}") from exc
    _assert_no_symlink_chain(path)
    try:
        item_stat = os.lstat(path)
    except OSError as exc:
        raise RecoveryValidationError(f"cannot inspect storage directory: {path}") from exc
    if not stat.S_ISDIR(item_stat.st_mode):
        raise RecoveryValidationError(f"storage path is not a directory: {path}")


def _read_regular_file(path: Path) -> bytes:
    try:
        _assert_no_symlink_chain(path)
    except RecoveryValidationError as exc:
        raise _InvalidArtifact("symlink", str(exc)) from exc
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _InvalidArtifact("missing_file", f"cannot open regular file: {path.name}") from exc
    try:
        item_stat = os.fstat(descriptor)
        if not stat.S_ISREG(item_stat.st_mode):
            raise _InvalidArtifact("unsafe_file", f"artifact is not regular: {path.name}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, payload: bytes) -> None:
    _ensure_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        # CPython cannot open directory handles with os.open() on Windows.
        # File contents are still flushed before every atomic replace; the
        # parent-directory flush is therefore a best-effort durability step.
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError:
        if os.name != "nt":
            raise
    finally:
        os.close(descriptor)


def _fsync_tree_directories(root: Path, files: Sequence[str]) -> None:
    directories = {root}
    for relative in files:
        parent = (root / PurePosixPath(relative)).parent
        while parent != root:
            directories.add(parent)
            parent = parent.parent
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)


def _atomic_replace_file(path: Path, payload: bytes) -> None:
    """Durably replace one regular file without following destination links."""

    _ensure_directory(path.parent)
    _assert_no_symlink_chain(path.parent)
    try:
        destination_stat = os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RecoveryValidationError(
            f"cannot inspect staging artifact: {path.name}"
        ) from exc
    else:
        if _is_link_or_reparse(destination_stat) or not stat.S_ISREG(
            destination_stat.st_mode
        ):
            raise RecoveryValidationError(
                f"staging artifact is not a regular non-symlink file: {path.name}"
            )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}-",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - defensive OS contract check
                raise OSError("short write while persisting staging artifact")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        if _read_regular_file(path) != payload:
            raise RecoveryValidationError(
                f"staging artifact bytes changed during replacement: {path.name}"
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _lock_descriptor_nonblocking(descriptor: int) -> None:
    """Acquire a one-byte Windows lock or a whole-file POSIX flock."""

    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        import msvcrt

        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise ActiveRunLockError(
                    "active analysis run is already locked by another process"
                ) from None
            raise RecoveryValidationError("cannot acquire the active-run lock") from exc
        return

    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            raise ActiveRunLockError(
                "active analysis run is already locked by another process"
            ) from None
        raise RecoveryValidationError("cannot acquire the active-run lock") from exc


def _unlock_descriptor(descriptor: int) -> None:
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _remove_private_temp(path: Path) -> None:
    try:
        item_stat = os.lstat(path)
    except FileNotFoundError:
        return
    if _is_link_or_reparse(item_stat):
        if stat.S_ISDIR(item_stat.st_mode):
            os.rmdir(path)
        else:
            path.unlink()
        return
    if not stat.S_ISDIR(item_stat.st_mode):
        path.unlink()
        return
    shutil.rmtree(path)


def _expected_directories(files: set[str]) -> set[str]:
    output: set[str] = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            output.add(parent.as_posix())
            parent = parent.parent
    return output


def _directory_inventory(directory: Path) -> tuple[set[str], set[str]]:
    try:
        _assert_no_symlink_chain(directory)
    except RecoveryValidationError as exc:
        raise _InvalidArtifact("symlink", str(exc)) from exc
    try:
        root_stat = os.lstat(directory)
    except OSError as exc:
        raise _InvalidArtifact("missing_directory", f"artifact directory is missing: {directory}") from exc
    if _is_link_or_reparse(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise _InvalidArtifact("unsafe_directory", f"artifact directory is unsafe: {directory}")

    files: set[str] = set()
    directories: set[str] = set()

    def walk(current: Path, prefix: PurePosixPath) -> None:
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError as exc:
            raise _InvalidArtifact("unreadable_directory", f"cannot scan {current}") from exc
        for entry in entries:
            relative = (prefix / entry.name).as_posix()
            _artifact_relative_path(relative, label="artifact path")
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise _InvalidArtifact(
                    "unreadable_entry", f"cannot inspect artifact: {relative}"
                ) from exc
            if _is_link_or_reparse(entry_stat):
                raise _InvalidArtifact(
                    "symlink", f"link or reparse point is forbidden: {relative}"
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                directories.add(relative)
                walk(Path(entry.path), prefix / entry.name)
            elif stat.S_ISREG(entry_stat.st_mode):
                files.add(relative)
            else:
                raise _InvalidArtifact("unsafe_file", f"non-regular artifact: {relative}")

    walk(directory, PurePosixPath("."))
    return files, directories


def _hash_manifest_bytes(payloads: Mapping[str, bytes]) -> bytes:
    return "".join(
        f"{_sha256(payloads[name])}  {name}\n" for name in sorted(payloads)
    ).encode("utf-8")


def _verify_hash_directory(
    directory: Path,
    *,
    expected_files: set[str] | None = None,
) -> _VerifiedDirectory:
    files, directories = _directory_inventory(directory)
    if _HASH_MANIFEST not in files:
        raise _InvalidArtifact("missing_manifest", "SHA256SUMS is missing")
    if expected_files is not None:
        if files != expected_files:
            raise _InvalidArtifact("file_set", "artifact file set is not exact")
        expected_dirs = _expected_directories(expected_files)
        if directories != expected_dirs:
            raise _InvalidArtifact("directory_set", "artifact directory set is not exact")

    raw_manifest = _read_regular_file(directory / _HASH_MANIFEST)
    try:
        text = raw_manifest.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _InvalidArtifact("manifest_encoding", "SHA256SUMS is not UTF-8") from exc
    if not text or not text.endswith("\n"):
        raise _InvalidArtifact("manifest_format", "SHA256SUMS must end with one line")

    observed: dict[str, str] = {}
    ordered_names: list[str] = []
    for line in text.splitlines():
        digest, separator, name = line.partition("  ")
        name = _artifact_relative_path(name, label="manifest path")
        if (
            not separator
            or not _DIGEST_RE.fullmatch(digest)
            or name == _HASH_MANIFEST
            or name in observed
        ):
            raise _InvalidArtifact("manifest_format", "SHA256SUMS has an invalid row")
        observed[name] = digest
        ordered_names.append(name)
    if ordered_names != sorted(ordered_names):
        raise _InvalidArtifact("manifest_order", "SHA256SUMS rows are not canonical")
    if set(observed) != files - {_HASH_MANIFEST}:
        raise _InvalidArtifact("manifest_file_set", "SHA256SUMS does not cover the exact file set")
    payloads: dict[str, bytes] = {}
    for name, expected in observed.items():
        payload = _read_regular_file(directory / PurePosixPath(name))
        if _sha256(payload) != expected:
            raise _InvalidArtifact("hash_mismatch", f"artifact hash mismatch: {name}")
        payloads[name] = payload
    payloads[_HASH_MANIFEST] = raw_manifest
    return _VerifiedDirectory(
        payloads=payloads,
        hashes=observed,
        directories=frozenset(directories),
    )


def _assert_verified_file_set(
    verified: _VerifiedDirectory,
    *,
    expected_files: set[str],
) -> None:
    if set(verified.payloads) != expected_files:
        raise _InvalidArtifact("file_set", "artifact file set is not exact")
    if verified.directories != _expected_directories(expected_files):
        raise _InvalidArtifact("directory_set", "artifact directory set is not exact")


def _assert_exact_bytes(directory: Path, expected: Mapping[str, bytes]) -> None:
    expected_files = set(expected)
    try:
        verified = _verify_hash_directory(directory, expected_files=expected_files)
        for name, payload in expected.items():
            if verified.payloads[name] != payload:
                raise _InvalidArtifact("byte_mismatch", f"immutable bytes differ: {name}")
    except _InvalidArtifact as exc:
        raise ImmutableEvidenceError(exc.message) from exc


def _parse_json_bytes(raw: bytes, *, label: str) -> Any:
    """Parse recovery evidence without accepting ambiguous JSON spellings."""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise ValueError("duplicate JSON key")
            output[key] = item
        return output

    def reject_non_finite_constant(_value: str) -> None:
        raise ValueError("non-finite JSON constant")

    def reject_non_finite_numbers(value: Any) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        if isinstance(value, dict):
            for item in value.values():
                reject_non_finite_numbers(item)
        elif isinstance(value, list):
            for item in value:
                reject_non_finite_numbers(item)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite_constant,
        )
        # ``parse_constant`` covers NaN/Infinity tokens.  A syntactically
        # ordinary exponent such as 1e999 can still overflow to infinity.
        reject_non_finite_numbers(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _InvalidArtifact("invalid_json", f"{label} is not valid JSON") from exc


def parse_strict_json_bytes(raw: bytes, *, label: str) -> Any:
    """Parse external JSON bytes and expose a stable public error type."""

    try:
        return _parse_json_bytes(raw, label=label)
    except _InvalidArtifact as exc:
        raise RecoveryValidationError(exc.message) from exc


def _parse_json_file(path: Path, *, label: str) -> Any:
    return _parse_json_bytes(_read_regular_file(path), label=label)


def _validated_quality_vector(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _QUALITY_VECTOR_FIELDS:
        raise _InvalidArtifact(
            "candidate_quality",
            f"{label} quality vector schema is not exact",
        )
    if type(value["fully_compiled"]) is not bool:
        raise _InvalidArtifact(
            "candidate_quality",
            f"{label} fully_compiled value is not boolean",
        )
    for name in _QUALITY_VECTOR_COUNT_FIELDS:
        count = value[name]
        if type(count) is not int or count < 0:
            raise _InvalidArtifact(
                "candidate_quality",
                f"{label} quality count is invalid: {name}",
            )
    return dict(value)


def _provisional_host_text(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value.strip() != value
        or len(value) > 256
    ):
        raise RecoveryValidationError(f"{label} must be non-empty host-owned text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RecoveryValidationError(f"{label} contains a control character")
    return value


def _provisional_portable_id(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise RecoveryValidationError(f"{label} must be host-owned text")
    return _portable_id(value, label=label)


def _provisional_identity_bytes(identity: ProvisionalRunIdentity) -> bytes:
    body = {
        "schema": PROVISIONAL_IDENTITY_SCHEMA,
        "run_id": identity.run_id,
        "project_id": identity.project_id,
        "started_at": identity.started_at,
        "snapshot_hash": identity.snapshot_hash,
    }
    return _pretty_json_bytes(
        {**body, "identity_hash": _sha256(_canonical_json_bytes(body))}
    )


def _parse_provisional_identity(payload: bytes) -> ProvisionalRunIdentity:
    value = _parse_json_bytes(payload, label=_PROVISIONAL_IDENTITY_FILE)
    expected_keys = {
        "schema",
        "run_id",
        "project_id",
        "started_at",
        "snapshot_hash",
        "identity_hash",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise _InvalidArtifact(
            "provisional_schema",
            "provisional run identity schema is not exact",
        )
    if value["schema"] != PROVISIONAL_IDENTITY_SCHEMA:
        raise _InvalidArtifact(
            "provisional_schema",
            "provisional run identity schema is unsupported",
        )
    try:
        run_id = _provisional_portable_id(
            value["run_id"], label="provisional run_id"
        )
        project_id = _provisional_portable_id(
            value["project_id"], label="provisional project_id"
        )
        started_at = _provisional_host_text(
            value["started_at"], label="provisional started_at"
        )
    except RecoveryValidationError as exc:
        raise _InvalidArtifact("provisional_identity", str(exc)) from exc
    snapshot_value = value["snapshot_hash"]
    if snapshot_value is None:
        snapshot_hash = None
    else:
        snapshot_hash = _artifact_digest(
            snapshot_value,
            label="provisional snapshot_hash",
        )
    identity_hash = _artifact_digest(
        value["identity_hash"],
        label="provisional identity_hash",
    )
    body = dict(value)
    body.pop("identity_hash")
    if _sha256(_canonical_json_bytes(body)) != identity_hash:
        raise _InvalidArtifact(
            "provisional_hash",
            "provisional run identity self-hash differs",
        )
    return ProvisionalRunIdentity(
        run_id=run_id,
        project_id=project_id,
        started_at=started_at,
        snapshot_hash=snapshot_hash,
    )


def _validated_compile_extras(
    compile_extras: Mapping[str, bytes | bytearray | memoryview | str],
) -> dict[str, bytes]:
    output: dict[str, bytes] = {}
    folded: dict[str, str] = {"main.tex": "main.tex"}
    for raw_path, raw_payload in compile_extras.items():
        logical_path = _safe_relative_path(raw_path, label="compile extra path")
        casefolded = logical_path.casefold()
        if casefolded in folded:
            raise RecoveryValidationError(
                f"compile input path collision: {folded[casefolded]!r} and {logical_path!r}"
            )
        folded[casefolded] = logical_path
        output[logical_path] = _as_bytes(raw_payload, label=f"compile extra {logical_path}")
    return dict(sorted(output.items()))


def _compile_manifest_hash(
    *,
    schema: str,
    main_tex: bytes,
    extras: Mapping[str, bytes],
) -> str:
    payloads = {"main.tex": main_tex, **extras}
    body = {
        "schema": schema,
        "file_count": len(payloads),
        "files": [
            {
                "path": name,
                "bytes": len(payloads[name]),
                "sha256": _sha256(payloads[name]),
            }
            for name in sorted(payloads)
        ],
    }
    compact = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256(compact)


def _validate_compile_manifest(
    value: Any,
    *,
    main_tex: bytes,
    extras: Mapping[str, bytes],
) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "file_count",
        "files",
        "manifest_sha256",
    }:
        raise RecoveryValidationError("compile input manifest schema is not exact")
    if value["schema"] != COMPILE_INPUT_SCHEMA:
        raise RecoveryValidationError("compile input manifest schema is unsupported")
    if type(value["file_count"]) is not int or value["file_count"] < 1:
        raise RecoveryValidationError("compile input file_count is invalid")
    rows = value["files"]
    if not isinstance(rows, list) or len(rows) != value["file_count"]:
        raise RecoveryValidationError("compile input rows do not match file_count")
    expected_payloads = {"main.tex": main_tex, **extras}
    observed_names: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise RecoveryValidationError("compile input row schema is not exact")
        name = _safe_relative_path(row["path"], label="compile input path")
        if name in observed_names:
            raise RecoveryValidationError("compile input path is duplicated")
        payload = expected_payloads.get(name)
        if payload is None:
            raise RecoveryValidationError("compile manifest contains an unfrozen input")
        if type(row["bytes"]) is not int or row["bytes"] != len(payload):
            raise RecoveryValidationError(f"compile input byte count differs: {name}")
        if row["sha256"] != _sha256(payload):
            raise RecoveryValidationError(f"compile input hash differs: {name}")
        observed_names.append(name)
    if observed_names != sorted(expected_payloads) or set(observed_names) != set(expected_payloads):
        raise RecoveryValidationError("compile manifest does not cover the exact frozen closure")
    expected_hash = _compile_manifest_hash(
        schema=value["schema"],
        main_tex=main_tex,
        extras=extras,
    )
    if value["manifest_sha256"] != expected_hash:
        raise RecoveryValidationError("compile input manifest hash is not recomputable")
    return value, expected_hash


def _validate_snapshot(
    value: Any,
    *,
    source_pdf: bytes,
    raw_ocr_tex: bytes,
    baseline_tex: bytes,
    baseline_pdf: bytes,
    compile_input_manifest_hash: str,
) -> tuple[dict[str, Any], str, str, str]:
    if not isinstance(value, dict):
        raise RecoveryValidationError("snapshot JSON must be an object")
    snapshot = dict(value)
    claimed = _require_digest(snapshot.get("snapshot_hash"), label="snapshot_hash")
    canonical = dict(snapshot)
    canonical.pop("snapshot_hash", None)
    if _sha256(_canonical_json_bytes(canonical)) != claimed:
        raise RecoveryValidationError("snapshot_hash does not cover the snapshot JSON")
    run_id = _portable_id(snapshot.get("run_id"), label="run_id")
    project_id = _portable_id(snapshot.get("project_id"), label="project_id")
    evidence = {
        "source_pdf_hash": source_pdf,
        "raw_ocr_tex_hash": raw_ocr_tex,
        "baseline_tex_hash": baseline_tex,
        "baseline_pdf_hash": baseline_pdf,
    }
    for name, payload in evidence.items():
        if snapshot.get(name) != _sha256(payload):
            raise RecoveryValidationError(f"snapshot {name} does not match frozen bytes")
    evidence_hashes = snapshot.get("evidence_hashes")
    if evidence_hashes is not None:
        if not isinstance(evidence_hashes, dict):
            raise RecoveryValidationError("snapshot evidence_hashes is not an object")
        frozen_compile = evidence_hashes.get("baseline_compile_inputs_hash")
        if frozen_compile is not None and frozen_compile != compile_input_manifest_hash:
            raise RecoveryValidationError(
                "snapshot baseline compile input hash differs from the frozen manifest"
            )
    return snapshot, claimed, run_id, project_id


class AnalysisRunStore:
    """Write-once active-run input and macro-round checkpoint repository."""

    def __init__(
        self,
        root: str | Path,
        *,
        candidates_directory: str | Path | None = None,
    ) -> None:
        self.root = _absolute_path(root)
        _ensure_directory(self.root)
        if candidates_directory is None:
            candidate_path = self.root / "candidates"
        else:
            candidate_path = _absolute_path(candidates_directory)
            if candidate_path.parent != self.root:
                raise RecoveryValidationError(
                    "candidate storage must be one direct child of the active run root"
                )
        name = _portable_storage_name(
            candidate_path.name,
            label="candidate storage name",
        )
        portable_alias = name.rstrip(". ").casefold()
        if portable_alias in {
            "inputs",
            "checkpoints",
            _PROVISIONAL_IDENTITY_FILE.casefold(),
        }:
            raise RecoveryValidationError(
                "candidate storage collides with reserved active-run evidence"
            )
        _assert_no_symlink_chain(candidate_path)
        try:
            candidate_stat = os.lstat(candidate_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RecoveryValidationError(
                "cannot inspect candidate storage directory"
            ) from exc
        else:
            if _is_link_or_reparse(candidate_stat):
                raise RecoveryValidationError(
                    "candidate storage must not be a link or reparse point"
                )
            if not stat.S_ISDIR(candidate_stat.st_mode):
                raise RecoveryValidationError(
                    "candidate storage path is not a directory"
                )
        self._candidates_directory = candidate_path
        self._candidate_storage_name = name
        self._lock_owner: tuple[int, int] | None = None

    @contextmanager
    def exclusive_lock(self) -> Iterator[None]:
        """Hold the active run's cross-process, non-blocking lifecycle lock.

        Callers must enter this context before reading or mutating active-run
        business state and keep it held through the entire run/resume lifecycle.
        A competing holder fails immediately with :class:`ActiveRunLockError`.
        """

        if self._lock_owner is not None:
            raise ActiveRunLockError("active analysis run lock is not reentrant")
        _ensure_directory(self.root)
        lock_path = self.root / ".analysis-run.lock"
        _assert_no_symlink_chain(lock_path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise RecoveryValidationError("cannot open the active-run lock") from exc
        acquired = False
        try:
            descriptor_stat = os.fstat(descriptor)
            if not stat.S_ISREG(descriptor_stat.st_mode):
                raise RecoveryValidationError(
                    "active-run lock must be a regular non-symlink file"
                )
            try:
                path_stat = os.lstat(lock_path)
            except OSError as exc:
                raise RecoveryValidationError(
                    "cannot verify the active-run lock identity"
                ) from exc
            if (
                _is_link_or_reparse(path_stat)
                or path_stat.st_dev != descriptor_stat.st_dev
                or path_stat.st_ino != descriptor_stat.st_ino
            ):
                raise RecoveryValidationError(
                    "active-run lock identity changed during acquisition"
                )
            _lock_descriptor_nonblocking(descriptor)
            acquired = True
            self._lock_owner = (os.getpid(), threading.get_ident())
            yield
        finally:
            self._lock_owner = None
            if acquired:
                try:
                    _unlock_descriptor(descriptor)
                except OSError:
                    pass
            os.close(descriptor)

    @property
    def inputs_directory(self) -> Path:
        return self.root / "inputs"

    @property
    def candidates_directory(self) -> Path:
        return self._candidates_directory

    @property
    def candidate_storage_name(self) -> str:
        return self._candidate_storage_name

    @property
    def checkpoints_directory(self) -> Path:
        return self.root / "checkpoints"

    @property
    def provisional_identity_path(self) -> Path:
        return self.root / _PROVISIONAL_IDENTITY_FILE

    def _require_exclusive_lock(self) -> None:
        if self._lock_owner != (os.getpid(), threading.get_ident()):
            raise ActiveRunLockError(
                "the active-run exclusive lock must be held by this caller"
            )

    def _load_provisional_identity(self) -> ProvisionalRunIdentity:
        try:
            payload = _read_regular_file(self.provisional_identity_path)
            return _parse_provisional_identity(payload)
        except _InvalidArtifact as exc:
            raise RecoveryValidationError(exc.message) from exc

    def stage_provisional_identity(
        self,
        *,
        run_id: str,
        project_id: str,
        started_at: str | None,
    ) -> ProvisionalRunIdentity:
        """Create or validate the host identity used before input freeze.

        ``started_at`` is required only when no staging record exists.  A retry
        passes ``None`` to recover the original host timestamp.  When supplied
        for an existing record it is an exact expectation, never an update.
        The caller must hold :meth:`exclusive_lock` for its entire lifecycle.
        """

        self._require_exclusive_lock()
        expected_run_id = _provisional_portable_id(
            run_id, label="provisional run_id"
        )
        expected_project_id = _provisional_portable_id(
            project_id, label="provisional project_id"
        )
        expected_started_at = (
            None
            if started_at is None
            else _provisional_host_text(started_at, label="provisional started_at")
        )
        try:
            os.lstat(self.provisional_identity_path)
        except FileNotFoundError:
            if expected_started_at is None:
                raise RecoveryValidationError(
                    "provisional started_at is required for a new active run"
                ) from None
            identity = ProvisionalRunIdentity(
                run_id=expected_run_id,
                project_id=expected_project_id,
                started_at=expected_started_at,
                snapshot_hash=None,
            )
            _atomic_replace_file(
                self.provisional_identity_path,
                _provisional_identity_bytes(identity),
            )
            stored = self._load_provisional_identity()
            if stored != identity:  # pragma: no cover - post-write defense
                raise RecoveryValidationError(
                    "provisional run identity changed during creation"
                )
            return stored
        except OSError as exc:
            raise RecoveryValidationError(
                "cannot inspect provisional run identity"
            ) from exc

        stored = self._load_provisional_identity()
        if stored.run_id != expected_run_id or stored.project_id != expected_project_id:
            raise RecoveryValidationError(
                "provisional run/project identity differs from the host request"
            )
        if expected_started_at is not None and stored.started_at != expected_started_at:
            raise RecoveryValidationError(
                "provisional started_at differs from the host request"
            )
        return stored

    def bind_provisional_snapshot(
        self,
        identity: ProvisionalRunIdentity,
        *,
        snapshot_hash: str,
    ) -> ProvisionalRunIdentity:
        """Atomically bind a staged host identity to one configuration snapshot."""

        self._require_exclusive_lock()
        if not isinstance(identity, ProvisionalRunIdentity):
            raise RecoveryValidationError(
                "provisional identity binding must use a staged identity"
            )
        expected_snapshot_hash = _require_digest(
            snapshot_hash,
            label="provisional snapshot_hash",
        )
        stored = self._load_provisional_identity()
        if (
            stored.run_id,
            stored.project_id,
            stored.started_at,
        ) != (
            identity.run_id,
            identity.project_id,
            identity.started_at,
        ):
            raise RecoveryValidationError(
                "provisional run identity changed before snapshot binding"
            )
        if identity.snapshot_hash not in {None, expected_snapshot_hash}:
            raise RecoveryValidationError(
                "requested snapshot differs from the staged configuration identity"
            )
        if stored.snapshot_hash is not None:
            if stored.snapshot_hash != expected_snapshot_hash:
                raise RecoveryValidationError(
                    "provisional snapshot differs from the host configuration"
                )
            return stored

        bound = ProvisionalRunIdentity(
            run_id=stored.run_id,
            project_id=stored.project_id,
            started_at=stored.started_at,
            snapshot_hash=expected_snapshot_hash,
        )
        _atomic_replace_file(
            self.provisional_identity_path,
            _provisional_identity_bytes(bound),
        )
        verified = self._load_provisional_identity()
        if verified != bound:  # pragma: no cover - post-write defense
            raise RecoveryValidationError(
                "provisional snapshot binding changed during replacement"
            )
        return verified

    def _verify_provisional_freeze_binding(
        self,
        *,
        snapshot: Mapping[str, Any],
        run_id: str,
        project_id: str,
        snapshot_hash: str,
    ) -> None:
        try:
            os.lstat(self.provisional_identity_path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RecoveryValidationError(
                "cannot inspect provisional run identity"
            ) from exc
        staged = self._load_provisional_identity()
        if staged.run_id != run_id or staged.project_id != project_id:
            raise RecoveryValidationError(
                "frozen input identity differs from the provisional run identity"
            )
        if snapshot.get("started_at") != staged.started_at:
            raise RecoveryValidationError(
                "frozen input started_at differs from the provisional run identity"
            )
        if staged.snapshot_hash is None:
            raise RecoveryValidationError(
                "provisional run identity is not bound to a snapshot"
            )
        if staged.snapshot_hash != snapshot_hash:
            raise RecoveryValidationError(
                "frozen input snapshot differs from the provisional configuration"
            )

    def freeze_inputs(
        self,
        *,
        snapshot: Mapping[str, Any],
        source_pdf: bytes | bytearray | memoryview,
        raw_ocr_tex: bytes | bytearray | memoryview | str,
        baseline_tex: bytes | bytearray | memoryview | str,
        baseline_pdf: bytes | bytearray | memoryview,
        baseline_compile_log: bytes | bytearray | memoryview | str,
        compile_extras: Mapping[
            str, bytes | bytearray | memoryview | str
        ] | None = None,
        compile_input_manifest: Mapping[str, Any],
        page_map: Mapping[str, Any] | Sequence[Any],
    ) -> FrozenAnalysisInputs:
        """Atomically freeze every non-model input before the first invocation."""

        self._require_exclusive_lock()
        _ensure_directory(self.root)
        source_bytes = _as_bytes(source_pdf, label="source PDF")
        raw_bytes = _as_bytes(raw_ocr_tex, label="raw OCR TeX")
        baseline_bytes = _as_bytes(baseline_tex, label="baseline TeX")
        baseline_pdf_bytes = _as_bytes(baseline_pdf, label="baseline PDF")
        log_bytes = _as_bytes(baseline_compile_log, label="baseline compile log")
        if not source_bytes or not baseline_pdf_bytes:
            raise RecoveryValidationError("source and baseline PDFs must be non-empty")

        supplied_extras = _validated_compile_extras(compile_extras or {})
        try:
            baseline_text = baseline_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RecoveryValidationError("baseline TeX must be UTF-8") from exc
        # Use the production materializer as the authority for implicit inputs
        # such as elegantbook.cls.  The frozen set therefore matches the
        # already-built compile manifest even when callers supplied only their
        # explicit extras.
        from .compilecheck import prepare_compile_inputs

        prepared_inputs = prepare_compile_inputs(baseline_text, dict(supplied_extras))
        if prepared_inputs.get("main.tex") != baseline_bytes:
            raise RecoveryValidationError("compile materializer changed baseline TeX bytes")
        extras: dict[str, bytes] = {}
        for name, payload in sorted(prepared_inputs.items()):
            canonical_name = _safe_relative_path(name, label="materialized compile input")
            if canonical_name != "main.tex":
                extras[canonical_name] = bytes(payload)
        compile_manifest_copy = _json_copy(
            dict(compile_input_manifest), label="compile input manifest"
        )
        _, compile_hash = _validate_compile_manifest(
            compile_manifest_copy,
            main_tex=baseline_bytes,
            extras=extras,
        )
        snapshot_copy = _json_copy(dict(snapshot), label="analysis snapshot")
        _, snapshot_hash, run_id, project_id = _validate_snapshot(
            snapshot_copy,
            source_pdf=source_bytes,
            raw_ocr_tex=raw_bytes,
            baseline_tex=baseline_bytes,
            baseline_pdf=baseline_pdf_bytes,
            compile_input_manifest_hash=compile_hash,
        )
        self._verify_provisional_freeze_binding(
            snapshot=snapshot_copy,
            run_id=run_id,
            project_id=project_id,
            snapshot_hash=snapshot_hash,
        )
        page_map_value = dict(page_map) if isinstance(page_map, Mapping) else page_map
        page_map_copy = _json_copy(page_map_value, label="page map")
        page_map_bytes = _pretty_json_bytes(page_map_copy)

        artifact_payloads = {
            _INPUT_ARTIFACT_PATHS["snapshot"]: _pretty_json_bytes(snapshot_copy),
            _INPUT_ARTIFACT_PATHS["source_pdf"]: source_bytes,
            _INPUT_ARTIFACT_PATHS["raw_ocr_tex"]: raw_bytes,
            _INPUT_ARTIFACT_PATHS["baseline_tex"]: baseline_bytes,
            _INPUT_ARTIFACT_PATHS["baseline_pdf"]: baseline_pdf_bytes,
            _INPUT_ARTIFACT_PATHS["baseline_compile_log"]: log_bytes,
            _INPUT_ARTIFACT_PATHS["compile_input_manifest"]: _pretty_json_bytes(
                compile_manifest_copy
            ),
            _INPUT_ARTIFACT_PATHS["page_map"]: page_map_bytes,
        }
        artifact_rows = {
            role: {
                "path": path,
                "sha256": _sha256(artifact_payloads[path]),
                "bytes": len(artifact_payloads[path]),
            }
            for role, path in _INPUT_ARTIFACT_PATHS.items()
        }
        extra_rows = []
        payloads = dict(artifact_payloads)
        for logical_path, payload in extras.items():
            stored_path = f"compile-inputs/{logical_path}"
            payloads[stored_path] = payload
            extra_rows.append(
                {
                    "logical_path": logical_path,
                    "stored_path": stored_path,
                    "sha256": _sha256(payload),
                    "bytes": len(payload),
                }
            )
        metadata = {
            "schema": FROZEN_INPUT_SCHEMA,
            "run_id": run_id,
            "project_id": project_id,
            "candidate_storage_name": self.candidate_storage_name,
            "snapshot_hash": snapshot_hash,
            "compile_input_manifest_hash": compile_hash,
            "page_map_sha256": _sha256(page_map_bytes),
            "artifacts": artifact_rows,
            "compile_extras": extra_rows,
        }
        payloads[_INPUT_METADATA] = _pretty_json_bytes(metadata)
        payloads[_HASH_MANIFEST] = _hash_manifest_bytes(payloads)

        destination = self.inputs_directory
        if destination.exists() or destination.is_symlink():
            _assert_exact_bytes(destination, payloads)
            return self.verify_frozen_inputs()

        temp = Path(tempfile.mkdtemp(prefix=".inputs-", dir=self.root))
        try:
            for name in sorted(payloads):
                _write_new_file(temp / PurePosixPath(name), payloads[name])
            _fsync_tree_directories(temp, tuple(payloads))
            _assert_no_symlink_chain(destination.parent)
            try:
                os.replace(temp, destination)
            except OSError:
                if destination.exists() and not destination.is_symlink():
                    _assert_exact_bytes(destination, payloads)
                else:
                    raise
            _fsync_directory(self.root)
        finally:
            _remove_private_temp(temp)
        return self.verify_frozen_inputs()

    def verify_frozen_inputs(self) -> FrozenAnalysisInputs:
        """Validate the exact frozen input set and every cross-file binding."""

        try:
            return self._load_frozen_inputs()
        except _InvalidArtifact as exc:
            raise RecoveryValidationError(exc.message) from exc

    def _load_frozen_inputs(self) -> FrozenAnalysisInputs:
        directory = self.inputs_directory
        verified = _verify_hash_directory(directory)
        metadata_payload = verified.payloads.get(_INPUT_METADATA)
        if metadata_payload is None:
            raise _InvalidArtifact("input_schema", "frozen input metadata is missing")
        metadata = _parse_json_bytes(metadata_payload, label=_INPUT_METADATA)
        expected_metadata_keys = {
            "schema",
            "run_id",
            "project_id",
            "candidate_storage_name",
            "snapshot_hash",
            "compile_input_manifest_hash",
            "page_map_sha256",
            "artifacts",
            "compile_extras",
        }
        legacy_metadata_keys = expected_metadata_keys - {"candidate_storage_name"}
        if not isinstance(metadata, dict):
            raise _InvalidArtifact("input_schema", "frozen input metadata schema is not exact")
        if metadata.get("schema") == FROZEN_INPUT_SCHEMA:
            if set(metadata) != expected_metadata_keys:
                raise _InvalidArtifact(
                    "input_schema", "frozen input metadata schema is not exact"
                )
            candidate_storage_name = metadata["candidate_storage_name"]
        elif metadata.get("schema") == _LEGACY_FROZEN_INPUT_SCHEMA:
            if set(metadata) != legacy_metadata_keys:
                raise _InvalidArtifact(
                    "input_schema", "legacy frozen input metadata schema is not exact"
                )
            candidate_storage_name = "candidates"
        else:
            raise _InvalidArtifact("input_schema", "frozen input metadata schema is unsupported")
        try:
            candidate_storage_name = _portable_storage_name(
                candidate_storage_name,
                label="frozen candidate storage name",
            )
        except RecoveryValidationError as exc:
            raise _InvalidArtifact("input_binding", str(exc)) from exc
        if candidate_storage_name != self.candidate_storage_name:
            raise _InvalidArtifact(
                "input_binding", "candidate storage differs from frozen input identity"
            )

        artifacts = metadata["artifacts"]
        if not isinstance(artifacts, dict) or set(artifacts) != set(_INPUT_ARTIFACT_PATHS):
            raise _InvalidArtifact("input_schema", "frozen artifact roles are not exact")
        for role, expected_path in _INPUT_ARTIFACT_PATHS.items():
            row = artifacts[role]
            if not isinstance(row, dict) or set(row) != {"path", "sha256", "bytes"}:
                raise _InvalidArtifact("input_schema", f"invalid frozen artifact row: {role}")
            if row["path"] != expected_path:
                raise _InvalidArtifact("unsafe_path", f"unexpected frozen path for {role}")

        raw_extra_rows = metadata["compile_extras"]
        if not isinstance(raw_extra_rows, list):
            raise _InvalidArtifact("input_schema", "compile_extras must be an array")
        extras: dict[str, bytes] = {}
        extra_bindings: list[CompileExtraBinding] = []
        expected_files = set(_INPUT_ARTIFACT_PATHS.values()) | {
            _INPUT_METADATA,
            _HASH_MANIFEST,
        }
        folded = {"main.tex": "main.tex"}
        for row in raw_extra_rows:
            if not isinstance(row, dict) or set(row) != {
                "logical_path",
                "stored_path",
                "sha256",
                "bytes",
            }:
                raise _InvalidArtifact("input_schema", "compile extra row schema is not exact")
            logical = _artifact_relative_path(row["logical_path"], label="compile extra path")
            stored = _artifact_relative_path(row["stored_path"], label="stored compile path")
            if stored != f"compile-inputs/{logical}":
                raise _InvalidArtifact("unsafe_path", "compile extra stored path is not canonical")
            if logical.casefold() in folded:
                raise _InvalidArtifact("path_collision", "compile input paths collide")
            folded[logical.casefold()] = logical
            if stored in expected_files:
                raise _InvalidArtifact("path_collision", "frozen stored paths collide")
            payload = verified.payloads.get(stored)
            if payload is None:
                raise _InvalidArtifact(
                    "missing_file", f"compile extra is missing: {logical}"
                )
            digest = _artifact_digest(row["sha256"], label="compile extra hash")
            if type(row["bytes"]) is not int or row["bytes"] != len(payload):
                raise _InvalidArtifact("byte_count", f"compile extra byte count differs: {logical}")
            if digest != _sha256(payload):
                raise _InvalidArtifact("hash_mismatch", f"compile extra hash differs: {logical}")
            expected_files.add(stored)
            extras[logical] = payload
            extra_bindings.append(
                CompileExtraBinding(
                    logical_path=logical,
                    stored_path=stored,
                    sha256=digest,
                    byte_count=len(payload),
                    payload=payload,
                )
            )
        if [item.logical_path for item in extra_bindings] != sorted(extras):
            raise _InvalidArtifact("input_order", "compile extras are not canonical")
        _assert_verified_file_set(verified, expected_files=expected_files)

        artifact_bytes: dict[str, bytes] = {}
        for role, expected_path in _INPUT_ARTIFACT_PATHS.items():
            row = artifacts[role]
            payload = verified.payloads.get(expected_path)
            if payload is None:
                raise _InvalidArtifact(
                    "missing_file", f"frozen artifact is missing: {role}"
                )
            digest = _artifact_digest(row["sha256"], label=f"{role} hash")
            if type(row["bytes"]) is not int or row["bytes"] != len(payload):
                raise _InvalidArtifact("byte_count", f"frozen byte count differs: {role}")
            if digest != _sha256(payload):
                raise _InvalidArtifact("hash_mismatch", f"frozen hash differs: {role}")
            artifact_bytes[role] = payload

        compile_manifest = _parse_json_bytes(
            artifact_bytes["compile_input_manifest"],
            label="compile input manifest",
        )
        try:
            _, compile_hash = _validate_compile_manifest(
                compile_manifest,
                main_tex=artifact_bytes["baseline_tex"],
                extras=extras,
            )
            snapshot = _parse_json_bytes(
                artifact_bytes["snapshot"], label="snapshot"
            )
            _, snapshot_hash, run_id, project_id = _validate_snapshot(
                snapshot,
                source_pdf=artifact_bytes["source_pdf"],
                raw_ocr_tex=artifact_bytes["raw_ocr_tex"],
                baseline_tex=artifact_bytes["baseline_tex"],
                baseline_pdf=artifact_bytes["baseline_pdf"],
                compile_input_manifest_hash=compile_hash,
            )
        except RecoveryValidationError as exc:
            raise _InvalidArtifact("input_binding", str(exc)) from exc

        page_map_sha = _sha256(artifact_bytes["page_map"])
        _parse_json_bytes(artifact_bytes["page_map"], label="page map")
        if (
            metadata["run_id"] != run_id
            or metadata["project_id"] != project_id
            or metadata["snapshot_hash"] != snapshot_hash
            or metadata["compile_input_manifest_hash"] != compile_hash
            or metadata["page_map_sha256"] != page_map_sha
        ):
            raise _InvalidArtifact("input_binding", "frozen input metadata bindings differ")

        return FrozenAnalysisInputs(
            directory=directory,
            run_id=run_id,
            project_id=project_id,
            candidate_storage_name=candidate_storage_name,
            snapshot_hash=snapshot_hash,
            compile_input_manifest_hash=compile_hash,
            page_map_sha256=page_map_sha,
            source_pdf_sha256=_sha256(artifact_bytes["source_pdf"]),
            raw_ocr_tex_sha256=_sha256(artifact_bytes["raw_ocr_tex"]),
            baseline_tex_sha256=_sha256(artifact_bytes["baseline_tex"]),
            baseline_pdf_sha256=_sha256(artifact_bytes["baseline_pdf"]),
            baseline_compile_log_sha256=_sha256(artifact_bytes["baseline_compile_log"]),
            compile_extras=tuple(extra_bindings),
            snapshot_bytes=artifact_bytes["snapshot"],
            source_pdf_bytes=artifact_bytes["source_pdf"],
            raw_ocr_tex_bytes=artifact_bytes["raw_ocr_tex"],
            baseline_tex_bytes=artifact_bytes["baseline_tex"],
            baseline_pdf_bytes=artifact_bytes["baseline_pdf"],
            baseline_compile_log_bytes=artifact_bytes["baseline_compile_log"],
            compile_input_manifest_bytes=artifact_bytes["compile_input_manifest"],
            page_map_bytes=artifact_bytes["page_map"],
        )

    def _compile_extras_from_frozen(
        self, frozen: FrozenAnalysisInputs
    ) -> dict[str, bytes]:
        return {item.logical_path: item.payload for item in frozen.compile_extras}

    def _load_candidate(
        self,
        candidate_id: object,
        *,
        reject_rejected: bool = True,
    ) -> CheckpointCandidateBinding:
        identifier = str(candidate_id or "")
        match = _CANDIDATE_ID_RE.fullmatch(identifier)
        if match is None:
            raise _InvalidArtifact("candidate_identity", "candidate id is not host-generated")
        directory = self.candidates_directory / identifier
        verified = _verify_hash_directory(directory)
        metadata_payload = verified.payloads.get("candidate.json")
        if metadata_payload is None:
            raise _InvalidArtifact("candidate_schema", "candidate metadata is missing")
        metadata = _parse_json_bytes(metadata_payload, label="candidate.json")
        if not isinstance(metadata, dict) or set(metadata) != _CANDIDATE_METADATA_FIELDS:
            raise _InvalidArtifact(
                "candidate_schema", "candidate metadata schema is not exact"
            )
        if metadata["candidate_id"] != identifier or metadata["artifact_directory"] != identifier:
            raise _InvalidArtifact("candidate_identity", "candidate metadata identity differs")
        if (
            type(metadata["parent_candidate_id"]) is not str
            or type(metadata["reason"]) is not str
        ):
            raise _InvalidArtifact(
                "candidate_schema", "candidate metadata text fields are not typed"
            )
        round_index = metadata["round_index"]
        if type(round_index) is not int or round_index < 0 or round_index > 9999:
            raise _InvalidArtifact("candidate_round", "candidate round is invalid")
        candidate_hash = _artifact_digest(metadata["tex_sha256"], label="candidate hash")
        if int(match.group("round")) != round_index or match.group("prefix") != candidate_hash[:12]:
            raise _InvalidArtifact("candidate_identity", "candidate id does not bind round and TeX")
        tex_payload = verified.payloads.get("candidate.tex")
        if tex_payload is None:
            raise _InvalidArtifact("missing_file", "candidate TeX is missing")
        if _sha256(tex_payload) != candidate_hash:
            raise _InvalidArtifact("candidate_hash", "candidate TeX hash differs")
        pdf_hash = str(metadata["pdf_sha256"] or "")
        expected_files = set(_CANDIDATE_FILES)
        pdf_payload: bytes | None = None
        if pdf_hash:
            _artifact_digest(pdf_hash, label="candidate PDF hash")
            expected_files.add("candidate.pdf")
            pdf_payload = verified.payloads.get("candidate.pdf")
            if pdf_payload is None or _sha256(pdf_payload) != pdf_hash:
                raise _InvalidArtifact("candidate_hash", "candidate PDF hash differs")
        _assert_verified_file_set(verified, expected_files=expected_files)
        metadata_quality = _validated_quality_vector(
            metadata["quality"], label="candidate.json"
        )
        quality_payload = _validated_quality_vector(
            _parse_json_bytes(
                verified.payloads["quality_vector.json"],
                label="quality_vector.json",
            ),
            label="quality_vector.json",
        )
        if _canonical_json_bytes(metadata_quality) != _canonical_json_bytes(
            quality_payload
        ):
            raise _InvalidArtifact(
                "candidate_quality",
                "candidate quality metadata differs from quality_vector.json",
            )
        for name in ("patch.json", "issue_ledger.json", "review.json"):
            _parse_json_bytes(verified.payloads[name], label=name)
        disposition = str(metadata["disposition"] or "")
        if disposition not in {"BASELINE", "ACCEPTED", _REJECTED_DISPOSITION}:
            raise _InvalidArtifact("candidate_disposition", "candidate disposition is invalid")
        if reject_rejected and disposition == _REJECTED_DISPOSITION:
            raise _InvalidArtifact("candidate_rejected", "rejected candidate is not recoverable")
        manifest_hash = _sha256(verified.payloads[_HASH_MANIFEST])
        return CheckpointCandidateBinding(
            candidate_id=identifier,
            candidate_hash=candidate_hash,
            pdf_sha256=pdf_hash,
            manifest_sha256=manifest_hash,
            round_index=round_index,
            disposition=disposition,
            directory=directory,
            candidate_tex_bytes=tex_payload,
            candidate_pdf_bytes=pdf_payload,
            compile_log_bytes=verified.payloads["compile.log"],
            issue_ledger_bytes=verified.payloads["issue_ledger.json"],
        )

    def _candidate_compile_input_hash(
        self,
        candidate: CheckpointCandidateBinding,
        frozen: FrozenAnalysisInputs,
    ) -> str:
        compile_manifest = _parse_json_bytes(
            frozen.compile_input_manifest_bytes,
            label="compile input manifest",
        )
        if not isinstance(compile_manifest, dict) or compile_manifest.get("schema") != COMPILE_INPUT_SCHEMA:
            raise _InvalidArtifact("compile_schema", "frozen compile schema differs")
        return _compile_manifest_hash(
            schema=COMPILE_INPUT_SCHEMA,
            main_tex=candidate.candidate_tex_bytes,
            extras=self._compile_extras_from_frozen(frozen),
        )

    def candidate_compile_input_hash(self, candidate_id: str) -> str:
        """Recompute the exact compile closure hash for one committed candidate."""

        frozen = self.verify_frozen_inputs()
        try:
            candidate = self._load_candidate(candidate_id)
            return self._candidate_compile_input_hash(candidate, frozen)
        except _InvalidArtifact as exc:
            raise RecoveryValidationError(exc.message) from exc

    def verify_candidate(
        self,
        candidate_id: str,
        *,
        reject_rejected: bool = True,
    ) -> CheckpointCandidateBinding:
        """Return one candidate entirely from its hash-verified byte snapshot."""

        try:
            return self._load_candidate(
                candidate_id,
                reject_rejected=reject_rejected,
            )
        except _InvalidArtifact as exc:
            raise RecoveryValidationError(exc.message) from exc

    @staticmethod
    def _candidate_metadata(candidate: CheckpointCandidateBinding) -> dict[str, Any]:
        return {
            "candidate_id": candidate.candidate_id,
            "candidate_hash": candidate.candidate_hash,
            "pdf_sha256": candidate.pdf_sha256,
            "manifest_sha256": candidate.manifest_sha256,
            "round_index": candidate.round_index,
            "disposition": candidate.disposition,
        }

    @staticmethod
    def _checkpoint_id(identity: Mapping[str, Any]) -> str:
        sequence = identity["sequence"]
        digest = _sha256(_canonical_json_bytes(identity))
        return f"checkpoint-{sequence:08d}-{digest[:16]}"

    def commit_checkpoint(
        self,
        *,
        sequence: int,
        run_id: str,
        project_id: str,
        snapshot_hash: str,
        compile_input_hash: str,
        round_index: int,
        current_candidate_id: str,
        current_candidate_hash: str,
        best_candidate_id: str,
        best_candidate_hash: str,
        run_state: Any,
        issue_ledger: Any,
        task_ledger: Any,
        budget_ledger: Any,
        invocation_ledger: Any,
        compile_history: Any,
        candidate_page_map: Any,
        rollback_history: Any,
    ) -> CommittedAnalysisCheckpoint:
        """Copy all mutable state into one immutable, atomically named checkpoint."""

        self._require_exclusive_lock()
        if type(sequence) is not int or sequence < 0 or sequence > 99_999_999:
            raise RecoveryValidationError("checkpoint sequence is invalid")
        if type(round_index) is not int or round_index < 0:
            raise RecoveryValidationError("checkpoint round is invalid")
        frozen = self.verify_frozen_inputs()
        normalized_run = _portable_id(run_id, label="run_id")
        normalized_project = _portable_id(project_id, label="project_id")
        normalized_snapshot = _require_digest(snapshot_hash, label="snapshot_hash")
        normalized_compile = _require_digest(compile_input_hash, label="compile_input_hash")
        if (
            normalized_run != frozen.run_id
            or normalized_project != frozen.project_id
            or normalized_snapshot != frozen.snapshot_hash
        ):
            raise RecoveryValidationError("checkpoint identity differs from frozen inputs")

        try:
            current = self._load_candidate(current_candidate_id)
            best = (
                current
                if best_candidate_id == current_candidate_id
                else self._load_candidate(best_candidate_id)
            )
            if current.candidate_hash != _require_digest(
                current_candidate_hash, label="current_candidate_hash"
            ):
                raise RecoveryValidationError("current candidate hash differs")
            if best.candidate_hash != _require_digest(
                best_candidate_hash, label="best_candidate_hash"
            ):
                raise RecoveryValidationError("best candidate hash differs")
            if current.round_index > round_index or best.round_index > round_index:
                raise RecoveryValidationError("checkpoint round predates a bound candidate")
            computed_compile = self._candidate_compile_input_hash(current, frozen)
            best_compile = self._candidate_compile_input_hash(best, frozen)
        except _InvalidArtifact as exc:
            raise RecoveryValidationError(exc.message) from exc
        if normalized_compile != computed_compile:
            raise RecoveryValidationError("checkpoint compile input hash differs from candidate")

        raw_states = {
            "run_state": run_state,
            "issue_ledger": issue_ledger,
            "task_ledger": task_ledger,
            "budget_ledger": budget_ledger,
            "invocation_ledger": invocation_ledger,
            "compile_history": compile_history,
            "candidate_page_map": candidate_page_map,
            "rollback_history": rollback_history,
        }
        states = {
            role: _json_copy(raw_states[role], label=role) for role in _STATE_FILES
        }
        state_payloads = {
            _STATE_FILES[role]: _pretty_json_bytes(states[role]) for role in _STATE_FILES
        }
        state_hashes = {name: _sha256(payload) for name, payload in state_payloads.items()}
        identity = {
            "schema": CHECKPOINT_SCHEMA,
            "sequence": sequence,
            "run_id": normalized_run,
            "project_id": normalized_project,
            "snapshot_hash": normalized_snapshot,
            "frozen_compile_input_manifest_hash": frozen.compile_input_manifest_hash,
            "compile_input_hash": computed_compile,
            "best_compile_input_hash": best_compile,
            "round_index": round_index,
            "current_candidate": self._candidate_metadata(current),
            "best_candidate": self._candidate_metadata(best),
            "state_files": dict(_STATE_FILES),
            "state_sha256": state_hashes,
        }
        checkpoint_id = self._checkpoint_id(identity)
        metadata = {**identity, "checkpoint_id": checkpoint_id}
        payloads = {
            **state_payloads,
            _CHECKPOINT_METADATA: _pretty_json_bytes(metadata),
        }
        payloads[_HASH_MANIFEST] = _hash_manifest_bytes(payloads)

        checkpoints = self.checkpoints_directory
        _ensure_directory(checkpoints)
        destination = checkpoints / checkpoint_id
        max_sequence = -1
        same_sequence: list[str] = []
        for entry in os.scandir(checkpoints):
            if entry.name == "LATEST" or entry.name.startswith("."):
                continue
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RecoveryValidationError(
                    "cannot inspect checkpoint storage entry"
                ) from exc
            if _is_link_or_reparse(entry_stat):
                raise RecoveryValidationError(
                    "link or reparse point is forbidden in checkpoint storage"
                )
            match = _CHECKPOINT_ID_RE.fullmatch(entry.name)
            if match and stat.S_ISDIR(entry_stat.st_mode):
                observed_sequence = int(match.group("sequence"))
                max_sequence = max(max_sequence, observed_sequence)
                if observed_sequence == sequence:
                    same_sequence.append(entry.name)
        if same_sequence and same_sequence != [checkpoint_id]:
            raise ImmutableEvidenceError("checkpoint sequence already has different evidence")
        historical_replay = max_sequence > sequence and checkpoint_id in same_sequence
        if max_sequence > sequence and not historical_replay:
            raise RecoveryValidationError("checkpoint sequence would move durable history backward")

        if destination.exists() or destination.is_symlink():
            _assert_exact_bytes(destination, payloads)
        else:
            temp = Path(
                tempfile.mkdtemp(prefix=f".checkpoint-{sequence:08d}-", dir=checkpoints)
            )
            try:
                for name in sorted(payloads):
                    _write_new_file(temp / name, payloads[name])
                _fsync_tree_directories(temp, tuple(payloads))
                os.replace(temp, destination)
                _fsync_directory(checkpoints)
            finally:
                _remove_private_temp(temp)
        # An exact replay of older immutable evidence is harmless, but it must
        # never move the advisory pointer behind a newer committed sequence.
        if not historical_replay:
            self._write_latest(checkpoint_id)
        return self._checkpoint_from_parts(
            metadata=metadata,
            directory=destination,
            current=current,
            best=best,
            states=states,
        )

    def _write_latest(self, checkpoint_id: str) -> None:
        checkpoints = self.checkpoints_directory
        _ensure_directory(checkpoints)
        latest = checkpoints / "LATEST"
        if latest.exists() or latest.is_symlink():
            try:
                latest_stat = os.lstat(latest)
            except OSError as exc:
                raise RecoveryValidationError("cannot inspect LATEST") from exc
            if _is_link_or_reparse(latest_stat) or not stat.S_ISREG(
                latest_stat.st_mode
            ):
                raise RecoveryValidationError("LATEST must be a regular non-symlink file")
        descriptor, temp_name = tempfile.mkstemp(prefix=".LATEST-", dir=checkpoints)
        temp = Path(temp_name)
        try:
            payload = f"{checkpoint_id}\n".encode("ascii")
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, latest)
            _fsync_directory(checkpoints)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _binding_from_metadata(
        value: Any,
        *,
        label: str,
    ) -> dict[str, Any]:
        expected = {
            "candidate_id",
            "candidate_hash",
            "pdf_sha256",
            "manifest_sha256",
            "round_index",
            "disposition",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise _InvalidArtifact("checkpoint_schema", f"{label} binding schema is not exact")
        return value

    @staticmethod
    def _check_candidate_binding(
        expected: Mapping[str, Any],
        actual: CheckpointCandidateBinding,
        *,
        label: str,
    ) -> None:
        observed = AnalysisRunStore._candidate_metadata(actual)
        if dict(expected) != observed:
            raise _InvalidArtifact(
                "candidate_binding", f"{label} candidate binding differs from immutable evidence"
            )

    @staticmethod
    def _check_optional_state_bindings(
        states: Mapping[str, Any],
        metadata: Mapping[str, Any],
    ) -> None:
        expected = {
            "run_id": metadata["run_id"],
            "project_id": metadata["project_id"],
            "snapshot_hash": metadata["snapshot_hash"],
            "round_index": metadata["round_index"],
            "current_candidate_id": metadata["current_candidate"]["candidate_id"],
            "current_candidate_hash": metadata["current_candidate"]["candidate_hash"],
            "best_candidate_id": metadata["best_candidate"]["candidate_id"],
            "best_candidate_hash": metadata["best_candidate"]["candidate_hash"],
            "compile_input_hash": metadata["compile_input_hash"],
            "compile_input_sha256": metadata["compile_input_hash"],
        }
        for role, state_value in states.items():
            if not isinstance(state_value, dict):
                continue
            for key, expected_value in expected.items():
                if key in state_value and state_value[key] != expected_value:
                    raise _InvalidArtifact(
                        "state_binding", f"{role}.{key} differs from checkpoint identity"
                    )

    def _load_checkpoint(
        self,
        directory: Path,
        frozen: FrozenAnalysisInputs,
    ) -> CommittedAnalysisCheckpoint:
        expected_files = set(_STATE_FILES.values()) | {
            _CHECKPOINT_METADATA,
            _HASH_MANIFEST,
        }
        verified = _verify_hash_directory(directory, expected_files=expected_files)
        metadata = _parse_json_bytes(
            verified.payloads[_CHECKPOINT_METADATA],
            label="checkpoint.json",
        )
        identity_keys = {
            "schema",
            "sequence",
            "run_id",
            "project_id",
            "snapshot_hash",
            "frozen_compile_input_manifest_hash",
            "compile_input_hash",
            "best_compile_input_hash",
            "round_index",
            "current_candidate",
            "best_candidate",
            "state_files",
            "state_sha256",
        }
        if not isinstance(metadata, dict) or set(metadata) != identity_keys | {"checkpoint_id"}:
            raise _InvalidArtifact("checkpoint_schema", "checkpoint metadata schema is not exact")
        if metadata["schema"] != CHECKPOINT_SCHEMA:
            raise _InvalidArtifact("checkpoint_schema", "checkpoint schema is unsupported")
        sequence = metadata["sequence"]
        round_index = metadata["round_index"]
        if (
            type(sequence) is not int
            or sequence < 0
            or type(round_index) is not int
            or round_index < 0
        ):
            raise _InvalidArtifact("checkpoint_round", "checkpoint sequence or round is invalid")
        identity = {key: metadata[key] for key in identity_keys}
        checkpoint_id = self._checkpoint_id(identity)
        if metadata["checkpoint_id"] != checkpoint_id or directory.name != checkpoint_id:
            raise _InvalidArtifact("checkpoint_identity", "checkpoint directory identity differs")
        if (
            metadata["run_id"] != frozen.run_id
            or metadata["project_id"] != frozen.project_id
            or metadata["snapshot_hash"] != frozen.snapshot_hash
            or metadata["frozen_compile_input_manifest_hash"]
            != frozen.compile_input_manifest_hash
        ):
            raise _InvalidArtifact("snapshot_mismatch", "checkpoint differs from frozen inputs")
        _artifact_digest(metadata["compile_input_hash"], label="compile input hash")
        _artifact_digest(metadata["best_compile_input_hash"], label="best compile input hash")
        if metadata["state_files"] != _STATE_FILES:
            raise _InvalidArtifact("checkpoint_schema", "checkpoint state file map differs")
        state_hashes = metadata["state_sha256"]
        if not isinstance(state_hashes, dict) or set(state_hashes) != set(_STATE_FILES.values()):
            raise _InvalidArtifact("checkpoint_schema", "checkpoint state hash map differs")
        for name, digest in state_hashes.items():
            _artifact_digest(digest, label=f"state hash {name}")
            if verified.hashes.get(name) != digest:
                raise _InvalidArtifact("state_hash", f"checkpoint state hash differs: {name}")

        current_raw = self._binding_from_metadata(
            metadata["current_candidate"], label="current"
        )
        best_raw = self._binding_from_metadata(metadata["best_candidate"], label="best")
        current = self._load_candidate(current_raw["candidate_id"])
        best = (
            current
            if best_raw["candidate_id"] == current_raw["candidate_id"]
            else self._load_candidate(best_raw["candidate_id"])
        )
        self._check_candidate_binding(current_raw, current, label="current")
        self._check_candidate_binding(best_raw, best, label="best")
        if current.round_index > round_index or best.round_index > round_index:
            raise _InvalidArtifact("checkpoint_round", "checkpoint predates its candidate")
        current_compile = self._candidate_compile_input_hash(current, frozen)
        best_compile = self._candidate_compile_input_hash(best, frozen)
        if metadata["compile_input_hash"] != current_compile:
            raise _InvalidArtifact("compile_mismatch", "current compile input hash differs")
        if metadata["best_compile_input_hash"] != best_compile:
            raise _InvalidArtifact("compile_mismatch", "best compile input hash differs")

        states = {
            role: _parse_json_bytes(verified.payloads[filename], label=filename)
            for role, filename in _STATE_FILES.items()
        }
        self._check_optional_state_bindings(states, metadata)
        return self._checkpoint_from_parts(
            metadata=metadata,
            directory=directory,
            current=current,
            best=best,
            states=states,
        )

    @staticmethod
    def _checkpoint_from_parts(
        *,
        metadata: Mapping[str, Any],
        directory: Path,
        current: CheckpointCandidateBinding,
        best: CheckpointCandidateBinding,
        states: Mapping[str, Any],
    ) -> CommittedAnalysisCheckpoint:
        return CommittedAnalysisCheckpoint(
            checkpoint_id=metadata["checkpoint_id"],
            sequence=metadata["sequence"],
            run_id=metadata["run_id"],
            project_id=metadata["project_id"],
            snapshot_hash=metadata["snapshot_hash"],
            frozen_compile_input_manifest_hash=metadata[
                "frozen_compile_input_manifest_hash"
            ],
            compile_input_hash=metadata["compile_input_hash"],
            best_compile_input_hash=metadata["best_compile_input_hash"],
            round_index=metadata["round_index"],
            directory=directory,
            current_candidate=current,
            best_candidate=best,
            run_state=states["run_state"],
            issue_ledger=states["issue_ledger"],
            task_ledger=states["task_ledger"],
            budget_ledger=states["budget_ledger"],
            invocation_ledger=states["invocation_ledger"],
            compile_history=states["compile_history"],
            candidate_page_map=states["candidate_page_map"],
            rollback_history=states["rollback_history"],
        )

    def recover_latest(
        self,
        *,
        expected_run_id: str | None = None,
        expected_project_id: str | None = None,
        expected_snapshot_hash: str | None = None,
        expected_frozen_compile_input_manifest_hash: str | None = None,
        semantic_validator: CheckpointSemanticValidator | None = None,
    ) -> RecoveryScanResult:
        """Scan newest-to-oldest and return the first complete recoverable checkpoint."""

        frozen = self.verify_frozen_inputs()
        expectations = {
            "run_id": (expected_run_id, frozen.run_id),
            "project_id": (expected_project_id, frozen.project_id),
            "snapshot_hash": (expected_snapshot_hash, frozen.snapshot_hash),
            "frozen compile input manifest hash": (
                expected_frozen_compile_input_manifest_hash,
                frozen.compile_input_manifest_hash,
            ),
        }
        for label, (expected, observed) in expectations.items():
            if expected is not None and str(expected) != observed:
                raise RecoveryValidationError(f"expected {label} differs from frozen inputs")

        checkpoints = self.checkpoints_directory
        if not checkpoints.exists():
            return RecoveryScanResult(
                frozen_inputs=frozen,
                checkpoint=None,
                rejected=(),
                latest_pointer=None,
                latest_pointer_valid=False,
            )
        try:
            _assert_no_symlink_chain(checkpoints)
            checkpoint_stat = os.lstat(checkpoints)
        except OSError as exc:
            raise RecoveryValidationError("checkpoint directory is unreadable") from exc
        if _is_link_or_reparse(checkpoint_stat) or not stat.S_ISDIR(
            checkpoint_stat.st_mode
        ):
            raise RecoveryValidationError("checkpoint directory is unsafe")

        rejected: list[RecoveryRejection] = []
        latest_pointer: str | None = None
        latest_syntax_valid = False
        latest = checkpoints / "LATEST"
        if latest.exists() or latest.is_symlink():
            try:
                raw_latest = _read_regular_file(latest)
                decoded = raw_latest.decode("ascii")
                if not decoded.endswith("\n") or decoded.count("\n") != 1:
                    raise ValueError
                latest_pointer = decoded[:-1]
                latest_syntax_valid = _CHECKPOINT_ID_RE.fullmatch(latest_pointer) is not None
                if not latest_syntax_valid:
                    raise ValueError
            except (_InvalidArtifact, UnicodeDecodeError, ValueError):
                rejected.append(
                    RecoveryRejection(
                        artifact="LATEST",
                        code="latest_pointer",
                        message="LATEST is missing a canonical checkpoint id",
                    )
                )
                latest_pointer = None
                latest_syntax_valid = False

        entries: list[tuple[int, Path]] = []
        sequence_counts: dict[int, int] = {}
        for entry in sorted(os.scandir(checkpoints), key=lambda item: item.name):
            if entry.name == "LATEST" or entry.name.startswith(".LATEST-"):
                continue
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                entry_stat = None
            if entry_stat is None or _is_link_or_reparse(entry_stat):
                rejected.append(
                    RecoveryRejection(
                        artifact=entry.name,
                        code="symlink",
                        message="link, reparse point, or unreadable entry is forbidden in checkpoint storage",
                    )
                )
                continue
            match = _CHECKPOINT_ID_RE.fullmatch(entry.name)
            if match is None or not stat.S_ISDIR(entry_stat.st_mode):
                code = "half_written" if entry.name.startswith(".checkpoint-") else "orphan"
                rejected.append(
                    RecoveryRejection(
                        artifact=entry.name,
                        code=code,
                        message="entry is not a committed checkpoint directory",
                    )
                )
                continue
            sequence = int(match.group("sequence"))
            entries.append((sequence, Path(entry.path)))
            sequence_counts[sequence] = sequence_counts.get(sequence, 0) + 1

        selected: CommittedAnalysisCheckpoint | None = None
        for sequence, directory in sorted(entries, key=lambda item: (item[0], item[1].name), reverse=True):
            if sequence_counts[sequence] != 1:
                rejected.append(
                    RecoveryRejection(
                        artifact=directory.name,
                        code="duplicate_sequence",
                        message="checkpoint sequence has multiple immutable histories",
                        sequence=sequence,
                    )
                )
                continue
            try:
                candidate = self._load_checkpoint(directory, frozen)
            except _InvalidArtifact as exc:
                rejected.append(
                    RecoveryRejection(
                        artifact=directory.name,
                        code=exc.code,
                        message=exc.message,
                        sequence=sequence,
                    )
                )
                continue
            if semantic_validator is not None:
                try:
                    verdict = semantic_validator(deepcopy(candidate))
                    if verdict is not None and type(verdict) is not bool:
                        raise TypeError("semantic validator must return bool or None")
                except Exception:
                    rejected.append(
                        RecoveryRejection(
                            artifact=directory.name,
                            code="semantic_validation",
                            message="checkpoint failed semantic validation",
                            sequence=sequence,
                        )
                    )
                    continue
                if verdict is False:
                    rejected.append(
                        RecoveryRejection(
                            artifact=directory.name,
                            code="semantic_validation",
                            message="checkpoint failed semantic validation",
                            sequence=sequence,
                        )
                    )
                    continue
            selected = candidate
            break

        pointer_valid = bool(
            latest_syntax_valid
            and selected is not None
            and latest_pointer == selected.checkpoint_id
        )
        if latest_syntax_valid and not pointer_valid:
            rejected.append(
                RecoveryRejection(
                    artifact="LATEST",
                    code="latest_stale_or_invalid",
                    message="LATEST does not name the selected complete checkpoint",
                )
            )
        return RecoveryScanResult(
            frozen_inputs=frozen,
            checkpoint=selected,
            rejected=tuple(rejected),
            latest_pointer=latest_pointer,
            latest_pointer_valid=pointer_valid,
        )


__all__ = [
    "ActiveRunLockError",
    "AnalysisRecoveryError",
    "AnalysisRunStore",
    "CheckpointCandidateBinding",
    "CheckpointSemanticValidator",
    "CommittedAnalysisCheckpoint",
    "CompileExtraBinding",
    "FrozenAnalysisInputs",
    "ImmutableEvidenceError",
    "RecoveryRejection",
    "RecoveryScanResult",
    "RecoveryValidationError",
    "assert_plain_storage_path",
    "path_is_link_or_reparse",
    "parse_strict_json_bytes",
]

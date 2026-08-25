# -*- coding: utf-8 -*-
"""Crash-safe task/result ledger for production analysis model work.

The store commits a validated response before marking its task completed.
Consequently a process crash can at worst leave an unreferenced response file;
it cannot create a completed task whose evidence is missing.  Task identities
are fully host-owned and content addressed, and callers replay completed
responses in their own deterministic plan order.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TASK_ID_RE = re.compile(r"^task-[a-z0-9-]+-[0-9a-f]{16}$")
_STATES = frozenset({"PENDING", "RUNNING", "COMPLETED", "BLOCKED"})
_IDENTITY_KEYS = frozenset({
    "task_id",
    "snapshot_hash",
    "candidate_hash",
    "operation",
    "role",
    "source_page_id",
    "scope_id",
    "binding_hash",
})
_RECORD_KEYS = frozenset({
    "identity",
    "identity_sha256",
    "state",
    "attempts",
    "response_path",
    "response_sha256",
    "error",
})


class TaskLedgerPersistenceError(RuntimeError):
    """The task ledger may no longer agree with durable storage."""

    retryable = False
    fatal_analysis = True


class TaskAttemptsExhaustedError(RuntimeError):
    """A recovered task already consumed its durable retry allowance."""

    retryable = False


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object members instead of accepting last-key-wins JSON."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry after an atomic replace when supported."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
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


def _is_link_or_reparse(item_stat: os.stat_result) -> bool:
    if stat.S_ISLNK(item_stat.st_mode):
        return True
    if os.name != "nt":
        return False
    attributes = int(getattr(item_stat, "st_file_attributes", 0) or 0)
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _assert_plain_path(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            item_stat = os.lstat(current)
        except FileNotFoundError:
            return
        if _is_link_or_reparse(item_stat):
            raise ValueError(f"link or reparse point is forbidden in task storage: {current}")


def _ensure_plain_directory(path: Path) -> None:
    _assert_plain_path(path)
    path.mkdir(parents=True, exist_ok=True)
    _assert_plain_path(path)
    item_stat = os.lstat(path)
    if _is_link_or_reparse(item_stat) or not stat.S_ISDIR(item_stat.st_mode):
        raise ValueError("analysis task storage is not a plain directory")


@dataclass(frozen=True, slots=True)
class AnalysisTaskIdentity:
    task_id: str
    snapshot_hash: str
    candidate_hash: str
    operation: str
    role: str
    source_page_id: str
    scope_id: str
    binding_hash: str

    def __post_init__(self) -> None:
        for name in _IDENTITY_KEYS:
            value = getattr(self, name)
            if not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
        if not _TASK_ID_RE.fullmatch(self.task_id):
            raise ValueError("task_id must be host generated")
        if not all(
            value.strip()
            for value in (
                self.operation,
                self.role,
                self.source_page_id,
                self.scope_id,
            )
        ):
            raise ValueError("task identity fields are required")
        for name in ("snapshot_hash", "candidate_hash", "binding_hash"):
            value = getattr(self, name).lower()
            if not _DIGEST_RE.fullmatch(value):
                raise ValueError(f"{name} must be a SHA-256 digest")
            object.__setattr__(self, name, value)

    @property
    def identity_hash(self) -> str:
        return _sha(_canonical_bytes(asdict(self)))


@dataclass(frozen=True, slots=True)
class AnalysisTaskRecord:
    identity: AnalysisTaskIdentity
    state: str
    attempts: int
    response_path: str = ""
    response_sha256: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if (
            not isinstance(self.state, str)
            or self.state not in _STATES
            or type(self.attempts) is not int
            or self.attempts < 0
        ):
            raise ValueError("invalid task record state")
        for name in ("response_path", "response_sha256", "error"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be a string")
        if self.state != "PENDING" and self.attempts < 1:
            raise ValueError("a non-pending task must have at least one attempt")
        if len(self.error) > 2_000:
            raise ValueError("task error exceeds the persisted size limit")
        if self.state == "COMPLETED" and self.error:
            raise ValueError("completed task cannot retain a prior error")
        if self.state == "BLOCKED" and not self.error.strip():
            raise ValueError("blocked task requires a permanent error")
        if self.state == "PENDING" and bool(self.attempts) != bool(self.error.strip()):
            raise ValueError("pending retry evidence conflicts with its attempt count")
        if self.response_sha256 and not _DIGEST_RE.fullmatch(self.response_sha256):
            raise ValueError("response_sha256 must be a SHA-256 digest")
        if self.state == "COMPLETED" and not (
            self.response_path and self.response_sha256
        ):
            raise ValueError("completed task requires committed response evidence")
        if self.state != "COMPLETED" and (
            self.response_path or self.response_sha256
        ):
            raise ValueError("non-completed task cannot reference response evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": asdict(self.identity),
            "identity_sha256": self.identity.identity_hash,
            "state": self.state,
            "attempts": self.attempts,
            "response_path": self.response_path,
            "response_sha256": self.response_sha256,
            "error": self.error,
        }


def make_task_identity(
    *,
    snapshot_hash: str,
    candidate_hash: str,
    operation: str,
    role: str,
    source_page_id: str,
    scope_id: str,
    binding_payload: Mapping[str, Any],
) -> AnalysisTaskIdentity:
    binding_hash = _sha(_canonical_bytes(dict(binding_payload)))
    seed = _canonical_bytes({
        "snapshot_hash": snapshot_hash,
        "candidate_hash": candidate_hash,
        "operation": operation,
        "role": role,
        "source_page_id": source_page_id,
        "scope_id": scope_id,
        "binding_hash": binding_hash,
    })
    safe_role = re.sub(r"[^a-z0-9]+", "-", role.casefold()).strip("-") or "role"
    return AnalysisTaskIdentity(
        task_id=f"task-{safe_role}-{_sha(seed)[:16]}",
        snapshot_hash=snapshot_hash,
        candidate_hash=candidate_hash,
        operation=operation,
        role=role,
        source_page_id=source_page_id,
        scope_id=scope_id,
        binding_hash=binding_hash,
    )


class AnalysisTaskStore:
    """Mutable task index with immutable, hash-verified response objects."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.responses = self.root / "responses"
        self.index_path = self.root / "task-ledger.json"
        _ensure_plain_directory(self.root)
        _ensure_plain_directory(self.responses)
        self._lock = threading.RLock()
        self._poisoned = False
        self._records: dict[str, AnalysisTaskRecord] = {}
        if self.index_path.exists():
            self._load()
        self.recover_interrupted()

    def _load(self) -> None:
        _assert_plain_path(self.index_path)
        try:
            index_stat = os.lstat(self.index_path)
        except OSError as exc:
            raise ValueError("analysis task ledger is not a regular file") from exc
        if _is_link_or_reparse(index_stat) or not stat.S_ISREG(index_stat.st_mode):
            raise ValueError("analysis task ledger is not a regular file")
        payload = json.loads(
            self.index_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
        )
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema", "records"}
            or payload.get("schema") != "latexstruct-analysis-task-ledger-v2"
        ):
            raise ValueError("unsupported analysis task ledger")
        raw_records = payload.get("records")
        if not isinstance(raw_records, dict):
            raise ValueError("analysis task ledger records are invalid")
        records: dict[str, AnalysisTaskRecord] = {}
        for task_id, raw in raw_records.items():
            if (
                not isinstance(task_id, str)
                or not isinstance(raw, dict)
                or set(raw) != _RECORD_KEYS
                or not isinstance(raw.get("identity"), dict)
                or set(raw["identity"]) != _IDENTITY_KEYS
                or not all(isinstance(value, str) for value in raw["identity"].values())
                or not isinstance(raw.get("identity_sha256"), str)
                or not isinstance(raw.get("state"), str)
                or type(raw.get("attempts")) is not int
                or not all(
                    isinstance(raw.get(name), str)
                    for name in ("response_path", "response_sha256", "error")
                )
            ):
                raise ValueError("analysis task record is invalid")
            identity = AnalysisTaskIdentity(**raw["identity"])
            if task_id != identity.task_id or raw.get("identity_sha256") != (
                identity.identity_hash
            ):
                raise ValueError("analysis task identity is stale")
            record = AnalysisTaskRecord(
                identity=identity,
                state=raw["state"],
                attempts=raw["attempts"],
                response_path=raw["response_path"],
                response_sha256=raw["response_sha256"],
                error=raw["error"],
            )
            if raw != record.to_dict():
                raise ValueError("analysis task record is not canonical")
            if record.state == "COMPLETED":
                self._read_response(record)
            records[task_id] = record
        self._records = records

    def _save(
        self,
        records: Mapping[str, AnalysisTaskRecord] | None = None,
    ) -> None:
        _ensure_plain_directory(self.root)
        _assert_plain_path(self.index_path)
        source = self._records if records is None else records
        payload = {
            "schema": "latexstruct-analysis-task-ledger-v2",
            "records": {
                task_id: record.to_dict()
                for task_id, record in sorted(source.items())
            },
        }
        encoded = (
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.index_path.name}.", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.index_path)
            _fsync_directory(self.index_path.parent)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _assert_healthy(self) -> None:
        if self._poisoned:
            raise TaskLedgerPersistenceError(
                "analysis task store is poisoned after a persistence failure"
            )

    def _raise_persistence_failure(self, message: str, exc: BaseException) -> None:
        self._poisoned = True
        raise TaskLedgerPersistenceError(message) from exc

    def register(self, identity: AnalysisTaskIdentity) -> AnalysisTaskRecord:
        with self._lock:
            self._assert_healthy()
            prior = self._records.get(identity.task_id)
            if prior is not None:
                if prior.identity != identity:
                    raise ValueError("task id collision or stale task identity")
                return prior
            record = AnalysisTaskRecord(identity, "PENDING", 0)
            self._commit_record(identity.task_id, record)
            return record

    def _commit_record(self, task_id: str, record: AnalysisTaskRecord) -> None:
        self._assert_healthy()
        next_records = dict(self._records)
        next_records[task_id] = record
        try:
            self._save(next_records)
        except BaseException as exc:
            self._raise_persistence_failure(
                f"cannot persist analysis task transition for {task_id}", exc
            )
        self._records = next_records

    def start(
        self,
        task_id: str,
        *,
        max_attempts: int | None = None,
    ) -> AnalysisTaskRecord:
        with self._lock:
            self._assert_healthy()
            if max_attempts is not None and (
                type(max_attempts) is not int or max_attempts < 1
            ):
                raise ValueError("max_attempts must be a positive integer")
            prior = self.get(task_id)
            if prior.state != "PENDING":
                raise ValueError("only a pending task can start")
            if max_attempts is not None and prior.attempts >= max_attempts:
                blocked = AnalysisTaskRecord(
                    prior.identity,
                    "BLOCKED",
                    prior.attempts,
                    error="durable retry allowance exhausted before restart",
                )
                self._commit_record(task_id, blocked)
                raise TaskAttemptsExhaustedError(blocked.error)
            record = AnalysisTaskRecord(
                prior.identity,
                "RUNNING",
                prior.attempts + 1,
                error=prior.error,
            )
            self._commit_record(task_id, record)
            return record

    def commit_success(self, task_id: str, response: Any) -> AnalysisTaskRecord:
        """Write and fsync response bytes before committing COMPLETED state."""

        with self._lock:
            self._assert_healthy()
            prior = self.get(task_id)
            if prior.state != "RUNNING":
                raise ValueError("only a running task can complete")
            response_bytes = (
                json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            response_hash = _sha(response_bytes)
            response_name = f"{task_id}-{response_hash[:16]}.json"
            destination = self.responses / response_name
            try:
                if destination.exists():
                    _assert_plain_path(destination)
                    destination_stat = os.lstat(destination)
                    if _is_link_or_reparse(destination_stat) or not stat.S_ISREG(
                        destination_stat.st_mode
                    ) or destination.read_bytes() != response_bytes:
                        raise ValueError("immutable task response is corrupt")
                else:
                    _ensure_plain_directory(self.responses)
                    fd, temp_name = tempfile.mkstemp(
                        prefix=f".{response_name}.", suffix=".tmp", dir=self.responses
                    )
                    try:
                        with os.fdopen(fd, "wb") as handle:
                            handle.write(response_bytes)
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.replace(temp_name, destination)
                        _fsync_directory(destination.parent)
                    finally:
                        if os.path.exists(temp_name):
                            os.unlink(temp_name)
            except BaseException as exc:
                self._raise_persistence_failure(
                    f"cannot persist immutable task response for {task_id}", exc
                )
            relative = destination.relative_to(self.root).as_posix()
            record = AnalysisTaskRecord(
                prior.identity,
                "COMPLETED",
                prior.attempts,
                response_path=relative,
                response_sha256=response_hash,
            )
            self._commit_record(task_id, record)
            return record

    def fail(
        self,
        task_id: str,
        error: str,
        *,
        retryable: bool,
        max_attempts: int,
    ) -> AnalysisTaskRecord:
        with self._lock:
            self._assert_healthy()
            if type(retryable) is not bool:
                raise ValueError("retryable must be a boolean")
            if type(max_attempts) is not int or max_attempts < 1:
                raise ValueError("max_attempts must be a positive integer")
            prior = self.get(task_id)
            if prior.state != "RUNNING":
                raise ValueError("only a running task can fail")
            state = "PENDING" if retryable and prior.attempts < max_attempts else "BLOCKED"
            record = AnalysisTaskRecord(
                prior.identity,
                state,
                prior.attempts,
                error=str(error)[:2000],
            )
            self._commit_record(task_id, record)
            return record

    def recover_interrupted(self) -> int:
        with self._lock:
            self._assert_healthy()
            next_records = dict(self._records)
            count = 0
            for task_id, prior in tuple(self._records.items()):
                if prior.state != "RUNNING":
                    continue
                next_records[task_id] = AnalysisTaskRecord(
                    prior.identity,
                    "PENDING",
                    prior.attempts,
                    error="process interrupted before task commit",
                )
                count += 1
            if count:
                try:
                    self._save(next_records)
                except BaseException as exc:
                    self._raise_persistence_failure(
                        "cannot persist interrupted task recovery", exc
                    )
                self._records = next_records
            return count

    def _read_response(self, record: AnalysisTaskRecord) -> Any:
        path = self.root / record.response_path
        try:
            path.resolve().relative_to(self.root.resolve())
        except ValueError as exc:
            raise ValueError("task response escapes its run root") from exc
        _assert_plain_path(path)
        try:
            path_stat = os.lstat(path)
        except OSError as exc:
            raise ValueError("completed task response is missing") from exc
        if _is_link_or_reparse(path_stat) or not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("completed task response is missing")
        payload = path.read_bytes()
        if _sha(payload) != record.response_sha256:
            raise ValueError("completed task response hash mismatch")
        return json.loads(payload.decode("utf-8"))

    def response(self, task_id: str) -> Any:
        with self._lock:
            record = self.get(task_id)
            if record.state != "COMPLETED":
                raise ValueError("task has no completed response")
            return self._read_response(record)

    def get(self, task_id: str) -> AnalysisTaskRecord:
        try:
            return self._records[task_id]
        except KeyError as exc:
            raise KeyError(f"unknown analysis task: {task_id}") from exc

    @property
    def records(self) -> tuple[AnalysisTaskRecord, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema": "latexstruct-analysis-task-ledger-v2",
                "records": {
                    task_id: record.to_dict()
                    for task_id, record in sorted(self._records.items())
                },
            }

    def summary(self) -> dict[str, int]:
        result = {state: 0 for state in sorted(_STATES)}
        for record in self.records:
            result[record.state] += 1
        return result


__all__ = [
    "AnalysisTaskIdentity",
    "AnalysisTaskRecord",
    "AnalysisTaskStore",
    "TaskAttemptsExhaustedError",
    "TaskLedgerPersistenceError",
    "make_task_identity",
]

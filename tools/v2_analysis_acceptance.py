#!/usr/bin/env python3
"""Run the real OCR -> v2 analysis/review release acceptance workflow.

This producer starts OCR through the real Playwright UI, imports the completed
OCR job through the local HTTP API, waits for the host-owned v2 analysis and two
independent final reviews, then downloads and verifies the immutable AI audit
submission ZIP.  A PASS attestation is published only after the release gate
has independently re-read the staged reports.  Failures retain diagnostics but
can never be promoted to VERIFIED.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable, Mapping
from urllib.parse import urlencode, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from tools.v2_acceptance_e2e import (
        AcceptanceConfig as OcrAcceptanceConfig,
        AcceptanceError,
        LocalHttpApi,
        PlaywrightUiDriver,
        count_pdf_pages,
        run_acceptance as run_ocr_acceptance,
    )
except ModuleNotFoundError:  # Direct ``python tools/...`` execution.
    from v2_acceptance_e2e import (  # type: ignore[no-redef]
        AcceptanceConfig as OcrAcceptanceConfig,
        AcceptanceError,
        LocalHttpApi,
        PlaywrightUiDriver,
        count_pdf_pages,
        run_acceptance as run_ocr_acceptance,
    )

from latexstruct.core.audit_sanitize import sanitize_log_text


ANALYSIS_PROFILES = {"analysis-37": 37}
DEFAULT_TIMEOUT_SECONDS = 4 * 3600.0
# The fixed source may gain a generated TOC and bounded reflow, but the known
# 37 -> 49 failure must remain impossible to attest.  Five extra pages is the
# explicit release ceiling, not a generic quality claim for other documents.
MAX_ANALYSIS_37_CANDIDATE_PAGES = 42
PROCESS_TERMINAL_STATUSES = frozenset({"done", "blocked", "error", "cancelled"})
PROCESS_ACTIVE_STATUSES = frozenset(
    {"running", "pausing", "paused", "cancelling", "committing"}
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
BUILD_ID_RE = re.compile(r"[1-9][0-9]*")
PRODUCER = "tools/v2_analysis_acceptance.py"
AUDIT_ZIP_FILENAME = "analysis-audit-submission.zip"


def _load_release_integrity() -> ModuleType:
    name = "_latexstruct_release_integrity_for_analysis_acceptance"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().parents[1] / "packaging" / "release_integrity.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the release-integrity verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RELEASE_INTEGRITY = _load_release_integrity()


@dataclass(frozen=True, slots=True)
class AnalysisAcceptanceConfig:
    base_url: str
    source: Path
    profile: str
    output_dir: Path
    expected_version: str
    expected_commit: str
    expected_build_id: str
    executable: Path
    expected_executable_sha256: str
    service_pid: int
    quality_tier: str = "high"
    template: str = "faithfulbook"
    poll_seconds: float = 2.0
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    browser_timeout_seconds: float = 90.0
    headed: bool = False
    max_wall_seconds: float | None = None
    max_consecutive_poll_errors: int = 5

    @property
    def expected_pages(self) -> int:
        return ANALYSIS_PROFILES.get(self.profile, 0)


@dataclass(slots=True)
class AnalysisRunEvidence:
    overall_started_at: str = ""
    measurement_started_at: str = ""
    ended_at: str = ""
    wall_time_seconds: float | None = None
    timed_out: bool = False
    completed_terminal_run: bool = False
    real_execution: bool = False
    health: dict[str, Any] = field(default_factory=dict)
    ocr_validation: dict[str, Any] = field(default_factory=dict)
    import_response: dict[str, Any] = field(default_factory=dict)
    project_id: str = ""
    process_job_id: str = ""
    process_history: list[dict[str, Any]] = field(default_factory=list)
    process_terminal: dict[str, Any] = field(default_factory=dict)
    audit_latest: dict[str, Any] = field(default_factory=dict)
    audit_submission: dict[str, Any] = field(default_factory=dict)
    audit_zip_sha256: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class VerifiedBundleFacts:
    source: dict[str, Any]
    selected_range: dict[str, Any]
    models: dict[str, Any]
    compilation: dict[str, Any]
    artifact_payloads: dict[str, bytes]
    independent_final_reviews: list[dict[str, Any]]
    visual_page_id_set_sha256: str
    page_layout: dict[str, Any]
    machine_report: dict[str, Any]
    manifest: dict[str, Any]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


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
    _atomic_write(path, _json_bytes(value))


def _safe_error(exc: BaseException, config: AnalysisAcceptanceConfig) -> str:
    return sanitize_log_text(
        f"{type(exc).__name__}: {exc}",
        (config.source, config.output_dir, config.executable),
    )[:2000]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _positive_int(value: object) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, result)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AcceptanceError(f"{label} is missing or is not a JSON object")
    return dict(value)


def _sequence(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AcceptanceError(f"{label} is missing or is not a JSON array")
    return value


def _process_image_path(pid: int) -> Path:
    """Resolve the executable image for the service process without trusting health JSON."""

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        process = kernel32.OpenProcess(0x1000, False, int(pid))
        if not process:
            raise AcceptanceError("cannot open the candidate service PID")
        try:
            capacity = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(capacity.value)
            ok = kernel32.QueryFullProcessImageNameW(
                process, 0, buffer, ctypes.byref(capacity)
            )
            if not ok:
                raise AcceptanceError("cannot resolve the candidate service executable")
            return Path(buffer.value)
        finally:
            kernel32.CloseHandle(process)
    probe = Path("/proc") / str(int(pid)) / "exe"
    try:
        return probe.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError("cannot resolve the candidate service executable") from exc


def _listening_pids(port: int) -> set[int]:
    if os.name != "nt":
        raise AcceptanceError("analysis-37 service-port ownership requires Windows")
    completed = subprocess.run(
        ["netstat.exe", "-ano", "-p", "tcp"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AcceptanceError("cannot inspect the candidate service listening port")
    owners: set[int] = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0].upper() != "TCP":
            continue
        if fields[-2].upper() != "LISTENING":
            continue
        try:
            local_port = int(fields[1].rsplit(":", 1)[1])
            owner = int(fields[-1])
        except (IndexError, ValueError):
            continue
        if local_port == port and owner > 0:
            owners.add(owner)
    return owners


def _process_parent_map() -> dict[int, int]:
    if os.name != "nt":
        parents: dict[int, int] = {}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_text(encoding="utf-8").split()
                parents[int(entry.name)] = int(fields[3])
            except (OSError, ValueError, IndexError):
                continue
        return parents

    import ctypes
    from ctypes import wintypes

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_handle = wintypes.HANDLE(-1).value
    if snapshot == invalid_handle:
        raise AcceptanceError("cannot inspect the candidate service process tree")
    parents: dict[int, int] = {}
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(ProcessEntry32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return parents


def _is_pid_or_descendant(pid: int, ancestor: int, parents: Mapping[int, int]) -> bool:
    current = int(pid)
    seen: set[int] = set()
    while current > 0 and current not in seen:
        if current == int(ancestor):
            return True
        seen.add(current)
        current = int(parents.get(current, 0))
    return False


def _bound_listener_pid(config: AnalysisAcceptanceConfig) -> tuple[int, int]:
    parsed = urlsplit(config.base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    owners = _listening_pids(port)
    _require(len(owners) == 1, "candidate base URL does not have exactly one listening PID")
    owner = next(iter(owners))
    parents = _process_parent_map()
    _require(
        _is_pid_or_descendant(owner, config.service_pid, parents),
        "candidate base URL listener is not the supplied service PID or its child",
    )
    owner_image = _process_image_path(owner)
    _require(
        owner_image.resolve() == config.executable.resolve()
        and _sha256_file(owner_image)
        == config.expected_executable_sha256.strip().lower(),
        "candidate base URL listener is not the supplied executable bytes",
    )
    return port, owner


def _validate_config(config: AnalysisAcceptanceConfig) -> None:
    _require(config.profile in ANALYSIS_PROFILES, "profile must be analysis-37")
    _require(config.source.is_file(), "source PDF does not exist")
    _require(config.source.suffix.lower() == ".pdf", "source must have a .pdf extension")
    _require(config.executable.is_file(), "tested executable does not exist")
    _require(config.executable.name == "LaTeXStruct.exe", "tested executable must be named LaTeXStruct.exe")
    _require(
        re.fullmatch(r"\d+\.\d+\.\d+", config.expected_version) is not None,
        "expected version is invalid",
    )
    _require(
        COMMIT_RE.fullmatch(config.expected_commit.strip().lower()) is not None,
        "expected commit must be 40-64 lowercase hexadecimal characters",
    )
    _require(
        BUILD_ID_RE.fullmatch(config.expected_build_id.strip()) is not None,
        "expected build id must be a numeric GitHub Actions run id",
    )
    expected_exe = config.expected_executable_sha256.strip().lower()
    _require(SHA256_RE.fullmatch(expected_exe) is not None, "expected executable SHA-256 is invalid")
    _require(
        _sha256_file(config.executable) == expected_exe,
        "tested executable bytes do not match --exe-sha256",
    )
    _require(
        _sha256_file(config.source) == RELEASE_INTEGRITY.RAMSEY_37_SOURCE_SHA256,
        "analysis-37 requires the fixed Ramsey 37-page source PDF SHA-256",
    )
    _require(config.quality_tier == "high", "analysis-37 requires quality tier high")
    _require(config.template == "faithfulbook", "analysis-37 requires the faithfulbook template")
    _require(config.service_pid > 0, "analysis-37 requires the candidate service PID")
    service_image = _process_image_path(config.service_pid)
    _require(
        service_image.resolve() == config.executable.resolve(),
        "candidate service PID is not running the supplied LaTeXStruct.exe",
    )
    _require(
        _sha256_file(service_image) == expected_exe,
        "running candidate service executable SHA-256 mismatch",
    )
    parsed = urlsplit(config.base_url)
    _require(
        parsed.scheme in {"http", "https"}
        and (parsed.hostname or "").lower() in {"127.0.0.1", "localhost", "::1"},
        "base URL must identify a loopback LaTeXStruct service",
    )
    _bound_listener_pid(config)
    _require(config.poll_seconds > 0 and config.timeout_seconds > 0, "poll and timeout values must be positive")


def _validate_health(config: AnalysisAcceptanceConfig, health: Mapping[str, Any]) -> None:
    _require(health.get("ok") is True, "service health is not OK")
    _require(str(health.get("version") or "") == config.expected_version, "service version does not match the candidate")
    _require(
        str(health.get("commit") or "").lower() == config.expected_commit.lower(),
        "service commit does not match the candidate",
    )
    _require(
        str(health.get("build_id") or "") == config.expected_build_id,
        "service build id does not match the candidate",
    )


def _process_marker(snapshot: Mapping[str, Any], elapsed: float) -> dict[str, Any]:
    return {
        "elapsed_seconds": round(max(0.0, elapsed), 3),
        "id": str(snapshot.get("id") or ""),
        "status": str(snapshot.get("status") or ""),
        "phase": str(snapshot.get("phase") or ""),
        "progress": snapshot.get("progress"),
        "execution_state": str(snapshot.get("execution_state") or ""),
        "verification_status": str(snapshot.get("verification_status") or ""),
        "message": str(snapshot.get("message") or "")[:500],
    }


def _poll_process(
    api: LocalHttpApi,
    config: AnalysisAcceptanceConfig,
    evidence: AnalysisRunEvidence,
    *,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
    started: float,
) -> dict[str, Any]:
    deadline = started + config.timeout_seconds
    previous: dict[str, Any] | None = None
    consecutive_errors = 0
    while True:
        now = monotonic()
        if now >= deadline:
            evidence.timed_out = True
            raise AcceptanceError(
                f"analysis polling timed out after {config.timeout_seconds:.1f} seconds"
            )
        try:
            snapshot = api.get_json(
                f"/api/projects/{evidence.project_id}/process/status"
            )
            consecutive_errors = 0
        except AcceptanceError as exc:
            consecutive_errors += 1
            if consecutive_errors > config.max_consecutive_poll_errors:
                raise AcceptanceError(
                    "analysis status remained unavailable after "
                    f"{consecutive_errors} attempts: {exc}"
                ) from exc
            sleep(config.poll_seconds)
            continue
        marker = _process_marker(snapshot, monotonic() - started)
        if marker != previous:
            evidence.process_history.append(marker)
            previous = marker
        status = str(snapshot.get("status") or "").lower()
        if status in PROCESS_TERMINAL_STATUSES:
            evidence.completed_terminal_run = True
            return snapshot
        if status not in PROCESS_ACTIVE_STATUSES:
            raise AcceptanceError(f"analysis returned unknown status {status!r}")
        sleep(config.poll_seconds)


def _validate_process_terminal(
    terminal: Mapping[str, Any],
    *,
    expected_job_id: str,
) -> str:
    _require(str(terminal.get("id") or "") == expected_job_id, "analysis terminal job id changed")
    _require(str(terminal.get("status") or "").lower() == "done", "analysis did not reach the successful done state")
    _require(terminal.get("verification_status") == "passed", "analysis process verification did not pass")
    _require(terminal.get("execution_state") == "completed", "analysis process did not complete")
    result = _mapping(terminal.get("result"), "analysis terminal result")
    _require(result.get("ok") is True, "analysis terminal result is not OK")
    archive = _mapping(result.get("analysis_archive"), "immutable analysis archive summary")
    _require(archive.get("archive_status") == "READY", "immutable analysis archive was not frozen")
    _require(archive.get("final_status") == "VERIFIED", "immutable analysis archive is not VERIFIED")
    _require(archive.get("verified") is True, "immutable analysis archive did not verify")
    archive_verification = _mapping(archive.get("verification"), "analysis archive verification")
    _require(archive_verification.get("status") == "VERIFIED", "analysis archive verification status is not VERIFIED")
    _require(_positive_int(archive_verification.get("review_pass_count")) == 2, "analysis archive lacks two independent review passes")
    backend = str(terminal.get("analysis_backend") or "").strip()
    _require(backend in {"api", "codex_cli"}, "analysis backend identity is missing")
    return backend


def _read_audit_zip(payload: bytes) -> tuple[dict[str, bytes], dict[str, Any]]:
    _require(payload.startswith(b"PK"), "audit submission download is not a ZIP archive")
    try:
        with zipfile.ZipFile(BytesIO(payload), "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            _require(len(names) == len(set(names)), "audit ZIP contains duplicate member names")
            collision_keys: set[str] = set()
            for name in names:
                path = PurePosixPath(name)
                _require(
                    bool(name)
                    and "\\" not in name
                    and not name.startswith("/")
                    and not path.is_absolute()
                    and ".." not in path.parts
                    and ":" not in name,
                    f"audit ZIP contains unsafe member {name!r}",
                )
                collision = name.casefold()
                _require(collision not in collision_keys, "audit ZIP contains case-colliding members")
                collision_keys.add(collision)
            members = {item.filename: archive.read(item) for item in infos if not item.is_dir()}
    except zipfile.BadZipFile as exc:
        raise AcceptanceError("audit submission ZIP is corrupt") from exc

    required = {
        "submission_manifest.json",
        "audit/packaging-integrity.json",
        "audit/SHA256SUMS",
    }
    _require(required <= set(members), "audit ZIP is missing required control files")
    try:
        manifest = json.loads(members["submission_manifest.json"].decode("utf-8"))
        integrity = json.loads(members["audit/packaging-integrity.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError("audit ZIP controls are not valid UTF-8 JSON") from exc
    _require(isinstance(manifest, dict) and isinstance(integrity, dict), "audit ZIP controls must be JSON objects")
    _require(integrity.get("valid") is True, "audit packaging integrity did not pass")
    _require(integrity.get("packaging_status") == "SUCCESS", "audit packaging did not succeed")
    _require(integrity.get("audit_package_status") == "VALID", "audit package is not VALID")

    sum_rows: dict[str, str] = {}
    try:
        lines = members["audit/SHA256SUMS"].decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptanceError("audit/SHA256SUMS is not UTF-8") from exc
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        _require(match is not None, "audit/SHA256SUMS contains an invalid row")
        filename = match.group(2)
        _require(filename not in sum_rows, "audit/SHA256SUMS repeats a filename")
        sum_rows[filename] = match.group(1)
    expected_sum_names = set(members) - {"audit/SHA256SUMS"}
    _require(set(sum_rows) == expected_sum_names, "audit/SHA256SUMS coverage is incomplete")
    for filename, digest in sum_rows.items():
        _require(_sha256_bytes(members[filename]) == digest, f"audit member digest mismatch: {filename}")

    records = _sequence(manifest.get("artifacts"), "audit manifest artifacts")
    for raw in records:
        record = _mapping(raw, "audit manifest artifact")
        digest = record.get("bytes_sha256")
        if digest is None:
            continue
        path = str(record.get("path") or "")
        _require(path in members, f"manifest artifact is absent from ZIP: {path}")
        _require(str(digest) == _sha256_bytes(members[path]), f"manifest artifact digest mismatch: {path}")
        _require(_positive_int(record.get("byte_count")) == len(members[path]), f"manifest artifact byte count mismatch: {path}")
    return members, manifest


def _role_bindings(
    manifest: Mapping[str, Any], role: str
) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    output: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for raw in _sequence(manifest.get("artifacts"), "audit manifest artifacts"):
        record = _mapping(raw, "audit manifest artifact")
        if record.get("artifact_role") == role:
            output.append((record, None))
        for raw_alias in record.get("aliases") or []:
            alias = _mapping(raw_alias, "audit artifact alias")
            if alias.get("artifact_role") == role:
                output.append((record, alias))
    return output


def _one_role(
    members: Mapping[str, bytes], manifest: Mapping[str, Any], role: str
) -> tuple[bytes, dict[str, Any], dict[str, Any] | None]:
    bindings = _role_bindings(manifest, role)
    _require(len(bindings) == 1, f"audit manifest must contain exactly one {role} binding")
    record, alias = bindings[0]
    path = str(record.get("path") or "")
    _require(path in members, f"audit ZIP lacks the physical payload for {role}")
    return members[path], record, alias


def _original_artifact_sha(record: Mapping[str, Any]) -> str:
    digest = str(record.get("source_bytes_sha256") or record.get("bytes_sha256") or "").lower()
    _require(SHA256_RE.fullmatch(digest) is not None, "artifact lacks a valid original SHA-256")
    return digest


def _active_tableofcontents_count(tex: str) -> int:
    count = 0
    for line in tex.splitlines():
        visible: list[str] = []
        for index, char in enumerate(line):
            if char == "%":
                backslashes = 0
                cursor = index - 1
                while cursor >= 0 and line[cursor] == "\\":
                    backslashes += 1
                    cursor -= 1
                if backslashes % 2 == 0:
                    break
            visible.append(char)
        count += len(re.findall(r"\\tableofcontents(?![A-Za-z@])", "".join(visible)))
    return count


def _review_context_sha(review: Mapping[str, Any]) -> str:
    context = {
        "pass_number": review.get("pass_number"),
        "context_id": review.get("context_id"),
        "candidate_hash": review.get("candidate_hash"),
        "checked_page_ids": review.get("checked_page_ids"),
    }
    return _sha256_bytes(
        json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _verified_bundle_facts(
    *,
    config: AnalysisAcceptanceConfig,
    members: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    source_pages: int,
    source_sha256: str,
    backend: str,
    expected_project_id: str,
    expected_run_id: str,
) -> VerifiedBundleFacts:
    _require(manifest.get("workflow") == "OCR_ANALYSIS_REVIEW", "audit workflow is not OCR_ANALYSIS_REVIEW")
    _require(manifest.get("source_run_status") == "SUCCESS", "audit source run did not succeed")
    _require(manifest.get("terminal_status") == "SUCCESS", "audit terminal status is not SUCCESS")
    _require(manifest.get("verification_status") == "VERIFIED", "audit machine verification is not VERIFIED")
    _require(manifest.get("packaging_status") == "SUCCESS", "audit packaging status is not SUCCESS")
    _require(manifest.get("audit_package_status") == "VALID", "audit package status is not VALID")
    _require(str(manifest.get("project_id") or "") == expected_project_id, "audit package belongs to a different project")
    _require(str(manifest.get("run_id") or "") == expected_run_id, "audit package belongs to a different analysis run")
    _require(str(manifest.get("app_version") or "") == config.expected_version, "audit app version differs from the candidate")
    _require(not manifest.get("blockers"), "VERIFIED audit package still declares blockers")
    _require(not manifest.get("missing_expected_roles"), "audit package is missing expected artifact roles")

    provenance = _mapping(manifest.get("provenance"), "audit provenance")
    runtime = _mapping(provenance.get("runtime"), "audit runtime provenance")
    _require(runtime.get("identity_status") == "RECORDED", "audit runtime identity was not recorded")
    _require(str(runtime.get("app_version") or "") == config.expected_version, "audit runtime version mismatch")
    _require(str(runtime.get("git_commit") or "").lower() == config.expected_commit.lower(), "audit runtime commit mismatch")
    _require(str(runtime.get("build_id") or "") == config.expected_build_id, "audit runtime build id mismatch")

    source_pdf, source_record, _source_alias = _one_role(members, manifest, "SOURCE_PDF")
    _require(source_pdf.startswith(b"%PDF-"), "packaged SOURCE_PDF is not a PDF")
    _require(_sha256_bytes(source_pdf) == source_sha256, "packaged SOURCE_PDF differs from the selected source")
    _require(_original_artifact_sha(source_record) == source_sha256, "SOURCE_PDF manifest hash differs from the selected source")
    source_pdf_info = _mapping(manifest.get("source_pdf"), "audit source_pdf facts")
    _require(_positive_int(source_pdf_info.get("page_count")) == source_pages, "audit source PDF page count mismatch")
    selected_info = _mapping(source_pdf_info.get("selected_page_range"), "audit selected page range")
    expected_page_numbers = list(range(1, config.expected_pages + 1))
    _require(
        selected_info.get("start") == 1
        and selected_info.get("end") == config.expected_pages
        and selected_info.get("pages") == expected_page_numbers,
        "audit selected page range does not cover the required profile",
    )
    source = {
        "filename": config.source.name,
        "sha256": source_sha256,
        "total_pages": source_pages,
    }
    selected = {
        "start_page": 1,
        "end_page": config.expected_pages,
        "expected_pages": config.expected_pages,
    }

    current_tex, current_record, _current_alias = _one_role(members, manifest, "CURRENT_TEX")
    try:
        current_tex_text = current_tex.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError("packaged CURRENT_TEX is not UTF-8") from exc
    _require(
        _active_tableofcontents_count(current_tex_text) == 1,
        "analysis-37 candidate must contain exactly one active \\tableofcontents",
    )
    candidate_tex_sha = _original_artifact_sha(current_record)
    _require(
        _sha256_bytes(current_tex) == candidate_tex_sha,
        "packaged CURRENT_TEX bytes differ from the compiled candidate",
    )
    current_pdf, current_pdf_record, _current_pdf_alias = _one_role(
        members, manifest, "CURRENT_PREVIEW"
    )
    _require(current_pdf.startswith(b"%PDF-"), "packaged CURRENT_PREVIEW is not a PDF")
    _require(current_pdf_record.get("preview_status") == "COMPILED", "CURRENT_PREVIEW is not COMPILED")
    candidate_pdf_sha = _sha256_bytes(current_pdf)
    _require(_original_artifact_sha(current_pdf_record) == candidate_pdf_sha, "CURRENT_PREVIEW hash binding is invalid")
    compile_log, _compile_log_record, _compile_log_alias = _one_role(
        members, manifest, "COMPILE_CURRENT_LOG"
    )
    _require(bool(compile_log.strip()), "packaged current compile log is empty")

    verification_bytes, _verification_record, _verification_alias = _one_role(
        members, manifest, "VERIFICATION"
    )
    try:
        verification_wrapper = json.loads(verification_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError("packaged verification record is invalid") from exc
    verification_wrapper = _mapping(verification_wrapper, "packaged verification record")
    _require(verification_wrapper.get("terminal_status") == "SUCCESS", "packaged verification terminal status is not SUCCESS")
    verification = _mapping(verification_wrapper.get("verification"), "machine verification payload")
    _require(verification.get("safe_to_export") is True, "machine verification did not authorize export")
    analysis_v2 = _mapping(verification.get("analysis_v2"), "analysis_v2 evidence")
    _require(analysis_v2.get("required") is True and analysis_v2.get("executed") is True, "v2 analysis was not required and executed")
    _require(analysis_v2.get("ok") is True and analysis_v2.get("verified") is True, "v2 analysis evidence is not verified")
    _require(analysis_v2.get("status") == "VERIFIED", "v2 analysis status is not VERIFIED")
    _require(str(analysis_v2.get("result_tex_sha256") or "") == candidate_tex_sha, "v2 analysis result TEX hash mismatch")
    _require(str(analysis_v2.get("result_pdf_sha256") or "") == candidate_pdf_sha, "v2 analysis result PDF hash mismatch")
    decision = _mapping(analysis_v2.get("decision"), "v2 verification decision")
    _require(decision.get("verified") is True and decision.get("status") == "VERIFIED", "v2 verification decision is not VERIFIED")
    _require(not decision.get("failures"), "v2 verification decision still contains failures")

    compile_after = _mapping(verification.get("compile_after"), "final compile record")
    passes_completed = _positive_int(compile_after.get("passes_completed"))
    _require(
        compile_after.get("available") is True
        and compile_after.get("ok") is True
        and compile_after.get("preview_status") == "COMPILED"
        and compile_after.get("exit_code") == 0
        and compile_after.get("timed_out") is False
        and passes_completed >= 2,
        "final candidate lacks two successful real compile passes",
    )
    _require(str(compile_after.get("pdf_sha256") or "") == candidate_pdf_sha, "final compile PDF hash mismatch")
    candidate_page_count = _positive_int(compile_after.get("page_count"))
    _require(candidate_page_count > 0, "final compile page count is missing")
    _require(
        candidate_page_count <= MAX_ANALYSIS_37_CANDIDATE_PAGES,
        "analysis-37 candidate PDF has abnormal page inflation",
    )
    _require(str(compile_after.get("log") or "").encode("utf-8") == compile_log, "packaged compile log differs from final compile record")
    compile_invocations = [
        _mapping(item, "v2 compile invocation")
        for item in _sequence(analysis_v2.get("compile_invocations"), "v2 compile invocations")
    ]
    final_compile_invocations = [
        item for item in compile_invocations
        if item.get("candidate_hash") == candidate_tex_sha
    ]
    _require(
        {1, 2} <= {_positive_int(item.get("run_number")) for item in final_compile_invocations}
        and all(item.get("ok") is True for item in final_compile_invocations)
        and all(item.get("pdf_hash") == candidate_pdf_sha for item in final_compile_invocations),
        "v2 compile invocation ledger does not prove two successful final-candidate passes",
    )
    compilation = {
        "status": "COMPILED",
        "successful_passes": 2,
        "pass_exit_codes": [0, 0],
        "compile_log_sha256": _sha256_bytes(compile_log),
        "candidate_tex_sha256": candidate_tex_sha,
        "candidate_pdf_sha256": candidate_pdf_sha,
    }

    snapshot = _mapping(analysis_v2.get("snapshot"), "v2 analysis snapshot")
    _require(snapshot.get("source_pdf_hash") == source_sha256, "v2 snapshot source PDF hash mismatch")
    _require(snapshot.get("page_range") == expected_page_numbers, "v2 snapshot page range mismatch")
    _require(_positive_int(snapshot.get("page_count")) == source_pages, "v2 snapshot source page count mismatch")
    model_bindings: dict[str, str] = {}
    for raw in _sequence(snapshot.get("models"), "v2 model bindings"):
        item = _mapping(raw, "v2 model binding")
        role = str(item.get("role") or "")
        model_id = str(item.get("model_id") or "").strip()
        _require(re.fullmatch(r"AI-[1-6]", role) is not None and bool(model_id), "v2 model binding is invalid")
        _require(role not in model_bindings, "v2 model role is duplicated")
        model_bindings[role] = model_id

    transport = [
        _mapping(item, "v2 transport invocation")
        for item in _sequence(analysis_v2.get("transport_invocations"), "v2 transport invocations")
    ]
    call_counts = Counter(str(item.get("role") or "") for item in transport)
    _require(all(role in model_bindings for role in call_counts), "v2 transport invocation has no model binding")
    for required_role in ("AI-1", "AI-2", "AI-3", "AI-5"):
        _require(call_counts[required_role] > 0, f"v2 evidence has no real {required_role} calls")
    role_map = {
        "AI-1": "structure",
        "AI-2": "analysis",
        "AI-3": "visual_review",
        "AI-4": "analysis",
        "AI-5": "visual_review",
        "AI-6": "review",
    }
    model_rows = [
        {
            "role": role_map[role],
            "model_id": model_bindings[role],
            "backend": backend,
            "calls": call_counts[role],
        }
        for role in sorted(call_counts, key=lambda item: int(item.split("-")[1]))
        if call_counts[role] > 0
    ]
    models = {"calls_total": len(transport), "roles": model_rows}

    final_reviews = [
        _mapping(item, "independent final review")
        for item in _sequence(analysis_v2.get("final_reviews"), "independent final reviews")
    ]
    machine_evidence = _mapping(
        analysis_v2.get("verification_evidence"), "v2 machine verification evidence"
    )
    _require(machine_evidence.get("final_reviews") == final_reviews, "machine evidence final reviews differ from the v2 ledger")
    _require(len(final_reviews) == 2, "v2 evidence requires exactly two final reviews")
    context_ids: set[str] = set()
    context_hashes: set[str] = set()
    release_reviews: list[dict[str, Any]] = []
    for expected_pass, review in enumerate(final_reviews, 1):
        context_id = str(review.get("context_id") or "").strip()
        checked_ids = review.get("checked_page_ids")
        _require(review.get("pass_number") == expected_pass, "final review pass numbers are not 1 and 2")
        _require(context_id and context_id not in context_ids, "final review contexts are not independent")
        _require(review.get("candidate_hash") == candidate_tex_sha, "final review checked a different candidate")
        _require(isinstance(checked_ids, list) and len(checked_ids) == config.expected_pages and len(set(checked_ids)) == config.expected_pages, "final review page coverage is incomplete")
        _require(
            review.get("compile_passes", 0) >= 2
            and review.get("content_conservation_ok") is True
            and review.get("math_conservation_ok") is True
            and review.get("formal_inventory_ok") is True
            and review.get("visual_review_ok") is True
            and _positive_int(review.get("new_high_risk_issues")) == 0
            and review.get("prior_pass_conclusion_visible") is False,
            f"final review pass {expected_pass} did not PASS",
        )
        operation = f"final-review-{expected_pass}"
        review_calls = sum(
            item.get("role") == "AI-5" and item.get("operation") == operation
            for item in transport
        )
        _require(review_calls == config.expected_pages, f"final review pass {expected_pass} lacks one real call per page")
        context_sha = _review_context_sha(review)
        _require(context_sha not in context_hashes, "final review context hashes are not distinct")
        context_ids.add(context_id)
        context_hashes.add(context_sha)
        release_reviews.append({
            "review_id": f"{expected_run_id}:final-review-{expected_pass}",
            "context_id": context_id,
            "context_sha256": context_sha,
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": candidate_tex_sha,
            "pages_checked": config.expected_pages,
            "model_id": model_bindings["AI-5"],
            "backend": backend,
            "calls": review_calls,
        })

    _require(machine_evidence.get("raw_ocr_frozen") is True, "machine evidence does not bind frozen raw OCR")
    _require(machine_evidence.get("candidate_hash") == candidate_tex_sha, "machine verification checked a different candidate")
    _require(machine_evidence.get("current_candidate_hash") == candidate_tex_sha, "machine verification current candidate hash mismatch")
    expected_page_ids = machine_evidence.get("expected_page_ids")
    checked_page_ids = machine_evidence.get("checked_page_ids")
    _require(
        isinstance(expected_page_ids, list)
        and isinstance(checked_page_ids, list)
        and checked_page_ids == expected_page_ids
        and len(expected_page_ids) == config.expected_pages
        and len(set(expected_page_ids)) == config.expected_pages,
        "machine verification page coverage is incomplete",
    )
    visual_page_id_set_sha256 = _sha256_bytes(
        json.dumps(
            expected_page_ids,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    candidate_mappings = _mapping(
        analysis_v2.get("candidate_mappings"), "v2 candidate page mappings"
    )
    final_mapping = _mapping(
        candidate_mappings.get(candidate_tex_sha), "final candidate page mapping"
    )
    _require(
        str(final_mapping.get("pdf_sha256") or "") == candidate_pdf_sha,
        "final candidate page mapping is bound to a different PDF",
    )
    mapping_sha256 = str(final_mapping.get("mapping_sha256") or "").lower()
    _require(
        SHA256_RE.fullmatch(mapping_sha256) is not None,
        "final candidate page mapping digest is missing",
    )
    candidate_only_pages = final_mapping.get("candidate_only_pages")
    _require(
        isinstance(candidate_only_pages, list)
        and len(candidate_only_pages) == len(set(candidate_only_pages))
        and all(
            isinstance(page, int) and 1 <= page <= candidate_page_count
            for page in candidate_only_pages
        ),
        "final candidate-only page evidence is invalid",
    )
    _require(
        len(candidate_only_pages)
        <= MAX_ANALYSIS_37_CANDIDATE_PAGES - config.expected_pages,
        "analysis-37 has too many candidate-only pages",
    )
    page_layout = {
        "source_page_count": config.expected_pages,
        "candidate_page_count": candidate_page_count,
        "maximum_candidate_pages": MAX_ANALYSIS_37_CANDIDATE_PAGES,
        "page_growth": candidate_page_count - config.expected_pages,
        "candidate_only_pages": list(candidate_only_pages),
        "candidate_mapping_sha256": mapping_sha256,
        "no_abnormal_page_inflation": True,
        "active_tableofcontents_count": 1,
        "template": config.template,
    }
    _require(_positive_int(machine_evidence.get("best_compile_passes")) >= 2, "machine verification lacks two compile passes")
    _require(machine_evidence.get("best_pdf_openable") is True, "machine verification could not open the final PDF")
    zero_fields = (
        "silent_page_omissions",
        "silent_text_losses",
        "unauthorized_math_changes",
        "formal_errors",
        "open_critical",
        "open_high",
        "regressions",
        "severe_equation_number_errors",
        "silent_footnote_losses",
        "silent_figure_caption_losses",
        "silent_bibliography_losses",
    )
    for name in zero_fields:
        _require(_positive_int(machine_evidence.get(name)) == 0, f"machine verification found {name}")
    machine_report = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_MACHINE_VERIFICATION_SCHEMA,
        "result": "PASS",
        "candidate_tex_sha256": candidate_tex_sha,
        "pages_checked": config.expected_pages,
        "silent_omissions": 0,
        "text_loss": 0,
        "unauthorized_math_changes": 0,
        "unclosed_formal_environments": 0,
        "open_critical_issues": 0,
        "open_high_issues": 0,
        "regressions": 0,
    }
    return VerifiedBundleFacts(
        source=source,
        selected_range=selected,
        models=models,
        compilation=compilation,
        artifact_payloads={
            "candidate_tex": current_tex,
            "candidate_pdf": current_pdf,
            "compile_log": compile_log,
        },
        independent_final_reviews=release_reviews,
        visual_page_id_set_sha256=visual_page_id_set_sha256,
        page_layout=page_layout,
        machine_report=machine_report,
        manifest=dict(manifest),
    )


def _runtime_identity(config: AnalysisAcceptanceConfig) -> dict[str, Any]:
    return {
        "version": config.expected_version,
        "commit": config.expected_commit.lower(),
        "build_id": config.expected_build_id,
        "executable_filename": config.executable.name,
        "executable_sha256": config.expected_executable_sha256.lower(),
    }


def _execution(real_execution: bool) -> dict[str, Any]:
    return {
        "real_execution": real_execution,
        "test_double": not real_execution,
        "simulated": not real_execution,
        "api_client": "LocalHttpApi" if real_execution else "test-double",
        "ui_driver": "PlaywrightUiDriver" if real_execution else "test-double",
        "workflow": "OCR_ANALYSIS_REVIEW",
        "producer": PRODUCER,
    }


def _timing(evidence: AnalysisRunEvidence) -> dict[str, Any]:
    return {
        "measurement": (
            "external monotonic wall clock started before browser upload/start click "
            "and stopped after terminal analysis plus immutable audit ZIP verification"
        ),
        "started_at": evidence.measurement_started_at,
        "ended_at": evidence.ended_at,
        "wall_time_seconds": evidence.wall_time_seconds,
        "timed_out": evidence.timed_out,
        "completed_terminal_run": evidence.completed_terminal_run,
    }


def _copy_plain_tree(source_root: Path, destination_root: Path) -> None:
    """Copy a previously verified evidence tree without following links."""
    _require(
        source_root.is_dir()
        and not RELEASE_INTEGRITY._path_is_reparse_point(source_root),
        "OCR baseline prerequisite directory is missing or is a link",
    )
    files: list[tuple[PurePosixPath, bytes]] = []
    seen: set[str] = set()
    total_bytes = 0
    stack = [source_root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = PurePosixPath(path.relative_to(source_root).as_posix())
                folded = relative.as_posix().casefold()
                _require(
                    folded not in seen,
                    "OCR baseline prerequisite contains colliding paths",
                )
                seen.add(folded)
                _require(
                    not entry.is_symlink()
                    and not RELEASE_INTEGRITY._path_is_reparse_point(path),
                    "OCR baseline prerequisite contains a link",
                )
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    data = path.read_bytes()
                    total_bytes += len(data)
                    _require(
                        len(files) < 8192 and total_bytes <= 2 * 1024 * 1024 * 1024,
                        "OCR baseline prerequisite exceeds bounded copy limits",
                    )
                    files.append((relative, data))
                else:
                    raise AcceptanceError(
                        "OCR baseline prerequisite contains a special filesystem entry"
                    )
    _require(bool(files), "OCR baseline prerequisite directory is empty")
    for relative, data in sorted(files, key=lambda item: item[0].as_posix()):
        _atomic_write(destination_root.joinpath(*relative.parts), data)


def _publish_pass(
    config: AnalysisAcceptanceConfig,
    evidence: AnalysisRunEvidence,
    facts: VerifiedBundleFacts,
) -> dict[str, Any]:
    runtime = _runtime_identity(config)
    execution = _execution(True)
    service_image = _process_image_path(config.service_pid)
    listener_port, listener_pid = _bound_listener_pid(config)
    listener_image = _process_image_path(listener_pid)
    service_binding = {
        "verified": True,
        "pid": config.service_pid,
        "process_image_filename": service_image.name,
        "process_image_sha256": _sha256_file(service_image),
        "listener_port": listener_port,
        "listener_pid": listener_pid,
        "listener_pid_verified": True,
        "listener_image_filename": listener_image.name,
        "listener_image_sha256": _sha256_file(listener_image),
    }
    timing = _timing(evidence)
    machine_bytes = _json_bytes(facts.machine_report)
    machine = {
        "passed": True,
        **{
            key: value
            for key, value in facts.machine_report.items()
            if key not in {"schema_version", "result"}
        },
        "verification_json_sha256": _sha256_bytes(machine_bytes),
    }
    target_met = bool(
        config.max_wall_seconds is None
        or (
            evidence.wall_time_seconds is not None
            and evidence.wall_time_seconds <= config.max_wall_seconds
        )
    )
    _require(target_met, "analysis wall time exceeded the configured release target")
    ocr_attestation_path = (
        config.output_dir / "ocr-prerequisite" / "acceptance-attestation.json"
    )
    _require(ocr_attestation_path.is_file(), "OCR prerequisite attestation is missing")
    try:
        ocr_attestation = json.loads(ocr_attestation_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError("OCR prerequisite attestation cannot be read") from exc
    ocr_baseline = _mapping(
        _mapping(ocr_attestation, "OCR prerequisite attestation").get("ocr_baseline"),
        "OCR prerequisite baseline binding",
    )
    _require(
        set(ocr_baseline)
        == {"package_directory", "manifest_filename", "manifest_sha256", "run_id"},
        "OCR prerequisite baseline binding fields are not exact",
    )
    _require(
        ocr_baseline.get("package_directory")
        == RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY
        and ocr_baseline.get("manifest_filename")
        == (
            f"{RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY}/"
            f"{RELEASE_INTEGRITY.OCR_BASELINE_MANIFEST_MEMBER}"
        )
        and SHA256_RE.fullmatch(
            str(ocr_baseline.get("manifest_sha256") or "").lower()
        )
        is not None
        and re.fullmatch(r"[0-9a-f]{16,64}", str(ocr_baseline.get("run_id") or ""))
        is not None,
        "OCR prerequisite baseline binding is invalid",
    )
    ocr_prerequisite = {
        "profile": "ocr-37",
        "attestation_filename": "ocr-prerequisite/acceptance-attestation.json",
        "attestation_sha256": _sha256_file(ocr_attestation_path),
        "result": "PASS",
        "acceptance_passed": True,
        "successful_pages": config.expected_pages,
        "source_sha256": facts.source["sha256"],
        "run_id": str(ocr_baseline["run_id"]),
        "baseline_manifest_sha256": str(
            ocr_baseline["manifest_sha256"]
        ).lower(),
        "runtime_identity": runtime,
        "selected_range": facts.selected_range,
    }
    visual_verification = {
        "passed": True,
        "expected_pages": config.expected_pages,
        "pages_checked": config.expected_pages,
        "independent_review_passes": len(facts.independent_final_reviews),
        "model_calls": sum(
            int(review["calls"]) for review in facts.independent_final_reviews
        ),
        "page_id_set_sha256": facts.visual_page_id_set_sha256,
        "candidate_tex_sha256": facts.compilation["candidate_tex_sha256"],
        "candidate_pdf_sha256": facts.compilation["candidate_pdf_sha256"],
        "render_compare_closed_loop": True,
    }
    audit_path = config.output_dir / AUDIT_ZIP_FILENAME
    _require(audit_path.is_file(), "verified audit submission ZIP is missing")
    audit_submission = {
        "filename": AUDIT_ZIP_FILENAME,
        "bytes": audit_path.stat().st_size,
        "sha256": _sha256_file(audit_path),
        "packaging_status": "SUCCESS",
        "audit_package_status": "VALID",
        "verification_status": "VERIFIED",
        "published_to_github": False,
    }
    performance = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_PERFORMANCE_SCHEMA,
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "source": facts.source,
        "selected_range": facts.selected_range,
        "models": facts.models,
        "compilation": facts.compilation,
        "timing": timing,
        "thresholds": {"maximum_wall_time_seconds": config.max_wall_seconds},
        "target_met": target_met,
    }
    validation = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_VALIDATION_SCHEMA,
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "source": facts.source,
        "execution": execution,
        "terminal_status": "VERIFIED",
        "independent_final_reviews": facts.independent_final_reviews,
        "machine_verification": machine,
    }

    with tempfile.TemporaryDirectory(
        prefix=".analysis-attestation-stage-", dir=config.output_dir
    ) as temporary:
        stage = Path(temporary)
        performance_path = stage / "analysis-performance.json"
        validation_path = stage / "analysis-validation-report.json"
        machine_path = stage / "analysis-machine-verification.json"
        artifacts: dict[str, dict[str, Any]] = {}
        for role, (filename, compilation_field) in (
            RELEASE_INTEGRITY.ANALYSIS_ARTIFACT_SPECS.items()
        ):
            payload = facts.artifact_payloads.get(role)
            _require(
                isinstance(payload, bytes) and bool(payload),
                f"verified audit bundle lacks actual {filename} bytes",
            )
            artifact_path = stage / filename
            _atomic_write(artifact_path, payload)
            digest = _sha256_file(artifact_path)
            _require(
                digest == str(facts.compilation.get(compilation_field) or "").lower(),
                f"actual {filename} differs from compilation evidence",
            )
            artifacts[role] = {
                "filename": filename,
                "bytes": artifact_path.stat().st_size,
                "sha256": digest,
            }
        _atomic_write(performance_path, _json_bytes(performance))
        _atomic_write(validation_path, _json_bytes(validation))
        _atomic_write(machine_path, machine_bytes)
        attestation = {
            "schema_version": RELEASE_INTEGRITY.ANALYSIS_ATTESTATION_SCHEMA,
            "profile_kind": "analysis",
            "profile": config.profile,
            "result": "PASS",
            "acceptance_passed": True,
            "terminal_status": "VERIFIED",
            "quality_tier": config.quality_tier,
            "template": config.template,
            "generated_at": evidence.ended_at,
            "execution": execution,
            "runtime_identity": runtime,
            "service_binding": service_binding,
            "source": facts.source,
            "selected_range": facts.selected_range,
            "models": facts.models,
            "compilation": facts.compilation,
            "artifacts": artifacts,
            "timing": timing,
            "ocr_prerequisite": ocr_prerequisite,
            "independent_final_reviews": facts.independent_final_reviews,
            "visual_verification": visual_verification,
            "page_layout": facts.page_layout,
            "machine_verification": machine,
            "audit_submission": audit_submission,
            "reports": {
                "performance": {
                    "filename": performance_path.name,
                    "sha256": _sha256_file(performance_path),
                },
                "validation": {
                    "filename": validation_path.name,
                    "sha256": _sha256_file(validation_path),
                },
                "verification": {
                    "filename": machine_path.name,
                    "sha256": _sha256_file(machine_path),
                },
            },
        }
        attestation_path = stage / "analysis-attestation.json"
        _atomic_write(attestation_path, _json_bytes(attestation))
        _atomic_write(stage / AUDIT_ZIP_FILENAME, audit_path.read_bytes())
        for name in (
            "acceptance-attestation.json",
            "performance.json",
            "validation-report.json",
        ):
            source_path = config.output_dir / "ocr-prerequisite" / name
            _require(source_path.is_file(), f"OCR prerequisite evidence is missing: {name}")
            _atomic_write(stage / "ocr-prerequisite" / name, source_path.read_bytes())
        _copy_plain_tree(
            config.output_dir
            / "ocr-prerequisite"
            / RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY,
            stage
            / "ocr-prerequisite"
            / RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY,
        )
        # This is the same strict verifier used by release assembly.  Only a
        # document it accepts is copied into the durable run directory.
        RELEASE_INTEGRITY.verify_analysis_attestation(
            stage,
            expected_pages=config.expected_pages,
            version=config.expected_version,
            commit=config.expected_commit.lower(),
        )
        for name in (
            "candidate.tex",
            "candidate.pdf",
            "compile.log",
            "analysis-performance.json",
            "analysis-validation-report.json",
            "analysis-machine-verification.json",
        ):
            _atomic_write(config.output_dir / name, (stage / name).read_bytes())
        # Publish the PASS attestation last so a partial copy is never releasable.
        _atomic_write(
            config.output_dir / "analysis-attestation.json",
            attestation_path.read_bytes(),
        )
    return validation


def _failure_documents(
    config: AnalysisAcceptanceConfig,
    evidence: AnalysisRunEvidence,
    *,
    source_pages: int | None,
    source_sha256: str,
) -> dict[str, Any]:
    runtime = _runtime_identity(config)
    execution = _execution(evidence.real_execution)
    selected = {
        "start_page": 1,
        "end_page": config.expected_pages,
        "expected_pages": config.expected_pages,
    }
    source = {
        "filename": config.source.name,
        "sha256": source_sha256,
        "total_pages": source_pages,
    }
    timing = _timing(evidence)
    result = "INCOMPLETE" if evidence.timed_out else "FAIL"
    zero_machine = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_MACHINE_VERIFICATION_SCHEMA,
        "result": result,
        "candidate_tex_sha256": "",
        "pages_checked": 0,
        "silent_omissions": 0,
        "text_loss": 0,
        "unauthorized_math_changes": 0,
        "unclosed_formal_environments": 0,
        "open_critical_issues": 0,
        "open_high_issues": 0,
        "regressions": 0,
        "errors": list(evidence.errors),
    }
    machine_path = config.output_dir / "analysis-machine-verification.json"
    _atomic_write(machine_path, _json_bytes(zero_machine))
    machine = {
        "passed": False,
        "candidate_tex_sha256": "",
        "pages_checked": 0,
        "silent_omissions": 0,
        "text_loss": 0,
        "unauthorized_math_changes": 0,
        "unclosed_formal_environments": 0,
        "open_critical_issues": 0,
        "open_high_issues": 0,
        "regressions": 0,
        "verification_json_sha256": _sha256_file(machine_path),
    }
    performance = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_PERFORMANCE_SCHEMA,
        "result": result,
        "acceptance_passed": False,
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "models": {"calls_total": 0, "roles": []},
        "compilation": {
            "status": "",
            "successful_passes": 0,
            "pass_exit_codes": [],
            "compile_log_sha256": "",
            "candidate_tex_sha256": "",
            "candidate_pdf_sha256": "",
        },
        "timing": timing,
        "thresholds": {"maximum_wall_time_seconds": config.max_wall_seconds},
        "target_met": False,
        "errors": list(evidence.errors),
    }
    validation = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_VALIDATION_SCHEMA,
        "result": result,
        "acceptance_passed": False,
        "runtime_identity": runtime,
        "source": source,
        "execution": execution,
        "terminal_status": "UNVERIFIED",
        "independent_final_reviews": [],
        "machine_verification": machine,
        "errors": list(evidence.errors),
    }
    performance_path = config.output_dir / "analysis-performance.json"
    validation_path = config.output_dir / "analysis-validation-report.json"
    _atomic_write(performance_path, _json_bytes(performance))
    _atomic_write(validation_path, _json_bytes(validation))
    attestation = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_ATTESTATION_SCHEMA,
        "profile_kind": "analysis",
        "profile": config.profile,
        "result": result,
        "acceptance_passed": False,
        "terminal_status": "UNVERIFIED",
        "generated_at": evidence.ended_at,
        "execution": execution,
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "models": performance["models"],
        "compilation": performance["compilation"],
        "timing": timing,
        "independent_final_reviews": [],
        "machine_verification": machine,
        "reports": {
            "performance": {
                "filename": performance_path.name,
                "sha256": _sha256_file(performance_path),
            },
            "validation": {
                "filename": validation_path.name,
                "sha256": _sha256_file(validation_path),
            },
            "verification": {
                "filename": machine_path.name,
                "sha256": _sha256_file(machine_path),
            },
        },
    }
    _atomic_write(config.output_dir / "analysis-attestation.json", _json_bytes(attestation))
    diagnostics = {
        "schema_version": "latexstruct-v2-analysis-acceptance-diagnostics/1",
        "profile": config.profile,
        "result": result,
        "acceptance_passed": False,
        "evidence": asdict(evidence),
    }
    _atomic_write(config.output_dir / "analysis-diagnostics.json", _json_bytes(diagnostics))
    return validation


def run_analysis_acceptance(
    config: AnalysisAcceptanceConfig,
    *,
    api: LocalHttpApi | None = None,
    ui_driver: PlaywrightUiDriver | None = None,
    pdf_page_counter: Callable[[Path], int] = count_pdf_pages,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    utc_now: Callable[[], str] = _utc_now,
) -> dict[str, Any]:
    if config.output_dir.exists() and any(config.output_dir.iterdir()):
        raise AcceptanceError("analysis acceptance output directory must be empty")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    evidence = AnalysisRunEvidence(overall_started_at=utc_now())
    source_pages: int | None = None
    source_sha256 = ""
    measurement_start: float | None = None
    api = api or LocalHttpApi(config.base_url)
    ui_driver = ui_driver or PlaywrightUiDriver()
    evidence.real_execution = type(api) is LocalHttpApi and type(ui_driver) is PlaywrightUiDriver
    try:
        _validate_config(config)
        _require(evidence.real_execution, "release PASS requires the real LocalHttpApi and PlaywrightUiDriver")
        source_pages = pdf_page_counter(config.source)
        _require(
            source_pages == config.expected_pages,
            "analysis-37 requires the exact 37-page source PDF",
        )
        source_sha256 = _sha256_file(config.source)
        _require(
            source_sha256 == RELEASE_INTEGRITY.RAMSEY_37_SOURCE_SHA256,
            "analysis-37 source PDF SHA-256 mismatch",
        )
        evidence.health = api.get_json("/api/health")
        _validate_health(config, evidence.health)

        measurement_start = monotonic()
        evidence.measurement_started_at = utc_now()
        ocr_output = config.output_dir / "ocr-prerequisite"
        ocr_config = OcrAcceptanceConfig(
            base_url=config.base_url,
            pdf=config.source,
            start_page=1,
            end_page=config.expected_pages,
            output_dir=ocr_output,
            expected_version=config.expected_version,
            expected_commit=config.expected_commit,
            expected_build_id=config.expected_build_id,
            executable=config.executable,
            quality_tier=config.quality_tier,
            poll_seconds=config.poll_seconds,
            timeout_seconds=config.timeout_seconds,
            browser_timeout_seconds=config.browser_timeout_seconds,
            headed=config.headed,
            min_successful_ppm=None,
            max_wall_seconds=None,
            max_consecutive_poll_errors=config.max_consecutive_poll_errors,
        )
        evidence.ocr_validation = run_ocr_acceptance(
            ocr_config,
            api=api,
            ui_driver=ui_driver,
            pdf_page_counter=lambda _path: source_pages,
            monotonic=monotonic,
            sleep=sleep,
            utc_now=utc_now,
        )
        _require(evidence.ocr_validation.get("acceptance_passed") is True, "real OCR prerequisite did not pass")
        RELEASE_INTEGRITY.verify_run_attestation(
            ocr_output,
            expected_pages=config.expected_pages,
            version=config.expected_version,
            commit=config.expected_commit.lower(),
        )
        job_id = str(evidence.ocr_validation.get("job_id") or "")
        _require(re.fullmatch(r"[0-9a-f]{32}", job_id) is not None, "OCR prerequisite did not retain a valid job id")

        query = urlencode({
            "name": f"v2 release acceptance {config.profile}",
            "mode": "ai",
            "template": config.template,
            "title": f"v2 release acceptance {config.profile}",
        })
        evidence.import_response = api.post_json(
            f"/api/ocr/jobs/{job_id}/import?{query}"
        )
        evidence.project_id = str(evidence.import_response.get("id") or "")
        _require(re.fullmatch(r"[0-9a-f]{32}", evidence.project_id) is not None, "OCR import returned an invalid project id")
        process = _mapping(evidence.import_response.get("process"), "OCR import process task")
        evidence.process_job_id = str(process.get("id") or "")
        _require(re.fullmatch(r"[0-9a-f]{12}", evidence.process_job_id) is not None, "OCR import did not start a valid analysis task")
        evidence.process_terminal = _poll_process(
            api,
            config,
            evidence,
            monotonic=monotonic,
            sleep=sleep,
            started=measurement_start,
        )
        _atomic_json(config.output_dir / "process-terminal.json", evidence.process_terminal)
        backend = _validate_process_terminal(
            evidence.process_terminal,
            expected_job_id=evidence.process_job_id,
        )

        evidence.audit_latest = api.get_json(
            f"/api/projects/{evidence.project_id}/audit-submission/latest"
        )
        _require(evidence.audit_latest.get("available") is True, "terminal audit snapshot is unavailable")
        _require(evidence.audit_latest.get("can_generate") is True, "terminal audit snapshot cannot be packaged")
        latest = _mapping(evidence.audit_latest.get("latest"), "latest audit snapshot")
        _require(latest.get("workflow") == "OCR_ANALYSIS_REVIEW", "latest audit snapshot is not the combined workflow")
        _require(latest.get("terminal_status") == "SUCCESS", "latest audit snapshot did not succeed")
        _require(latest.get("verification_status") == "VERIFIED", "latest audit snapshot is not VERIFIED")
        _require(latest.get("stale") is False, "latest audit snapshot is stale")
        snapshot_id = str(latest.get("snapshot_id") or "")
        _require(bool(snapshot_id), "latest audit snapshot id is missing")
        created = api.post_json(
            f"/api/projects/{evidence.project_id}/audit-submission",
            {
                "snapshot_id": snapshot_id,
                "profile": "standard",
                "depth": "standard",
                "audit_focus": "v2 release acceptance evidence",
                "include_source_files": True,
                "include_compile_logs": True,
                "include_verification_records": True,
                "include_page_images": False,
                "include_formula_crops": False,
                "sanitize_sensitive": True,
            },
        )
        _require(created.get("ok") is True, "audit submission endpoint did not succeed")
        evidence.audit_submission = _mapping(created.get("submission"), "audit submission response")
        submission = evidence.audit_submission
        _require(submission.get("state") == "READY", "audit ZIP was not committed")
        _require(submission.get("packaging_status") == "SUCCESS", "audit ZIP packaging did not succeed")
        _require(submission.get("audit_package_status") == "VALID", "audit ZIP is not VALID")
        _require(submission.get("workflow") == "OCR_ANALYSIS_REVIEW", "audit ZIP workflow mismatch")
        _require(submission.get("terminal_status") == "SUCCESS", "audit ZIP source run status mismatch")
        _require(submission.get("verification_status") == "VERIFIED", "audit ZIP verification status mismatch")
        _require(submission.get("snapshot_id") == snapshot_id, "audit ZIP snapshot id changed")
        _require(submission.get("stale") is False and submission.get("is_latest") is True, "audit ZIP became stale or historical")
        download_url = str(submission.get("download_url") or "")
        _require(download_url.startswith("/api/projects/"), "audit ZIP download URL is missing")
        download = api.download(download_url)
        _require(str(download.headers.get("x-latexstruct-stale") or "").lower() == "false", "downloaded audit ZIP is stale")
        evidence.audit_zip_sha256 = _sha256_bytes(download.body)
        _require(evidence.audit_zip_sha256 == str(submission.get("zip_sha256") or ""), "downloaded audit ZIP hash mismatch")
        _atomic_write(config.output_dir / AUDIT_ZIP_FILENAME, download.body)
        members, manifest = _read_audit_zip(download.body)
        facts = _verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=source_pages,
            source_sha256=source_sha256,
            backend=backend,
            expected_project_id=evidence.project_id,
            expected_run_id=evidence.process_job_id,
        )
        evidence.wall_time_seconds = round(max(0.0, monotonic() - measurement_start), 3)
        evidence.ended_at = utc_now()
        validation = _publish_pass(config, evidence, facts)
        _atomic_json(
            config.output_dir / "analysis-diagnostics.json",
            {
                "schema_version": "latexstruct-v2-analysis-acceptance-diagnostics/1",
                "profile": config.profile,
                "result": "PASS",
                "acceptance_passed": True,
                "audit_manifest": facts.manifest,
                "evidence": asdict(evidence),
            },
        )
        return validation
    except Exception as exc:  # noqa: BLE001 - release boundary must fail closed.
        if "timed out" in str(exc).lower():
            evidence.timed_out = True
        evidence.errors.append(_safe_error(exc, config))
        if measurement_start is not None:
            evidence.wall_time_seconds = round(max(0.0, monotonic() - measurement_start), 3)
        evidence.ended_at = utc_now()
        return _failure_documents(
            config,
            evidence,
            source_pages=source_pages,
            source_sha256=source_sha256,
        )


def _default_output(source: Path, profile: str) -> Path:
    safe_stem = re.sub(r"[^0-9A-Za-z._-]+", "-", source.stem).strip("-.") or "pdf"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("output") / "playwright" / "v2-analysis-acceptance" / (
        f"{safe_stem[:48]}-{profile}-{stamp}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="source PDF uploaded through the real OCR UI")
    parser.add_argument("--profile", choices=tuple(ANALYSIS_PROFILES), required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-version", default="2.0.0")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument(
        "--service-pid",
        type=int,
        required=True,
        help="PID of the loopback service process running the supplied LaTeXStruct.exe",
    )
    parser.add_argument(
        "--exe-sha256",
        "--expected-executable-sha256",
        dest="expected_executable_sha256",
        required=True,
        help="SHA-256 of the exact LaTeXStruct.exe used by the local service",
    )
    parser.add_argument(
        "--quality-tier", choices=("fast", "recommended", "high"), default="high"
    )
    parser.add_argument("--template", default="faithfulbook")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--browser-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--max-wall-seconds", type=float)
    parser.add_argument("--headed", action="store_true")
    return parser


def _config_from_args(args: argparse.Namespace) -> AnalysisAcceptanceConfig:
    output = args.output or _default_output(args.source, args.profile)
    return AnalysisAcceptanceConfig(
        base_url=args.base_url,
        source=args.source.resolve(),
        profile=args.profile,
        output_dir=output.resolve(),
        expected_version=args.expected_version,
        expected_commit=args.expected_commit,
        expected_build_id=args.expected_build_id,
        executable=args.executable.resolve(),
        expected_executable_sha256=args.expected_executable_sha256,
        service_pid=args.service_pid,
        quality_tier=args.quality_tier,
        template=args.template,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
        browser_timeout_seconds=args.browser_timeout_seconds,
        headed=args.headed,
        max_wall_seconds=args.max_wall_seconds,
    )


def main(argv: list[str] | None = None) -> int:
    config = _config_from_args(build_parser().parse_args(argv))
    try:
        validation = run_analysis_acceptance(config)
    except (AcceptanceError, OSError, ValueError) as exc:
        print(f"v2 analysis acceptance could not start: {exc}", file=sys.stderr)
        return 2
    result = str(validation.get("result") or "FAIL")
    print(f"v2 analysis acceptance ({config.profile}): {result}")
    print(f"validation: {config.output_dir / 'analysis-validation-report.json'}")
    print(f"performance: {config.output_dir / 'analysis-performance.json'}")
    print(f"attestation: {config.output_dir / 'analysis-attestation.json'}")
    for error in validation.get("errors") or ():
        print(f"error: {error}", file=sys.stderr)
    return 0 if validation.get("acceptance_passed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())

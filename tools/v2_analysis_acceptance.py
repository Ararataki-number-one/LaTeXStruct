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
import math
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
from latexstruct.pricing import estimate_call_cost


ANALYSIS_PROFILES = {"analysis-37": 37}
DEFAULT_TIMEOUT_SECONDS = 4 * 3600.0
# The fixed source may gain a generated TOC and bounded reflow, but the known
# 37 -> 49 failure must remain impossible to attest.  The symmetric 32..42
# interval allows at most five pages of honest reflow in either direction;
# it is deliberately a fixed-document gate, not a general quality claim.
PROCESS_TERMINAL_STATUSES = frozenset({"done", "blocked", "error", "cancelled"})
PROCESS_ACTIVE_STATUSES = frozenset(
    {"running", "pausing", "paused", "cancelling", "committing"}
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMPILE_WORKDIR_RE = re.compile(r"compile-workdir:sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
BUILD_ID_RE = re.compile(r"[1-9][0-9]*")
PRODUCER = "tools/v2_analysis_acceptance.py"
AUDIT_ZIP_FILENAME = "analysis-audit-submission.zip"
PAGE_RISK_ADMISSION_SCHEMA = "latexstruct-analysis-page-risk-admission-v2"
PAGE_RISK_ADMISSION_STRATEGY = (
    "deterministic-preflight-and-fixed-low-risk-sampling-v2"
)
OCR_COVERAGE_CHECK_NAMES = (
    "source_hash_bound",
    "candidate_created",
    "visual_authority_checked",
    "reading_order_checked",
    "text_coverage_checked",
    "math_region_coverage_checked",
    "syntax_checked",
    "persisted",
)
DISCOVERY_ROLE_OPERATIONS = {
    "AI-1": "structure-findings",
    "AI-2": "content-math-findings",
    "AI-3": "visual-findings",
}


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
MIN_ANALYSIS_37_CANDIDATE_PAGES = (
    RELEASE_INTEGRITY.MIN_ANALYSIS_37_CANDIDATE_PAGES
)
MAX_ANALYSIS_37_CANDIDATE_PAGES = (
    RELEASE_INTEGRITY.MAX_ANALYSIS_37_CANDIDATE_PAGES
)


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
    expected_model_id: str = RELEASE_INTEGRITY.ANALYSIS_STABLE_MODEL_ID
    expected_reasoning_effort: str = (
        RELEASE_INTEGRITY.ANALYSIS_STABLE_REASONING_EFFORT
    )
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
    runtime_model_configuration: dict[str, Any] = field(default_factory=dict)
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
    snapshot_binding: dict[str, Any]
    page_risk_admission: dict[str, Any]
    independent_final_reviews: list[dict[str, Any]]
    visual_page_id_set_sha256: str
    closed_loop_evidence: dict[str, Any]
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


def _verified_compile_input_hash(
    raw_manifest: object,
    *,
    candidate_tex: bytes,
) -> str:
    manifest = _mapping(raw_manifest, "final compile input manifest")
    _require(
        set(manifest) == {"schema", "file_count", "files", "manifest_sha256"}
        and manifest.get("schema") == "latexstruct-compile-input-set-v1",
        "final compile input manifest schema is invalid",
    )
    rows = [
        _mapping(item, "final compile input row")
        for item in _sequence(manifest.get("files"), "final compile input rows")
    ]
    _require(
        _positive_int(manifest.get("file_count")) == len(rows)
        and len(rows) > 0,
        "final compile input manifest count is invalid",
    )
    paths: list[str] = []
    for row in rows:
        _require(
            set(row) == {"path", "bytes", "sha256"}
            and isinstance(row.get("path"), str)
            and SHA256_RE.fullmatch(str(row.get("sha256") or "")) is not None
            and type(row.get("bytes")) is int
            and int(row["bytes"]) >= 0,
            "final compile input row is invalid",
        )
        paths.append(str(row["path"]))
    _require(paths == sorted(set(paths)), "final compile input paths are not canonical")
    main_rows = [row for row in rows if row["path"] == "main.tex"]
    _require(
        len(main_rows) == 1
        and main_rows[0]["bytes"] == len(candidate_tex)
        and main_rows[0]["sha256"] == _sha256_bytes(candidate_tex),
        "final compile input manifest does not bind candidate TeX bytes",
    )
    body = {
        "schema": manifest["schema"],
        "file_count": manifest["file_count"],
        "files": rows,
    }
    digest = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    _require(
        manifest.get("manifest_sha256") == digest,
        "final compile input manifest hash is not recomputable",
    )
    return digest


def _require_atomic_compile_invocation(
    row: Mapping[str, Any],
    *,
    candidate_hash: str,
    pdf_hash: str,
    compile_input_hash: str,
    label: str,
) -> None:
    _require(
        row.get("candidate_hash") == candidate_hash
        and row.get("pdf_hash") == pdf_hash
        and row.get("ok") is True
        and row.get("same_workdir_verified") is True
        and _positive_int(row.get("passes_requested")) >= 2
        and _positive_int(row.get("passes_attempted")) >= 2
        and _positive_int(row.get("passes_completed")) >= 2
        and COMPILE_WORKDIR_RE.fullmatch(
            str(row.get("compile_workdir") or "")
        )
        is not None
        and row.get("compile_input_sha256") == compile_input_hash,
        f"{label} lacks an atomic same-workdir two-pass compile proof",
    )


def _fresh_import_identity(response: object) -> tuple[str, str]:
    payload = _mapping(response, "OCR import response")
    _require(
        payload.get("reused", False) is False,
        "OCR import unexpectedly reused a project",
    )
    _require(
        payload.get("processed") is False,
        "OCR import did not create an unprocessed project",
    )
    project_id = payload.get("id")
    _require(
        isinstance(project_id, str)
        and re.fullmatch(r"[0-9a-f]{12}", project_id) is not None,
        "OCR import returned an invalid project id",
    )
    process = _mapping(payload.get("process"), "OCR import process task")
    process_job_id = process.get("id")
    _require(
        isinstance(process_job_id, str)
        and re.fullmatch(r"[0-9a-f]{12}", process_job_id) is not None,
        "OCR import did not start a valid analysis task",
    )
    _require(
        process.get("pid") == project_id,
        "OCR import analysis task belongs to a different project",
    )
    return project_id, process_job_id


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
    _require(
        config.expected_model_id
        in RELEASE_INTEGRITY.ANALYSIS_RELEASE_ALLOWED_MODEL_IDS
        and config.expected_reasoning_effort
        in RELEASE_INTEGRITY.ANALYSIS_RELEASE_ALLOWED_REASONING_EFFORTS,
        "analysis-37 declared model/effort is not allowed for release",
    )
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


def _verified_runtime_model_configuration(
    config: AnalysisAcceptanceConfig,
    value: object,
) -> dict[str, Any]:
    raw = _mapping(value, "candidate runtime configuration")
    projected = {
        name: str(raw.get(name) or "").strip()
        for name in (
            "analysis_backend",
            "codex_model",
            "codex_reasoning_effort",
            "codex_triage_model",
            "codex_triage_reasoning_effort",
        )
    }
    _require(
        projected
        == {
            "analysis_backend": "codex_cli",
            "codex_model": config.expected_model_id,
            "codex_reasoning_effort": config.expected_reasoning_effort,
            "codex_triage_model": config.expected_model_id,
            "codex_triage_reasoning_effort": config.expected_reasoning_effort,
        },
        "candidate runtime model configuration differs from the declared release policy",
    )
    return projected


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
    return RELEASE_INTEGRITY.review_context_sha256(
        pass_number=review.get("pass_number"),
        context_id=str(review.get("context_id") or ""),
        candidate_tex_sha256=str(review.get("candidate_hash") or ""),
        checked_page_ids=review.get("checked_page_ids") or (),
    )


def _verified_snapshot_binding(
    snapshot: Mapping[str, Any],
    transport: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Recompute the production snapshot and bind every model invocation to it."""

    snapshot_fields = {
        "run_id",
        "project_id",
        "workflow_version",
        "prompt_version",
        "application_version",
        "source_pdf_hash",
        "raw_ocr_tex_hash",
        "baseline_tex_hash",
        "baseline_pdf_hash",
        "page_count",
        "page_range",
        "latex_engine",
        "models",
        "concurrency_limit",
        "started_at",
        "performance_target_seconds",
        "max_input_tokens",
        "max_output_tokens",
        "max_cost",
        "max_requests",
        "max_strong_model_calls",
        "max_wall_time_minutes",
        "transport_contracts",
        "page_map",
        "initial_compile_state",
        "initial_issue_counts",
        "config_hash",
        "evidence_hashes",
        "snapshot_hash",
    }
    _require(
        set(snapshot) == snapshot_fields,
        "production analysis snapshot fields are incomplete or unsupported",
    )
    evidence_hashes = _mapping(
        snapshot.get("evidence_hashes"), "production snapshot evidence hashes"
    )
    _require(
        set(evidence_hashes) == set(RELEASE_INTEGRITY.ANALYSIS_EVIDENCE_HASH_FIELDS)
        and all(
            SHA256_RE.fullmatch(str(value or "").lower()) is not None
            for value in evidence_hashes.values()
        ),
        "production snapshot evidence_hashes closure is incomplete",
    )
    config_hash = str(snapshot.get("config_hash") or "").lower()
    _require(
        SHA256_RE.fullmatch(config_hash) is not None
        and config_hash == str(evidence_hashes.get("analysis_config_hash") or "").lower(),
        "production snapshot config hash is not bound to evidence_hashes",
    )
    canonical_snapshot = {
        key: value for key, value in snapshot.items() if key != "snapshot_hash"
    }
    snapshot_hash = RELEASE_INTEGRITY._canonical_json_sha256(canonical_snapshot)
    _require(
        str(snapshot.get("snapshot_hash") or "").lower() == snapshot_hash,
        "production analysis snapshot_hash digest mismatch",
    )
    try:
        from latexstruct.core.analysis_production import analysis_response_schema_hash
        from latexstruct.core.analysis_schema import ANALYSIS_RESPONSE_SCHEMA_VERSIONS
    except (ImportError, AttributeError) as exc:
        raise AcceptanceError(
            "cannot load the authoritative analysis response-schema closure"
        ) from exc
    response_schema_hash = analysis_response_schema_hash()
    _require(
        str(evidence_hashes.get("response_schema_hash") or "").lower()
        == response_schema_hash,
        "production snapshot response-schema digest differs from this candidate commit",
    )
    prompt_version = str(snapshot.get("prompt_version") or "").strip()
    _require(bool(prompt_version), "production snapshot prompt version is missing")
    model_bindings = [
        dict(_mapping(item, "production snapshot model binding"))
        for item in _sequence(snapshot.get("models"), "production snapshot models")
    ]
    try:
        transport_contracts = (
            RELEASE_INTEGRITY._validated_analysis_transport_contracts(
                snapshot.get("transport_contracts"),
                model_bindings=model_bindings,
                require_stable_policy=True,
            )
        )
    except RELEASE_INTEGRITY.ReleaseIntegrityError as exc:
        raise AcceptanceError(str(exc)) from exc
    _require(bool(transport), "production analysis has no transport invocations")
    for index, invocation in enumerate(transport, 1):
        operation = str(invocation.get("operation") or "")
        expected_response_version = ANALYSIS_RESPONSE_SCHEMA_VERSIONS.get(operation)
        _require(
            str(invocation.get("snapshot_hash") or "").lower() == snapshot_hash,
            f"transport invocation {index} snapshot_hash differs from the authoritative snapshot",
        )
        _require(
            str(invocation.get("prompt_version") or "") == prompt_version,
            f"transport invocation {index} prompt_version differs from the authoritative snapshot",
        )
        _require(
            bool(expected_response_version)
            and invocation.get("response_schema_version") == expected_response_version,
            f"transport invocation {index} response_schema_version is not authoritative",
        )
    return {
        "snapshot_hash": snapshot_hash,
        "prompt_version": prompt_version,
        "response_schema_hash": response_schema_hash,
        "evidence_hashes": dict(evidence_hashes),
        "model_bindings": model_bindings,
        "model_bindings_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            model_bindings
        ),
        "transport_contracts_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            transport_contracts
        ),
        "transport_invocation_count": len(transport),
    }


def _pair_mapping(value: object, label: str) -> dict[str, Any]:
    """Decode one JSON object or dataclass tuple-of-pairs without key loss."""

    if isinstance(value, Mapping):
        pairs = list(value.items())
    elif isinstance(value, list):
        pairs = []
        for item in value:
            _require(
                isinstance(item, list) and len(item) == 2,
                f"{label} is not a JSON object or pair ledger",
            )
            pairs.append((item[0], item[1]))
    else:
        raise AcceptanceError(f"{label} is not a JSON object or pair ledger")
    output: dict[str, Any] = {}
    for key, item in pairs:
        _require(
            isinstance(key, str) and bool(key) and key not in output,
            f"{label} contains an invalid or duplicated key",
        )
        output[key] = item
    return output


def _usage_token_value(
    usage: Mapping[str, Any], *names: str
) -> tuple[int | None, bool]:
    values = [usage[name] for name in names if name in usage]
    if not values:
        return None, False
    _require(
        all(type(value) is int and value >= 0 for value in values)
        and len(set(values)) == 1,
        f"transport usage aliases {names!r} are invalid or contradictory",
    )
    return int(values[0]), True


def _strict_usage_tokens(value: object, label: str) -> tuple[dict[str, Any], dict[str, int]]:
    usage = _pair_mapping(value, label)
    input_tokens, input_present = _usage_token_value(
        usage, "input_tokens", "prompt_tokens"
    )
    output_tokens, output_present = _usage_token_value(
        usage, "output_tokens", "completion_tokens"
    )
    cached_tokens, cached_present = _usage_token_value(
        usage, "cached_input_tokens", "cached_tokens"
    )
    details = usage.get("prompt_tokens_details")
    if details is not None:
        _require(isinstance(details, Mapping), f"{label} prompt token details are invalid")
        if "cached_tokens" in details:
            nested_cached, nested_present = _usage_token_value(
                details, "cached_tokens"
            )
            if nested_present:
                _require(
                    not cached_present or cached_tokens == nested_cached,
                    f"{label} cached-token claims are contradictory",
                )
                cached_tokens = nested_cached
                cached_present = True
    total_tokens, total_present = _usage_token_value(usage, "total_tokens")
    _require(
        input_present
        and output_present
        and input_tokens is not None
        and output_tokens is not None,
        f"{label} lacks provider input/output token evidence",
    )
    if not cached_present:
        cached_tokens = 0
    _require(
        cached_tokens is not None and cached_tokens <= input_tokens,
        f"{label} cached tokens exceed input tokens",
    )
    derived_total = input_tokens + output_tokens
    _require(
        not total_present or total_tokens == derived_total,
        f"{label} total_tokens is not input_tokens + output_tokens",
    )
    return usage, {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_tokens": cached_tokens,
        "total_tokens": derived_total,
    }


def _verified_invocation_transport_closure(
    *,
    analysis_v2: Mapping[str, Any],
    transport: list[Mapping[str, Any]],
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Independently close identities, attempts, and usage for every call."""

    try:
        from latexstruct.core.analysis_schema import ANALYSIS_RESPONSE_SCHEMA_VERSIONS
    except (ImportError, AttributeError) as exc:
        raise AcceptanceError(
            "cannot load the authoritative analysis response-schema closure"
        ) from exc

    expected_material_keys = {
        "source_pdf_page_hash",
        "baseline_tex_region_hash",
        "current_tex_region_hash",
        "current_pdf_page_hash",
    }
    transport_fields = {
        "role",
        "operation",
        "candidate_hash",
        "source_page_id",
        "issue_id",
        "material_hashes",
        "snapshot_hash",
        "prompt_version",
        "response_schema_version",
        "budget_claim",
        "budget_actual_usage",
        "usage",
        "attempts",
        "attempt_evidence_complete",
    }
    claim_fields = {
        "input_tokens",
        "output_tokens",
        "cost",
        "requests",
        "strong_model_calls",
    }
    actual_fields = {"input_tokens", "output_tokens", "cost"}
    limit_fields = {
        "max_input_tokens",
        "max_output_tokens",
        "max_cost",
        "max_requests",
        "max_strong_model_calls",
        "max_wall_time_minutes",
    }

    def finite_nonnegative_number(value: object, label: str) -> float:
        _require(
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
            and float(value) >= 0,
            f"{label} is not a finite non-negative number",
        )
        return float(value)

    def number_equal(left: object, right: object) -> bool:
        if left is None or right is None:
            return left is right
        if isinstance(left, bool) or isinstance(right, bool):
            return False
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            return False
        return math.isclose(
            float(left), float(right), rel_tol=1e-12, abs_tol=1e-12
        )

    limits: dict[str, int | float] = {}
    for name in limit_fields:
        raw_limit = snapshot.get(name)
        if name in {
            "max_input_tokens",
            "max_output_tokens",
            "max_requests",
            "max_strong_model_calls",
        }:
            _require(
                type(raw_limit) is int and raw_limit >= 0,
                f"production snapshot {name} is invalid",
            )
            limits[name] = raw_limit
        else:
            limit = finite_nonnegative_number(
                raw_limit, f"production snapshot {name}"
            )
            _require(
                name != "max_wall_time_minutes" or limit > 0,
                "production snapshot max_wall_time_minutes must be positive",
            )
            limits[name] = limit

    model_ids: dict[str, str] = {}
    model_bindings: list[dict[str, Any]] = []
    for raw_model in _sequence(snapshot.get("models"), "production snapshot models"):
        model = _mapping(raw_model, "production snapshot model")
        model_bindings.append(dict(model))
        role = str(model.get("role") or "")
        model_id = str(model.get("model_id") or "").strip()
        _require(
            re.fullmatch(r"AI-[1-6]", role) is not None
            and bool(model_id)
            and role not in model_ids,
            "production snapshot model binding is invalid or duplicated",
        )
        model_ids[role] = model_id
    try:
        transport_contracts = (
            RELEASE_INTEGRITY._validated_analysis_transport_contracts(
                snapshot.get("transport_contracts"),
                model_bindings=model_bindings,
                require_stable_policy=True,
            )
        )
    except RELEASE_INTEGRITY.ReleaseIntegrityError as exc:
        raise AcceptanceError(str(exc)) from exc
    contract_by_role = {str(item["role"]): item for item in transport_contracts}

    for index, item in enumerate(transport, 1):
        _require(
            set(item) == transport_fields,
            f"transport invocation {index} fields are incomplete or unsupported",
        )

    def material_pairs(value: object, label: str) -> tuple[tuple[str, str], ...]:
        if isinstance(value, Mapping):
            pairs = tuple(sorted((str(key), str(item).lower()) for key, item in value.items()))
        elif isinstance(value, list):
            normalized: list[tuple[str, str]] = []
            for item in value:
                _require(
                    isinstance(item, list) and len(item) == 2,
                    f"{label} material_hashes is malformed",
                )
                normalized.append((str(item[0]), str(item[1]).lower()))
            pairs = tuple(sorted(normalized))
        else:
            raise AcceptanceError(f"{label} material_hashes is malformed")
        _require(
            {key for key, _digest in pairs} == expected_material_keys
            and len(pairs) == len(expected_material_keys)
            and all(SHA256_RE.fullmatch(digest) is not None for _key, digest in pairs),
            f"{label} material_hashes closure is incomplete",
        )
        return pairs

    def identity(
        operation: object, value: Mapping[str, Any], label: str
    ) -> tuple[object, ...]:
        fields = tuple(
            value.get(name)
            for name in (
                "role",
                "candidate_hash",
                "source_page_id",
                "issue_id",
                "snapshot_hash",
                "prompt_version",
                "response_schema_version",
            )
        )
        _require(
            isinstance(operation, str)
            and bool(operation)
            and all(isinstance(item, str) and bool(item) for item in fields),
            f"{label} identity is malformed",
        )
        return (
            operation,
            *fields[:4],
            material_pairs(value.get("material_hashes"), label),
            *fields[4:],
        )

    invocations = [
        _mapping(item, "v2 orchestration invocation")
        for item in _sequence(
            analysis_v2.get("invocations"), "v2 orchestration invocations"
        )
    ]
    _require(bool(invocations), "production orchestration invocation evidence is empty")
    _require(
        [item.get("ordinal") for item in invocations]
        == list(range(1, len(invocations) + 1)),
        "production orchestration invocation ordinals are incomplete",
    )
    _require(
        all(item.get("succeeded") is True for item in invocations),
        "production orchestration contains an unsuccessful invocation",
    )
    snapshot_hash = str(snapshot.get("snapshot_hash") or "")
    prompt_version = str(snapshot.get("prompt_version") or "")
    run_id = str(snapshot.get("run_id") or "")
    invocation_identities: list[tuple[object, ...]] = []
    for index, item in enumerate(invocations, 1):
        operation = item.get("operation")
        binding = _mapping(item.get("binding"), f"orchestration invocation {index} binding")
        expected_schema = ANALYSIS_RESPONSE_SCHEMA_VERSIONS.get(str(operation))
        _require(
            binding.get("run_id") == run_id
            and binding.get("snapshot_hash") == snapshot_hash
            and binding.get("prompt_version") == prompt_version
            and bool(expected_schema)
            and binding.get("response_schema_version") == expected_schema,
            f"orchestration invocation {index} is not bound to the authoritative snapshot",
        )
        invocation_identities.append(
            identity(operation, binding, f"orchestration invocation {index}")
        )
    transport_identities = [
        identity(item.get("operation"), item, f"transport invocation {index}")
        for index, item in enumerate(transport, 1)
    ]
    _require(
        Counter(invocation_identities) == Counter(transport_identities),
        "production transport evidence does not close over orchestration invocations",
    )
    cache_hits = analysis_v2.get("cache_hit_evidence")
    _require(
        isinstance(cache_hits, list) and not cache_hits,
        "release acceptance requires a real transport call for every orchestration invocation",
    )

    token_totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "total_tokens": 0,
    }
    budget_totals: dict[str, int | float] = {
        "observed_input_tokens": 0,
        "observed_output_tokens": 0,
        "observed_cost": 0.0,
        "accounted_input_tokens": 0,
        "accounted_output_tokens": 0,
        "accounted_cost": 0.0,
        "requests": 0,
        "strong_model_calls": 0,
        "unknown_input_token_requests": 0,
        "unknown_output_token_requests": 0,
        "unknown_cost_requests": 0,
        "committed_reservations": 0,
    }
    unbounded_unknown_dimensions: set[str] = set()
    attempt_count = 0
    sanitized_budget_ledger: list[dict[str, Any]] = []
    allowed_failure_stages = {
        "http_error",
        "invalid_json",
        "invalid_response_envelope",
        "missing_turn_evidence",
        "network_error",
        "runtime_failure_without_turn_evidence",
        "timeout",
        "turn_failed",
    }
    for invocation_index, item in enumerate(transport, 1):
        role = str(item.get("role") or "")
        _require(
            role in model_ids,
            f"transport invocation {invocation_index} has no frozen model binding",
        )
        contract = contract_by_role.get(role)
        _require(
            contract is not None
            and item.get("operation") in contract["operations"],
            f"transport invocation {invocation_index} is outside its frozen role/operation contract",
        )
        claim = _mapping(
            item.get("budget_claim"),
            f"transport invocation {invocation_index} budget claim",
        )
        actual = _mapping(
            item.get("budget_actual_usage"),
            f"transport invocation {invocation_index} budget actual usage",
        )
        _require(
            set(claim) == claim_fields and set(actual) == actual_fields,
            f"transport invocation {invocation_index} budget fields are incomplete or unsupported",
        )
        for name in ("input_tokens", "output_tokens", "requests", "strong_model_calls"):
            _require(
                type(claim.get(name)) is int and claim[name] >= 0,
                f"transport invocation {invocation_index} claim {name} is invalid",
            )
        claim_cost = finite_nonnegative_number(
            claim.get("cost"),
            f"transport invocation {invocation_index} claim cost",
        )
        request_bound = int(contract["max_retries"]) + 1
        expected_claim_cost = 0.0
        if float(limits["max_cost"]) > 0:
            per_attempt_input = int(claim["input_tokens"]) // request_bound
            estimate = (
                estimate_call_cost(
                    model_ids[role],
                    {
                        "input_tokens": per_attempt_input,
                        "output_tokens": int(contract["max_tokens"]),
                    },
                )
                if int(contract["max_tokens"]) > 0
                else None
            )
            expected_claim_cost = (
                float(estimate["cny"]) * request_bound
                if estimate is not None
                else float(limits["max_cost"])
            )
        _require(
            int(claim["requests"]) == request_bound
            and int(claim["strong_model_calls"])
            == (request_bound if role == "AI-6" else 0)
            and int(claim["input_tokens"]) % request_bound == 0
            and int(claim["output_tokens"])
            == int(contract["max_tokens"]) * request_bound
            and number_equal(claim_cost, expected_claim_cost),
            f"transport invocation {invocation_index} budget claim differs from its frozen transport contract",
        )
        for claim_name, limit_name in (
            ("input_tokens", "max_input_tokens"),
            ("output_tokens", "max_output_tokens"),
            ("cost", "max_cost"),
            ("requests", "max_requests"),
            ("strong_model_calls", "max_strong_model_calls"),
        ):
            maximum = float(limits[limit_name])
            _require(
                maximum <= 0 or float(claim[claim_name]) <= maximum,
                f"transport invocation {invocation_index} claim exceeds frozen {limit_name}",
            )
        _require(
            item.get("attempt_evidence_complete") is True,
            f"transport invocation {invocation_index} attempt ledger is incomplete",
        )
        attempts = item.get("attempts")
        _require(
            isinstance(attempts, list)
            and bool(attempts)
            and len(attempts) <= request_bound,
            f"transport invocation {invocation_index} has an empty attempt ledger or exceeds its reserved request bound",
        )
        final_usage, _final_tokens = _strict_usage_tokens(
            item.get("usage"), f"transport invocation {invocation_index} usage"
        )
        invocation_actual_tokens = {"input_tokens": 0, "output_tokens": 0}
        invocation_actual_costs: list[float | None] = []
        sanitized_attempts: list[dict[str, Any]] = []
        for attempt_index, raw_attempt in enumerate(attempts, 1):
            attempt = _mapping(
                raw_attempt,
                f"transport invocation {invocation_index} attempt {attempt_index}",
            )
            _require(
                set(attempt)
                == {
                    "attempt_number",
                    "succeeded",
                    "usage_complete",
                    "failure_stage",
                    "usage",
                },
                f"transport invocation {invocation_index} attempt {attempt_index} fields are unsupported",
            )
            succeeded = attempt.get("succeeded")
            failure_stage = attempt.get("failure_stage")
            _require(
                type(attempt.get("attempt_number")) is int
                and attempt["attempt_number"] == attempt_index
                and type(succeeded) is bool
                and attempt.get("usage_complete") is True
                and isinstance(failure_stage, str)
                and (
                    (succeeded is True and failure_stage == "")
                    or (
                        succeeded is False
                        and failure_stage in allowed_failure_stages
                    )
                ),
                f"transport invocation {invocation_index} attempt {attempt_index} is not a complete provider attempt",
            )
            _require(
                succeeded is (attempt_index == len(attempts)),
                f"transport invocation {invocation_index} attempt success ordering is invalid",
            )
            attempt_usage, attempt_tokens = _strict_usage_tokens(
                attempt.get("usage"),
                f"transport invocation {invocation_index} attempt {attempt_index} usage",
            )
            billing_mode = str(attempt_usage.get("billing_mode") or "").strip()
            _require(
                billing_mode == "chatgpt_subscription",
                f"transport invocation {invocation_index} attempt {attempt_index} is not bound to Codex subscription billing",
            )
            if attempt_index == len(attempts):
                _require(
                    attempt_usage == final_usage,
                    f"transport invocation {invocation_index} terminal attempt usage differs from returned usage",
                )
            for name in token_totals:
                token_totals[name] += attempt_tokens[name]
            invocation_actual_tokens["input_tokens"] += attempt_tokens["input_tokens"]
            invocation_actual_tokens["output_tokens"] += attempt_tokens["output_tokens"]
            if billing_mode == "chatgpt_subscription":
                attempt_cost = None
                cost_provenance = "chatgpt_subscription"
            else:
                estimate = estimate_call_cost(
                    model_ids[role],
                    {
                        **attempt_usage,
                        "input_tokens": attempt_tokens["input_tokens"],
                        "output_tokens": attempt_tokens["output_tokens"],
                        "cached_input_tokens": attempt_tokens["cached_tokens"],
                    },
                )
                attempt_cost = None if estimate is None else float(estimate["cny"])
                cost_provenance = (
                    "unknown_price" if estimate is None else "pricing_table"
                )
            invocation_actual_costs.append(attempt_cost)
            sanitized_attempts.append({
                "attempt_number": attempt_index,
                "succeeded": succeeded,
                "usage_complete": True,
                "failure_stage": failure_stage,
                "input_tokens": attempt_tokens["input_tokens"],
                "output_tokens": attempt_tokens["output_tokens"],
                "cached_tokens": attempt_tokens["cached_tokens"],
                "billing_mode": billing_mode,
                "cost": attempt_cost,
                "cost_provenance": cost_provenance,
            })
            attempt_count += 1

        expected_actual: dict[str, int | float | None] = {
            **invocation_actual_tokens,
            "cost": (
                sum(value for value in invocation_actual_costs if value is not None)
                if all(value is not None for value in invocation_actual_costs)
                else None
            ),
        }
        for name in actual_fields:
            raw_actual = actual.get(name)
            if raw_actual is not None:
                if name in {"input_tokens", "output_tokens"}:
                    _require(
                        type(raw_actual) is int and raw_actual >= 0,
                        f"transport invocation {invocation_index} actual {name} is invalid",
                    )
                else:
                    finite_nonnegative_number(
                        raw_actual,
                        f"transport invocation {invocation_index} actual cost",
                    )
            _require(
                number_equal(raw_actual, expected_actual[name]),
                f"transport invocation {invocation_index} budget actual {name} differs from complete attempts",
            )
        sanitized_budget_ledger.append({
            "ordinal": invocation_index,
            "role": role,
            "budget_claim": dict(claim),
            "budget_actual_usage": dict(actual),
            "attempts": sanitized_attempts,
        })

        budget_totals["requests"] += request_bound
        budget_totals["strong_model_calls"] += int(claim["strong_model_calls"])
        budget_totals["committed_reservations"] += 1
        for dimension, observed_name, accounted_name, unknown_name, limit_name in (
            (
                "input_tokens",
                "observed_input_tokens",
                "accounted_input_tokens",
                "unknown_input_token_requests",
                "max_input_tokens",
            ),
            (
                "output_tokens",
                "observed_output_tokens",
                "accounted_output_tokens",
                "unknown_output_token_requests",
                "max_output_tokens",
            ),
            (
                "cost",
                "observed_cost",
                "accounted_cost",
                "unknown_cost_requests",
                "max_cost",
            ),
        ):
            actual_value = expected_actual[dimension]
            if actual_value is None:
                budget_totals[accounted_name] += claim[dimension]
                budget_totals[unknown_name] += request_bound
                if float(claim[dimension]) == 0 and float(limits[limit_name]) > 0:
                    unbounded_unknown_dimensions.add(dimension)
            else:
                budget_totals[observed_name] += actual_value
                budget_totals[accounted_name] += actual_value

    budget_state = _mapping(
        analysis_v2.get("budget_state"), "v2 persisted budget state"
    )
    budget_usage = _mapping(
        analysis_v2.get("budget_usage"), "v2 persisted budget usage"
    )
    _require(
        set(budget_state)
        == {
            "schema_version",
            "limits",
            "usage",
            "low_priority_threshold",
            "stop_reason",
            "stop_details",
            "unbounded_unknown_dimensions",
            "reservations",
        }
        and budget_state.get("schema_version") == "analysis-budget-v1",
        "v2 persisted budget state fields are incomplete or unsupported",
    )
    state_limits = _mapping(budget_state.get("limits"), "v2 budget limits")
    _require(
        set(state_limits) == limit_fields
        and RELEASE_INTEGRITY._canonical_json_sha256(state_limits)
        == RELEASE_INTEGRITY._canonical_json_sha256(limits),
        "v2 budget limits differ from the authoritative snapshot",
    )
    state_usage = _mapping(budget_state.get("usage"), "v2 budget state usage")
    _require(
        RELEASE_INTEGRITY._canonical_json_sha256(state_usage)
        == RELEASE_INTEGRITY._canonical_json_sha256(budget_usage),
        "v2 budget_state usage differs from archived budget_usage",
    )
    _require(
        set(state_usage)
        == {
            "observed",
            "actual",
            "accounted",
            "requests",
            "strong_model_calls",
            "unknown",
            "committed_reservations",
            "cancelled_reservations",
            "wall_time_minutes",
        },
        "v2 budget usage fields are incomplete or unsupported",
    )
    observed = _mapping(state_usage.get("observed"), "v2 observed budget usage")
    actual_usage = _mapping(state_usage.get("actual"), "v2 actual budget usage")
    accounted = _mapping(state_usage.get("accounted"), "v2 accounted budget usage")
    unknown = _mapping(state_usage.get("unknown"), "v2 unknown budget usage")
    _require(
        set(observed) == {"input_tokens", "output_tokens", "cost"}
        and set(actual_usage) == {"input_tokens", "output_tokens", "cost"}
        and set(accounted) == {"input_tokens", "output_tokens", "cost"}
        and set(unknown)
        == {"input_token_requests", "output_token_requests", "cost_requests"},
        "v2 nested budget usage fields are incomplete or unsupported",
    )
    wall_time_minutes = finite_nonnegative_number(
        state_usage.get("wall_time_minutes"), "v2 budget wall_time_minutes"
    )
    expected_actual_usage = {
        "input_tokens": (
            None
            if budget_totals["unknown_input_token_requests"]
            else budget_totals["observed_input_tokens"]
        ),
        "output_tokens": (
            None
            if budget_totals["unknown_output_token_requests"]
            else budget_totals["observed_output_tokens"]
        ),
        "cost": (
            None
            if budget_totals["unknown_cost_requests"]
            else budget_totals["observed_cost"]
        ),
    }
    expected_usage = {
        "observed": {
            "input_tokens": budget_totals["observed_input_tokens"],
            "output_tokens": budget_totals["observed_output_tokens"],
            "cost": budget_totals["observed_cost"],
        },
        "actual": expected_actual_usage,
        "accounted": {
            "input_tokens": budget_totals["accounted_input_tokens"],
            "output_tokens": budget_totals["accounted_output_tokens"],
            "cost": budget_totals["accounted_cost"],
        },
        "requests": budget_totals["requests"],
        "strong_model_calls": budget_totals["strong_model_calls"],
        "unknown": {
            "input_token_requests": budget_totals[
                "unknown_input_token_requests"
            ],
            "output_token_requests": budget_totals[
                "unknown_output_token_requests"
            ],
            "cost_requests": budget_totals["unknown_cost_requests"],
        },
        "committed_reservations": budget_totals["committed_reservations"],
        "cancelled_reservations": 0,
        "wall_time_minutes": wall_time_minutes,
    }
    _require(
        RELEASE_INTEGRITY._canonical_json_sha256(state_usage)
        == RELEASE_INTEGRITY._canonical_json_sha256(expected_usage),
        "v2 persisted budget usage differs from recomputed transport claims/actual usage",
    )
    _require(
        isinstance(budget_state.get("reservations"), list)
        and budget_state["reservations"] == []
        and type(state_usage.get("cancelled_reservations")) is int
        and state_usage["cancelled_reservations"] == 0,
        "v2 VERIFIED budget contains active or cancelled reservations",
    )
    threshold = finite_nonnegative_number(
        budget_state.get("low_priority_threshold"),
        "v2 budget low_priority_threshold",
    )
    stop_reason = budget_state.get("stop_reason")
    stop_details = budget_state.get("stop_details")
    _require(
        0 < threshold <= 1
        and stop_reason
        in {None, "STOP_LOW_PRIORITY", "LIMIT_REACHED", "LIMIT_EXCEEDED", "UNKNOWN_USAGE"}
        and isinstance(stop_details, list)
        and all(isinstance(item, str) and bool(item) for item in stop_details),
        "v2 budget terminal metadata is invalid",
    )
    archived_unbounded = budget_state.get("unbounded_unknown_dimensions")
    _require(
        isinstance(archived_unbounded, list)
        and archived_unbounded == sorted(unbounded_unknown_dimensions),
        "v2 unbounded unknown budget dimensions differ from transport evidence",
    )
    stop_reasons = analysis_v2.get("stop_reasons")
    _require(
        isinstance(stop_reasons, list)
        and "recovery_budget_evidence_ahead_of_checkpoint" not in stop_reasons,
        "v2 VERIFIED evidence retains an unclosed recovery budget residual",
    )
    for usage_name, limit_name in (
        ("accounted_input_tokens", "max_input_tokens"),
        ("accounted_output_tokens", "max_output_tokens"),
        ("accounted_cost", "max_cost"),
        ("requests", "max_requests"),
        ("strong_model_calls", "max_strong_model_calls"),
    ):
        maximum = float(limits[limit_name])
        _require(
            maximum <= 0 or float(budget_totals[usage_name]) <= maximum,
            f"v2 VERIFIED budget exceeds frozen {limit_name}",
        )
    _require(
        wall_time_minutes <= float(limits["max_wall_time_minutes"]),
        "v2 VERIFIED budget exceeds frozen max_wall_time_minutes",
    )
    budget_closure = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_BUDGET_CLOSURE_SCHEMA,
        "budget_state_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            budget_state
        ),
        "budget_state": dict(budget_state),
        "budget_usage_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            budget_usage
        ),
        "budget_usage": dict(budget_usage),
        "limits_sha256": RELEASE_INTEGRITY._canonical_json_sha256(limits),
        "limits": limits,
        "transport_contracts_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            transport_contracts
        ),
        "transport_contracts": transport_contracts,
        "transport_budget_ledger_sha256": (
            RELEASE_INTEGRITY._canonical_json_sha256(sanitized_budget_ledger)
        ),
        "transport_budget_ledger": sanitized_budget_ledger,
        "observed": expected_usage["observed"],
        "actual": expected_usage["actual"],
        "accounted": expected_usage["accounted"],
        "requests": budget_totals["requests"],
        "strong_model_calls": budget_totals["strong_model_calls"],
        "unknown": expected_usage["unknown"],
        "transport_claim_count": len(transport),
        "committed_reservations": budget_totals["committed_reservations"],
        "cancelled_reservations": 0,
        "active_reservations": 0,
        "wall_time_minutes": wall_time_minutes,
        "unbounded_unknown_dimensions": sorted(unbounded_unknown_dimensions),
        "all_claims_verified": True,
        "all_actual_usage_verified": True,
        "exact_aggregate_verified": True,
    }

    performance = _mapping(analysis_v2.get("performance"), "v2 performance evidence")
    expected_performance = {
        "input_tokens": token_totals["input_tokens"],
        "output_tokens": token_totals["output_tokens"],
        "cached_tokens": token_totals["cached_tokens"],
        "total_tokens": token_totals["total_tokens"],
        "observed_input_tokens": token_totals["input_tokens"],
        "observed_output_tokens": token_totals["output_tokens"],
        "observed_cached_tokens": token_totals["cached_tokens"],
        "observed_total_tokens": token_totals["total_tokens"],
        "orchestration_invocation_count": len(invocations),
        "transport_call_count": len(transport),
        "usage_observed_call_count": len(transport),
        "usage_missing_call_count": 0,
        "transport_attempt_count": attempt_count,
        "observed_transport_attempt_count": attempt_count,
        "usage_observed_attempt_count": attempt_count,
        "usage_missing_attempt_count": 0,
        "cache_hit_evidence_count": 0,
    }
    _require(
        performance.get("usage_complete") is True
        and performance.get("attempt_evidence_complete") is True,
        "v2 performance does not certify complete transport attempt usage",
    )
    for name, expected in expected_performance.items():
        _require(
            type(performance.get(name)) is int and performance[name] == expected,
            f"v2 performance {name} differs from the recomputed transport ledger",
        )
    _require(
        token_totals["input_tokens"] > 0
        and token_totals["output_tokens"] > 0
        and token_totals["total_tokens"]
        == token_totals["input_tokens"] + token_totals["output_tokens"],
        "transport token closure is empty or algebraically inconsistent",
    )
    return {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_TRANSPORT_CLOSURE_SCHEMA,
        "transport_evidence_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            transport
        ),
        "orchestration_invocation_count": len(invocations),
        "transport_invocation_count": len(transport),
        "transport_attempt_count": attempt_count,
        "usage_observed_call_count": len(transport),
        "usage_observed_attempt_count": attempt_count,
        "usage_missing_call_count": 0,
        "usage_missing_attempt_count": 0,
        **token_totals,
        "usage_complete": True,
        "attempt_evidence_complete": True,
        "budget_closure": budget_closure,
    }


def _verified_ocr_artifact(
    *,
    config: AnalysisAcceptanceConfig,
    members: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    role: str,
    expected_sha256: str,
) -> bytes:
    """Load one artifact from the audit ZIP or verified nested OCR package."""

    bindings = _role_bindings(manifest, role)
    if bindings:
        payload, _record, _alias = _one_role(members, manifest, role)
    else:
        ocr_dir = config.output_dir / "ocr-prerequisite"
        verified = RELEASE_INTEGRITY.verify_run_attestation(
            ocr_dir,
            expected_pages=config.expected_pages,
            version=config.expected_version,
            commit=config.expected_commit.lower(),
            expected_source_sha256=_sha256_file(config.source),
        )
        baseline = _mapping(
            verified.get("ocr_baseline"), "verified nested OCR baseline"
        )
        payload = RELEASE_INTEGRITY._verified_nested_ocr_artifact_bytes(
            ocr_dir,
            baseline,
            role=role,
        )
    _require(
        _sha256_bytes(payload) == expected_sha256,
        f"OCR {role} bytes differ from the analysis snapshot digest",
    )
    return payload


def _verified_ocr_page_records(
    *,
    config: AnalysisAcceptanceConfig,
    members: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    expected_sha256: str,
) -> bytes:
    return _verified_ocr_artifact(
        config=config,
        members=members,
        manifest=manifest,
        role="PAGE_RECORDS",
        expected_sha256=expected_sha256,
    )


def _verified_page_risk_admission(
    *,
    config: AnalysisAcceptanceConfig,
    members: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    analysis_v2: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    transport: list[Mapping[str, Any]],
    expected_pages: int,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Verify typed admission, preflight facts, config, and route closure."""

    admission = _mapping(
        analysis_v2.get("page_risk_admission"), "v2 page-risk admission"
    )
    preflight = _mapping(
        analysis_v2.get("page_risk_preflight"), "v2 page-risk preflight"
    )
    route = _mapping(
        analysis_v2.get("page_route_closure"), "v2 page-route closure"
    )
    configuration = _mapping(
        analysis_v2.get("analysis_configuration"),
        "v2 frozen analysis configuration",
    )
    configuration_sha256 = str(
        analysis_v2.get("analysis_configuration_sha256") or ""
    ).lower()
    source_hash = str(snapshot.get("source_pdf_hash") or "").lower()
    evidence_hashes = _mapping(
        snapshot.get("evidence_hashes"), "v2 snapshot evidence hashes"
    )
    admission_sha = str(admission.get("admission_sha256") or "").lower()
    _require(
        SHA256_RE.fullmatch(admission_sha) is not None
        and admission.get("schema_version") == PAGE_RISK_ADMISSION_SCHEMA
        and admission.get("strategy") == PAGE_RISK_ADMISSION_STRATEGY,
        "v2 page-risk admission schema/digest is invalid",
    )
    page_records_bytes = _verified_ocr_page_records(
        config=config,
        members=members,
        manifest=manifest,
        expected_sha256=str(evidence_hashes["ocr_page_records_hash"]).lower(),
    )
    runtime_page_records_bytes = _verified_ocr_artifact(
        config=config,
        members=members,
        manifest=manifest,
        role="RUNTIME_PAGE_RECORDS",
        expected_sha256=str(
            evidence_hashes["ocr_runtime_page_records_hash"]
        ).lower(),
    )
    baseline_tex_sha256 = str(admission.get("baseline_tex_sha256") or "").lower()
    baseline_pdf_sha256 = str(admission.get("baseline_pdf_sha256") or "").lower()
    _require(
        SHA256_RE.fullmatch(baseline_tex_sha256) is not None
        and SHA256_RE.fullmatch(baseline_pdf_sha256) is not None,
        "v2 page-risk admission lacks baseline artifact digests",
    )
    baseline_tex_bytes = _verified_ocr_artifact(
        config=config,
        members=members,
        manifest=manifest,
        role="BASELINE_TEX",
        expected_sha256=baseline_tex_sha256,
    )
    baseline_pdf_bytes = _verified_ocr_artifact(
        config=config,
        members=members,
        manifest=manifest,
        role="BASELINE_PDF",
        expected_sha256=baseline_pdf_sha256,
    )
    source_pdf, _source_record, _source_alias = _one_role(
        members, manifest, "SOURCE_PDF"
    )
    try:
        configuration = RELEASE_INTEGRITY._verify_analysis_configuration(
            configuration,
            claimed_sha256=configuration_sha256,
            expected_pages=expected_pages,
            admission=admission,
            model_bindings=snapshot.get("models"),
            expected_contracts_sha256=(
                RELEASE_INTEGRITY._canonical_json_sha256(
                    snapshot.get("transport_contracts")
                )
            ),
            snapshot_config_sha256=str(snapshot.get("config_hash") or ""),
        )
    except RELEASE_INTEGRITY.ReleaseIntegrityError as exc:
        raise AcceptanceError(str(exc)) from exc
    for config_field in (
        "workflow_version",
        "prompt_version",
        "application_version",
        "latex_engine",
        "concurrency_limit",
        "models",
        "transport_contracts",
        "page_range",
        "max_input_tokens",
        "max_output_tokens",
        "max_cost",
        "max_requests",
        "max_strong_model_calls",
        "max_wall_time_minutes",
    ):
        _require(
            configuration.get(config_field) == snapshot.get(config_field),
            f"v2 analysis configuration {config_field} differs from the snapshot",
        )
    snapshot_page_map = _sequence(snapshot.get("page_map"), "v2 snapshot page map")
    _require(
        len(snapshot_page_map) == expected_pages,
        "v2 snapshot page map does not cover every admitted page",
    )
    config_candidate_map = _sequence(
        configuration.get("candidate_page_map"),
        "v2 analysis configuration candidate map",
    )
    admission_pages = _sequence(admission.get("pages"), "v2 admission pages")
    _require(
        len(admission_pages) == expected_pages,
        "v2 page-risk admission does not cover every source page",
    )
    for page_number, (raw_entry, config_row) in enumerate(
        zip(snapshot_page_map, config_candidate_map, strict=True), 1
    ):
        entry = _mapping(raw_entry, f"v2 snapshot page-map row {page_number}")
        admitted_row = _mapping(
            admission_pages[page_number - 1],
            f"v2 admission page {page_number}",
        )
        summary = _mapping(
            admitted_row.get("summary"), f"v2 admission summary {page_number}"
        )
        _require(
            entry.get("source_page_number") == page_number
            and entry.get("source_page_id") == summary.get("source_page_id")
            and isinstance(config_row, list)
            and config_row[0] == page_number
            and entry.get("candidate_pdf_page_ids")
            == [f"candidate-page-{page:06d}" for page in config_row[1]],
            f"v2 snapshot page-map row {page_number} differs from the admission payload",
        )
    route_operations = set(RELEASE_INTEGRITY.ANALYSIS_OPERATION_ROLES)
    transport_route_calls = sorted(
        [
            {
                "role": str(item.get("role") or ""),
                "operation": str(item.get("operation") or ""),
                "source_page_id": str(item.get("source_page_id") or ""),
                "candidate_hash": str(item.get("candidate_hash") or ""),
                "issue_id": str(item.get("issue_id") or ""),
                "snapshot_hash": str(item.get("snapshot_hash") or ""),
                "response_schema_version": str(
                    item.get("response_schema_version") or ""
                ),
                "succeeded": True,
            }
            for item in transport
            if item.get("operation") in route_operations
        ],
        key=lambda item: (
            item["role"],
            item["operation"],
            item["source_page_id"],
            item["candidate_hash"],
            item["issue_id"],
        ),
    )
    _require(
        route.get("route_call_keys") == transport_route_calls,
        "v2 page-route closure differs from the real transport invocation ledger",
    )
    page_ids = [
        str(_mapping(row, "v2 admitted page").get("summary", {}).get("source_page_id") or "")
        for row in _sequence(admission.get("pages"), "v2 admitted pages")
    ]
    projection = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_PAGE_RISK_CLOSURE_SCHEMA,
        "admission_sha256": admission_sha,
        "admission": dict(admission),
        "preflight_sha256": str(preflight.get("preflight_sha256") or "").lower(),
        "preflight": dict(preflight),
        "route_closure_sha256": str(route.get("closure_sha256") or "").lower(),
        "route_closure": dict(route),
        "page_count": expected_pages,
        "page_ids_sha256": RELEASE_INTEGRITY.page_id_sequence_sha256(page_ids),
        "risk_counts": route.get("risk_counts"),
        "low_risk_sampling": admission.get("low_risk_sampling"),
        "all_preflight_bindings_verified": True,
        "all_route_bindings_verified": True,
    }
    try:
        projection = RELEASE_INTEGRITY._verify_analysis_page_risk_closure(
            projection,
            expected_pages=expected_pages,
            source_sha256=source_hash,
            evidence_hashes=evidence_hashes,
            page_records_bytes=page_records_bytes,
            runtime_page_records_bytes=runtime_page_records_bytes,
            source_pdf_bytes=source_pdf,
            baseline_tex_bytes=baseline_tex_bytes,
            baseline_pdf_bytes=baseline_pdf_bytes,
            analysis_configuration=configuration,
            final_candidate_sha256=str(analysis_v2.get("result_tex_sha256") or ""),
        )
    except RELEASE_INTEGRITY.ReleaseIntegrityError as exc:
        raise AcceptanceError(str(exc)) from exc
    return projection, configuration, configuration_sha256


def _canonical_candidate_mapping(
    *,
    final_mapping: Mapping[str, Any],
    source_page_count: int,
    candidate_page_count: int,
    candidate_tex_sha256: str,
    candidate_pdf_sha256: str,
) -> dict[str, Any]:
    raw_map = _mapping(final_mapping.get("map"), "final candidate page mapping rows")
    expected_keys = {str(page) for page in range(1, source_page_count + 1)}
    _require(
        set(raw_map) == expected_keys,
        "final candidate page mapping does not cover source pages 1-37 exactly",
    )
    rows: list[dict[str, Any]] = []
    for source_page in range(1, source_page_count + 1):
        pages = raw_map.get(str(source_page))
        _require(
            isinstance(pages, list),
            f"final candidate page mapping row {source_page} is missing",
        )
        rows.append({"source_page": source_page, "candidate_pages": list(pages)})
    candidate_only = final_mapping.get("candidate_only_pages")
    _require(
        isinstance(candidate_only, list),
        "final candidate-only page evidence is missing",
    )
    return RELEASE_INTEGRITY.build_candidate_page_mapping(
        source_page_count=source_page_count,
        candidate_page_count=candidate_page_count,
        candidate_tex_sha256=candidate_tex_sha256,
        candidate_pdf_sha256=candidate_pdf_sha256,
        upstream_mapping_sha256=str(final_mapping.get("mapping_sha256") or ""),
        canonical_rows=rows,
        candidate_only_pages=candidate_only,
    )


def _recompute_production_alignment(
    *,
    source_pdf: bytes,
    candidate_pdf: bytes,
    selected_source_pages: list[int],
) -> dict[str, Any]:
    """Re-run the production reflow aligner against the packaged PDF bytes."""

    try:
        import pymupdf
        from latexstruct.core.visual_quality import (
            CANDIDATE_SCOPE_REFLOW,
            build_page_alignment,
        )

        def page_texts(
            payload: bytes, targets: list[int] | None
        ) -> tuple[int, dict[int, str]]:
            with pymupdf.open(stream=bytes(payload), filetype="pdf") as document:
                count = int(document.page_count)
                pages = targets or list(range(1, count + 1))
                _require(
                    count > 0 and all(1 <= page <= count for page in pages),
                    "production page-alignment PDF range is invalid",
                )
                output: dict[int, str] = {}
                for page in pages:
                    loaded = document.load_page(page - 1)
                    try:
                        text = loaded.get_text("text", sort=True)
                    except TypeError:  # pragma: no cover - old PyMuPDF
                        text = loaded.get_text("text")
                    output[page] = re.sub(r"\s+", " ", str(text or "")).strip()[:20000]
                return count, output

        source_count, source_texts = page_texts(source_pdf, selected_source_pages)
        candidate_count, candidate_texts = page_texts(candidate_pdf, None)
        alignment = build_page_alignment(
            source_count,
            candidate_count,
            selected_source_pages,
            candidate_scope=CANDIDATE_SCOPE_REFLOW,
            source_page_texts=source_texts,
            candidate_page_texts=candidate_texts,
        )
    except AcceptanceError:
        raise
    except Exception as exc:
        raise AcceptanceError(
            f"cannot recompute production candidate page alignment: {exc}"
        ) from exc
    _require(
        alignment.mapping_reliable
        and not alignment.requires_model_review
        and not alignment.missing_source_pages
        and not alignment.ambiguous_candidate_pages,
        "recomputed production candidate page alignment is not reliable",
    )
    grouped: dict[int, list[int]] = {
        page: [] for page in selected_source_pages
    }
    candidate_only = set(alignment.candidate_only_pages)
    for item in alignment.mappings:
        candidate_page = item.candidate_page
        _require(
            candidate_page is not None
            and candidate_page not in candidate_only
            and item.source_page in grouped,
            "recomputed production candidate page alignment contains an invalid row",
        )
        if candidate_page not in grouped[item.source_page]:
            grouped[item.source_page].append(candidate_page)
    _require(
        all(grouped[page] for page in selected_source_pages),
        "recomputed production candidate page alignment misses a source page",
    )
    return {
        "mapping_sha256": alignment.mapping_sha256,
        "candidate_only_pages": list(alignment.candidate_only_pages),
        "source_page_count": source_count,
        "candidate_page_count": candidate_count,
        "map": {str(page): pages for page, pages in grouped.items()},
    }


def _derive_render_compare_closed_loop(
    *,
    analysis_v2: Mapping[str, Any],
    compile_invocations: list[Mapping[str, Any]],
    final_review_context_sha256s: list[str],
    final_candidate_tex_sha256: str,
    final_candidate_pdf_sha256: str,
) -> dict[str, Any]:
    """Derive, never assert, the release closed-loop result from host ledgers."""

    ledger = [
        _mapping(item, "v2 issue ledger item")
        for item in _sequence(analysis_v2.get("ledger"), "v2 issue ledger")
    ]
    fixes: list[dict[str, Any]] = []
    rejected = 0
    for issue in ledger:
        status = str(issue.get("current_status") or "")
        patch_id = str(issue.get("proposed_patch_id") or "")
        if status == "REJECTED_FALSE_POSITIVE" and not patch_id:
            rejected += 1
            continue
        _require(
            status == "VERIFIED_CLOSED"
            and patch_id
            and issue.get("review_result") == "PASS",
            "v2 issue ledger contains an issue without a reviewed terminal resolution",
        )
        issue_id = str(issue.get("issue_id") or "")
        candidate_hash = str(issue.get("candidate_hash") or "").lower()
        runs = [
            row
            for row in compile_invocations
            if row.get("candidate_hash") == candidate_hash
            and patch_id in str(row.get("reason") or "")
        ]
        _require(
            len(runs) == 1,
            f"reviewed fix {issue_id} lacks one atomic recompile invocation",
        )
        run = runs[0]
        pdf_hash = str(run.get("pdf_hash") or "").lower()
        compile_input_hash = str(run.get("compile_input_sha256") or "").lower()
        _require(
            SHA256_RE.fullmatch(candidate_hash) is not None
            and SHA256_RE.fullmatch(pdf_hash) is not None
            and SHA256_RE.fullmatch(compile_input_hash) is not None,
            f"reviewed fix {issue_id} lacks stable compiled bytes",
        )
        _require_atomic_compile_invocation(
            run,
            candidate_hash=candidate_hash,
            pdf_hash=pdf_hash,
            compile_input_hash=compile_input_hash,
            label=f"reviewed fix {issue_id}",
        )
        fixes.append({
            "issue_id": issue_id,
            "patch_id": patch_id,
            "candidate_tex_sha256": candidate_hash,
            "candidate_pdf_sha256": pdf_hash,
            "compile_invocation_number": _positive_int(run.get("run_number")),
            "review_result": "PASS",
        })
    branch = "FIX_REVIEW_RECOMPILE" if fixes else "NO_FIX_NEEDED"
    payload: dict[str, Any] = {
        "schema_version": RELEASE_INTEGRITY.RENDER_COMPARE_CLOSED_LOOP_SCHEMA,
        "branch": branch,
        "detected_issue_count": len(ledger),
        "fixed_issue_count": len(fixes),
        "rejected_false_positive_count": rejected,
        "fixes": fixes,
        "final_review_context_sha256s": list(final_review_context_sha256s),
        "final_candidate_tex_sha256": final_candidate_tex_sha256,
        "final_candidate_pdf_sha256": final_candidate_pdf_sha256,
    }
    payload["evidence_sha256"] = RELEASE_INTEGRITY._canonical_json_sha256(payload)
    return RELEASE_INTEGRITY.verify_render_compare_closed_loop(payload)


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
    compile_input_hash = _verified_compile_input_hash(
        compile_after.get("input_manifest"),
        candidate_tex=current_tex,
    )
    _require(
        compile_after.get("available") is True
        and compile_after.get("ok") is True
        and compile_after.get("preview_status") == "COMPILED"
        and compile_after.get("exit_code") == 0
        and compile_after.get("timed_out") is False
        and passes_completed >= 2,
        "final candidate lacks two successful real compile passes",
    )
    _require(
        compile_after.get("same_workdir_verified") is True
        and _positive_int(compile_after.get("passes_requested")) >= 2
        and _positive_int(compile_after.get("passes_attempted")) >= 2
        and COMPILE_WORKDIR_RE.fullmatch(
            str(compile_after.get("compile_workdir") or "")
        )
        is not None
        and compile_after.get("compile_input_sha256") == compile_input_hash,
        "final compile record lacks an atomic same-workdir input closure",
    )
    _require(str(compile_after.get("pdf_sha256") or "") == candidate_pdf_sha, "final compile PDF hash mismatch")
    candidate_page_count = _positive_int(compile_after.get("page_count"))
    _require(candidate_page_count > 0, "final compile page count is missing")
    _require(
        MIN_ANALYSIS_37_CANDIDATE_PAGES
        <= candidate_page_count
        <= MAX_ANALYSIS_37_CANDIDATE_PAGES,
        "analysis-37 candidate PDF is outside the conservative 32-42 page range",
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
        len(final_compile_invocations) == 1,
        "v2 compile invocation ledger must contain one atomic final-candidate compile",
    )
    _require_atomic_compile_invocation(
        final_compile_invocations[0],
        candidate_hash=candidate_tex_sha,
        pdf_hash=candidate_pdf_sha,
        compile_input_hash=compile_input_hash,
        label="final candidate",
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
        reasoning_effort = str(item.get("reasoning_effort") or "").strip()
        _require(
            re.fullmatch(r"AI-[1-6]", role) is not None
            and model_id == config.expected_model_id
            and reasoning_effort == config.expected_reasoning_effort,
            "v2 model binding differs from the declared release model policy",
        )
        _require(role not in model_bindings, "v2 model role is duplicated")
        model_bindings[role] = model_id

    transport = [
        _mapping(item, "v2 transport invocation")
        for item in _sequence(analysis_v2.get("transport_invocations"), "v2 transport invocations")
    ]
    snapshot_binding = _verified_snapshot_binding(snapshot, transport)
    transport_closure = _verified_invocation_transport_closure(
        analysis_v2=analysis_v2,
        transport=transport,
        snapshot=snapshot,
    )
    snapshot_binding["transport_closure"] = transport_closure
    snapshot_binding["all_transport_bindings_verified"] = True
    (
        page_risk_admission,
        analysis_configuration,
        analysis_configuration_sha256,
    ) = _verified_page_risk_admission(
        config=config,
        members=members,
        manifest=manifest,
        analysis_v2=analysis_v2,
        snapshot=snapshot,
        transport=transport,
        expected_pages=config.expected_pages,
    )
    snapshot_binding["analysis_configuration"] = analysis_configuration
    snapshot_binding["analysis_configuration_sha256"] = (
        analysis_configuration_sha256
    )
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
    context_ids: set[str] = set()
    context_hashes: set[str] = set()
    release_reviews: list[dict[str, Any]] = []
    for expected_pass, review in enumerate(final_reviews, 1):
        context_id = str(review.get("context_id") or "").strip()
        checked_ids = review.get("checked_page_ids")
        _require(review.get("pass_number") == expected_pass, "final review pass numbers are not 1 and 2")
        _require(context_id and context_id not in context_ids, "final review contexts are not independent")
        _require(review.get("candidate_hash") == candidate_tex_sha, "final review checked a different candidate")
        _require(
            isinstance(checked_ids, list)
            and checked_ids == expected_page_ids
            and len(checked_ids) == config.expected_pages
            and len(set(checked_ids)) == config.expected_pages,
            "final review checked_page_ids differ from expected_page_ids",
        )
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
        checked_page_ids_sha256 = RELEASE_INTEGRITY.page_id_sequence_sha256(
            checked_ids
        )
        _require(context_sha not in context_hashes, "final review context hashes are not distinct")
        context_ids.add(context_id)
        context_hashes.add(context_sha)
        release_reviews.append({
            "pass_number": expected_pass,
            "review_id": f"{expected_run_id}:final-review-{expected_pass}",
            "context_id": context_id,
            "context_sha256": context_sha,
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": candidate_tex_sha,
            "pages_checked": config.expected_pages,
            "expected_page_ids": list(expected_page_ids),
            "checked_page_ids": list(checked_ids),
            "checked_page_ids_sha256": checked_page_ids_sha256,
            "model_id": model_bindings["AI-5"],
            "backend": backend,
            "calls": review_calls,
        })

    _require(machine_evidence.get("raw_ocr_frozen") is True, "machine evidence does not bind frozen raw OCR")
    _require(machine_evidence.get("candidate_hash") == candidate_tex_sha, "machine verification checked a different candidate")
    _require(machine_evidence.get("current_candidate_hash") == candidate_tex_sha, "machine verification current candidate hash mismatch")
    visual_page_id_set_sha256 = RELEASE_INTEGRITY.page_id_sequence_sha256(
        expected_page_ids
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
    recomputed_mapping = _recompute_production_alignment(
        source_pdf=source_pdf,
        candidate_pdf=current_pdf,
        selected_source_pages=expected_page_numbers,
    )
    _require(
        recomputed_mapping["source_page_count"] == source_pages
        and recomputed_mapping["candidate_page_count"] == candidate_page_count,
        "recomputed production candidate page counts differ from packaged evidence",
    )
    _require(
        final_mapping.get("map") == recomputed_mapping["map"]
        and final_mapping.get("candidate_only_pages")
        == recomputed_mapping["candidate_only_pages"]
        and mapping_sha256 == recomputed_mapping["mapping_sha256"],
        "candidate page mapping differs from production alignment recomputed from the packaged PDFs",
    )
    canonical_mapping = _canonical_candidate_mapping(
        final_mapping=recomputed_mapping,
        source_page_count=config.expected_pages,
        candidate_page_count=candidate_page_count,
        candidate_tex_sha256=candidate_tex_sha,
        candidate_pdf_sha256=candidate_pdf_sha,
    )
    candidate_only_pages = canonical_mapping["candidate_only_pages"]
    _require(
        len(candidate_only_pages)
        <= MAX_ANALYSIS_37_CANDIDATE_PAGES - config.expected_pages,
        "analysis-37 has too many candidate-only pages",
    )
    page_layout = {
        "source_page_count": config.expected_pages,
        "candidate_page_count": candidate_page_count,
        "minimum_candidate_pages": MIN_ANALYSIS_37_CANDIDATE_PAGES,
        "maximum_candidate_pages": MAX_ANALYSIS_37_CANDIDATE_PAGES,
        "page_growth": candidate_page_count - config.expected_pages,
        "candidate_only_pages": list(candidate_only_pages),
        "candidate_mapping_sha256": canonical_mapping["mapping_sha256"],
        "candidate_mapping": canonical_mapping,
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
    closed_loop_evidence = _derive_render_compare_closed_loop(
        analysis_v2=analysis_v2,
        compile_invocations=compile_invocations,
        final_review_context_sha256s=[
            str(review["context_sha256"]).lower() for review in release_reviews
        ],
        final_candidate_tex_sha256=candidate_tex_sha,
        final_candidate_pdf_sha256=candidate_pdf_sha,
    )
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
        snapshot_binding=snapshot_binding,
        page_risk_admission=page_risk_admission,
        independent_final_reviews=release_reviews,
        visual_page_id_set_sha256=visual_page_id_set_sha256,
        closed_loop_evidence=closed_loop_evidence,
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


def _release_model_policy(
    config: AnalysisAcceptanceConfig,
    evidence: AnalysisRunEvidence,
    facts: VerifiedBundleFacts,
) -> dict[str, Any]:
    runtime = dict(evidence.runtime_model_configuration)
    policy = {
        "schema_version": RELEASE_INTEGRITY.ANALYSIS_RELEASE_MODEL_POLICY_SCHEMA,
        "declared_model_id": config.expected_model_id,
        "declared_reasoning_effort": config.expected_reasoning_effort,
        "runtime_configuration": runtime,
        "runtime_configuration_sha256": RELEASE_INTEGRITY._canonical_json_sha256(
            runtime
        ),
        "model_bindings_sha256": str(
            facts.snapshot_binding.get("model_bindings_sha256") or ""
        ).lower(),
        "transport_contracts_sha256": str(
            facts.snapshot_binding.get("transport_contracts_sha256") or ""
        ).lower(),
        "runtime_matches_declared": True,
        "all_role_bindings_match_declared": True,
        "all_transport_contracts_match_declared": True,
        "allowed_by_release": True,
    }
    RELEASE_INTEGRITY._verify_analysis_release_model_policy(
        policy,
        model_bindings=facts.snapshot_binding.get("model_bindings"),
        transport_contracts=_mapping(
            facts.snapshot_binding.get("analysis_configuration"),
            "analysis frozen configuration",
        ).get("transport_contracts"),
    )
    return policy


def _publish_pass(
    config: AnalysisAcceptanceConfig,
    evidence: AnalysisRunEvidence,
    facts: VerifiedBundleFacts,
) -> dict[str, Any]:
    runtime = _runtime_identity(config)
    snapshot_binding = dict(facts.snapshot_binding)
    snapshot_binding["release_model_policy"] = _release_model_policy(
        config, evidence, facts
    )
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
    closed_loop_evidence = RELEASE_INTEGRITY.verify_render_compare_closed_loop(
        facts.closed_loop_evidence
    )
    render_compare_closed_loop = bool(
        closed_loop_evidence.get("final_candidate_tex_sha256")
        == facts.compilation["candidate_tex_sha256"]
        and closed_loop_evidence.get("final_candidate_pdf_sha256")
        == facts.compilation["candidate_pdf_sha256"]
        and closed_loop_evidence.get("final_review_context_sha256s")
        == [
            str(review["context_sha256"]).lower()
            for review in facts.independent_final_reviews
        ]
    )
    _require(
        render_compare_closed_loop,
        "derived compile/render/compare branch is not bound to the final evidence",
    )
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
        "render_compare_closed_loop": render_compare_closed_loop,
        "closed_loop_evidence": closed_loop_evidence,
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
        "thresholds": {"maximum_wall_time_seconds": None},
        "target_status": "NOT_EVALUATED",
        "target_met": None,
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
            "snapshot_binding": snapshot_binding,
            "page_risk_admission": facts.page_risk_admission,
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
        "thresholds": {"maximum_wall_time_seconds": None},
        "target_status": "NOT_EVALUATED",
        "target_met": None,
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
        evidence.runtime_model_configuration = _verified_runtime_model_configuration(
            config,
            api.get_json("/api/config"),
        )

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
        evidence.project_id, evidence.process_job_id = _fresh_import_identity(
            evidence.import_response
        )
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
    parser.add_argument(
        "--expected-model-id",
        choices=tuple(sorted(RELEASE_INTEGRITY.ANALYSIS_RELEASE_ALLOWED_MODEL_IDS)),
        default=RELEASE_INTEGRITY.ANALYSIS_STABLE_MODEL_ID,
    )
    parser.add_argument(
        "--expected-reasoning-effort",
        choices=tuple(
            sorted(RELEASE_INTEGRITY.ANALYSIS_RELEASE_ALLOWED_REASONING_EFFORTS)
        ),
        default=RELEASE_INTEGRITY.ANALYSIS_STABLE_REASONING_EFFORT,
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
        expected_model_id=args.expected_model_id,
        expected_reasoning_effort=args.expected_reasoning_effort,
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

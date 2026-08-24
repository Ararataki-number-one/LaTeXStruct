#!/usr/bin/env python3
"""Fail-closed LaTeXStruct v2 OCR acceptance against a running service.

The browser performs the same upload/range/start flow as a user.  HTTP is then
used only for polling the created job and downloading immutable artifacts.  No
model setting or credential is accepted by this tool: it uses the configuration
already frozen by the running LaTeXStruct instance.

Examples::

    python tools/v2_acceptance_e2e.py book.pdf --end-page 17 \
        --executable dist/LaTeXStruct.exe --expected-commit COMMIT \
        --expected-build-id BUILD_ID
    python tools/v2_acceptance_e2e.py book.pdf --end-page 600 \
        --output output/playwright/v2-acceptance/book-p1-600 \
        --executable dist/LaTeXStruct.exe --expected-commit COMMIT \
        --expected-build-id BUILD_ID

Exit status is zero only when every machine check passes against the real local
HTTP service through real Playwright and the tested executable/build identity is
explicitly bound.  Missing browser automation, status evidence, pages, hashes,
or artifacts produces reports with ``acceptance_passed=false`` and a non-zero
exit status.  Test doubles can exercise this module, but can never mint a release
attestation that says PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from pathlib import PurePosixPath
from types import ModuleType
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urljoin, urlsplit


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_release_integrity() -> ModuleType:
    name = "_latexstruct_release_integrity_for_ocr_acceptance"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = REPO_ROOT / "packaging" / "release_integrity.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the release-integrity verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RELEASE_INTEGRITY = _load_release_integrity()

SCHEMA_VERSION = "latexstruct-v2-ocr-acceptance/2"
ATTESTATION_SCHEMA = RELEASE_INTEGRITY.RUN_ATTESTATION_SCHEMA
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS = 3600.0
# A 600-page run must be allowed to reach a real terminal state.  Its 30-minute
# OCR target is still checked separately; this four-hour observation window
# prevents the old one-hour polling timeout from being mistaken for a completed
# 600-page result.
LARGE_RUN_TIMEOUT_SECONDS = 4 * 3600.0
TERMINAL_STATUSES = frozenset({"done", "partial", "error", "failed", "cancelled"})
ACTIVE_STATUSES = frozenset({"ready", "starting", "running", "pausing", "paused"})
VALID_COMPILE_STATUSES = frozenset(
    {"COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"}
)
SUCCESS_PAGE_STATUSES = frozenset({"SUCCESS", "DONE"})
REVIEW_PAGE_STATUSES = frozenset({"NEEDS_REVIEW", "PARTIAL"})
FAILED_PAGE_STATUSES = frozenset({"FAILED", "ERROR", "CANCELLED"})
REQUIRED_ARTIFACTS = (
    "source",
    "raw-ocr",
    "baseline-tex",
    "baseline-pdf",
    "compile-log",
    "snapshot",
    "baseline-manifest",
)
OCR_BASELINE_ARCHIVE_PREFIX = "evidence/ocr-baseline/"
OCR_BASELINE_PACKAGE_DIRECTORY = RELEASE_INTEGRITY.OCR_BASELINE_PACKAGE_DIRECTORY
OCR_BASELINE_MANIFEST_MEMBER = RELEASE_INTEGRITY.OCR_BASELINE_MANIFEST_MEMBER
MAX_PACKAGE_MEMBERS = 8192
MAX_PACKAGE_MEMBER_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


class AcceptanceError(RuntimeError):
    """The acceptance run cannot truthfully continue."""


class BrowserAutomationUnavailable(AcceptanceError):
    """A real browser could not be started."""


@dataclass(frozen=True, slots=True)
class AcceptanceConfig:
    base_url: str
    pdf: Path
    start_page: int
    end_page: int
    output_dir: Path
    expected_version: str = "2.0.0"
    expected_commit: str = ""
    expected_build_id: str = ""
    executable: Path | None = None
    quality_tier: str = "recommended"
    poll_seconds: float = 2.0
    timeout_seconds: float = 3600.0
    browser_timeout_seconds: float = 90.0
    headed: bool = False
    min_successful_ppm: float | None = None
    max_wall_seconds: float | None = None
    max_consecutive_poll_errors: int = 5

    @property
    def expected_pages(self) -> int:
        return self.end_page - self.start_page + 1


@dataclass(frozen=True, slots=True)
class UiStartEvidence:
    job_id: str
    source_total_pages: int
    ui_version_text: str
    selected_range_text: str
    start_response_status: int
    screenshot: str = ""


@dataclass(frozen=True, slots=True)
class DownloadedArtifact:
    role: str
    filename: str
    sha256: str
    size: int
    media_type: str


@dataclass(slots=True)
class Check:
    id: str
    passed: bool
    evidence: Any


@dataclass(slots=True)
class RunEvidence:
    health: dict[str, Any] = field(default_factory=dict)
    ui: UiStartEvidence | None = None
    final_snapshot: dict[str, Any] = field(default_factory=dict)
    poll_history: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, DownloadedArtifact] = field(default_factory=dict)
    ocr_baseline: dict[str, str] = field(default_factory=dict)
    ocr_package_compilation: dict[str, Any] = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)
    execution_errors: list[str] = field(default_factory=list)
    overall_started_at: str = ""
    measurement_started_at: str = ""
    ocr_started_at: str = ""
    ended_at: str = ""
    ui_setup_seconds: float | None = None
    wall_time_seconds: float | None = None
    timed_out: bool = False
    real_execution: bool = False
    api_client: str = ""
    ui_driver: str = ""
    executable_filename: str = ""
    executable_sha256: str = ""

    def add_check(self, check_id: str, passed: bool, evidence: Any) -> None:
        self.checks.append(Check(check_id, bool(passed), evidence))


@dataclass(frozen=True, slots=True)
class HttpDownload:
    body: bytes
    headers: Mapping[str, str]
    status: int


class AcceptanceApi(Protocol):
    def get_json(self, path: str) -> dict[str, Any]: ...

    def download(self, path: str) -> HttpDownload: ...


class UiDriver(Protocol):
    def start_ocr(
        self,
        config: AcceptanceConfig,
        *,
        expected_source_pages: int,
    ) -> UiStartEvidence: ...


class LocalHttpApi:
    """Small stdlib-only client restricted to one configured local origin."""

    def __init__(self, base_url: str, timeout: float = 60.0):
        normalized = base_url.rstrip("/") + "/"
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise AcceptanceError("base_url must be an absolute HTTP(S) URL")
        self.base_url = normalized
        self.origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self.timeout = max(1.0, float(timeout))

    def _url(self, path: str) -> str:
        url = urljoin(self.base_url, str(path).lstrip("/"))
        parsed = urlsplit(url)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self.origin:
            raise AcceptanceError("cross-origin artifact URL was rejected")
        return url

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> HttpDownload:
        request_headers = {
            "Accept": "application/json, application/octet-stream",
            **dict(headers or {}),
        }
        request = urllib.request.Request(
            self._url(path),
            data=body,
            method=str(method or "GET").upper(),
            headers=request_headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return HttpDownload(
                    body=response.read(),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    status=int(response.status),
                )
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", errors="replace").strip()
            raise AcceptanceError(
                f"{request.method} {urlsplit(self._url(path)).path} returned "
                f"HTTP {exc.code}: {detail}"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise AcceptanceError(
                f"{request.method} {urlsplit(self._url(path)).path} failed: {exc}"
            ) from exc

    def get_json(self, path: str) -> dict[str, Any]:
        response = self._request(path)
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcceptanceError(f"GET {path} did not return valid JSON") from exc
        if not isinstance(payload, dict):
            raise AcceptanceError(f"GET {path} did not return a JSON object")
        return payload

    def download(self, path: str) -> HttpDownload:
        return self._request(path)

    def post_json(
        self,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST one same-origin request and require a JSON-object response."""

        body = None
        headers: dict[str, str] = {}
        if payload is not None:
            body = json.dumps(
                dict(payload), ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        response = self._request(
            path,
            method="POST",
            body=body,
            headers=headers,
        )
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcceptanceError(f"POST {path} did not return valid JSON") from exc
        if not isinstance(value, dict):
            raise AcceptanceError(f"POST {path} did not return a JSON object")
        return value


class PlaywrightUiDriver:
    """Real Chromium UI driver; unavailable environments fail closed."""

    def start_ocr(
        self,
        config: AcceptanceConfig,
        *,
        expected_source_pages: int,
    ) -> UiStartEvidence:
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as exc:
            raise BrowserAutomationUnavailable(
                "browser_automation_unavailable: Python Playwright is not installed; "
                "the UI step was not executed"
            ) from exc

        timeout_ms = int(max(1.0, config.browser_timeout_seconds) * 1000)
        screenshot_path = config.output_dir / "ui-started.png"
        try:
            with sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(headless=not config.headed)
                except PlaywrightError as exc:
                    raise BrowserAutomationUnavailable(
                        "browser_automation_unavailable: Chromium could not be launched; "
                        "the UI step was not executed"
                    ) from exc
                try:
                    context = browser.new_context(accept_downloads=False)
                    page = context.new_page()
                    page.set_default_timeout(timeout_ms)
                    page.goto(config.base_url, wait_until="networkidle")
                    page.get_by_role("button", name="OCR 导入", exact=True).click()
                    page.get_by_role("heading", name="OCR 识别", exact=True).wait_for()
                    ui_version = page.locator(".brand-copy .sub").inner_text().strip()
                    file_input = page.locator(
                        'input[type="file"][accept*=".pdf"]'
                    )
                    if file_input.count() != 1:
                        raise AcceptanceError(
                            "the OCR UI did not expose exactly one PDF file input"
                        )
                    file_input.set_input_files(str(config.pdf))
                    total_locator = page.get_by_text(
                        re.compile(rf"PDF\s*共\s*{expected_source_pages}\s*页")
                    )
                    total_locator.wait_for()
                    total_text = total_locator.first.inner_text().strip()
                    total_match = re.search(r"PDF\s*共\s*(\d+)\s*页", total_text)
                    if total_match is None:
                        raise AcceptanceError("the OCR UI page count could not be read")
                    ui_source_pages = int(total_match.group(1))
                    page.get_by_label("起始页", exact=True).fill(str(config.start_page))
                    page.get_by_label("结束页", exact=True).fill(str(config.end_page))
                    tier = page.locator(
                        f'input[name="ocr-quality-tier"][value="{config.quality_tier}"]'
                    )
                    if tier.count() != 1:
                        raise AcceptanceError(
                            f"the OCR UI does not contain quality tier {config.quality_tier!r}"
                        )
                    tier.check()
                    expected_range = (
                        f"本次处理 {config.expected_pages} 页"
                        f"（原第 {config.start_page}-{config.end_page} 页）"
                    )
                    range_locator = page.get_by_text(expected_range, exact=False)
                    range_locator.wait_for()
                    selected_range_text = range_locator.first.inner_text().strip()
                    start_button = page.get_by_role(
                        "button", name="开始 OCR", exact=True
                    )
                    if not start_button.is_enabled():
                        readiness = page.locator(".ocr-config-status").inner_text().strip()
                        raise AcceptanceError(
                            "OCR UI start button is disabled: " + readiness[:500]
                        )
                    with page.expect_response(
                        lambda response: (
                            response.request.method == "POST"
                            and re.search(
                                r"/api/ocr/jobs/[0-9a-f]{32}/start(?:\?|$)",
                                response.url,
                            )
                            is not None
                        ),
                        timeout=timeout_ms,
                    ) as response_info:
                        start_button.click()
                    response = response_info.value
                    if not response.ok:
                        raise AcceptanceError(
                            f"OCR UI start request returned HTTP {response.status}"
                        )
                    payload = response.json()
                    job_id = str(payload.get("id") or "")
                    if re.fullmatch(r"[0-9a-f]{32}", job_id) is None:
                        raise AcceptanceError("OCR UI returned an invalid job id")
                    page.get_by_label("OCR 进度", exact=True).wait_for()
                    page.screenshot(path=str(screenshot_path), full_page=True)
                    return UiStartEvidence(
                        job_id=job_id,
                        source_total_pages=ui_source_pages,
                        ui_version_text=ui_version,
                        selected_range_text=selected_range_text,
                        start_response_status=int(response.status),
                        screenshot=screenshot_path.name,
                    )
                finally:
                    browser.close()
        except (PlaywrightTimeoutError, PlaywrightError) as exc:
            raise AcceptanceError(f"real browser UI flow failed: {exc}") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalized_commit(value: object) -> str:
    commit = str(value or "").strip().lower()
    return commit if COMMIT_RE.fullmatch(commit) else ""


def _positive_int(value: object) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, result)


def _model_call_count(snapshot: Mapping[str, Any]) -> int:
    usage = snapshot.get("usage")
    if isinstance(usage, Mapping):
        calls = _positive_int(usage.get("calls"))
        if calls:
            return calls
    # Older compatible servers expose bounded per-page attempt counts but no
    # aggregate usage counter.  Preserve that evidence explicitly rather than
    # inventing a smaller network-call count for batched requests.
    return sum(
        _positive_int(record.get("attempts"))
        for record in _page_records(snapshot)
    )


def _load_snapshot_artifact(
    config: AcceptanceConfig,
    evidence: RunEvidence,
) -> tuple[dict[str, Any], str]:
    artifact = evidence.artifacts.get("snapshot")
    if artifact is None:
        return {}, "snapshot artifact is unavailable"
    try:
        loaded = json.loads(
            (config.output_dir / artifact.filename).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {}, f"snapshot artifact cannot be read: {exc}"
    if not isinstance(loaded, dict):
        return {}, "snapshot artifact is not a JSON object"
    return loaded, ""


def _load_json_artifact(
    config: AcceptanceConfig,
    evidence: RunEvidence,
    role: str,
) -> tuple[dict[str, Any], str]:
    artifact = evidence.artifacts.get(role)
    if artifact is None:
        return {}, f"{role} artifact is unavailable"
    try:
        loaded = json.loads(
            (config.output_dir / artifact.filename).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {}, f"{role} artifact cannot be read: {exc}"
    if not isinstance(loaded, dict):
        return {}, f"{role} artifact is not a JSON object"
    return loaded, ""


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


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    _atomic_write(
        path,
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )


def _strict_zip_member(info: zipfile.ZipInfo) -> tuple[str, bool]:
    name = str(info.filename or "")
    if not name or "\x00" in name or "\\" in name:
        raise AcceptanceError("OCR package contains an invalid ZIP member path")
    is_directory = info.is_dir()
    logical = name[:-1] if is_directory and name.endswith("/") else name
    if (
        not logical
        or logical.startswith("/")
        or re.match(r"^[A-Za-z]:", logical)
    ):
        raise AcceptanceError("OCR package contains an absolute ZIP member path")
    member = PurePosixPath(logical)
    if (
        member.as_posix() != logical
        or any(part in {"", ".", ".."} for part in member.parts)
    ):
        raise AcceptanceError("OCR package contains a non-normalized ZIP member path")
    if info.flag_bits & 0x1:
        raise AcceptanceError("OCR package contains an encrypted ZIP member")
    mode = (int(info.external_attr) >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    allowed_types = {0, stat.S_IFDIR if is_directory else stat.S_IFREG}
    if file_type not in allowed_types or stat.S_ISLNK(mode):
        raise AcceptanceError("OCR package contains a link or special ZIP member")
    if info.file_size < 0 or info.file_size > MAX_PACKAGE_MEMBER_BYTES:
        raise AcceptanceError("OCR package ZIP member exceeds the size limit")
    if (
        info.file_size > 0
        and info.compress_size <= 0
        and info.compress_type != zipfile.ZIP_STORED
    ):
        raise AcceptanceError("OCR package ZIP member has invalid compression metadata")
    if (
        info.compress_size > 0
        and info.file_size / info.compress_size > 2000
    ):
        raise AcceptanceError("OCR package ZIP member compression ratio is unsafe")
    return logical, is_directory


def _verified_ocr_baseline_members(
    package_bytes: bytes,
    *,
    expected_source_sha256: str,
) -> tuple[dict[str, bytes], object]:
    """Read only the recomputable baseline subtree from a fully validated ZIP."""
    if not bytes(package_bytes).startswith(b"PK"):
        raise AcceptanceError("OCR package response is not a ZIP archive")
    try:
        archive = zipfile.ZipFile(BytesIO(package_bytes), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise AcceptanceError("OCR package response is not a valid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_PACKAGE_MEMBERS:
            raise AcceptanceError("OCR package ZIP member count is invalid")
        total_declared = sum(int(info.file_size) for info in infos)
        if total_declared > MAX_PACKAGE_TOTAL_BYTES:
            raise AcceptanceError("OCR package uncompressed size exceeds the limit")
        identities: set[str] = set()
        folded_identities: set[str] = set()
        selected: list[tuple[zipfile.ZipInfo, str]] = []
        for info in infos:
            logical, is_directory = _strict_zip_member(info)
            folded = logical.casefold()
            if logical in identities or folded in folded_identities:
                raise AcceptanceError("OCR package contains duplicate ZIP member paths")
            identities.add(logical)
            folded_identities.add(folded)
            if not is_directory and logical.startswith(OCR_BASELINE_ARCHIVE_PREFIX):
                relative = logical[len(OCR_BASELINE_ARCHIVE_PREFIX):]
                if not relative:
                    raise AcceptanceError("OCR baseline ZIP member path is empty")
                selected.append((info, relative))
        if not selected:
            raise AcceptanceError("OCR package lacks the recomputable baseline subtree")
        files: dict[str, bytes] = {}
        selected_total = 0
        for info, relative in selected:
            try:
                with archive.open(info, "r") as stream:
                    chunks: list[bytes] = []
                    size = 0
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        selected_total += len(chunk)
                        if (
                            size > MAX_PACKAGE_MEMBER_BYTES
                            or selected_total > MAX_PACKAGE_TOTAL_BYTES
                        ):
                            raise AcceptanceError(
                                "OCR baseline package exceeds the extraction limit"
                            )
                        chunks.append(chunk)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise AcceptanceError("OCR baseline ZIP member failed CRC validation") from exc
            if size != info.file_size:
                raise AcceptanceError("OCR baseline ZIP member size changed while reading")
            files[relative] = b"".join(chunks)

    manifest_bytes = files.get(OCR_BASELINE_MANIFEST_MEMBER)
    if manifest_bytes is None:
        raise AcceptanceError("OCR baseline package manifest is missing")
    artifacts = {
        path: data
        for path, data in files.items()
        if path != OCR_BASELINE_MANIFEST_MEMBER
    }
    try:
        from latexstruct.core.ocr_manifest import (
            OcrBaselineManifestError,
            verify_ocr_baseline_manifest,
        )
    except ImportError as exc:
        raise AcceptanceError(
            "OCR baseline production recomputation code is unavailable"
        ) from exc
    try:
        verified = verify_ocr_baseline_manifest(
            manifest_bytes,
            artifacts,
            expected_source_sha256=expected_source_sha256,
        )
    except OcrBaselineManifestError as exc:
        raise AcceptanceError(
            f"OCR baseline package failed production recomputation: {exc}"
        ) from exc
    return files, verified


def _download_ocr_baseline_package(
    api: AcceptanceApi,
    job_id: str,
    config: AcceptanceConfig,
    evidence: RunEvidence,
    *,
    source_sha256: str,
) -> None:
    try:
        response = api.download(f"/api/ocr/jobs/{job_id}/package")
        if response.status != 200:
            raise AcceptanceError("OCR package endpoint did not return HTTP 200")
        media_type = str(response.headers.get("content-type") or "").split(";", 1)[0]
        if media_type.strip().lower() not in {"application/zip", "application/x-zip-compressed"}:
            raise AcceptanceError("OCR package endpoint did not return a ZIP media type")
        files, verified = _verified_ocr_baseline_members(
            response.body,
            expected_source_sha256=source_sha256,
        )
        payload = verified.to_dict()
        run_id = str(payload.get("run_id") or "")
        if run_id != job_id:
            raise AcceptanceError("OCR baseline package run_id differs from the UI job")
        status = payload.get("status")
        compile_evidence = payload.get("compile")
        descriptors = payload.get("artifacts")
        if (
            not isinstance(status, Mapping)
            or not isinstance(compile_evidence, Mapping)
            or not isinstance(descriptors, list)
        ):
            raise AcceptanceError("OCR baseline package lacks compilation evidence")
        passes = compile_evidence.get("passes")
        if (
            not isinstance(passes, list)
            or not passes
            or not isinstance(passes[-1], Mapping)
        ):
            raise AcceptanceError("OCR baseline package lacks a final compile pass")
        final_pass = passes[-1]
        final_log_role = str(final_pass.get("log_role") or "")
        descriptors_by_role = {
            str(item.get("role") or ""): item
            for item in descriptors
            if isinstance(item, Mapping)
        }
        final_log = descriptors_by_role.get(final_log_role)
        baseline_pdf = descriptors_by_role.get("BASELINE_PDF")
        final_log_sha256 = (
            str(final_log.get("sha256") or "").lower()
            if isinstance(final_log, Mapping)
            else ""
        )
        baseline_pdf_sha256 = (
            str(baseline_pdf.get("sha256") or "").lower()
            if isinstance(baseline_pdf, Mapping)
            else ""
        )
        if SHA256_RE.fullmatch(final_log_sha256) is None:
            raise AcceptanceError("OCR baseline package final compile log is unbound")
        if baseline_pdf_sha256 and SHA256_RE.fullmatch(baseline_pdf_sha256) is None:
            raise AcceptanceError("OCR baseline package baseline PDF is unbound")
        package_compilation = {
            "status": str(status.get("compile_status") or ""),
            "successful_passes": compile_evidence.get("successful_passes"),
            "exit_code": final_pass.get("exit_code"),
            "compile_log_sha256": final_log_sha256,
            "baseline_pdf_sha256": baseline_pdf_sha256,
        }
        package_root = config.output_dir / OCR_BASELINE_PACKAGE_DIRECTORY
        if package_root.exists():
            raise AcceptanceError("OCR baseline evidence directory already exists")
        for relative, data in sorted(files.items()):
            target = package_root.joinpath(*PurePosixPath(relative).parts)
            _atomic_write(target, data)
        evidence.ocr_package_compilation = package_compilation
        evidence.ocr_baseline = {
            "package_directory": OCR_BASELINE_PACKAGE_DIRECTORY,
            "manifest_filename": (
                f"{OCR_BASELINE_PACKAGE_DIRECTORY}/{OCR_BASELINE_MANIFEST_MEMBER}"
            ),
            "manifest_sha256": verified.sha256,
            "run_id": run_id,
        }
        evidence.add_check(
            "ocr-baseline-package",
            True,
            dict(evidence.ocr_baseline),
        )
    except (AcceptanceError, OSError, ValueError) as exc:
        evidence.add_check("ocr-baseline-package", False, str(exc))


def count_pdf_pages(path: Path) -> int:
    try:
        import fitz
    except ModuleNotFoundError as exc:
        raise AcceptanceError(
            "PyMuPDF is unavailable, so the source PDF page count cannot be verified"
        ) from exc
    try:
        with fitz.open(path) as document:
            if not document.is_pdf:
                raise AcceptanceError("the selected source is not a valid PDF")
            return int(document.page_count)
    except AcceptanceError:
        raise
    except Exception as exc:  # PyMuPDF has version-specific exception classes.
        raise AcceptanceError(f"the source PDF could not be opened: {exc}") from exc


def _page_records(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = snapshot.get("page_records") or snapshot.get("pages") or {}
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, Mapping)]
    if not isinstance(raw, Mapping):
        return []
    records: list[dict[str, Any]] = []
    for key, value in raw.items():
        if not isinstance(value, Mapping):
            continue
        record = dict(value)
        record.setdefault("source_page", key)
        records.append(record)
    return records


def _record_status(record: Mapping[str, Any]) -> str:
    return str(record.get("final_status") or record.get("status") or "").upper()


def _page_number(record: Mapping[str, Any]) -> int | None:
    for key in ("source_page_number", "source_page", "page"):
        value = record.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number >= 1:
            return number
    return None


def derive_page_evidence(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    records = _page_records(snapshot)
    successful: list[int] = []
    needs_review: list[int] = []
    failed: list[int] = []
    pending: list[int] = []
    page_ids: list[str] = []
    for record in records:
        number = _page_number(record)
        status = _record_status(record)
        page_id = str(record.get("page_id") or "")
        if page_id:
            page_ids.append(page_id)
        if number is None:
            continue
        if status in SUCCESS_PAGE_STATUSES:
            successful.append(number)
        elif status in REVIEW_PAGE_STATUSES:
            needs_review.append(number)
        elif status in FAILED_PAGE_STATUSES:
            failed.append(number)
        else:
            pending.append(number)
    return {
        "record_count": len(records),
        "successful_pages": sorted(set(successful)),
        "needs_review_pages": sorted(set(needs_review)),
        "failed_pages": sorted(set(failed)),
        "pending_pages": sorted(set(pending)),
        "page_ids_present": len(page_ids),
        "page_ids_unique": len(page_ids) == len(set(page_ids)),
    }


def _compile_status(snapshot: Mapping[str, Any]) -> str:
    direct = str(snapshot.get("compile_status") or "").upper()
    if direct:
        return direct
    artifacts = snapshot.get("artifacts")
    if isinstance(artifacts, Mapping):
        baseline = artifacts.get("baseline_pdf")
        if isinstance(baseline, Mapping):
            return str(baseline.get("preview_status") or "").upper()
    metrics = snapshot.get("progress_metrics")
    if isinstance(metrics, Mapping):
        return str(metrics.get("compile_status") or "").upper()
    return ""


def _progress_marker(snapshot: Mapping[str, Any], elapsed: float) -> dict[str, Any]:
    metrics = snapshot.get("progress_metrics")
    metrics = metrics if isinstance(metrics, Mapping) else {}
    return {
        "elapsed_seconds": round(max(0.0, elapsed), 3),
        "status": str(snapshot.get("status") or ""),
        "phase": str(snapshot.get("phase") or ""),
        "done": int(snapshot.get("done") or 0),
        "total": int(snapshot.get("total") or metrics.get("total_pages") or 0),
        "average_pages_per_minute": metrics.get(
            "average_pages_per_minute", snapshot.get("average_pages_per_minute")
        ),
        "recent_pages_per_minute": metrics.get(
            "recent_pages_per_minute", snapshot.get("recent_pages_per_minute")
        ),
    }


def _poll_job(
    api: AcceptanceApi,
    job_id: str,
    config: AcceptanceConfig,
    evidence: RunEvidence,
    *,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
    started: float,
) -> dict[str, Any]:
    deadline = started + config.timeout_seconds
    last_marker: dict[str, Any] | None = None
    consecutive_errors = 0
    while True:
        now = monotonic()
        if now >= deadline:
            evidence.timed_out = True
            raise AcceptanceError(
                f"OCR polling timed out after {config.timeout_seconds:.1f} seconds"
            )
        try:
            snapshot = api.get_json(f"/api/ocr/jobs/{job_id}")
            consecutive_errors = 0
        except AcceptanceError as exc:
            consecutive_errors += 1
            if consecutive_errors > config.max_consecutive_poll_errors:
                raise AcceptanceError(
                    "OCR status remained unavailable after "
                    f"{consecutive_errors} attempts: {exc}"
                ) from exc
            sleep(config.poll_seconds)
            continue
        status = str(snapshot.get("status") or "").lower()
        marker = _progress_marker(snapshot, monotonic() - started)
        if marker != last_marker:
            evidence.poll_history.append(marker)
            last_marker = marker
        if status in TERMINAL_STATUSES:
            return snapshot
        if status not in ACTIVE_STATUSES:
            raise AcceptanceError(f"OCR returned unknown non-terminal status {status!r}")
        sleep(config.poll_seconds)


def _artifact_filename(role: str, compile_status: str, source_suffix: str) -> str:
    if role == "source":
        return "source" + (source_suffix if source_suffix.lower() == ".pdf" else ".bin")
    if role == "raw-ocr":
        return "raw-ocr.tex"
    if role == "baseline-tex":
        return "baseline.tex"
    if role == "compile-log":
        return "compile-baseline.log"
    if role == "snapshot":
        return "run-snapshot.json"
    if role == "baseline-manifest":
        return "baseline-manifest.json"
    if compile_status == "PARTIAL_COMPILED":
        return "partial-baseline.pdf"
    if compile_status == "SOURCE_PREVIEW":
        return "source-preview.pdf"
    return "baseline.pdf"


def _validate_artifact_bytes(role: str, data: bytes) -> str:
    if not data:
        return "artifact is empty"
    if role in {"source", "baseline-pdf"} and not data.startswith(b"%PDF-"):
        return "artifact is not a PDF"
    if role in {"raw-ocr", "baseline-tex"}:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return "artifact is not UTF-8 text"
        if not text.strip():
            return "artifact contains no TeX text"
    if role in {"snapshot", "baseline-manifest"}:
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "snapshot is not valid JSON"
        if not isinstance(value, dict):
            return "snapshot is not a JSON object"
    return ""


def _download_artifacts(
    api: AcceptanceApi,
    job_id: str,
    config: AcceptanceConfig,
    evidence: RunEvidence,
    compile_status: str,
) -> None:
    artifacts_dir = config.output_dir / "artifacts"
    for role in REQUIRED_ARTIFACTS:
        endpoint = f"/api/ocr/jobs/{job_id}/artifacts/{role}"
        try:
            response = api.download(endpoint)
            problem = _validate_artifact_bytes(role, response.body)
            if problem:
                raise AcceptanceError(problem)
            filename = _artifact_filename(role, compile_status, config.pdf.suffix)
            output = artifacts_dir / filename
            _atomic_write(output, response.body)
            record = DownloadedArtifact(
                role=role,
                filename=str(output.relative_to(config.output_dir)).replace("\\", "/"),
                sha256=_sha256_bytes(response.body),
                size=len(response.body),
                media_type=str(response.headers.get("content-type") or ""),
            )
            evidence.artifacts[role] = record
            evidence.add_check(
                f"artifact:{role}",
                True,
                {"filename": record.filename, "sha256": record.sha256, "size": record.size},
            )
        except (AcceptanceError, OSError) as exc:
            evidence.add_check(f"artifact:{role}", False, str(exc))


def _check(
    evidence: RunEvidence,
    check_id: str,
    passed: bool,
    success_evidence: Any,
    failure_evidence: Any | None = None,
) -> None:
    evidence.add_check(
        check_id,
        passed,
        success_evidence if passed or failure_evidence is None else failure_evidence,
    )


def _evaluate(
    config: AcceptanceConfig,
    evidence: RunEvidence,
    *,
    source_pages: int,
    source_sha256: str,
) -> dict[str, Any]:
    final = evidence.final_snapshot
    status = str(final.get("status") or "").lower()
    compile_status = _compile_status(final)
    pages = derive_page_evidence(final)
    expected_range = list(range(config.start_page, config.end_page + 1))
    observed_pages = sorted(
        pages["successful_pages"]
        + pages["needs_review_pages"]
        + pages["failed_pages"]
        + pages["pending_pages"]
    )

    _check(
        evidence,
        "real-runtime-drivers",
        evidence.real_execution,
        {"api_client": evidence.api_client, "ui_driver": evidence.ui_driver},
        "release acceptance requires LocalHttpApi plus PlaywrightUiDriver",
    )
    _check(evidence, "service-health", evidence.health.get("ok") is True, evidence.health)
    _check(
        evidence,
        "service-version",
        str(evidence.health.get("version") or "") == config.expected_version,
        str(evidence.health.get("version") or ""),
        f"expected {config.expected_version}, got {evidence.health.get('version')!r}",
    )
    observed_commit = _normalized_commit(evidence.health.get("commit"))
    expected_commit = _normalized_commit(config.expected_commit)
    _check(
        evidence,
        "service-commit",
        bool(expected_commit) and observed_commit == expected_commit,
        {"expected": expected_commit, "observed": observed_commit},
        "expected commit is missing/invalid or does not match /api/health",
    )
    observed_build_id = str(evidence.health.get("build_id") or "").strip()
    expected_build_id = str(config.expected_build_id or "").strip()
    _check(
        evidence,
        "service-build-id",
        bool(expected_build_id) and observed_build_id == expected_build_id,
        {"expected": expected_build_id, "observed": observed_build_id},
        "expected build id is missing or does not match /api/health",
    )
    _check(
        evidence,
        "tested-executable-sha256",
        bool(evidence.executable_filename)
        and SHA256_RE.fullmatch(evidence.executable_sha256) is not None,
        {
            "filename": evidence.executable_filename,
            "sha256": evidence.executable_sha256,
        },
        "the tested executable was not supplied and SHA-256 hashed",
    )
    _check(
        evidence,
        "ui-started-real-job",
        evidence.ui is not None
        and re.fullmatch(r"[0-9a-f]{32}", evidence.ui.job_id) is not None
        and evidence.ui.start_response_status < 400,
        asdict(evidence.ui) if evidence.ui else {},
        "the real UI did not return a valid OCR job",
    )
    _check(
        evidence,
        "ui-version",
        evidence.ui is not None and f"v{config.expected_version}" in evidence.ui.ui_version_text,
        evidence.ui.ui_version_text if evidence.ui else "missing",
    )
    _check(
        evidence,
        "ui-source-page-count",
        evidence.ui is not None and evidence.ui.source_total_pages == source_pages,
        {
            "ui_source_pages": evidence.ui.source_total_pages if evidence.ui else None,
            "verified_source_pages": source_pages,
        },
    )
    expected_range_text = (
        f"本次处理 {config.expected_pages} 页"
        f"（原第 {config.start_page}-{config.end_page} 页）"
    )
    _check(
        evidence,
        "ui-selected-range",
        evidence.ui is not None and expected_range_text in evidence.ui.selected_range_text,
        evidence.ui.selected_range_text if evidence.ui else "missing",
    )
    _check(
        evidence,
        "source-page-count",
        source_pages >= config.end_page,
        {"source_pages": source_pages, "selected_end": config.end_page},
    )
    selected_start = int(final.get("selected_start") or 0)
    selected_end = int(final.get("selected_end") or 0)
    selected_total = int(final.get("total") or 0)
    _check(
        evidence,
        "selected-range",
        (selected_start, selected_end, selected_total)
        == (config.start_page, config.end_page, config.expected_pages),
        {
            "start": selected_start,
            "end": selected_end,
            "total": selected_total,
            "expected_total": config.expected_pages,
        },
    )
    _check(evidence, "terminal-status", status == "done", status or "missing")
    _check(
        evidence,
        "raw-ocr-frozen",
        final.get("raw_frozen") is True and final.get("raw_ready") is True,
        {"raw_frozen": final.get("raw_frozen"), "raw_ready": final.get("raw_ready")},
    )
    _check(
        evidence,
        "compile-status-recognized",
        compile_status in VALID_COMPILE_STATUSES,
        compile_status or "missing",
    )
    _check(
        evidence,
        "compile-status-acceptance",
        compile_status == "COMPILED",
        compile_status or "missing",
        f"acceptance requires COMPILED, got {compile_status or 'missing'}",
    )
    _check(
        evidence,
        "page-record-coverage",
        pages["record_count"] == config.expected_pages and observed_pages == expected_range,
        {
            "record_count": pages["record_count"],
            "observed_pages": observed_pages,
            "expected_pages": expected_range,
        },
    )
    _check(
        evidence,
        "stable-unique-page-ids",
        pages["page_ids_present"] == config.expected_pages and pages["page_ids_unique"],
        {
            "present": pages["page_ids_present"],
            "expected": config.expected_pages,
            "unique": pages["page_ids_unique"],
        },
    )
    _check(
        evidence,
        "all-pages-successful",
        len(pages["successful_pages"]) == config.expected_pages
        and not pages["needs_review_pages"]
        and not pages["failed_pages"]
        and not pages["pending_pages"],
        pages,
    )
    source_artifact = evidence.artifacts.get("source")
    _check(
        evidence,
        "source-bytes-match-upload",
        source_artifact is not None and source_artifact.sha256 == source_sha256,
        {
            "uploaded_sha256": source_sha256,
            "downloaded_sha256": source_artifact.sha256 if source_artifact else None,
        },
    )
    baseline_binding = evidence.ocr_baseline
    _check(
        evidence,
        "ocr-baseline-binding",
        bool(baseline_binding)
        and baseline_binding.get("package_directory")
        == OCR_BASELINE_PACKAGE_DIRECTORY
        and baseline_binding.get("manifest_filename")
        == f"{OCR_BASELINE_PACKAGE_DIRECTORY}/{OCR_BASELINE_MANIFEST_MEMBER}"
        and SHA256_RE.fullmatch(
            str(baseline_binding.get("manifest_sha256") or "")
        )
        is not None
        and evidence.ui is not None
        and baseline_binding.get("run_id") == evidence.ui.job_id,
        baseline_binding or "recomputable OCR baseline package is unavailable",
    )
    snapshot_payload, snapshot_problem = _load_snapshot_artifact(config, evidence)
    try:
        snapshot_source_pages = int(snapshot_payload.get("source_total_pages") or 0)
    except (TypeError, ValueError):
        snapshot_source_pages = 0
    _check(
        evidence,
        "snapshot-bound-to-source-and-range",
        not snapshot_problem
        and snapshot_payload.get("source_sha256") == source_sha256
        and snapshot_source_pages == source_pages
        and snapshot_payload.get("selected_pages") == expected_range
        and str(snapshot_payload.get("app_version") or "") == config.expected_version,
        {
            "source_sha256": snapshot_payload.get("source_sha256"),
            "source_total_pages": snapshot_payload.get("source_total_pages"),
            "selected_pages": snapshot_payload.get("selected_pages"),
            "app_version": snapshot_payload.get("app_version"),
        },
        snapshot_problem or "immutable snapshot does not match the tested source/run",
    )
    model_id = str(snapshot_payload.get("ocr_model") or "").strip()
    api_backend = str(snapshot_payload.get("api_backend") or "").strip()
    observed_model = str(final.get("model") or "").strip()
    observed_backend = str(final.get("backend") or "").strip()
    _check(
        evidence,
        "model-bound-to-snapshot",
        bool(model_id)
        and bool(api_backend)
        and observed_model == model_id
        and observed_backend == api_backend,
        {
            "snapshot_model": model_id,
            "snapshot_backend": api_backend,
            "terminal_model": observed_model,
            "terminal_backend": observed_backend,
        },
    )
    model_calls = _model_call_count(final)
    _check(
        evidence,
        "real-model-calls-recorded",
        model_calls > 0,
        {"calls": model_calls},
        "no model-call evidence was recorded",
    )
    baseline_compile, baseline_problem = _load_json_artifact(
        config, evidence, "baseline-manifest"
    )
    successful_compile_passes = _positive_int(
        baseline_compile.get("successful_passes")
    )
    compile_exit_code = baseline_compile.get("exit_code")
    baseline_tex_artifact = evidence.artifacts.get("baseline-tex")
    baseline_pdf_artifact = evidence.artifacts.get("baseline-pdf")
    compile_log_artifact = evidence.artifacts.get("compile-log")
    terminal_compile = final.get("baseline_compile")
    terminal_compile = (
        dict(terminal_compile) if isinstance(terminal_compile, Mapping) else {}
    )
    _check(
        evidence,
        "two-successful-real-compile-passes",
        not baseline_problem
        and compile_status == "COMPILED"
        and baseline_compile.get("preview_status") == "COMPILED"
        and successful_compile_passes >= 2
        and compile_exit_code == 0,
        {
            "compile_status": compile_status,
            "successful_passes": successful_compile_passes,
            "exit_code": compile_exit_code,
        },
        baseline_problem or "immutable baseline manifest lacks two successful passes",
    )
    _check(
        evidence,
        "baseline-manifest-artifact-bindings",
        not baseline_problem
        and baseline_tex_artifact is not None
        and baseline_pdf_artifact is not None
        and compile_log_artifact is not None
        and baseline_compile.get("baseline_tex_sha256")
        == baseline_tex_artifact.sha256
        and baseline_compile.get("pdf_sha256") == baseline_pdf_artifact.sha256
        and baseline_compile.get("compile_log_sha256")
        == compile_log_artifact.sha256
        and all(
            terminal_compile.get(field) == baseline_compile.get(field)
            for field in ("preview_status", "successful_passes", "exit_code")
        ),
        {
            "baseline_tex_sha256": baseline_compile.get("baseline_tex_sha256"),
            "pdf_sha256": baseline_compile.get("pdf_sha256"),
            "compile_log_sha256": baseline_compile.get("compile_log_sha256"),
        },
        baseline_problem or "baseline manifest does not bind downloaded artifacts",
    )

    successful_count = len(pages["successful_pages"])
    wall = evidence.wall_time_seconds
    successful_ppm = (
        successful_count * 60.0 / wall
        if wall is not None and wall > 0 and successful_count > 0
        else None
    )
    if config.min_successful_ppm is not None:
        _check(
            evidence,
            "minimum-throughput",
            successful_ppm is not None and successful_ppm >= config.min_successful_ppm,
            {
                "successful_pages_per_minute": successful_ppm,
                "minimum": config.min_successful_ppm,
            },
        )
    if config.max_wall_seconds is not None:
        _check(
            evidence,
            "maximum-wall-time",
            wall is not None and wall <= config.max_wall_seconds,
            {"wall_time_seconds": wall, "maximum": config.max_wall_seconds},
        )
    return {
        "page_evidence": pages,
        "compile_status": compile_status,
        "successful_pages_per_minute": successful_ppm,
        "snapshot": snapshot_payload,
        "model_id": model_id,
        "api_backend": api_backend,
        "model_calls": model_calls,
        "successful_compile_passes": successful_compile_passes,
        "compile_exit_code": compile_exit_code,
    }


def _reports(
    config: AcceptanceConfig,
    evidence: RunEvidence,
    evaluation: Mapping[str, Any],
    *,
    source_pages: int | None,
    source_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    failed_checks = [asdict(check) for check in evidence.checks if not check.passed]
    passed = (
        bool(evidence.checks)
        and not failed_checks
        and not evidence.execution_errors
        and not evidence.timed_out
    )
    page_evidence = evaluation.get("page_evidence") or {}
    result = "PASS" if passed else ("INCOMPLETE" if evidence.timed_out else "FAIL")
    performance = {
        "schema_version": SCHEMA_VERSION,
        "acceptance_passed": passed,
        "result": result,
        "measurement": (
            "external monotonic wall clock started before browser upload/start click "
            "and stopped only after the OCR job reached a terminal compile state"
        ),
        "overall_started_at": evidence.overall_started_at,
        "measurement_started_at": evidence.measurement_started_at,
        "ocr_started_at": evidence.ocr_started_at,
        "ended_at": evidence.ended_at,
        "ui_setup_seconds": evidence.ui_setup_seconds,
        "wall_time_seconds": evidence.wall_time_seconds,
        "successful_pages_per_minute": evaluation.get("successful_pages_per_minute"),
        "terminal_status": str(evidence.final_snapshot.get("status") or "NOT_STARTED"),
        "compile_status": evaluation.get("compile_status") or "",
        "successful_compile_passes": evaluation.get("successful_compile_passes", 0),
        "compile_exit_code": evaluation.get("compile_exit_code"),
        "timed_out": evidence.timed_out,
        "completed_terminal_run": bool(evidence.final_snapshot) and not evidence.timed_out,
        "source": {
            "filename": config.pdf.name,
            "sha256": source_sha256,
            "total_pages": source_pages,
        },
        "selected_range": {
            "start_page": config.start_page,
            "end_page": config.end_page,
            "expected_pages": config.expected_pages,
        },
        "pages": {
            "successful": len(page_evidence.get("successful_pages") or []),
            "needs_review": len(page_evidence.get("needs_review_pages") or []),
            "failed": len(page_evidence.get("failed_pages") or []),
            "pending": len(page_evidence.get("pending_pages") or []),
            "failed_page_numbers": page_evidence.get("failed_pages") or [],
            "needs_review_page_numbers": page_evidence.get("needs_review_pages") or [],
        },
        "thresholds": {
            "minimum_successful_pages_per_minute": config.min_successful_ppm,
            "maximum_wall_time_seconds": config.max_wall_seconds,
        },
        "server_reported": {
            "average_pages_per_minute": evidence.final_snapshot.get(
                "average_pages_per_minute"
            ),
            "recent_pages_per_minute": evidence.final_snapshot.get(
                "recent_pages_per_minute"
            ),
        },
        "runtime_identity": {
            "version": str(evidence.health.get("version") or ""),
            "commit": _normalized_commit(evidence.health.get("commit")),
            "build_id": str(evidence.health.get("build_id") or ""),
            "executable_filename": evidence.executable_filename,
            "executable_sha256": evidence.executable_sha256,
        },
        "model": {
            "id": evaluation.get("model_id") or "",
            "backend": evaluation.get("api_backend") or "",
            "calls": evaluation.get("model_calls", 0),
        },
        "poll_history": evidence.poll_history,
    }
    validation = {
        "schema_version": SCHEMA_VERSION,
        "result": result,
        "acceptance_passed": passed,
        "generated_at": evidence.ended_at or _utc_now(),
        "job_id": evidence.ui.job_id if evidence.ui else "",
        "server": evidence.health,
        "execution": {
            "real_execution": evidence.real_execution,
            "test_double": not evidence.real_execution,
            "simulated": not evidence.real_execution,
            "api_client": evidence.api_client,
            "ui_driver": evidence.ui_driver,
        },
        "runtime_identity": performance["runtime_identity"],
        "model": performance["model"],
        "ui_evidence": asdict(evidence.ui) if evidence.ui else None,
        "checks": [asdict(check) for check in evidence.checks],
        "failed_checks": failed_checks,
        "execution_errors": evidence.execution_errors,
        "artifacts": {role: asdict(item) for role, item in evidence.artifacts.items()},
        "terminal_evidence": {
            "status": evidence.final_snapshot.get("status"),
            "selected_start": evidence.final_snapshot.get("selected_start"),
            "selected_end": evidence.final_snapshot.get("selected_end"),
            "total": evidence.final_snapshot.get("total"),
            "raw_frozen": evidence.final_snapshot.get("raw_frozen"),
            "raw_ready": evidence.final_snapshot.get("raw_ready"),
            "compile_status": evaluation.get("compile_status") or "",
            "successful_compile_passes": evaluation.get(
                "successful_compile_passes", 0
            ),
            "compile_exit_code": evaluation.get("compile_exit_code"),
            "page_evidence": page_evidence,
        },
    }
    return performance, validation


def _acceptance_attestation(
    config: AcceptanceConfig,
    evidence: RunEvidence,
    performance_path: Path,
    validation_path: Path,
    performance: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> dict[str, Any]:
    source = performance.get("source")
    source = dict(source) if isinstance(source, Mapping) else {}
    model = performance.get("model")
    model = dict(model) if isinstance(model, Mapping) else {}
    runtime = performance.get("runtime_identity")
    runtime = dict(runtime) if isinstance(runtime, Mapping) else {}
    compilation = dict(evidence.ocr_package_compilation)
    if not compilation:
        compilation = {
            "status": performance.get("compile_status") or "",
            "successful_passes": performance.get("successful_compile_passes", 0),
            "exit_code": performance.get("compile_exit_code"),
            "compile_log_sha256": (
                evidence.artifacts["compile-log"].sha256
                if "compile-log" in evidence.artifacts
                else ""
            ),
            "baseline_pdf_sha256": (
                evidence.artifacts["baseline-pdf"].sha256
                if "baseline-pdf" in evidence.artifacts
                else ""
            ),
        }
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "profile_kind": "ocr",
        "result": validation.get("result") or "FAIL",
        "acceptance_passed": validation.get("acceptance_passed") is True,
        "generated_at": validation.get("generated_at") or evidence.ended_at,
        "execution": validation.get("execution") or {},
        "runtime_identity": runtime,
        "source": source,
        "selected_range": performance.get("selected_range") or {},
        "pages": performance.get("pages") or {},
        "model": model,
        "compilation": compilation,
        "timing": {
            "measurement": performance.get("measurement") or "",
            "started_at": performance.get("measurement_started_at") or "",
            "ended_at": performance.get("ended_at") or "",
            "wall_time_seconds": performance.get("wall_time_seconds"),
            "successful_pages_per_minute": performance.get(
                "successful_pages_per_minute"
            ),
            "timed_out": performance.get("timed_out") is True,
            "completed_terminal_run": performance.get("completed_terminal_run")
            is True,
        },
        "reports": {
            "performance": {
                "filename": performance_path.name,
                "sha256": _sha256_file(performance_path),
            },
            "validation": {
                "filename": validation_path.name,
                "sha256": _sha256_file(validation_path),
            },
        },
        "ocr_baseline": dict(evidence.ocr_baseline),
    }


def run_acceptance(
    config: AcceptanceConfig,
    *,
    api: AcceptanceApi | None = None,
    ui_driver: UiDriver | None = None,
    pdf_page_counter: Callable[[Path], int] = count_pdf_pages,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    utc_now: Callable[[], str] = _utc_now,
) -> dict[str, Any]:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    evidence = RunEvidence(overall_started_at=utc_now())
    source_pages: int | None = None
    source_sha256 = ""
    evaluation: dict[str, Any] = {}
    ui_driver = ui_driver or PlaywrightUiDriver()
    evidence.ui_driver = type(ui_driver).__name__
    measurement_start: float | None = None
    try:
        api = api or LocalHttpApi(config.base_url)
        evidence.api_client = type(api).__name__
        evidence.real_execution = isinstance(api, LocalHttpApi) and isinstance(
            ui_driver, PlaywrightUiDriver
        )
        if not config.pdf.is_file():
            raise AcceptanceError("source PDF does not exist")
        if config.pdf.suffix.lower() != ".pdf":
            raise AcceptanceError("source must have a .pdf extension")
        if config.start_page < 1 or config.end_page < config.start_page:
            raise AcceptanceError("selected page range is invalid")
        if config.quality_tier not in {"fast", "recommended", "high"}:
            raise AcceptanceError("quality_tier must be fast, recommended, or high")
        if config.poll_seconds <= 0 or config.timeout_seconds <= 0:
            raise AcceptanceError("poll and timeout values must be positive")
        if (
            config.expected_pages == 600
            and config.timeout_seconds < LARGE_RUN_TIMEOUT_SECONDS
        ):
            raise AcceptanceError(
                "600-page acceptance requires a polling timeout of at least "
                f"{LARGE_RUN_TIMEOUT_SECONDS:.0f} seconds so a one-hour timeout "
                "cannot masquerade as a completed result"
            )
        if config.expected_pages == 600 and (
            config.min_successful_ppm is None
            or config.min_successful_ppm < 20
            or config.max_wall_seconds is None
            or config.max_wall_seconds > 1800
        ):
            raise AcceptanceError(
                "600-page acceptance requires at least 20 successful pages/minute "
                "and at most 1800 seconds wall time"
            )
        expected_commit = _normalized_commit(config.expected_commit)
        if not expected_commit:
            raise AcceptanceError("expected_commit must be a 40-64 character Git commit")
        if not str(config.expected_build_id or "").strip():
            raise AcceptanceError("expected_build_id is required")
        if config.executable is None or not config.executable.is_file():
            raise AcceptanceError("the tested executable does not exist")
        evidence.executable_filename = config.executable.name
        evidence.executable_sha256 = _sha256_file(config.executable)
        source_pages = pdf_page_counter(config.pdf)
        if config.end_page > source_pages:
            raise AcceptanceError(
                f"selected page {config.end_page} exceeds source page count {source_pages}"
            )
        source_sha256 = _sha256_file(config.pdf)
        evidence.health = api.get_json("/api/health")
        # This starts before Playwright uploads the file, configures the range,
        # and clicks Start.  It therefore cannot omit click/request latency.
        measurement_start = monotonic()
        evidence.measurement_started_at = utc_now()
        evidence.ocr_started_at = evidence.measurement_started_at
        evidence.ui = ui_driver.start_ocr(
            config, expected_source_pages=source_pages
        )
        evidence.ui_setup_seconds = round(monotonic() - measurement_start, 3)
        final = _poll_job(
            api,
            evidence.ui.job_id,
            config,
            evidence,
            monotonic=monotonic,
            sleep=sleep,
            started=measurement_start,
        )
        evidence.final_snapshot = final
        evidence.wall_time_seconds = round(
            max(0.0, monotonic() - measurement_start), 3
        )
        compile_status = _compile_status(final)
        _download_artifacts(
            api, evidence.ui.job_id, config, evidence, compile_status
        )
        if evidence.real_execution:
            _download_ocr_baseline_package(
                api,
                evidence.ui.job_id,
                config,
                evidence,
                source_sha256=source_sha256,
            )
        evaluation = _evaluate(
            config,
            evidence,
            source_pages=source_pages,
            source_sha256=source_sha256,
        )
    except (AcceptanceError, OSError, ValueError) as exc:
        evidence.execution_errors.append(str(exc))
        evidence.add_check("execution", False, str(exc))
        if measurement_start is not None:
            evidence.wall_time_seconds = round(
                max(0.0, monotonic() - measurement_start), 3
            )
    finally:
        evidence.ended_at = utc_now()
        performance, validation = _reports(
            config,
            evidence,
            evaluation,
            source_pages=source_pages,
            source_sha256=source_sha256,
        )
        performance_path = config.output_dir / "performance.json"
        validation_path = config.output_dir / "validation-report.json"
        _atomic_write_json(performance_path, performance)
        _atomic_write_json(validation_path, validation)
        attestation = _acceptance_attestation(
            config,
            evidence,
            performance_path,
            validation_path,
            performance,
            validation,
        )
        _atomic_write_json(
            config.output_dir / "acceptance-attestation.json", attestation
        )
        if validation.get("acceptance_passed") is True:
            try:
                RELEASE_INTEGRITY.verify_run_attestation(
                    config.output_dir,
                    expected_pages=config.expected_pages,
                    version=config.expected_version,
                    commit=config.expected_commit.lower(),
                    expected_source_sha256=source_sha256,
                )
            except Exception as exc:  # noqa: BLE001 - release boundary fails closed
                message = f"release-integrity self-verification failed: {exc}"
                evidence.execution_errors.append(message[:1000])
                evidence.add_check(
                    "release-integrity-self-verification",
                    False,
                    message[:1000],
                )
                performance, validation = _reports(
                    config,
                    evidence,
                    evaluation,
                    source_pages=source_pages,
                    source_sha256=source_sha256,
                )
                _atomic_write_json(performance_path, performance)
                _atomic_write_json(validation_path, validation)
                attestation = _acceptance_attestation(
                    config,
                    evidence,
                    performance_path,
                    validation_path,
                    performance,
                    validation,
                )
                _atomic_write_json(
                    config.output_dir / "acceptance-attestation.json",
                    attestation,
                )
    return validation


def _default_output(pdf: Path, start: int, end: int) -> Path:
    safe_stem = re.sub(r"[^0-9A-Za-z._-]+", "-", pdf.stem).strip("-.") or "pdf"
    return Path("output") / "playwright" / "v2-acceptance" / (
        f"{safe_stem[:60]}-p{start}-{end}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pdf", type=Path, help="PDF source passed through the real OCR UI")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--start-page", type=int, default=1)
    parser.add_argument("--end-page", type=int, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-version", default="2.0.0")
    parser.add_argument(
        "--expected-commit",
        required=True,
        help="Git commit expected from /api/health (40-64 lowercase hex characters)",
    )
    parser.add_argument(
        "--expected-build-id",
        required=True,
        help="build id expected from /api/health",
    )
    parser.add_argument(
        "--executable",
        type=Path,
        required=True,
        help="exact LaTeXStruct executable used by the tested service",
    )
    parser.add_argument(
        "--quality-tier", choices=("fast", "recommended", "high"), default="recommended"
    )
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        help=(
            "polling observation window; defaults to 4 hours for exactly 600 "
            "pages and 1 hour otherwise"
        ),
    )
    parser.add_argument("--browser-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument(
        "--min-ppm",
        type=float,
        help="minimum successful pages/minute; defaults to 20 for exactly 600 pages",
    )
    parser.add_argument(
        "--max-wall-seconds",
        type=float,
        help="maximum OCR wall time; defaults to 1800 for exactly 600 pages",
    )
    return parser


def _config_from_args(args: argparse.Namespace) -> AcceptanceConfig:
    expected_pages = args.end_page - args.start_page + 1
    min_ppm = args.min_ppm
    max_wall = args.max_wall_seconds
    timeout_seconds = args.timeout_seconds
    if expected_pages == 600:
        if min_ppm is None:
            min_ppm = 20.0
        if max_wall is None:
            max_wall = 1800.0
        if timeout_seconds is None:
            timeout_seconds = LARGE_RUN_TIMEOUT_SECONDS
    elif timeout_seconds is None:
        timeout_seconds = DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS
    output = args.output or _default_output(args.pdf, args.start_page, args.end_page)
    return AcceptanceConfig(
        base_url=args.base_url,
        pdf=args.pdf.resolve(),
        start_page=args.start_page,
        end_page=args.end_page,
        output_dir=output.resolve(),
        expected_version=args.expected_version,
        expected_commit=args.expected_commit,
        expected_build_id=args.expected_build_id,
        executable=args.executable.resolve(),
        quality_tier=args.quality_tier,
        poll_seconds=args.poll_seconds,
        timeout_seconds=timeout_seconds,
        browser_timeout_seconds=args.browser_timeout_seconds,
        headed=args.headed,
        min_successful_ppm=min_ppm,
        max_wall_seconds=max_wall,
    )


def main(argv: list[str] | None = None) -> int:
    config = _config_from_args(build_parser().parse_args(argv))
    validation = run_acceptance(config)
    result = str(validation.get("result") or "FAIL")
    print(f"v2 OCR acceptance: {result}")
    print(f"validation: {config.output_dir / 'validation-report.json'}")
    print(f"performance: {config.output_dir / 'performance.json'}")
    print(f"attestation: {config.output_dir / 'acceptance-attestation.json'}")
    print(
        "release note: this standalone runner emits diagnostic OCR evidence only; "
        "the stable gate requires strict analysis-37 with its nested ocr-37 prerequisite"
    )
    if validation.get("execution_errors"):
        for error in validation["execution_errors"]:
            print(f"error: {error}", file=sys.stderr)
    return 0 if validation.get("acceptance_passed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())

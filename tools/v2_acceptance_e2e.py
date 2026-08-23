#!/usr/bin/env python3
"""Fail-closed LaTeXStruct v2 OCR acceptance against a running service.

The browser performs the same upload/range/start flow as a user.  HTTP is then
used only for polling the created job and downloading immutable artifacts.  No
model setting or credential is accepted by this tool: it uses the configuration
already frozen by the running LaTeXStruct instance.

Examples::

    python tools/v2_acceptance_e2e.py book.pdf --end-page 17
    python tools/v2_acceptance_e2e.py book.pdf --end-page 600 \
        --output output/playwright/v2-acceptance/book-p1-600

Exit status is zero only when every machine check passes.  Missing browser
automation, status evidence, pages, hashes, or artifacts produces reports with
``acceptance_passed=false`` and a non-zero exit status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urljoin, urlsplit


SCHEMA_VERSION = "latexstruct-v2-ocr-acceptance/1"
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
)


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
    checks: list[Check] = field(default_factory=list)
    execution_errors: list[str] = field(default_factory=list)
    overall_started_at: str = ""
    ocr_started_at: str = ""
    ended_at: str = ""
    ui_setup_seconds: float | None = None
    wall_time_seconds: float | None = None
    timed_out: bool = False

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

    def _request(self, path: str) -> HttpDownload:
        request = urllib.request.Request(
            self._url(path),
            method="GET",
            headers={"Accept": "application/json, application/octet-stream"},
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
                f"GET {urlsplit(self._url(path)).path} returned HTTP {exc.code}: {detail}"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise AcceptanceError(
                f"GET {urlsplit(self._url(path)).path} failed: {exc}"
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
    if role == "snapshot":
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

    _check(evidence, "service-health", evidence.health.get("ok") is True, evidence.health)
    _check(
        evidence,
        "service-version",
        str(evidence.health.get("version") or "") == config.expected_version,
        str(evidence.health.get("version") or ""),
        f"expected {config.expected_version}, got {evidence.health.get('version')!r}",
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
    snapshot_payload: dict[str, Any] = {}
    snapshot_problem = "snapshot artifact is unavailable"
    snapshot_artifact = evidence.artifacts.get("snapshot")
    if snapshot_artifact is not None:
        try:
            snapshot_path = config.output_dir / snapshot_artifact.filename
            loaded = json.loads(snapshot_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                snapshot_payload = loaded
                snapshot_problem = ""
            else:
                snapshot_problem = "snapshot artifact is not a JSON object"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            snapshot_problem = f"snapshot artifact cannot be read: {exc}"
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
    performance = {
        "schema_version": SCHEMA_VERSION,
        "acceptance_passed": passed,
        "measurement": "external monotonic wall clock from OCR start acknowledgement to terminal status",
        "overall_started_at": evidence.overall_started_at,
        "ocr_started_at": evidence.ocr_started_at,
        "ended_at": evidence.ended_at,
        "ui_setup_seconds": evidence.ui_setup_seconds,
        "wall_time_seconds": evidence.wall_time_seconds,
        "successful_pages_per_minute": evaluation.get("successful_pages_per_minute"),
        "terminal_status": str(evidence.final_snapshot.get("status") or "NOT_STARTED"),
        "compile_status": evaluation.get("compile_status") or "",
        "timed_out": evidence.timed_out,
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
        "poll_history": evidence.poll_history,
    }
    validation = {
        "schema_version": SCHEMA_VERSION,
        "result": "PASS" if passed else "FAIL",
        "acceptance_passed": passed,
        "generated_at": evidence.ended_at or _utc_now(),
        "job_id": evidence.ui.job_id if evidence.ui else "",
        "server": evidence.health,
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
            "page_evidence": page_evidence,
        },
    }
    return performance, validation


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
    overall_start = monotonic()
    ocr_start: float | None = None
    ui_driver = ui_driver or PlaywrightUiDriver()
    try:
        api = api or LocalHttpApi(config.base_url)
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
        source_pages = pdf_page_counter(config.pdf)
        if config.end_page > source_pages:
            raise AcceptanceError(
                f"selected page {config.end_page} exceeds source page count {source_pages}"
            )
        source_sha256 = _sha256_file(config.pdf)
        evidence.health = api.get_json("/api/health")
        evidence.ui = ui_driver.start_ocr(
            config, expected_source_pages=source_pages
        )
        evidence.ui_setup_seconds = round(monotonic() - overall_start, 3)
        ocr_start = monotonic()
        evidence.ocr_started_at = utc_now()
        final = _poll_job(
            api,
            evidence.ui.job_id,
            config,
            evidence,
            monotonic=monotonic,
            sleep=sleep,
            started=ocr_start,
        )
        evidence.final_snapshot = final
        evidence.wall_time_seconds = round(max(0.0, monotonic() - ocr_start), 3)
        compile_status = _compile_status(final)
        _download_artifacts(
            api, evidence.ui.job_id, config, evidence, compile_status
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
        if ocr_start is not None:
            evidence.wall_time_seconds = round(max(0.0, monotonic() - ocr_start), 3)
    finally:
        evidence.ended_at = utc_now()
        performance, validation = _reports(
            config,
            evidence,
            evaluation,
            source_pages=source_pages,
            source_sha256=source_sha256,
        )
        _atomic_write_json(config.output_dir / "performance.json", performance)
        _atomic_write_json(config.output_dir / "validation-report.json", validation)
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
        "--quality-tier", choices=("fast", "recommended", "high"), default="recommended"
    )
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--timeout-seconds", type=float, default=3600.0)
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
    if expected_pages == 600:
        if min_ppm is None:
            min_ppm = 20.0
        if max_wall is None:
            max_wall = 1800.0
    output = args.output or _default_output(args.pdf, args.start_page, args.end_page)
    return AcceptanceConfig(
        base_url=args.base_url,
        pdf=args.pdf.resolve(),
        start_page=args.start_page,
        end_page=args.end_page,
        output_dir=output.resolve(),
        expected_version=args.expected_version,
        quality_tier=args.quality_tier,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
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
    if validation.get("execution_errors"):
        for error in validation["execution_errors"]:
            print(f"error: {error}", file=sys.stderr)
    return 0 if validation.get("acceptance_passed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())

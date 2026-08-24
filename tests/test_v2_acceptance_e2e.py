from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "tools" / "v2_acceptance_e2e.py"
SPEC = importlib.util.spec_from_file_location("v2_acceptance_e2e", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TEST_COMMIT = "c" * 40
TEST_BUILD_ID = "build-200"


class FakeClock:
    def __init__(self, step: float = 2.0):
        self.value = 100.0
        self.step = step
        self.utc_tick = 0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += max(self.step, seconds)

    def utc_now(self) -> str:
        self.utc_tick += 1
        return f"2026-08-23T00:00:0{self.utc_tick}Z"


class FakeUi:
    def __init__(self, source_pages: int = 17, error: Exception | None = None):
        self.source_pages = source_pages
        self.error = error
        self.calls = []

    def start_ocr(self, config, *, expected_source_pages):
        self.calls.append((config.start_page, config.end_page, expected_source_pages))
        if self.error:
            raise self.error
        return MODULE.UiStartEvidence(
            job_id="a" * 32,
            source_total_pages=self.source_pages,
            ui_version_text="LaTeXStruct v2.0.0",
            selected_range_text=(
                f"本次处理 {config.expected_pages} 页"
                f"（原第 {config.start_page}-{config.end_page} 页）"
            ),
            start_response_status=200,
            screenshot="ui-started.png",
        )


def _status(page_count: int, *, status: str = "done", compile_status: str = "COMPILED"):
    pages = {
        str(page): {
            "page_id": f"ocr-p{page:06d}",
            "source_page": page,
            "final_status": "SUCCESS",
            "attempts": 1,
        }
        for page in range(1, page_count + 1)
    }
    return {
        "id": "a" * 32,
        "status": status,
        "selected_start": 1,
        "selected_end": page_count,
        "total": page_count,
        "done": page_count,
        "raw_frozen": True,
        "raw_ready": True,
        "compile_status": compile_status,
        "baseline_compile": {
            "preview_status": compile_status,
            "successful_passes": 2 if compile_status == "COMPILED" else 0,
            "exit_code": 0 if compile_status == "COMPILED" else 1,
        },
        "model": "qwen-vl-test",
        "backend": "test-provider",
        "usage": {"calls": page_count},
        "pages": pages,
    }


class FakeApi:
    def __init__(self, source: bytes, statuses, missing: set[str] | None = None):
        self.source = source
        self.statuses = list(statuses)
        terminal = self.statuses[-1] if self.statuses else {}
        self.page_count = int(terminal.get("total") or 0)
        self.compile_status = str(terminal.get("compile_status") or "COMPILED")
        self.missing = missing or set()
        self.downloaded = []

    def get_json(self, path: str):
        if path == "/api/health":
            return {
                "ok": True,
                "version": "2.0.0",
                "commit": TEST_COMMIT,
                "build_id": TEST_BUILD_ID,
            }
        if not self.statuses:
            raise AssertionError("unexpected extra poll")
        if len(self.statuses) > 1:
            return self.statuses.pop(0)
        return self.statuses[0]

    def download(self, path: str):
        role = path.rsplit("/", 1)[-1]
        self.downloaded.append(role)
        if role in self.missing:
            raise MODULE.AcceptanceError(f"{role} missing")
        bodies = {
            "source": self.source,
            "raw-ocr": b"\\documentclass{article}\n\\begin{document}x\\end{document}\n",
            "baseline-tex": b"\\documentclass{article}\n\\begin{document}x\\end{document}\n",
            "baseline-pdf": b"%PDF-1.7\ncompiled\n",
            "compile-log": b"pass 1 ok\npass 2 ok\n",
            "snapshot": json.dumps(
                {
                    "run_id": "b" * 32,
                    "source_sha256": MODULE._sha256_bytes(self.source),
                    "source_total_pages": self.page_count,
                    "selected_pages": list(range(1, self.page_count + 1)),
                    "app_version": "2.0.0",
                    "ocr_model": "qwen-vl-test",
                    "api_backend": "test-provider",
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            "baseline-manifest": json.dumps(
                {
                    "preview_status": self.compile_status,
                    "successful_passes": (
                        2 if self.compile_status == "COMPILED" else 0
                    ),
                    "exit_code": 0 if self.compile_status == "COMPILED" else 1,
                    "baseline_tex_sha256": MODULE._sha256_bytes(
                        b"\\documentclass{article}\n\\begin{document}x\\end{document}\n"
                    ),
                    "compile_log_sha256": MODULE._sha256_bytes(
                        b"pass 1 ok\npass 2 ok\n"
                    ),
                    "pdf_sha256": MODULE._sha256_bytes(b"%PDF-1.7\ncompiled\n"),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        }
        media = "application/pdf" if role in {"source", "baseline-pdf"} else "text/plain"
        return MODULE.HttpDownload(bodies[role], {"content-type": media}, 200)


def _config(tmp_path: Path, pdf: Path, pages: int = 17, **overrides):
    executable = tmp_path / "LaTeXStruct.exe"
    executable.write_bytes(b"MZ\x00test executable")
    values = {
        "base_url": "http://127.0.0.1:8080",
        "pdf": pdf,
        "start_page": 1,
        "end_page": pages,
        "output_dir": tmp_path / "acceptance",
        "expected_commit": TEST_COMMIT,
        "expected_build_id": TEST_BUILD_ID,
        "executable": executable,
        "poll_seconds": 1,
        "timeout_seconds": 100,
    }
    values.update(overrides)
    return MODULE.AcceptanceConfig(**values)


def test_test_doubles_cannot_mint_release_pass_but_reports_are_recomputable(tmp_path: Path):
    source = b"%PDF-1.7\nsource bytes\n"
    pdf = tmp_path / "17-pages.pdf"
    pdf.write_bytes(source)
    clock = FakeClock()
    api = FakeApi(source, [{"status": "running", "total": 17}, _status(17)])
    ui = FakeUi()

    result = MODULE.run_acceptance(
        _config(tmp_path, pdf),
        api=api,
        ui_driver=ui,
        pdf_page_counter=lambda _path: 17,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utc_now=clock.utc_now,
    )

    assert result["acceptance_passed"] is False
    assert {item["id"] for item in result["failed_checks"]} == {
        "real-runtime-drivers"
    }
    assert ui.calls == [(1, 17, 17)]
    assert api.downloaded == list(MODULE.REQUIRED_ARTIFACTS)
    performance = json.loads(
        (tmp_path / "acceptance" / "performance.json").read_text(encoding="utf-8")
    )
    assert performance["pages"]["successful"] == 17
    assert performance["wall_time_seconds"] == 2
    assert performance["successful_pages_per_minute"] == 510
    assert performance["runtime_identity"]["commit"] == TEST_COMMIT
    assert performance["runtime_identity"]["build_id"] == TEST_BUILD_ID
    assert performance["runtime_identity"]["executable_sha256"] == MODULE._sha256_file(
        tmp_path / "LaTeXStruct.exe"
    )
    assert performance["model"] == {
        "id": "qwen-vl-test",
        "backend": "test-provider",
        "calls": 17,
    }
    assert performance["successful_compile_passes"] == 2
    raw = tmp_path / "acceptance" / "artifacts" / "raw-ocr.tex"
    assert result["artifacts"]["raw-ocr"]["sha256"] == MODULE._sha256_file(raw)
    attestation = json.loads(
        (tmp_path / "acceptance" / "acceptance-attestation.json").read_text(
            encoding="utf-8"
        )
    )
    assert attestation["result"] == "FAIL"
    assert attestation["execution"]["real_execution"] is False
    assert attestation["timing"]["measurement"].startswith(
        "external monotonic wall clock started before browser upload/start click"
    )


def test_missing_artifact_is_recorded_and_never_reported_as_pass(tmp_path: Path):
    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(source)
    clock = FakeClock()

    result = MODULE.run_acceptance(
        _config(tmp_path, pdf),
        api=FakeApi(source, [_status(17)], missing={"baseline-pdf"}),
        ui_driver=FakeUi(),
        pdf_page_counter=lambda _path: 17,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utc_now=clock.utc_now,
    )

    assert result["acceptance_passed"] is False
    failed = {item["id"] for item in result["failed_checks"]}
    assert "artifact:baseline-pdf" in failed
    assert "baseline-pdf" not in result["artifacts"]


def test_partial_source_preview_and_failed_page_remain_failed(tmp_path: Path):
    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(source)
    final = _status(17, status="partial", compile_status="SOURCE_PREVIEW")
    final["pages"]["7"]["final_status"] = "FAILED"
    clock = FakeClock()

    result = MODULE.run_acceptance(
        _config(tmp_path, pdf),
        api=FakeApi(source, [final]),
        ui_driver=FakeUi(),
        pdf_page_counter=lambda _path: 17,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utc_now=clock.utc_now,
    )

    assert result["acceptance_passed"] is False
    assert result["terminal_evidence"]["compile_status"] == "SOURCE_PREVIEW"
    assert result["terminal_evidence"]["page_evidence"]["failed_pages"] == [7]
    assert result["artifacts"]["baseline-pdf"]["filename"].endswith(
        "source-preview.pdf"
    )
    assert "compiled" not in result["artifacts"]["baseline-pdf"]["filename"]


def test_browser_unavailable_writes_fail_closed_reports_without_http_start(tmp_path: Path):
    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(source)
    clock = FakeClock()
    api = FakeApi(source, [])
    ui = FakeUi(
        error=MODULE.BrowserAutomationUnavailable(
            "browser_automation_unavailable: UI was not executed"
        )
    )

    result = MODULE.run_acceptance(
        _config(tmp_path, pdf),
        api=api,
        ui_driver=ui,
        pdf_page_counter=lambda _path: 17,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utc_now=clock.utc_now,
    )

    assert result["acceptance_passed"] is False
    assert "browser_automation_unavailable" in result["execution_errors"][0]
    performance = json.loads(
        (tmp_path / "acceptance" / "performance.json").read_text(encoding="utf-8")
    )
    assert performance["terminal_status"] == "NOT_STARTED"
    assert performance["successful_pages_per_minute"] is None


def test_600_page_defaults_and_slow_measurement_fail_thresholds(tmp_path: Path):
    parser = MODULE.build_parser()
    args = parser.parse_args([
        "book.pdf",
        "--end-page",
        "600",
        "--expected-commit",
        TEST_COMMIT,
        "--expected-build-id",
        TEST_BUILD_ID,
        "--executable",
        "LaTeXStruct.exe",
    ])
    config = MODULE._config_from_args(args)
    assert config.min_successful_ppm == 20
    assert config.max_wall_seconds == 1800
    assert config.timeout_seconds == MODULE.LARGE_RUN_TIMEOUT_SECONDS

    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "book.pdf"
    pdf.write_bytes(source)
    slow = _status(600)
    clock = FakeClock(step=1900)
    result = MODULE.run_acceptance(
        _config(
            tmp_path,
            pdf,
            pages=600,
            timeout_seconds=MODULE.LARGE_RUN_TIMEOUT_SECONDS,
            min_successful_ppm=20,
            max_wall_seconds=1800,
        ),
        api=FakeApi(source, [{"status": "running", "total": 600}, slow]),
        ui_driver=FakeUi(source_pages=600),
        pdf_page_counter=lambda _path: 654,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utc_now=clock.utc_now,
    )

    assert result["acceptance_passed"] is False
    failed = {item["id"] for item in result["failed_checks"]}
    assert {"minimum-throughput", "maximum-wall-time"} <= failed


def test_600_page_one_hour_timeout_is_rejected_before_ui_and_not_reported_complete(
    tmp_path: Path,
):
    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "book.pdf"
    pdf.write_bytes(source)
    ui = FakeUi(source_pages=600)

    result = MODULE.run_acceptance(
        _config(tmp_path, pdf, pages=600, timeout_seconds=3600),
        api=FakeApi(source, [_status(600)]),
        ui_driver=ui,
        pdf_page_counter=lambda _path: 600,
    )

    assert result["acceptance_passed"] is False
    assert result["result"] == "FAIL"
    assert ui.calls == []
    assert "one-hour timeout" in result["execution_errors"][0]
    performance = json.loads(
        (tmp_path / "acceptance" / "performance.json").read_text(encoding="utf-8")
    )
    assert performance["completed_terminal_run"] is False


def test_600_page_thresholds_cannot_be_disabled_programmatically(tmp_path: Path):
    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "book.pdf"
    pdf.write_bytes(source)
    ui = FakeUi(source_pages=600)

    result = MODULE.run_acceptance(
        _config(
            tmp_path,
            pdf,
            pages=600,
            timeout_seconds=MODULE.LARGE_RUN_TIMEOUT_SECONDS,
        ),
        api=FakeApi(source, [_status(600)]),
        ui_driver=ui,
        pdf_page_counter=lambda _path: 600,
    )

    assert result["acceptance_passed"] is False
    assert ui.calls == []
    assert "at least 20 successful pages/minute" in result["execution_errors"][0]


def test_poll_timeout_is_incomplete_never_a_terminal_acceptance(tmp_path: Path):
    source = b"%PDF-1.7\nsource\n"
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(source)
    clock = FakeClock(step=100)

    result = MODULE.run_acceptance(
        _config(tmp_path, pdf, timeout_seconds=10),
        api=FakeApi(source, [{"status": "running", "total": 17}]),
        ui_driver=FakeUi(),
        pdf_page_counter=lambda _path: 17,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        utc_now=clock.utc_now,
    )

    assert result["result"] == "INCOMPLETE"
    assert result["acceptance_passed"] is False
    attestation = json.loads(
        (tmp_path / "acceptance" / "acceptance-attestation.json").read_text(
            encoding="utf-8"
        )
    )
    assert attestation["result"] == "INCOMPLETE"
    assert attestation["timing"]["timed_out"] is True
    assert attestation["timing"]["completed_terminal_run"] is False

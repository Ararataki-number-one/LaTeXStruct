import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pymupdf
import pytest

from latexstruct.core import compilecheck
from latexstruct.core.preview import COMPILED, PARTIAL_COMPILED, SOURCE_PREVIEW


SIMPLE = "\\documentclass{article}\n\\begin{document}\nBody\n\\end{document}\n"


def _pdf_bytes(pages: int) -> bytes:
    document = pymupdf.open()
    try:
        for index in range(pages):
            page = document.new_page()
            page.insert_text((72, 72), f"page {index + 1}")
        return document.tobytes()
    finally:
        document.close()


def _fake_compile(monkeypatch, *, return_code: int, log: str, pdf_pages: int = 0):
    workdirs = []

    def fake_run(_command, *, cwd, capture_output, timeout, env):
        assert capture_output is True
        assert timeout > 0
        assert env["TEXMFVAR"] == env["TEXMFCACHE"]
        assert Path(env["TEXMFVAR"]).is_dir()
        workdirs.append(Path(cwd))
        rendered_log = log.replace("{workdir}", str(cwd))
        Path(cwd, "main.log").write_text(rendered_log, encoding="utf-8")
        if pdf_pages:
            Path(cwd, "main.pdf").write_bytes(_pdf_bytes(pdf_pages))
        return SimpleNamespace(returncode=return_code, stdout=b"", stderr=b"")

    monkeypatch.setattr(compilecheck, "find_xelatex", lambda: "xelatex-test")
    monkeypatch.setattr(compilecheck.subprocess, "run", fake_run)
    return workdirs


def test_artifact_captures_complete_pdf_and_full_sanitized_log(monkeypatch):
    prefix = "early-log-evidence\n" + ("x" * 5000)
    workdirs = _fake_compile(
        monkeypatch,
        return_code=0,
        pdf_pages=1,
        log=(
            prefix
            + "\nworking directory: {workdir}\n"
            + "Output written on main.pdf (1 page).\n"
        ),
    )

    artifact = compilecheck.compile_latex_artifact(SIMPLE)

    assert artifact["ok"] is True
    assert artifact["process_status"] == compilecheck.COMPILE_SUCCEEDED
    assert artifact["preview_status"] == COMPILED
    assert artifact["pages"] == 1
    assert artifact["page_count"] == 1
    assert artifact["engine"] == "xelatex-test"
    assert artifact["return_code"] == 0
    assert artifact["exit_code"] == 0
    assert artifact["passes_attempted"] == 1
    assert artifact["fatal_line"] is None
    assert artifact["fatal_error"] == ""
    assert artifact["pdf_bytes"].startswith(b"%PDF-")
    assert artifact["pdf_sha256"] == hashlib.sha256(
        artifact["pdf_bytes"]
    ).hexdigest()
    assert artifact["compile_input_sha256"] == artifact["input_manifest"][
        "manifest_sha256"
    ]
    assert artifact["log_path"] == "main.log"
    assert "early-log-evidence" in artifact["log"]
    assert "<compile-workdir>" in artifact["log"]
    assert str(workdirs[0]) not in artifact["log"]
    assert not workdirs[0].exists()


def test_fatal_compile_preserves_real_partial_pdf_and_fatal_line(monkeypatch):
    workdirs = _fake_compile(
        monkeypatch,
        return_code=1,
        pdf_pages=2,
        log=(
            "This is XeTeX\n"
            "! Missing $ inserted.\n"
            "<inserted text>\n"
            "                $\n"
            "l.95 \\end{equation}\n"
            "Output written on main.pdf (2 pages).\n"
        ),
    )

    artifact = compilecheck.compile_latex_artifact(SIMPLE)

    assert artifact["ok"] is False
    assert artifact["process_status"] == compilecheck.COMPILE_FAILED
    assert artifact["preview_status"] == PARTIAL_COMPILED
    assert artifact["pages"] == 2
    assert artifact["page_count"] == 2
    assert artifact["return_code"] == 1
    assert artifact["exit_code"] == 1
    assert artifact["passes_attempted"] == 1
    assert artifact["fatal_line"] == 95
    assert artifact["errors"] == ["Missing $ inserted. @l.95: \\end{equation}"]
    assert artifact["fatal_error"] == artifact["errors"][0]
    assert artifact["pdf_bytes"].startswith(b"%PDF-")
    assert artifact["pdf_sha256"] == hashlib.sha256(
        artifact["pdf_bytes"]
    ).hexdigest()
    assert not workdirs[0].exists()


def test_failed_compile_without_pdf_is_source_preview_not_compiled(monkeypatch):
    _fake_compile(
        monkeypatch,
        return_code=1,
        log="! Undefined control sequence.\nl.4 \\badcommand\n",
    )

    artifact = compilecheck.compile_latex_artifact(SIMPLE)

    assert artifact["preview_status"] == SOURCE_PREVIEW
    assert artifact["pages"] == 0
    assert artifact["pdf_bytes"] == b""
    assert artifact["fatal_line"] == 4


def test_preloaded_main_pdf_cannot_be_mistaken_for_failed_compile_output(monkeypatch):
    _fake_compile(
        monkeypatch,
        return_code=1,
        log="! Undefined control sequence.\nl.4 \\badcommand\n",
    )

    artifact = compilecheck.compile_latex_artifact(
        SIMPLE,
        extra_files={
            "MAIN.PDF": _pdf_bytes(1),
            "Main.AUX": b"stale auxiliary state",
            "main.toc": b"stale table of contents",
        },
    )

    assert artifact["ok"] is False
    assert artifact["preview_status"] == SOURCE_PREVIEW
    assert artifact["pages"] == 0
    assert artifact["pdf_bytes"] == b""


def test_compile_reserved_outputs_cannot_use_windows_trailing_aliases(tmp_path):
    compilecheck._write_compile_inputs(
        str(tmp_path),
        "selected candidate",
        {
            "main.pdf.": b"stale pdf",
            "MAIN.LOG ": b"stale log",
            "Main.Aux...": b"stale aux",
            "nested/main.pdf": b"legitimate nested resource",
        },
    )

    assert (tmp_path / "main.tex").read_text(encoding="utf-8") == "selected candidate"
    assert not any(
        path.name.rstrip(" .").casefold()
        in compilecheck.COMPILE_RESERVED_ROOT_FILENAMES
        for path in tmp_path.iterdir()
        if path.name.casefold() != "main.tex"
    )
    assert (tmp_path / "nested" / "main.pdf").read_bytes() == (
        b"legitimate nested resource"
    )


def test_compile_inputs_reject_other_windows_trailing_aliases(tmp_path):
    try:
        compilecheck._write_compile_inputs(
            str(tmp_path),
            "selected candidate",
            {"figures./plot.pdf": b"ambiguous path"},
        )
    except ValueError as exc:
        assert "Windows 尾随点或空格" in str(exc)
    else:
        raise AssertionError("Windows trailing-dot path must be rejected")


def test_compile_input_manifest_matches_materialized_closure():
    text = "\\documentclass{elegantbook}\n\\begin{document}x\\end{document}\n"
    extra = {
        "main.pdf": b"stale output",
        "chapters/one.tex": b"child",
        "assets/data.bin": b"resource",
    }

    prepared = compilecheck.prepare_compile_inputs(text, extra)
    manifest = compilecheck.build_compile_input_manifest(text, extra)

    assert set(prepared) == {
        "main.tex",
        "elegantbook.cls",
        "chapters/one.tex",
        "assets/data.bin",
    }
    assert manifest["schema"] == "latexstruct-compile-input-set-v1"
    assert manifest["file_count"] == len(prepared)
    assert {item["path"] for item in manifest["files"]} == set(prepared)
    for item in manifest["files"]:
        assert item["bytes"] == len(prepared[item["path"]])
        assert item["sha256"] == hashlib.sha256(prepared[item["path"]]).hexdigest()
    assert len(manifest["manifest_sha256"]) == 64


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "CON",
        "figures/aux.txt",
        "data:stream",
        "nested/NUL.bin",
        "nested/COM1 .txt",
    ],
)
def test_compile_inputs_reject_windows_device_and_ads_paths(unsafe_path):
    with pytest.raises(ValueError, match="Windows-unsafe|device name"):
        compilecheck.prepare_compile_inputs(SIMPLE, {unsafe_path: b"unsafe"})


def test_compile_inputs_reject_file_directory_prefix_collision():
    with pytest.raises(ValueError, match="file/directory path collision"):
        compilecheck.prepare_compile_inputs(
            SIMPLE,
            {"assets": b"file", "assets/figure.pdf": b"child"},
        )


def test_timeout_is_explicit_and_keeps_pdf_emitted_before_termination(monkeypatch):
    workdirs = []

    def timeout_run(command, *, cwd, capture_output, timeout, env):
        workdirs.append(Path(cwd))
        Path(cwd, "main.log").write_text(
            "! Emergency stop.\nl.27 \\loop\nOutput written on main.pdf (1 page).\n",
            encoding="utf-8",
        )
        Path(cwd, "main.pdf").write_bytes(_pdf_bytes(1))
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(compilecheck, "find_xelatex", lambda: "xelatex-test")
    monkeypatch.setattr(compilecheck.subprocess, "run", timeout_run)

    artifact = compilecheck.compile_latex_artifact(SIMPLE, timeout=7)

    assert artifact["process_status"] == compilecheck.COMPILE_TIMEOUT
    assert artifact["timed_out"] is True
    assert artifact["return_code"] is None
    assert artifact["exit_code"] is None
    assert artifact["passes_attempted"] == 1
    assert artifact["passes_completed"] == 0
    assert artifact["preview_status"] == PARTIAL_COMPILED
    assert artifact["pages"] == 1
    assert artifact["fatal_line"] == 27
    assert artifact["errors"][0] == "编译超时（>7s）"
    assert not workdirs[0].exists()


def test_unavailable_engine_requires_source_preview(monkeypatch):
    monkeypatch.setattr(compilecheck, "find_xelatex", lambda: None)

    artifact = compilecheck.compile_latex_artifact(SIMPLE)

    assert artifact["available"] is False
    assert artifact["ok"] is None
    assert artifact["process_status"] == compilecheck.COMPILE_UNAVAILABLE
    assert artifact["preview_status"] == SOURCE_PREVIEW
    assert artifact["return_code"] is None
    assert artifact["exit_code"] is None
    assert artifact["timed_out"] is False
    assert artifact["passes_attempted"] == 0
    assert artifact["input_manifest"]["schema"] == (
        "latexstruct-compile-input-set-v1"
    )
    assert artifact["pdf_bytes"] == b""


def test_explicit_disable_avoids_known_broken_local_tex_installation(monkeypatch):
    monkeypatch.setenv("LATEXSTRUCT_DISABLE_LATEX", "true")
    monkeypatch.setattr(
        compilecheck.shutil,
        "which",
        lambda _name: pytest.fail("disabled TeX must not be probed"),
    )

    assert compilecheck.find_xelatex() is None


def test_legacy_compile_result_remains_json_safe_and_omits_binary_pdf(monkeypatch):
    _fake_compile(
        monkeypatch,
        return_code=0,
        pdf_pages=1,
        log="Output written on main.pdf (1 page).\n",
    )

    result = compilecheck.compile_latex(SIMPLE)

    assert set(result) == {
        "engine",
        "available",
        "ok",
        "pages",
        "page_count",
        "errors",
        "fatal_error",
        "log",
        "log_path",
        "preview_status",
        "process_status",
        "pdf_sha256",
        "return_code",
        "exit_code",
        "fatal_line",
        "timed_out",
        "passes_requested",
        "passes_attempted",
        "passes_completed",
        "input_manifest",
        "compile_input_sha256",
    }
    assert result["ok"] is True
    assert result["preview_status"] == COMPILED
    assert result["process_status"] == compilecheck.COMPILE_SUCCEEDED
    assert result["return_code"] == 0
    assert result["fatal_line"] is None
    assert result["timed_out"] is False
    assert result["passes_requested"] == 1
    assert result["passes_attempted"] == 1
    assert result["passes_completed"] == 1
    assert "pdf_bytes" not in result
    json.dumps(result)


def test_compile_result_can_return_pdf_for_separate_persistence(monkeypatch):
    _fake_compile(
        monkeypatch,
        return_code=0,
        pdf_pages=1,
        log="Output written on main.pdf (1 page).\n",
    )

    result = compilecheck.compile_latex(SIMPLE, include_pdf=True)

    assert result["preview_status"] == COMPILED
    assert result["pdf_bytes"].startswith(b"%PDF-")


def test_second_pass_failure_is_partial_even_when_first_pass_made_pdf(monkeypatch):
    calls = 0

    def fake_run(_command, *, cwd, capture_output, timeout, env):
        nonlocal calls
        calls += 1
        Path(cwd, "main.pdf").write_bytes(_pdf_bytes(1))
        if calls == 1:
            Path(cwd, "main.log").write_text(
                "Output written on main.pdf (1 page).\n", encoding="utf-8"
            )
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        Path(cwd, "main.log").write_text(
            "! Undefined control sequence.\nl.8 \\bad\n"
            "Output written on main.pdf (1 page).\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")

    monkeypatch.setattr(compilecheck, "find_xelatex", lambda: "xelatex-test")
    monkeypatch.setattr(compilecheck.subprocess, "run", fake_run)

    artifact = compilecheck.compile_latex_artifact(
        SIMPLE.replace("Body", "\\tableofcontents\nBody")
    )

    assert calls == 2
    assert artifact["passes_requested"] == 2
    assert artifact["passes_attempted"] == 2
    assert artifact["passes_completed"] == 2
    assert artifact["ok"] is False
    assert artifact["preview_status"] == PARTIAL_COMPILED


@pytest.mark.skipif(compilecheck.os.name != "nt", reason="Windows-only guard")
def test_windows_crash_dialog_guard_is_inherited_and_restored(monkeypatch):
    calls = []

    def fake_set_error_mode(mode):
        calls.append(mode)
        return 0x20 if len(calls) == 1 else calls[-2]

    monkeypatch.setattr(compilecheck, "_set_windows_error_mode", fake_set_error_mode)
    monkeypatch.setattr(compilecheck, "_ERROR_MODE_USERS", 0)
    monkeypatch.setattr(compilecheck, "_ERROR_MODE_ORIGINAL", None)

    with compilecheck._suppress_windows_child_crash_dialogs():
        with compilecheck._suppress_windows_child_crash_dialogs():
            assert compilecheck._ERROR_MODE_USERS == 2

    assert calls == [
        0,
        0x20
        | compilecheck._SEM_FAILCRITICALERRORS
        | compilecheck._SEM_NOGPFAULTERRORBOX,
        0x20,
    ]
    assert compilecheck._ERROR_MODE_USERS == 0
    assert compilecheck._ERROR_MODE_ORIGINAL is None


@pytest.mark.parametrize(
    (
        "driver_log",
        "driver_stderr",
        "driver_return_code",
        "alternate_engine",
        "lua_engine",
    ),
    [
        (
            "Error -1073740777 (driver return code) generating output;\n"
            "file main.pdf may not be valid.\n",
            b"",
            1,
            None,
            "lualatex-test",
        ),
        (
            "TeX run ended before driver output.\n",
            b"xelatex.exe: fwrite: Broken pipe\r\n",
            1,
            None,
            "lualatex-test",
        ),
        (
            "TeX run ended before driver output.\n",
            b"xelatex.exe: fwrite: Broken pipe\r\n",
            1,
            "xelatex-legacy",
            "lualatex-test",
        ),
        (
            "TeX run ended before driver output.\n",
            b"xelatex.exe: fwrite: Broken pipe\r\n",
            1,
            "xelatex-legacy",
            None,
        ),
        (
            "TeX run ended without a driver diagnostic.\n",
            b"",
            0xC0000417,
            None,
            "lualatex-test",
        ),
        (
            "TeX run ended without a driver diagnostic.\n",
            b"",
            -1073740777,
            None,
            "lualatex-test",
        ),
    ],
)
def test_xdvipdfmx_windows_crash_retries_with_healthy_engine(
    monkeypatch,
    driver_log,
    driver_stderr,
    driver_return_code,
    alternate_engine,
    lua_engine,
):
    commands = []

    def fake_run(command, *, cwd, capture_output, timeout, env):
        commands.append(command[0])
        assert capture_output is True
        assert timeout > 0
        if command[0] == "xelatex-test":
            Path(cwd, "main.log").write_text(
                driver_log,
                encoding="utf-8",
            )
            Path(cwd, "main.xdv").write_bytes(b"broken")
            return SimpleNamespace(
                returncode=driver_return_code, stdout=b"", stderr=driver_stderr
            )
        if command[0] == "xelatex-legacy":
            assert "-no-pdf" in command
            Path(cwd, "main.log").write_text(
                "TeX pass completed and wrote main.xdv.\n", encoding="utf-8"
            )
            Path(cwd, "main.xdv").write_bytes(b"real-xdv")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if str(command[0]).replace("\\", "/").endswith("xdvipdfmx.exe"):
            Path(cwd, "main.pdf").write_bytes(_pdf_bytes(1))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        Path(cwd, "main.log").write_text(
            "Output written on main.pdf (1 page).\n", encoding="utf-8"
        )
        Path(cwd, "main.pdf").write_bytes(_pdf_bytes(1))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(compilecheck, "find_xelatex", lambda: "xelatex-test")
    monkeypatch.setattr(
        compilecheck,
        "find_alternate_xelatex",
        lambda _primary: alternate_engine,
    )
    monkeypatch.setattr(compilecheck, "find_lualatex", lambda: lua_engine)
    monkeypatch.setattr(compilecheck.subprocess, "run", fake_run)

    artifact = compilecheck.compile_latex_artifact(SIMPLE)

    expected_fallback = lua_engine or alternate_engine
    expected_commands = ["xelatex-test", expected_fallback]
    if expected_fallback == alternate_engine:
        expected_commands.append("xdvipdfmx.exe")
    assert commands == expected_commands
    assert artifact["ok"] is True
    assert artifact["engine"] == expected_fallback
    assert artifact["preview_status"] == COMPILED
    assert "0xc0000417" in artifact["log"]


def test_failed_lualatex_fallback_continues_to_alternate_xelatex(monkeypatch):
    commands = []

    def fake_run(command, *, cwd, capture_output, timeout, env):
        commands.append(command[0])
        if command[0] == "xelatex-test":
            Path(cwd, "main.log").write_text(
                "Error -1073740777 (driver return code)\n", encoding="utf-8"
            )
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        if command[0] == "lualatex-test":
            Path(cwd, "main.log").write_text(
                "! Undefined control sequence.\n", encoding="utf-8"
            )
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        if command[0] == "xelatex-legacy":
            assert "-no-pdf" in command
            Path(cwd, "main.log").write_text(
                "TeX pass completed and wrote main.xdv.\n", encoding="utf-8"
            )
            Path(cwd, "main.xdv").write_bytes(b"real-xdv")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        assert str(command[0]).replace("\\", "/").endswith("xdvipdfmx.exe")
        Path(cwd, "main.pdf").write_bytes(_pdf_bytes(1))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(compilecheck, "find_xelatex", lambda: "xelatex-test")
    monkeypatch.setattr(compilecheck, "find_lualatex", lambda: "lualatex-test")
    monkeypatch.setattr(
        compilecheck,
        "find_alternate_xelatex",
        lambda _primary: "xelatex-legacy",
    )
    monkeypatch.setattr(compilecheck.subprocess, "run", fake_run)

    artifact = compilecheck.compile_latex_artifact(SIMPLE)

    assert commands == [
        "xelatex-test",
        "lualatex-test",
        "xelatex-legacy",
        "xdvipdfmx.exe",
    ]
    assert artifact["ok"] is True
    assert artifact["engine"] == "xelatex-legacy"
    assert artifact["preview_status"] == COMPILED
    assert "fallback 1/2" in artifact["log"]
    assert "fallback 2/2" in artifact["log"]

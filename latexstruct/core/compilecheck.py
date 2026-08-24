# -*- coding: utf-8 -*-
"""LaTeX compile checks and immutable compile artifacts.

``compile_latex`` keeps the historical JSON-safe result used by the pipeline.
``compile_latex_artifact`` is the evidence-producing variant: it captures a
real PDF (including a valid PDF emitted before a fatal error), the complete
sanitized log and explicit process/preview state before deleting its temporary
working directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Dict, Optional

from .preview import SOURCE_PREVIEW, classify_compile_preview

PAGES_RE = re.compile(r"Output written on .*\((\d+) pages?")
ERROR_RE = re.compile(r"^! ", re.M)
FATAL_LINE_RE = re.compile(r"^l\.(\d+)\s*(.*)$")
XDV_DRIVER_CRASH_RE = re.compile(
    r"(?:Error\s+-1073740777\s+\(driver return code\)|0xc0000417|"
    r"xelatex(?:\.exe)?:\s*fwrite:\s*Broken pipe)",
    re.I,
)
_XDV_DRIVER_CRASH_EXIT_CODE = 0xC0000417
_XDV_DRIVER_CRASH_SIGNED_EXIT_CODE = _XDV_DRIVER_CRASH_EXIT_CODE - (1 << 32)

COMPILE_SUCCEEDED = "SUCCESS"
COMPILE_FAILED = "FAILED"
COMPILE_TIMEOUT = "TIMEOUT"
COMPILE_UNAVAILABLE = "UNAVAILABLE"
COMPILE_INPUT_MANIFEST_SCHEMA = "latexstruct-compile-input-set-v1"
COMPILE_WORKDIR_ID_PREFIX = "compile-workdir:sha256:"

# A broken TeX helper (notably ``xdvipdfmx.exe``) can otherwise display a
# modal Windows "application error" dialog. Such a dialog blocks unattended
# runs even though Python is correctly waiting for/capturing the compiler.
# SetErrorMode is inherited by child processes, so keep the process-wide mode
# active while any compiler invocation is running and restore it afterwards.
_SEM_FAILCRITICALERRORS = 0x0001
_SEM_NOGPFAULTERRORBOX = 0x0002
_ERROR_MODE_LOCK = threading.Lock()
_ERROR_MODE_USERS = 0
_ERROR_MODE_ORIGINAL: Optional[int] = None


def _set_windows_error_mode(mode: int) -> Optional[int]:
    """Set the Win32 process error mode, returning the previous value."""
    if os.name != "nt":
        return None
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        setter = kernel32.SetErrorMode
        setter.argtypes = [ctypes.c_uint]
        setter.restype = ctypes.c_uint
        return int(setter(int(mode)))
    except (AttributeError, OSError):
        # Compilation remains usable on unusual Windows runtimes. Failure to
        # install this UI guard is diagnostic-only; subprocess errors are still
        # captured by the normal compile result below.
        return None


@contextmanager
def _suppress_windows_child_crash_dialogs():
    """Prevent compiler/helper crashes from opening blocking system dialogs."""
    global _ERROR_MODE_ORIGINAL, _ERROR_MODE_USERS

    enabled = os.name == "nt"
    if enabled:
        with _ERROR_MODE_LOCK:
            if _ERROR_MODE_USERS == 0:
                previous = _set_windows_error_mode(0)
                if previous is None:
                    enabled = False
                else:
                    _ERROR_MODE_ORIGINAL = previous
                    _set_windows_error_mode(
                        previous | _SEM_FAILCRITICALERRORS | _SEM_NOGPFAULTERRORBOX
                    )
            if enabled:
                _ERROR_MODE_USERS += 1
    try:
        yield
    finally:
        if enabled:
            with _ERROR_MODE_LOCK:
                _ERROR_MODE_USERS -= 1
                if _ERROR_MODE_USERS == 0:
                    original = _ERROR_MODE_ORIGINAL
                    _ERROR_MODE_ORIGINAL = None
                    if original is not None:
                        _set_windows_error_mode(original)

# ``compile_latex`` owns these root-level paths in its private work directory.
# Project uploads may legitimately contain old build products, but seeding one
# here could make a failed run look like it emitted a partial PDF or could let
# stale auxiliary state influence the comparison.  Nested files with the same
# basename remain ordinary resources.
COMPILE_RESERVED_ROOT_FILENAMES = frozenset({
    "main.tex",
    "main.pdf",
    "main.log",
    "main.aux",
    "main.toc",
    "main.out",
    "main.xdv",
    "main.dvi",
    "main.ps",
    "main.synctex",
    "main.synctex.gz",
    "main.fls",
    "main.fdb_latexmk",
    "main.lof",
    "main.lot",
    "main.nav",
    "main.snm",
    "main.vrb",
})


def find_xelatex() -> Optional[str]:
    if os.environ.get("LATEXSTRUCT_DISABLE_LATEX", "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return None
    exe = shutil.which("xelatex")
    if exe:
        return exe
    for p in (
        r"C:\texlive\2026\bin\windows\xelatex.exe",
        r"C:\Program Files\MiKTeX\miktex\bin\x64\xelatex.exe",
    ):
        if os.path.exists(p):
            return p
    return None


def find_lualatex() -> Optional[str]:
    """Find the direct-PDF fallback used only after an xdvipdfmx crash."""
    exe = shutil.which("lualatex")
    if exe:
        return exe
    for p in (
        r"C:\texlive\2026\bin\windows\lualatex.exe",
        r"C:\Program Files\MiKTeX\miktex\bin\x64\lualatex.exe",
    ):
        if os.path.exists(p):
            return p
    return None


def find_alternate_xelatex(primary: str) -> Optional[str]:
    """Find a second installed XeLaTeX distribution after a driver crash."""
    primary_key = os.path.normcase(os.path.abspath(str(primary)))
    candidates: list[Path] = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry:
            candidates.append(Path(entry, "xelatex.exe"))
    texlive_root = Path(r"C:\texlive")
    try:
        candidates.extend(
            sorted(
                texlive_root.glob("*/bin/windows/xelatex.exe"),
                reverse=True,
            )
        )
    except OSError:
        pass
    seen = set()
    for candidate in candidates:
        try:
            candidate_key = os.path.normcase(os.path.abspath(str(candidate)))
        except OSError:
            continue
        if candidate_key == primary_key or candidate_key in seen:
            continue
        seen.add(candidate_key)
        if candidate.is_file():
            return str(candidate)
    return None


def _xdv_driver_crashed(return_code: Optional[int], log: str) -> bool:
    """Recognize xdvipdfmx failures even when Windows emits no console text."""
    if return_code is not None:
        normalized = int(return_code)
        if normalized in {
            _XDV_DRIVER_CRASH_EXIT_CODE,
            _XDV_DRIVER_CRASH_SIGNED_EXIT_CODE,
        }:
            return True
        if normalized >= 0 and normalized & 0xFFFFFFFF == _XDV_DRIVER_CRASH_EXIT_CODE:
            return True
    return bool(XDV_DRIVER_CRASH_RE.search(str(log or "")))


def _run_latex_engine(
    executable: str,
    *,
    workdir: str,
    timeout: int,
    environment: dict[str, str],
    passes_requested: int,
    no_pdf: bool = False,
    command_history: list[list[str]] | None = None,
) -> tuple[object, int, int, int]:
    """Run one TeX engine deterministically for the requested pass count."""
    process: object = None
    return_code = 0
    passes_attempted = 0
    passes_completed = 0
    for _ in range(passes_requested):
        passes_attempted += 1
        command = [
            executable,
            "-interaction=nonstopmode",
            "-halt-on-error",
        ]
        if no_pdf:
            command.append("-no-pdf")
        command.append("main.tex")
        if command_history is not None:
            # Capture the command before execution so a timeout still retains
            # exact invocation evidence.  Public serialization strips only
            # the executable's local directory below.
            command_history.append(list(command))
        try:
            process = subprocess.run(
                command,
                cwd=workdir,
                capture_output=True,
                timeout=timeout,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            # Preserve progress across the helper boundary; the caller still
            # owns the public timeout result and any partial PDF evidence.
            exc.latexstruct_passes_attempted = passes_attempted
            exc.latexstruct_passes_completed = passes_completed
            raise
        return_code = int(process.returncode)
        passes_completed += 1
        if return_code != 0:
            break
    return process, return_code, passes_attempted, passes_completed


def _compile_workdir_identifier(workdir: str) -> str:
    """Return an opaque per-directory identifier without exposing its path."""
    normalized = os.path.normcase(os.path.abspath(str(workdir)))
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"{COMPILE_WORKDIR_ID_PREFIX}{digest}"


def _public_compile_command(command: list[str]) -> list[str]:
    """Remove only the executable directory from an actual command."""
    if not command:
        return []
    public = [str(token) for token in command]
    public[0] = public[0].replace("\\", "/").rsplit("/", 1)[-1]
    return public


def _public_compile_commands(command_history: list[list[str]]) -> list[list[str]]:
    return [_public_compile_command(command) for command in command_history]


def _selected_engine_command(command_history: list[list[str]]) -> list[str]:
    """Return the last actual TeX-engine command, excluding a PDF driver."""
    for command in reversed(command_history):
        if command and command[-1] == "main.tex":
            return _public_compile_command(command)
    return _public_compile_command(command_history[-1]) if command_history else []


def _clear_failed_engine_outputs(workdir: str) -> None:
    """Remove only private compiler outputs before a clean fallback attempt."""
    for name in COMPILE_RESERVED_ROOT_FILENAMES:
        if name == "main.tex":
            continue
        try:
            Path(workdir, name).unlink(missing_ok=True)
        except OSError:
            # A locked corrupt output will make the fallback fail normally; it
            # must never make us delete anything outside the private workdir.
            pass


def _compiler_environment(workdir: str) -> dict[str, str]:
    """Give TeX a private writable cache without changing user environment."""
    environment = dict(os.environ)
    candidates = []
    app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if app_data:
        candidates.append(Path(app_data, "LaTeXStruct", "cache", "texmf"))
    temporary_root = Path(tempfile.gettempdir())
    try:
        temporary_is_cwd = temporary_root.resolve() == Path.cwd().resolve()
    except OSError:
        temporary_is_cwd = False
    candidates.append(
        Path.cwd() / ".test-tmp" / "texmf-cache"
        if temporary_is_cwd
        else temporary_root / "LaTeXStruct" / "texmf-cache"
    )
    candidates.append(Path(workdir, ".texmf-cache"))

    cache_path = candidates[-1]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=candidate):
                pass
        except OSError:
            continue
        cache_path = candidate
        break
    cache_value = str(cache_path)
    # LuaTeX/fontconfig can fail before reading the document if the global TeX
    # cache is read-only. A per-run cache is deterministic, private and removed
    # together with the compile work directory.
    environment["TEXMFVAR"] = cache_value
    environment["TEXMFCACHE"] = cache_value
    return environment


def _sanitize_compile_log(log: str, workdir: str) -> str:
    """Remove the per-run temporary absolute path without truncating the log."""
    sanitized = str(log or "")
    candidates = {
        str(workdir),
        os.path.abspath(workdir),
        str(Path(workdir).resolve()),
        Path(workdir).resolve().as_posix(),
    }
    for candidate in sorted((item for item in candidates if item), key=len, reverse=True):
        # TeX and Python may render the same Windows path with either separator.
        variants = {
            candidate,
            candidate.replace("\\", "/"),
            candidate.replace("/", "\\"),
        }
        for variant in variants:
            sanitized = re.sub(
                re.escape(variant), "<compile-workdir>", sanitized, flags=re.I
            )
    return sanitized


def _process_output_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _read_compile_log(workdir: str, process: object = None) -> str:
    log_path = os.path.join(workdir, "main.log")
    file_log = ""
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            file_log = handle.read()
    stdout = _process_output_text(getattr(process, "stdout", ""))
    stderr = _process_output_text(getattr(process, "stderr", ""))
    parts = [file_log] if file_log else []
    # XeLaTeX writes driver-process failures to its console after main.log is
    # closed. Preserve those streams as evidence instead of silently returning
    # only the apparently clean TeX log.
    for label, stream in (("stdout", stdout), ("stderr", stderr)):
        if not stream:
            continue
        if not file_log:
            parts.extend((f"[compiler {label}]", stream))
            continue
        # Console output normally repeats almost all of main.log.  Appending
        # it wholesale duplicates typeout markers and error messages, while
        # the one class of evidence missing from main.log is the late
        # xdvipdfmx/pipe crash. Preserve just those unique diagnostic lines.
        diagnostics = []
        for line in stream.splitlines():
            cleaned = line.strip()
            if (
                cleaned
                and XDV_DRIVER_CRASH_RE.search(cleaned)
                and cleaned not in file_log
                and cleaned not in diagnostics
            ):
                diagnostics.append(cleaned)
        if diagnostics:
            parts.extend((f"[compiler {label}]", "\n".join(diagnostics)))
    return "\n".join(part for part in parts if part)


def _compile_errors(log: str) -> tuple[list[str], Optional[int]]:
    errors: list[str] = []
    fatal_line: Optional[int] = None
    lines = str(log or "").split("\n")
    for index, line in enumerate(lines):
        if not line.startswith("!"):
            continue
        message = line[1:].strip() or "（错误详情见下行）"
        for detail in lines[index + 1 : index + 9]:
            line_match = FATAL_LINE_RE.match(detail)
            if not line_match:
                continue
            line_number = int(line_match.group(1))
            if fatal_line is None:
                fatal_line = line_number
            source = line_match.group(2).strip()
            message += f" @l.{line_number}"
            if source:
                message += ": " + source[:80]
            break
        errors.append(message[:140])
    return errors[:5], fatal_line


def _valid_pdf_bytes(workdir: str) -> tuple[bytes, int]:
    """Return only a readable, non-empty PDF and its actual page count."""
    pdf_path = os.path.join(workdir, "main.pdf")
    try:
        payload = Path(pdf_path).read_bytes()
    except OSError:
        return b"", 0
    if not payload.startswith(b"%PDF-"):
        return b"", 0
    try:
        import pymupdf

        with pymupdf.open(stream=payload, filetype="pdf") as document:
            pages = int(document.page_count)
    except Exception:  # noqa: BLE001 - corrupt output is not a usable preview artifact
        return b"", 0
    return (payload, pages) if pages > 0 else (b"", 0)


def prepare_compile_inputs(text: str, extra_files: dict = None) -> dict[str, bytes]:
    """Return the exact path/byte mapping materialized in the TeX workdir."""
    compile_files = dict(extra_files or {})
    from .template import uses_elegantbook_class

    if uses_elegantbook_class(text):
        from ..elegantbook import CLASS_FILENAME, elegantbook_class_bytes

        compile_files.setdefault(CLASS_FILENAME, elegantbook_class_bytes())

    prepared = {"main.tex": str(text).encode("utf-8")}
    folded_paths = {"main.tex": "main.tex"}
    for rel, data in compile_files.items():
        safe = PurePosixPath(str(rel).replace("\\", "/"))
        if safe.is_absolute() or any(part in ("", ".", "..") for part in safe.parts):
            raise ValueError(f"编译附加文件路径不安全：{rel!r}")
        # Win32 aliases each component after trimming trailing dots/spaces.
        # Recognize root compiler outputs under that canonical form, and reject
        # every other ambiguous path rather than writing to a different file
        # than the audit record names.
        windows_name = safe.name.rstrip(" .").casefold()
        if len(safe.parts) == 1 and windows_name in COMPILE_RESERVED_ROOT_FILENAMES:
            continue
        if any(part.endswith((".", " ")) for part in safe.parts):
            raise ValueError(f"编译附加文件路径含 Windows 尾随点或空格：{rel!r}")
        normalized = safe.as_posix()
        folded = normalized.casefold()
        previous = folded_paths.get(folded)
        if previous is not None:
            raise ValueError(f"编译输入路径大小写冲突：{previous!r}、{normalized!r}")
        folded_paths[folded] = normalized
        prepared[normalized] = bytes(data)
    from .runbundle import validate_archive_namespace

    validate_archive_namespace(
        [(path, False) for path in prepared],
    )
    return prepared


def _manifest_from_prepared_inputs(prepared: dict[str, bytes]) -> dict:
    body = {
        "schema": COMPILE_INPUT_MANIFEST_SCHEMA,
        "file_count": len(prepared),
        "files": [
            {
                "path": path,
                "bytes": len(prepared[path]),
                "sha256": hashlib.sha256(prepared[path]).hexdigest(),
            }
            for path in sorted(prepared)
        ],
    }
    canonical = json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        **body,
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def build_compile_input_manifest(text: str, extra_files: dict = None) -> dict:
    """Build a deterministic digest inventory for the exact compile closure."""
    return _manifest_from_prepared_inputs(prepare_compile_inputs(text, extra_files))


def _write_materialized_compile_inputs(
    workdir: str, prepared: dict[str, bytes]
) -> None:
    for rel, data in prepared.items():
        safe = PurePosixPath(rel)
        path = os.path.join(workdir, *safe.parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)


def _write_compile_inputs(workdir: str, text: str, compile_files: dict) -> None:
    """Compatibility wrapper used by focused filesystem safety tests."""
    _write_materialized_compile_inputs(
        workdir, prepare_compile_inputs(text, compile_files)
    )


def compile_latex_artifact(
    text: str,
    timeout: int = 240,
    extra_files: dict = None,
) -> Dict:
    """Compile and return both machine state and the immutable PDF/log evidence.

    ``preview_status`` is always one of ``COMPILED``, ``PARTIAL_COMPILED`` or
    ``SOURCE_PREVIEW``. The last value explicitly means that ``pdf_bytes`` is
    empty: callers may generate a line-numbered source rendering, but must not
    describe it as a LaTeX compilation.
    """
    prepared_inputs = prepare_compile_inputs(text, extra_files)
    input_manifest = _manifest_from_prepared_inputs(prepared_inputs)
    exe = find_xelatex()
    if not exe:
        return {
            "engine": "xelatex",
            "available": False,
            "ok": None,
            "process_status": COMPILE_UNAVAILABLE,
            "preview_status": SOURCE_PREVIEW,
            "pages": 0,
            "page_count": 0,
            "logged_pages": 0,
            "errors": [],
            "fatal_error": "",
            "log": "",
            "log_path": "main.log",
            "pdf_bytes": b"",
            "pdf_sha256": "",
            "return_code": None,
            "exit_code": None,
            "fatal_line": None,
            "timed_out": False,
            "passes_requested": 0,
            "passes_attempted": 0,
            "passes_completed": 0,
            "command": [],
            "command_history": [],
            "compile_workdir": None,
            "input_manifest": input_manifest,
            "compile_input_sha256": input_manifest["manifest_sha256"],
        }

    workdir = tempfile.mkdtemp(prefix="ls-compile-")
    compile_workdir = _compile_workdir_identifier(workdir)
    command_history: list[list[str]] = []
    process = None
    engine_exe = exe
    fallback_notices: list[str] = []
    timed_out = False
    passes_requested = 2 if any(
        token in text
        for token in ("\\tableofcontents", "\\ref{", "\\pageref{", "\\cite{")
    ) else 1
    passes_attempted = 0
    passes_completed = 0
    return_code: Optional[int] = None
    try:
        _write_materialized_compile_inputs(workdir, prepared_inputs)
        compiler_environment = _compiler_environment(workdir)
        try:
            with _suppress_windows_child_crash_dialogs():
                (
                    process,
                    return_code,
                    passes_attempted,
                    passes_completed,
                ) = _run_latex_engine(
                    exe,
                    workdir=workdir,
                    timeout=timeout,
                    environment=compiler_environment,
                    passes_requested=passes_requested,
                    command_history=command_history,
                )
                first_log = _read_compile_log(workdir, process)
                fallback_engines: list[str] = []
                if return_code != 0 and _xdv_driver_crashed(return_code, first_log):
                    # LuaLaTeX writes PDF directly and avoids the failing
                    # xdvipdfmx path entirely. Prefer it first; an independent
                    # XeLaTeX installation remains a final compatibility
                    # fallback when LuaLaTeX is unavailable or rejects the
                    # otherwise valid XeLaTeX document.
                    lua_exe = find_lualatex()
                    alternate_xe = find_alternate_xelatex(exe)
                    for candidate in (lua_exe, alternate_xe):
                        if candidate and candidate not in fallback_engines:
                            fallback_engines.append(candidate)
                for fallback_index, fallback_exe in enumerate(fallback_engines):
                    fallback_engine = (
                        str(fallback_exe)
                        .replace("\\", "/")
                        .rsplit("/", 1)[-1]
                    )
                    fallback_is_xelatex = fallback_engine.casefold().startswith(
                        "xelatex"
                    )
                    fallback_notices.append(
                        "[LaTeXStruct] xdvipdfmx crashed with Windows exception "
                        "0xc0000417; retried the unchanged compile input with "
                        f"{fallback_engine} (fallback {fallback_index + 1}/"
                        f"{len(fallback_engines)})."
                    )
                    _clear_failed_engine_outputs(workdir)
                    engine_exe = fallback_exe
                    fallback_environment = dict(compiler_environment)
                    fallback_directory = str(Path(fallback_exe).parent)
                    fallback_environment["PATH"] = os.pathsep.join(
                        part
                        for part in (
                            fallback_directory,
                            compiler_environment.get("PATH", ""),
                        )
                        if part
                    )
                    (
                        process,
                        return_code,
                        passes_attempted,
                        passes_completed,
                    ) = _run_latex_engine(
                        fallback_exe,
                        workdir=workdir,
                        timeout=timeout,
                        environment=fallback_environment,
                        passes_requested=passes_requested,
                        no_pdf=fallback_is_xelatex,
                        command_history=command_history,
                    )
                    if fallback_is_xelatex and Path(workdir, "main.xdv").is_file():
                        tex_return_code = return_code
                        driver_exe = str(
                            Path(fallback_exe).with_name("xdvipdfmx.exe")
                        )
                        driver_command = [
                            driver_exe,
                            "-o",
                            "main.pdf",
                            "main.xdv",
                        ]
                        command_history.append(driver_command)
                        process = subprocess.run(
                            driver_command,
                            cwd=workdir,
                            capture_output=True,
                            timeout=timeout,
                            env=fallback_environment,
                        )
                        driver_return_code = int(process.returncode)
                        return_code = (
                            tex_return_code
                            if tex_return_code not in (None, 0)
                            else driver_return_code
                        )
                    if return_code == 0:
                        break
        except subprocess.TimeoutExpired as exc:
            process = exc
            timed_out = True
            return_code = None
            passes_attempted = int(
                getattr(exc, "latexstruct_passes_attempted", passes_attempted)
            )
            passes_completed = int(
                getattr(exc, "latexstruct_passes_completed", passes_completed)
            )

        raw_log = _read_compile_log(workdir, process)
        if fallback_notices:
            raw_log = "\n".join((*fallback_notices, raw_log))
        log = _sanitize_compile_log(raw_log, workdir)
        cache_path = compiler_environment.get("TEXMFCACHE", "")
        if cache_path and not Path(cache_path).is_relative_to(Path(workdir)):
            for variant in {
                cache_path,
                cache_path.replace("\\", "/"),
                cache_path.replace("/", "\\"),
            }:
                log = re.sub(re.escape(variant), "<tex-cache>", log, flags=re.I)
        errors, fatal_line = _compile_errors(log)
        pdf_bytes, actual_pages = _valid_pdf_bytes(workdir)
        match = PAGES_RE.search(log)
        logged_pages = int(match.group(1)) if match else 0
        # ``pages`` always describes the captured PDF. A log assertion without
        # a readable PDF remains separate diagnostic evidence.
        pages = actual_pages

        if timed_out:
            timeout_error = f"编译超时（>{timeout}s）"
            errors = [timeout_error, *errors][:5]
        ok = bool(
            not timed_out
            and return_code == 0
            and passes_completed == passes_requested
            and actual_pages > 0
            and not errors
        )
        preview_status = classify_compile_preview(ok=ok, pdf_bytes=pdf_bytes)
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest() if pdf_bytes else ""
        process_status = (
            COMPILE_TIMEOUT
            if timed_out
            else COMPILE_SUCCEEDED if ok else COMPILE_FAILED
        )
        return {
            # Store only the executable basename; a Windows path must remain
            # private even when this code is inspected on another OS.
            "engine": (
                str(engine_exe).replace("\\", "/").rsplit("/", 1)[-1]
                or "xelatex"
            ),
            "available": True,
            "ok": ok,
            "process_status": process_status,
            "preview_status": preview_status,
            "pages": pages,
            "page_count": pages,
            "logged_pages": logged_pages,
            "errors": errors,
            "fatal_error": errors[0] if errors else "",
            "log": log,
            "log_path": "main.log",
            "pdf_bytes": pdf_bytes,
            "pdf_sha256": pdf_sha256,
            "return_code": return_code,
            "exit_code": return_code,
            "fatal_line": fatal_line,
            "timed_out": timed_out,
            "passes_requested": passes_requested,
            "passes_attempted": passes_attempted,
            "passes_completed": passes_completed,
            "command": _selected_engine_command(command_history),
            "command_history": _public_compile_commands(command_history),
            "compile_workdir": compile_workdir,
            "input_manifest": input_manifest,
            "compile_input_sha256": input_manifest["manifest_sha256"],
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def compile_latex(
    text: str,
    timeout: int = 240,
    extra_files: dict = None,
    *,
    include_pdf: bool = False,
) -> Dict:
    """Return compile evidence, optionally carrying the captured PDF bytes.

    The default remains JSON-safe.  The pipeline may opt into ``include_pdf``
    long enough to persist the immutable preview separately; it removes the
    binary value before writing ``verification.json``.
    """
    artifact = compile_latex_artifact(text, timeout=timeout, extra_files=extra_files)
    result = {
        "engine": artifact["engine"],
        "available": artifact["available"],
        "ok": artifact["ok"],
        # Preserve the legacy log-derived count while the artifact API exposes
        # only the page count of a PDF whose bytes were actually captured.
        "pages": artifact["pages"] or artifact.get("logged_pages", 0),
        "page_count": artifact["page_count"],
        "errors": artifact["errors"],
        "fatal_error": artifact["fatal_error"],
        "log": str(artifact["log"]),
        "log_path": artifact["log_path"],
        # Additive JSON-safe evidence lets existing pipeline verification and a
        # future run-bundle exporter distinguish a real partial PDF from a source
        # fallback without embedding binary bytes in verification.json.
        "preview_status": artifact["preview_status"],
        "process_status": artifact["process_status"],
        "pdf_sha256": artifact["pdf_sha256"],
        "return_code": artifact["return_code"],
        "exit_code": artifact["exit_code"],
        "fatal_line": artifact["fatal_line"],
        "timed_out": artifact["timed_out"],
        "passes_requested": artifact["passes_requested"],
        "passes_attempted": artifact["passes_attempted"],
        "passes_completed": artifact["passes_completed"],
        "input_manifest": artifact["input_manifest"],
        "compile_input_sha256": artifact["compile_input_sha256"],
    }
    if include_pdf:
        result["pdf_bytes"] = bytes(artifact["pdf_bytes"])
    return result

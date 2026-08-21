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
from pathlib import Path, PurePosixPath
from typing import Dict, Optional

from .preview import SOURCE_PREVIEW, classify_compile_preview

PAGES_RE = re.compile(r"Output written on .*\((\d+) pages?")
ERROR_RE = re.compile(r"^! ", re.M)
FATAL_LINE_RE = re.compile(r"^l\.(\d+)\s*(.*)$")

COMPILE_SUCCEEDED = "SUCCESS"
COMPILE_FAILED = "FAILED"
COMPILE_TIMEOUT = "TIMEOUT"
COMPILE_UNAVAILABLE = "UNAVAILABLE"
COMPILE_INPUT_MANIFEST_SCHEMA = "latexstruct-compile-input-set-v1"

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
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    stdout = _process_output_text(getattr(process, "stdout", ""))
    stderr = _process_output_text(getattr(process, "stderr", ""))
    return "\n".join(part for part in (stdout, stderr) if part)


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
            "available": False,
            "ok": None,
            "process_status": COMPILE_UNAVAILABLE,
            "preview_status": SOURCE_PREVIEW,
            "pages": 0,
            "logged_pages": 0,
            "errors": [],
            "log": "",
            "pdf_bytes": b"",
            "return_code": None,
            "fatal_line": None,
            "timed_out": False,
            "passes_requested": 0,
            "passes_completed": 0,
            "input_manifest": input_manifest,
        }

    workdir = tempfile.mkdtemp(prefix="ls-compile-")
    process = None
    timed_out = False
    passes_requested = 2 if any(
        token in text
        for token in ("\\tableofcontents", "\\ref{", "\\pageref{", "\\cite{")
    ) else 1
    passes_completed = 0
    return_code: Optional[int] = None
    try:
        _write_materialized_compile_inputs(workdir, prepared_inputs)
        try:
            for _ in range(passes_requested):
                process = subprocess.run(
                    [exe, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
                    cwd=workdir,
                    capture_output=True,
                    timeout=timeout,
                )
                return_code = int(process.returncode)
                passes_completed += 1
                if return_code != 0:
                    break
        except subprocess.TimeoutExpired as exc:
            process = exc
            timed_out = True
            return_code = None

        raw_log = _read_compile_log(workdir, process)
        log = _sanitize_compile_log(raw_log, workdir)
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
        process_status = (
            COMPILE_TIMEOUT
            if timed_out
            else COMPILE_SUCCEEDED if ok else COMPILE_FAILED
        )
        return {
            "available": True,
            "ok": ok,
            "process_status": process_status,
            "preview_status": preview_status,
            "pages": pages,
            "logged_pages": logged_pages,
            "errors": errors,
            "log": log,
            "pdf_bytes": pdf_bytes,
            "return_code": return_code,
            "fatal_line": fatal_line,
            "timed_out": timed_out,
            "passes_requested": passes_requested,
            "passes_completed": passes_completed,
            "input_manifest": input_manifest,
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
        "available": artifact["available"],
        "ok": artifact["ok"],
        # Preserve the legacy log-derived count while the artifact API exposes
        # only the page count of a PDF whose bytes were actually captured.
        "pages": artifact["pages"] or artifact.get("logged_pages", 0),
        "errors": artifact["errors"],
        "log": str(artifact["log"]),
        # Additive JSON-safe evidence lets existing pipeline verification and a
        # future run-bundle exporter distinguish a real partial PDF from a source
        # fallback without embedding binary bytes in verification.json.
        "preview_status": artifact["preview_status"],
        "process_status": artifact["process_status"],
        "return_code": artifact["return_code"],
        "fatal_line": artifact["fatal_line"],
        "timed_out": artifact["timed_out"],
        "passes_requested": artifact["passes_requested"],
        "passes_completed": artifact["passes_completed"],
        "input_manifest": artifact["input_manifest"],
    }
    if include_pdf:
        result["pdf_bytes"] = bytes(artifact["pdf_bytes"])
    return result

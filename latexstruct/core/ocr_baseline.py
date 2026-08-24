# -*- coding: utf-8 -*-
"""Real, syntax-only OCR baseline compilation.

The OCR stage is deliberately not allowed to infer document semantics.  This
module therefore performs at most the small, reversible syntax repairs already
proven by the host (blank paragraphs inside display math and misplaced closing
environment lines), then compiles the resulting text.  It never adds headings,
formal environments, templates, or model-authored content.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .compilecheck import compile_latex_artifact
from .ocr_runtime import OcrPreviewStatus
from .ocrstruct import _build_syntax_repair_ops
from .patch import Decision, apply_patches, validate_ops


_SOURCE_PREVIEW_NOTICE = (
    "This PDF is a readable fallback rendered from TeX source. "
    "It is not evidence that LaTeX compilation succeeded."
)


@dataclass(frozen=True, slots=True)
class OcrBaselineResult:
    tex: str
    log: str
    preview_status: OcrPreviewStatus
    pdf_bytes: bytes
    exit_code: int
    successful_passes: int
    syntax_repairs: tuple[dict, ...]
    error_lines: tuple[dict, ...]
    engine: str


def build_source_preview_pdf(source: str) -> bytes:
    """Create a readable, unmistakably non-compiled PDF fallback.

    The first page contains the mandatory notice.  The remaining pages are a
    bounded source rendering, never a simulation of LaTeX layout.
    """
    try:
        import pymupdf
    except ImportError:  # pragma: no cover - declared runtime dependency
        import fitz as pymupdf  # type: ignore

    document = pymupdf.open()
    try:
        notice_page = document.new_page(width=595, height=842)
        notice_page.insert_text(
            pymupdf.Point(54, 82),
            "SOURCE_PREVIEW: NOT A LATEX COMPILED RESULT.",
            fontname="helv",
            fontsize=11,
        )
        notice_page.insert_text(
            pymupdf.Point(54, 104),
            "NOT A LATEX COMPILE RESULT.",
            fontname="helv",
            fontsize=11,
        )
        notice_page.insert_textbox(
            pymupdf.Rect(54, 130, 541, 230),
            _SOURCE_PREVIEW_NOTICE,
            fontname="china-s",
            fontsize=11,
            lineheight=1.45,
        )
        notice_page.insert_textbox(
            pymupdf.Rect(54, 240, 541, 780),
            "TeX source preview begins on the following page.",
            fontname="china-s",
            fontsize=10,
        )
        lines = str(source or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        # Keep the fallback deterministic and readable without claiming TeX
        # pagination.  Very long source lines are visibly wrapped as text.
        wrapped: list[str] = []
        for line in lines:
            if not line:
                wrapped.append("")
                continue
            wrapped.extend(line[index:index + 92] for index in range(0, len(line), 92))
        for offset in range(0, max(1, len(wrapped)), 58):
            page = document.new_page(width=595, height=842)
            chunk = wrapped[offset:offset + 58] or [""]
            page.insert_textbox(
                pymupdf.Rect(36, 36, 559, 806),
                "\n".join(chunk),
                fontname="china-s",
                fontsize=8,
                lineheight=1.15,
            )
        payload = document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()
    if not payload.startswith(b"%PDF-"):
        raise RuntimeError("failed to create SOURCE_PREVIEW PDF")
    return payload


def _syntax_only_repair(text: str) -> tuple[str, tuple[dict, ...]]:
    lines = text.split("\n")
    operations, notes = _build_syntax_repair_ops(lines)
    if not operations:
        return text, ()
    decision = Decision(
        candidate_id="ocr-baseline-syntax-only",
        action="none",
        source="host",
        reason="reversible OCR syntax-only baseline recovery",
    )
    planned, rejected = validate_ops(lines, [(decision, operations)])
    if rejected:
        return text, ({
            "status": "rejected",
            "reason": rejected[0].error,
        },)
    output, applied, rejected = apply_patches(lines, planned)
    if rejected or not applied:
        return text, tuple(notes)
    return "\n".join(output), tuple(notes)


def compile_ocr_baseline(
    raw_tex: str,
    *,
    extra_files: Mapping[str, bytes] | None = None,
    timeout: int = 240,
) -> OcrBaselineResult:
    """Compile the frozen OCR text without semantic or layout transformations.

    Two successful engine executions are required for ``COMPILED`` even when
    the document itself needs only one TeX pass.  A readable PDF captured from
    a failing compile is reported honestly as ``PARTIAL_COMPILED``; otherwise
    callers receive ``SOURCE_PREVIEW`` and may show the TeX source.
    """
    source = str(raw_tex or "")
    files = dict(extra_files or {})
    first = compile_latex_artifact(source, timeout=timeout, extra_files=files)
    candidate = source
    repairs: tuple[dict, ...] = ()
    attempts = [first]
    if first.get("ok") is not True:
        candidate, repairs = _syntax_only_repair(source)
        if candidate != source:
            attempts.append(
                compile_latex_artifact(candidate, timeout=timeout, extra_files=files)
            )
    chosen = attempts[-1]
    successful_runs = 1 if chosen.get("ok") is True else 0
    if chosen.get("ok") is True:
        second = compile_latex_artifact(candidate, timeout=timeout, extra_files=files)
        attempts.append(second)
        chosen = second
        if second.get("ok") is True:
            successful_runs += 1
    pdf_bytes = bytes(chosen.get("pdf_bytes") or b"")
    if chosen.get("ok") is True and successful_runs >= 2 and pdf_bytes.startswith(b"%PDF-"):
        status = OcrPreviewStatus.COMPILED
        exit_code = 0
    elif pdf_bytes.startswith(b"%PDF-"):
        status = OcrPreviewStatus.PARTIAL_COMPILED
        raw_code = chosen.get("exit_code")
        exit_code = int(raw_code) if isinstance(raw_code, int) and raw_code != 0 else 1
    else:
        status = OcrPreviewStatus.SOURCE_PREVIEW
        raw_code = chosen.get("exit_code")
        exit_code = int(raw_code) if isinstance(raw_code, int) else 1
    logs = []
    for index, result in enumerate(attempts, start=1):
        logs.append(
            f"[LaTeXStruct OCR baseline attempt {index}] engine={result.get('engine') or 'xelatex'} "
            f"ok={result.get('ok')} exit_code={result.get('exit_code')} "
            f"passes_completed={result.get('passes_completed', 0)}"
        )
        if result.get("log"):
            logs.append(str(result["log"]))
    if status == OcrPreviewStatus.SOURCE_PREVIEW:
        logs.append("[LaTeXStruct] SOURCE_PREVIEW：这不是 LaTeX 编译结果；当前仅可查看 TeX 源码。")
        pdf_bytes = build_source_preview_pdf(candidate)
    errors = tuple(
        {"message": str(message)[:500]}
        for message in (chosen.get("errors") or ())
    )
    return OcrBaselineResult(
        tex=candidate,
        log="\n".join(logs),
        preview_status=status,
        pdf_bytes=pdf_bytes,
        exit_code=exit_code,
        successful_passes=successful_runs,
        syntax_repairs=repairs,
        error_lines=errors,
        engine=str(chosen.get("engine") or "xelatex"),
    )


__all__ = ["OcrBaselineResult", "build_source_preview_pdf", "compile_ocr_baseline"]

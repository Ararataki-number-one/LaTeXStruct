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


__all__ = ["OcrBaselineResult", "compile_ocr_baseline"]

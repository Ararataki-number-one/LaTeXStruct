# -*- coding: utf-8 -*-
"""Real, syntax-only OCR baseline compilation.

The OCR stage is deliberately not allowed to infer document semantics.  This
module therefore performs at most the small, reversible syntax repairs already
proven by the host (blank paragraphs inside display math and misplaced closing
environment lines), then compiles the resulting text.  It never adds headings,
formal environments, templates, or model-authored content.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from .compilecheck import (
    COMPILE_INPUT_MANIFEST_SCHEMA,
    COMPILE_WORKDIR_ID_PREFIX,
    compile_latex_artifact,
    prepare_compile_inputs,
)
from .ocr_page_map import (
    OcrPageAnchor,
    OcrPdfPageMapEntry,
    build_pdf_page_map,
    inject_page_anchors,
)
from .ocr_runtime import OcrPreviewStatus
from .ocrstruct import _build_syntax_repair_ops
from .patch import Decision, apply_patches, validate_ops


_SOURCE_PREVIEW_NOTICE = (
    "This PDF is a readable fallback rendered from TeX source. "
    "It is not evidence that LaTeX compilation succeeded."
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(str(value).encode("utf-8"))


def _engine_basename(value: object) -> str:
    """Keep compiler identity without leaking its local absolute path."""
    return str(value or "xelatex").replace("\\", "/").rsplit("/", 1)[-1] or "xelatex"


def _exit_code(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _command_tokens(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError("compile invocation command must be a token sequence")
    tokens = tuple(str(token) for token in value)
    if any(not token or "\x00" in token for token in tokens):
        raise ValueError("compile invocation command contains an invalid token")
    if tokens and ("/" in tokens[0] or "\\" in tokens[0]):
        raise ValueError("compile invocation command executable must not expose a path")
    for token in tokens[1:]:
        if token.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", token):
            raise ValueError("compile invocation command must not expose an absolute path")
    return tokens


@dataclass(frozen=True, slots=True)
class OcrCompileInputFileEvidence:
    """One exact file materialized in the isolated compiler directory."""

    path: str
    byte_count: int
    sha256: str

    def __post_init__(self) -> None:
        path = str(self.path or "").replace("\\", "/")
        if (
            not path
            or path.startswith("/")
            or re.match(r"^[A-Za-z]:/", path)
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise ValueError("compile input inventory path must be safe and relative")
        if (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
        ):
            raise ValueError("compile input inventory bytes must be a non-negative integer")
        digest = str(self.sha256 or "").lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ValueError("compile input inventory sha256 is invalid")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "sha256", digest)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "bytes": self.byte_count,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class OcrCompileInvocationEvidence:
    """Exact evidence captured from one independent compiler invocation.

    ``sequence`` counts calls to :func:`compile_latex_artifact`, not TeX engine
    passes claimed inside one returned log.  Consequently a single call with
    ``passes_completed=2`` remains one evidence record and can never satisfy
    the two-independent-invocation OCR baseline gate by itself.
    """

    sequence: int
    exit_code: int | None
    ok: bool | None
    engine: str
    log: str
    input_tex_sha256: str
    output_pdf_sha256: str
    passes_requested: int
    passes_attempted: int
    passes_completed: int
    command: tuple[str, ...] = ()
    command_history: tuple[tuple[str, ...], ...] = ()
    compile_workdir: str = ""
    input_inventory: tuple[OcrCompileInputFileEvidence, ...] = ()
    compile_input_sha256: str = ""
    input_artifacts: tuple[tuple[str, bytes], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise ValueError("compile invocation sequence must be a positive integer")
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool)
        ):
            raise ValueError("compile invocation exit_code must be an integer or None")
        if self.ok is not True and self.ok is not False and self.ok is not None:
            raise ValueError("compile invocation ok must be true, false, or None")
        engine = _engine_basename(self.engine)
        if not engine.strip():
            raise ValueError("compile invocation engine is required")
        input_sha = str(self.input_tex_sha256 or "").lower()
        output_sha = str(self.output_pdf_sha256 or "").lower()
        if not _SHA256_RE.fullmatch(input_sha):
            raise ValueError("compile invocation input_tex_sha256 is invalid")
        if output_sha and not _SHA256_RE.fullmatch(output_sha):
            raise ValueError("compile invocation output_pdf_sha256 is invalid")
        counts = (self.passes_requested, self.passes_attempted, self.passes_completed)
        if any(not isinstance(value, int) or isinstance(value, bool) for value in counts):
            raise ValueError("compile invocation pass counters must be integers")
        if any(value < 0 for value in counts):
            raise ValueError("compile invocation pass counters cannot be negative")
        if counts[2] > counts[1] or (counts[0] and counts[1] > counts[0]):
            raise ValueError("compile invocation pass counters are contradictory")
        command = _command_tokens(self.command)
        command_history = tuple(_command_tokens(item) for item in self.command_history)
        compile_workdir = str(self.compile_workdir or "")
        if compile_workdir and not re.fullmatch(
            re.escape(COMPILE_WORKDIR_ID_PREFIX) + r"[0-9a-f]{64}",
            compile_workdir,
        ):
            raise ValueError("compile invocation workdir identifier is invalid")
        inventory = tuple(self.input_inventory)
        if any(not isinstance(item, OcrCompileInputFileEvidence) for item in inventory):
            raise ValueError("compile input inventory items must be immutable evidence")
        paths = [item.path for item in inventory]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("compile input inventory must use unique sorted paths")
        compile_input_sha = str(self.compile_input_sha256 or "").lower()
        if compile_input_sha and not _SHA256_RE.fullmatch(compile_input_sha):
            raise ValueError("compile invocation compile_input_sha256 is invalid")
        if bool(inventory) != bool(compile_input_sha):
            raise ValueError("compile input inventory and digest must be recorded together")
        input_artifacts = tuple(
            (str(path or "").replace("\\", "/"), bytes(data))
            for path, data in self.input_artifacts
        )
        artifact_paths = [path for path, _data in input_artifacts]
        if (
            artifact_paths != sorted(artifact_paths)
            or len(artifact_paths) != len(set(artifact_paths))
            or len(artifact_paths) != len({path.casefold() for path in artifact_paths})
        ):
            raise ValueError("compile input artifacts must use unique sorted paths")
        if bool(inventory) != bool(input_artifacts):
            raise ValueError(
                "compile input inventory and exact input artifacts must be recorded together"
            )
        if inventory:
            body = {
                "schema": COMPILE_INPUT_MANIFEST_SCHEMA,
                "file_count": len(inventory),
                "files": [item.to_dict() for item in inventory],
            }
            canonical = json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if _sha256_bytes(canonical) != compile_input_sha:
                raise ValueError("compile input inventory digest does not match its files")
            main_tex = next((item for item in inventory if item.path == "main.tex"), None)
            if main_tex is None or main_tex.sha256 != input_sha:
                raise ValueError("compile input inventory does not bind the candidate TeX")
            if len(input_artifacts) != len(inventory):
                raise ValueError("compile input artifact coverage differs from inventory")
            for item, (path, data) in zip(inventory, input_artifacts, strict=True):
                if (
                    path != item.path
                    or len(data) != item.byte_count
                    or _sha256_bytes(data) != item.sha256
                ):
                    raise ValueError(
                        "compile input artifact bytes do not match the measured inventory"
                    )
        actual_command_metadata = bool(command or command_history or compile_workdir)
        if actual_command_metadata and not (
            command and command_history and compile_workdir and inventory
        ):
            raise ValueError("compile invocation command metadata is incomplete")
        if command and command not in command_history:
            raise ValueError("compile invocation command is absent from command history")
        object.__setattr__(self, "engine", engine)
        object.__setattr__(self, "log", str(self.log or ""))
        object.__setattr__(self, "input_tex_sha256", input_sha)
        object.__setattr__(self, "output_pdf_sha256", output_sha)
        object.__setattr__(self, "passes_requested", counts[0])
        object.__setattr__(self, "passes_attempted", counts[1])
        object.__setattr__(self, "passes_completed", counts[2])
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "command_history", command_history)
        object.__setattr__(self, "compile_workdir", compile_workdir)
        object.__setattr__(self, "input_inventory", inventory)
        object.__setattr__(self, "compile_input_sha256", compile_input_sha)
        object.__setattr__(self, "input_artifacts", input_artifacts)

    @property
    def log_sha256(self) -> str:
        return _sha256_text(self.log)

    @property
    def evidence_sha256(self) -> str:
        return _sha256_bytes(
            json.dumps(
                self.to_dict(include_evidence_sha256=False),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )

    def to_dict(self, *, include_evidence_sha256: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "sequence": self.sequence,
            "exit_code": self.exit_code,
            "ok": self.ok,
            "engine": self.engine,
            "log": self.log,
            "log_sha256": self.log_sha256,
            "input_tex_sha256": self.input_tex_sha256,
            "output_pdf_sha256": self.output_pdf_sha256 or None,
            "passes_requested": self.passes_requested,
            "passes_attempted": self.passes_attempted,
            "passes_completed": self.passes_completed,
            "command": list(self.command),
            "command_history": [list(command) for command in self.command_history],
            "compile_workdir": self.compile_workdir or None,
            "input_inventory": [item.to_dict() for item in self.input_inventory],
            "compile_input_sha256": self.compile_input_sha256 or None,
        }
        if include_evidence_sha256:
            payload["evidence_sha256"] = self.evidence_sha256
        return payload


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
    compile_invocations: tuple[OcrCompileInvocationEvidence, ...] = ()
    page_anchors: tuple[OcrPageAnchor, ...] = ()
    page_map_entries: tuple[OcrPdfPageMapEntry, ...] = ()
    page_map_json: bytes = b""

    def compile_invocation_dicts(self) -> tuple[dict[str, object], ...]:
        """Return serialization-ready per-call evidence without merging logs."""
        return tuple(item.to_dict() for item in self.compile_invocations)


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


def _compile_input_inventory(
    result: Mapping[str, object],
) -> tuple[tuple[OcrCompileInputFileEvidence, ...], str]:
    raw_manifest = result.get("input_manifest")
    if raw_manifest is None:
        return (), ""
    if not isinstance(raw_manifest, Mapping):
        raise ValueError("compile input manifest must be a mapping")
    if raw_manifest.get("schema") != COMPILE_INPUT_MANIFEST_SCHEMA:
        raise ValueError("compile input manifest schema is invalid")
    raw_files = raw_manifest.get("files")
    if isinstance(raw_files, (str, bytes, bytearray)) or not isinstance(
        raw_files, Sequence
    ):
        raise ValueError("compile input manifest files must be a sequence")
    inventory: list[OcrCompileInputFileEvidence] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, Mapping):
            raise ValueError("compile input manifest file must be a mapping")
        byte_count = raw_file.get("bytes")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool):
            raise ValueError("compile input manifest bytes is invalid")
        inventory.append(
            OcrCompileInputFileEvidence(
                path=str(raw_file.get("path") or ""),
                byte_count=byte_count,
                sha256=str(raw_file.get("sha256") or ""),
            )
        )
    declared_count = raw_manifest.get("file_count")
    if (
        not isinstance(declared_count, int)
        or isinstance(declared_count, bool)
        or declared_count != len(inventory)
    ):
        raise ValueError("compile input manifest file_count is invalid")
    manifest_sha = str(raw_manifest.get("manifest_sha256") or "").lower()
    result_sha = str(result.get("compile_input_sha256") or "").lower()
    if result_sha and result_sha != manifest_sha:
        raise ValueError("compile input manifest digests disagree")
    return tuple(inventory), manifest_sha


def _compile_command_history(result: Mapping[str, object]) -> tuple[tuple[str, ...], ...]:
    raw_history = result.get("command_history")
    if raw_history is None:
        return ()
    if isinstance(raw_history, (str, bytes, bytearray)) or not isinstance(
        raw_history, Sequence
    ):
        raise ValueError("compile invocation command history must be a sequence")
    return tuple(_command_tokens(command) for command in raw_history)


def _compile_evidence(
    sequence: int,
    candidate: str,
    result: Mapping[str, object],
    input_artifacts: Mapping[str, bytes],
) -> OcrCompileInvocationEvidence:
    pdf_bytes = bytes(result.get("pdf_bytes") or b"")
    raw_ok = result.get("ok")
    ok = raw_ok if raw_ok is True or raw_ok is False or raw_ok is None else None
    completed = int(result.get("passes_completed") or 0)
    attempted = int(result.get("passes_attempted") or completed)
    requested = int(result.get("passes_requested") or attempted)
    inventory, compile_input_sha = _compile_input_inventory(result)
    return OcrCompileInvocationEvidence(
        sequence=sequence,
        exit_code=_exit_code(result.get("exit_code")),
        ok=ok,
        engine=_engine_basename(result.get("engine")),
        log=str(result.get("log") or ""),
        input_tex_sha256=_sha256_text(candidate),
        output_pdf_sha256=_sha256_bytes(pdf_bytes) if pdf_bytes else "",
        passes_requested=requested,
        passes_attempted=attempted,
        passes_completed=completed,
        command=_command_tokens(result.get("command")),
        command_history=_compile_command_history(result),
        compile_workdir=str(result.get("compile_workdir") or ""),
        input_inventory=inventory,
        compile_input_sha256=compile_input_sha,
        input_artifacts=(
            tuple(
                (path, bytes(data))
                for path, data in sorted(input_artifacts.items())
            )
            if inventory else ()
        ),
    )


def _is_real_success(
    evidence: OcrCompileInvocationEvidence,
    result: Mapping[str, object],
) -> bool:
    """Fail closed on optimistic flags that lack process/log/PDF evidence."""
    return bool(
        evidence.ok is True
        and evidence.exit_code == 0
        and evidence.log.strip()
        and bytes(result.get("pdf_bytes") or b"").startswith(b"%PDF-")
    )


def _trailing_successful_invocations(
    evidence: Sequence[OcrCompileInvocationEvidence],
    results: Sequence[Mapping[str, object]],
    *,
    candidate_sha256: str,
) -> int:
    count = 0
    for item, result in reversed(tuple(zip(evidence, results, strict=True))):
        if item.input_tex_sha256 != candidate_sha256 or not _is_real_success(item, result):
            break
        count += 1
    return count


def compile_ocr_baseline(
    raw_tex: str,
    *,
    extra_files: Mapping[str, bytes] | None = None,
    timeout: int = 240,
    selected_pages: Sequence[int] | None = None,
) -> OcrBaselineResult:
    """Compile the frozen OCR text without semantic or layout transformations.

    Two successful engine executions are required for ``COMPILED`` even when
    the document itself needs only one TeX pass.  A readable PDF captured from
    a failing compile is reported honestly as ``PARTIAL_COMPILED``; otherwise
    callers receive ``SOURCE_PREVIEW`` and may show the TeX source.
    """
    source = str(raw_tex or "")
    files = dict(extra_files or {})
    anchor_injection = inject_page_anchors(
        source,
        expected_selected_pages=selected_pages,
    )
    candidate = anchor_injection.syntax_tex
    repairs: tuple[dict, ...] = ()
    attempts: list[Mapping[str, object]] = []
    invocation_evidence: list[OcrCompileInvocationEvidence] = []

    def invoke(candidate_tex: str) -> Mapping[str, object]:
        prepared_inputs = prepare_compile_inputs(candidate_tex, files)
        result = compile_latex_artifact(candidate_tex, timeout=timeout, extra_files=files)
        if not isinstance(result, Mapping):
            raise TypeError("compile_latex_artifact must return a mapping")
        attempts.append(result)
        invocation_evidence.append(
            _compile_evidence(
                len(invocation_evidence) + 1,
                candidate_tex,
                result,
                prepared_inputs,
            )
        )
        return result

    first = invoke(candidate)
    if not _is_real_success(invocation_evidence[-1], first):
        repaired_candidate, repairs = _syntax_only_repair(candidate)
        if repaired_candidate != candidate:
            candidate = repaired_candidate
            invoke(candidate)
    chosen = attempts[-1]
    if _is_real_success(invocation_evidence[-1], chosen):
        second = invoke(candidate)
        chosen = second
    candidate_sha256 = _sha256_text(candidate)
    successful_runs = _trailing_successful_invocations(
        invocation_evidence,
        attempts,
        candidate_sha256=candidate_sha256,
    )
    pdf_bytes = bytes(chosen.get("pdf_bytes") or b"")
    if successful_runs >= 2 and pdf_bytes.startswith(b"%PDF-"):
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
    for index, (result, evidence) in enumerate(
        zip(attempts, invocation_evidence, strict=True),
        start=1,
    ):
        logs.append(
            f"[LaTeXStruct OCR baseline attempt {index}] engine={evidence.engine} "
            f"ok={evidence.ok} exit_code={evidence.exit_code} "
            f"input_tex_sha256={evidence.input_tex_sha256} "
            f"passes_completed={result.get('passes_completed', 0)}"
        )
        if evidence.log:
            logs.append(evidence.log)
    if status == OcrPreviewStatus.SOURCE_PREVIEW:
        logs.append("[LaTeXStruct] SOURCE_PREVIEW：这不是 LaTeX 编译结果；当前仅可查看 TeX 源码。")
        pdf_bytes = build_source_preview_pdf(candidate)
    page_map_entries: tuple[OcrPdfPageMapEntry, ...] = ()
    page_map_json = b""
    if status == OcrPreviewStatus.COMPILED and anchor_injection.anchors:
        compiled_page_map = build_pdf_page_map(pdf_bytes, anchor_injection.anchors)
        page_map_entries = compiled_page_map.entries
        page_map_json = compiled_page_map.to_json_bytes()
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
        engine=_engine_basename(chosen.get("engine")),
        compile_invocations=tuple(invocation_evidence),
        page_anchors=anchor_injection.anchors,
        page_map_entries=page_map_entries,
        page_map_json=page_map_json,
    )


__all__ = [
    "OcrBaselineResult",
    "OcrCompileInputFileEvidence",
    "OcrCompileInvocationEvidence",
    "build_source_preview_pdf",
    "compile_ocr_baseline",
]

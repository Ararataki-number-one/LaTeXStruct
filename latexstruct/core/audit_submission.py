# -*- coding: utf-8 -*-
"""Build portable, privacy-cleaned AI audit submission packages."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import uuid
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .audit_prompt import render_full_prompt, render_readme, render_short_prompt
from .audit_packaging_integrity import AuditPackagingIntegrityGate
from .audit_evidence import (
    compile_input_manifest_sha256,
    outline_evidence_errors,
    template_manifest_sha256,
)
from .audit_sanitize import (
    SanitizationSpan,
    sanitize_json_text,
    sanitize_log_text,
    sanitize_plain_text,
    sanitize_tex_text_with_spans,
)
from .audit_schema import (
    ArtifactRole,
    AuditArtifact,
    AuditDepth,
    AuditManifestArtifact,
    AuditPackageStatus,
    AuditStageExecution,
    AuditSubmissionManifest,
    AuditSubmissionRequest,
    AuditSubmissionResult,
    AuditWorkflow,
    PackagingStatus,
    RunSnapshot,
    StageExecutionStatus,
    TerminalStatus,
    normalize_artifact_role,
    thaw_json,
)
from .preview import COMPILED, PARTIAL_COMPILED, SOURCE_PREVIEW
from .runbundle import validate_archive_namespace


README_PATH = "00_README_FIRST.md"
SHORT_PROMPT_PATH = "01_PROMPT_SHORT.txt"
FULL_PROMPT_PATH = "02_PROMPT_FULL.md"
MANIFEST_PATH = "submission_manifest.json"
SHA256SUMS_PATH = "audit/SHA256SUMS"
PACKAGING_INTEGRITY_PATH = "audit/packaging-integrity.json"
PACKAGING_ERROR_PATH = "audit/packaging-error.json"
MAX_AUDIT_ZIP_BYTES = 500 * 1024 * 1024

CONTROL_PATHS = frozenset({
    README_PATH,
    SHORT_PROMPT_PATH,
    FULL_PROMPT_PATH,
    MANIFEST_PATH,
    SHA256SUMS_PATH,
    PACKAGING_INTEGRITY_PATH,
    PACKAGING_ERROR_PATH,
})

_CANONICAL_ROLE_PATHS = {
    ArtifactRole.SOURCE_TEX: "inputs/source.tex",
    ArtifactRole.SOURCE_PDF: "inputs/source.pdf",
    ArtifactRole.STAGE_SOURCE_TEX: "stages/00_source.tex",
    ArtifactRole.RAW_OCR_TEX: "stages/00_raw_ocr.tex",
    ArtifactRole.AI_ANALYZED_TEX: "stages/10_ai_analyzed.tex",
    ArtifactRole.RULE_ANALYZED_TEX: "stages/10_rule_analyzed.tex",
    ArtifactRole.AI_REVIEWED_TEX: "stages/20_ai_reviewed.tex",
    ArtifactRole.CURRENT_TEX: "stages/30_current.tex",
    ArtifactRole.REPORT: "audit/report.md",
    ArtifactRole.VERIFICATION: "audit/verification.json",
    ArtifactRole.DECISIONS: "audit/decisions.json",
    ArtifactRole.RAW_TO_CURRENT_DIFF: "audit/raw_to_current.diff",
    ArtifactRole.COMPILE_CURRENT_LOG: "audit/compile_current.log",
    ArtifactRole.COMPILE_RAW_LOG: "audit/compile_raw.log",
    ArtifactRole.ERROR_LOG: "audit/error.log",
    ArtifactRole.OUTLINE: "evidence/outline.json",
    ArtifactRole.REPORT_JSON: "audit/report.json",
    ArtifactRole.ISSUES_CSV: "audit/issues.csv",
    ArtifactRole.METRICS: "audit/metrics.json",
    ArtifactRole.TEMPLATE_MANIFEST: "audit/template-manifest.json",
    ArtifactRole.COMPILE_INPUT_MANIFEST: "audit/compile-input-manifest.json",
    ArtifactRole.RAW_COMPILE_INPUT_MANIFEST: "audit/compile-input-raw-manifest.json",
    ArtifactRole.PACKAGING_INTEGRITY: PACKAGING_INTEGRITY_PATH,
    ArtifactRole.PACKAGING_ERROR: PACKAGING_ERROR_PATH,
}

_EXPECTED_ROLES = {
    AuditWorkflow.ANALYSIS_REVIEW_ONLY: {
        ArtifactRole.SOURCE_TEX,
        ArtifactRole.STAGE_SOURCE_TEX,
        ArtifactRole.AI_ANALYZED_TEX,
        ArtifactRole.AI_REVIEWED_TEX,
        ArtifactRole.CURRENT_TEX,
        ArtifactRole.CURRENT_PREVIEW,
        ArtifactRole.REPORT,
        ArtifactRole.VERIFICATION,
        ArtifactRole.DECISIONS,
        ArtifactRole.RAW_TO_CURRENT_DIFF,
        ArtifactRole.COMPILE_CURRENT_LOG,
    },
    AuditWorkflow.OCR_ONLY: {
        ArtifactRole.SOURCE_PDF,
        ArtifactRole.RAW_OCR_TEX,
        ArtifactRole.RAW_OCR_PREVIEW,
        ArtifactRole.REPORT,
        ArtifactRole.VERIFICATION,
        ArtifactRole.DECISIONS,
        ArtifactRole.COMPILE_RAW_LOG,
        ArtifactRole.OUTLINE,
    },
    AuditWorkflow.OCR_ANALYSIS_REVIEW: {
        ArtifactRole.SOURCE_PDF,
        ArtifactRole.RAW_OCR_TEX,
        ArtifactRole.RAW_OCR_PREVIEW,
        ArtifactRole.AI_ANALYZED_TEX,
        ArtifactRole.AI_REVIEWED_TEX,
        ArtifactRole.CURRENT_TEX,
        ArtifactRole.CURRENT_PREVIEW,
        ArtifactRole.REPORT,
        ArtifactRole.VERIFICATION,
        ArtifactRole.DECISIONS,
        ArtifactRole.RAW_TO_CURRENT_DIFF,
        ArtifactRole.COMPILE_RAW_LOG,
        ArtifactRole.COMPILE_CURRENT_LOG,
        ArtifactRole.OUTLINE,
    },
    AuditWorkflow.TEMPLATE_CONVERSION: {
        ArtifactRole.SOURCE_TEX,
        ArtifactRole.STAGE_SOURCE_TEX,
        ArtifactRole.AI_ANALYZED_TEX,
        ArtifactRole.AI_REVIEWED_TEX,
        ArtifactRole.CURRENT_TEX,
        ArtifactRole.CURRENT_PREVIEW,
        ArtifactRole.REPORT,
        ArtifactRole.VERIFICATION,
        ArtifactRole.DECISIONS,
        ArtifactRole.RAW_TO_CURRENT_DIFF,
        ArtifactRole.COMPILE_CURRENT_LOG,
    },
    AuditWorkflow.MULTIFILE_PROJECT: {
        ArtifactRole.CURRENT_TEX,
        ArtifactRole.CURRENT_PREVIEW,
        ArtifactRole.PROJECT_FILE,
        ArtifactRole.REPORT,
        ArtifactRole.VERIFICATION,
        ArtifactRole.DECISIONS,
        ArtifactRole.COMPILE_CURRENT_LOG,
    },
}

_MACHINE_REPORT_ROLES = {
    ArtifactRole.REPORT_JSON,
    ArtifactRole.ISSUES_CSV,
    ArtifactRole.METRICS,
}
_TEX_SUFFIXES = frozenset({".tex", ".ltx", ".bib", ".cls", ".sty"})

_QUICK_ROLES = {
    ArtifactRole.SOURCE_TEX,
    ArtifactRole.SOURCE_PDF,
    ArtifactRole.SOURCE_IMAGE,
    ArtifactRole.RAW_OCR_TEX,
    ArtifactRole.CURRENT_TEX,
    ArtifactRole.CURRENT_PREVIEW,
    ArtifactRole.RAW_OCR_PREVIEW,
    ArtifactRole.REPORT,
    ArtifactRole.VERIFICATION,
    ArtifactRole.DECISIONS,
    ArtifactRole.ERROR_LOG,
    ArtifactRole.TEMPLATE_MANIFEST,
    ArtifactRole.COMPILE_INPUT_MANIFEST,
    ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
}

_SOURCE_ROLES = {
    ArtifactRole.SOURCE_TEX,
    ArtifactRole.SOURCE_PDF,
    ArtifactRole.SOURCE_IMAGE,
    ArtifactRole.STAGE_SOURCE_TEX,
}
_COMPILE_LOG_ROLES = {ArtifactRole.COMPILE_CURRENT_LOG, ArtifactRole.COMPILE_RAW_LOG}
_VERIFICATION_ROLES = {ArtifactRole.VERIFICATION, ArtifactRole.DECISIONS}

_WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:[\\/][^\r\n\t\"'<>|{}\[\](),;]+|"
    r"\\\\[^\\\s{}\[\](),;]+\\[^\r\n\t\"'<>|{}\[\](),;]+)"
)
_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])/(?:Users|home|root|tmp|private(?:/tmp)?|var|workspace(?:s)?|"
    r"mnt|opt|data|srv|etc|usr|Applications|Volumes|Library|System|media|run)"
    r"(?:/[^\r\n\t\"'<> {}\[\](),;]*)?"
)
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(
        r"(?im)(\bAuthorization[\"']?\s*[:=]\s*[\"']?(?:Bearer\s+)?)"
        r"[^\s,;\"'{}\[\]()]+"
    ),
    re.compile(
        r"(?im)(\b(?:[A-Z][A-Z0-9]*[_-])*API[_-]?KEY\b[\"']?\s*[:=]\s*[\"']?)"
        r"[^\s,;\"'{}\[\]()]+"
    ),
    re.compile(
        r"(?im)(\b(?:(?:CODEX|CHATGPT)(?:[ _-](?:TOKEN|AUTH|LOGIN|SESSION|ACCOUNT|EMAIL|ID)){1,4}|"
        r"ACCESS_TOKEN|REFRESH_TOKEN|ID_TOKEN|ACCOUNT_ID|ACCOUNT_EMAIL|EMAIL|ACCOUNT)\b"
        r"[\"']?\s*[:=]\s*[\"']?)[^\s,;\"'{}\[\]()]+"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
)
_TEXT_SUFFIXES = frozenset({
    ".tex", ".txt", ".md", ".json", ".csv", ".log", ".diff", ".patch",
    ".yaml", ".yml", ".xml", ".sty", ".cls", ".bib",
})
_SENSITIVE_PROJECT_FILE_SUFFIXES = frozenset({
    ".env",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
})
_SENSITIVE_PROJECT_FILE_BASENAMES = frozenset({
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "_netrc",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secret.json",
    "secrets.json",
    "service-account.json",
})
_SOURCE_NOTICE = "SOURCE_PREVIEW: NOT A LATEX COMPILED RESULT."
_SUBMISSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _is_sensitive_metadata_key(value: object) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(value).casefold())
    return (
        normalized.endswith("apikey")
        or (
            normalized.startswith(("codex", "chatgpt"))
            and normalized.endswith(
                ("token", "email", "accountid", "userid", "login", "auth", "session", "account")
            )
        )
        or normalized in {
            "authorization", "codextoken", "codexlogin", "codexauth",
            "codexsession", "codexaccount", "chatgptaccount", "accesstoken",
            "refreshtoken", "idtoken", "accountid", "accountemail", "email",
            "account",
        }
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def canonical_artifact_path(
    role: str,
    *,
    preview_status: str | None = None,
    index: int | None = None,
    filename: str | None = None,
) -> str:
    """Return the host-controlled standard path for a built-in role."""
    role = normalize_artifact_role(role)
    if role == ArtifactRole.CURRENT_PREVIEW:
        names = {
            COMPILED: "current.pdf",
            PARTIAL_COMPILED: "current-partial-compiled.pdf",
            SOURCE_PREVIEW: "current-source-preview.pdf",
        }
        try:
            return f"previews/{names[str(preview_status)]}"
        except KeyError as exc:
            raise ValueError("current preview requires a valid preview_status") from exc
    if role == ArtifactRole.RAW_OCR_PREVIEW:
        names = {
            COMPILED: "raw-ocr.pdf",
            PARTIAL_COMPILED: "raw_ocr_PARTIAL_COMPILED.pdf",
            SOURCE_PREVIEW: "raw-ocr-source-preview.pdf",
        }
        try:
            return f"previews/{names[str(preview_status)]}"
        except KeyError as exc:
            raise ValueError("raw OCR preview requires a valid preview_status") from exc
    if role == ArtifactRole.SOURCE_IMAGE:
        suffix = Path(str(filename or "source.png")).suffix.lower()
        if suffix == ".jpeg":
            suffix = ".jpg"
        if suffix not in {".png", ".jpg"}:
            raise ValueError("SOURCE_IMAGE requires a PNG or JPEG filename")
        return f"inputs/source-image{suffix}"
    if role == ArtifactRole.PAGE_IMAGE:
        suffix = Path(str(filename or "page.png")).suffix.lower() or ".png"
        return f"evidence/page-images/page-{int(index or 1):04d}{suffix}"
    if role == ArtifactRole.FORMULA_CROP:
        suffix = Path(str(filename or "formula.png")).suffix.lower() or ".png"
        return f"evidence/formula-crops/formula-{int(index or 1):04d}{suffix}"
    if role == ArtifactRole.PROJECT_FILE:
        if not filename:
            raise ValueError("PROJECT_FILE requires a portable filename")
        return f"project/{_safe_bundle_path(filename)}"
    if role == ArtifactRole.EVIDENCE:
        if not filename:
            raise ValueError("EVIDENCE requires a portable filename")
        return f"evidence/{_safe_bundle_path(filename)}"
    try:
        return _CANONICAL_ROLE_PATHS[role]
    except KeyError as exc:
        raise ValueError(f"role {role} requires an explicit portable package path") from exc


def make_audit_artifact(
    role: str,
    data: bytes,
    *,
    path: str | None = None,
    media_type: str = "application/octet-stream",
    parent_artifact_ids: Iterable[str] = (),
    preview_status: str | None = None,
    index: int | None = None,
    filename: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AuditArtifact:
    """Convenience factory that applies the standard package path contract."""
    role = normalize_artifact_role(role)
    requested = path or canonical_artifact_path(
        role,
        preview_status=preview_status,
        index=index,
        filename=filename,
    )
    return AuditArtifact(
        artifact_role=role,
        path=requested,
        data=bytes(data),
        media_type=media_type,
        parent_artifact_ids=tuple(parent_artifact_ids),
        preview_status=preview_status,
        metadata=dict(metadata or {}),
    )


def _safe_bundle_path(value: str) -> str:
    raw = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if (
        not raw
        or raw.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part or "\x00" in part for part in path.parts)
        or any(part.endswith((".", " ")) for part in path.parts)
        or any("\r" in part or "\n" in part for part in path.parts)
    ):
        raise ValueError(f"unsafe or non-portable audit package path: {value!r}")
    safe = path.as_posix()
    validate_archive_namespace([(safe, False)])
    return safe


def _collision_variant(path: str, index: int) -> str:
    pure = PurePosixPath(path)
    suffixes = "".join(pure.suffixes)
    stem = pure.name[:-len(suffixes)] if suffixes else pure.name
    return (pure.parent / f"{stem}-{index}{suffixes}").as_posix()


def _allocate_path(requested: str, used: list[str]) -> str:
    requested = _safe_bundle_path(requested)
    candidates = [requested]
    candidates.extend(_collision_variant(requested, index) for index in range(2, 10000))
    for candidate in candidates:
        try:
            validate_archive_namespace(
                [(path, False) for path in used],
                additions=(candidate,),
            )
        except ValueError:
            continue
        return candidate
    raise ValueError(f"cannot allocate a collision-free package path for {requested!r}")


def _role_is_included(role: str, request: AuditSubmissionRequest) -> bool:
    if request.depth is AuditDepth.QUICK and role not in _QUICK_ROLES:
        return False
    if not request.include_source_files and role in _SOURCE_ROLES:
        return False
    if not request.include_compile_logs and role in _COMPILE_LOG_ROLES:
        return False
    if not request.include_verification and role in _VERIFICATION_ROLES:
        return False
    if role == ArtifactRole.PAGE_IMAGE and not request.effective_page_images:
        return False
    if role == ArtifactRole.FORMULA_CROP and not request.effective_formula_crops:
        return False
    return True


def _sensitive_project_file_reason(path: str) -> str:
    """Return a host policy reason for credential-like project filenames."""
    portable = _safe_bundle_path(path)
    basename = PurePosixPath(portable).name.casefold()
    suffix = PurePosixPath(basename).suffix.casefold()
    if basename == ".env" or basename.startswith(".env."):
        return "credential-like project-file basename"
    if basename in _SENSITIVE_PROJECT_FILE_BASENAMES:
        return "credential-like project-file basename"
    if suffix in _SENSITIVE_PROJECT_FILE_SUFFIXES:
        return "credential-like project-file suffix"
    return ""


def _redact_local_paths(text: str) -> tuple[str, int]:
    count = 0
    text, changed = _WINDOWS_PATH_RE.subn("<LOCAL_PATH>", str(text))
    count += changed
    text, changed = _POSIX_PATH_RE.subn("<LOCAL_PATH>", text)
    count += changed
    return text, count


def _redact_text(text: str) -> tuple[str, int]:
    text = str(text)
    count = 0
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            text, changed = pattern.subn(lambda match: match.group(1) + "<REDACTED>", text)
        else:
            text, changed = pattern.subn("<REDACTED>", text)
        count += changed
    text, changed = _redact_local_paths(text)
    count += changed
    return text, count


def _decode_text(data: bytes, path: str, media_type: str) -> tuple[str, str] | None:
    suffix = PurePosixPath(path).suffix.lower()
    declared_text = media_type.lower().startswith("text/") or suffix in _TEXT_SUFFIXES
    if not declared_text and (b"\x00" in data[:4096] or data.startswith(b"%PDF-")):
        return None
    encodings = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        encodings.append("utf-8-sig")
    encodings.append("utf-8")
    if declared_text:
        encodings.extend(("gb18030", "latin-1"))
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return None


@dataclass(frozen=True, slots=True)
class _SanitizedArtifactData:
    data: bytes
    changes: int = 0
    tex_spans: tuple[SanitizationSpan, ...] = ()
    is_tex: bool = False


def _is_tex_payload(path: str, media_type: str) -> bool:
    suffix = PurePosixPath(path).suffix.casefold()
    media = str(media_type or "").casefold()
    return suffix in _TEX_SUFFIXES or media.startswith("application/x-tex")


def _absolute_path_values(value: object) -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for item in value.values():
            result.extend(_absolute_path_values(item))
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        result = []
        for item in value:
            result.extend(_absolute_path_values(item))
        return result
    text = str(value or "").strip()
    if re.match(r"(?i)^[A-Z]:[\\/]", text) or text.startswith(("/", "\\\\")):
        return [text]
    return []


def _snapshot_known_paths(snapshot: RunSnapshot) -> tuple[str, ...]:
    """Collect only host-recorded path evidence; never infer paths from TeX prose."""
    accepted_keys = {
        "known_paths",
        "project_root",
        "compile_workdir",
        "workdir",
        "temp_dir",
        "cache_dir",
        "user_home",
        "resource_absolute_paths",
        "absolute_path",
        "source_path",
    }
    values: list[str] = [str(Path.home())]
    try:
        import tempfile

        values.append(str(Path(tempfile.gettempdir())))
    except (OSError, RuntimeError):  # pragma: no cover - unusual host failure
        pass

    def collect(mapping: Mapping[str, object]) -> None:
        for key, value in mapping.items():
            if str(key).casefold() in accepted_keys:
                values.extend(_absolute_path_values(value))

    collect(thaw_json(snapshot.metadata))
    for artifact in snapshot.artifacts:
        collect(thaw_json(artifact.metadata))
    # Longest prefixes are evaluated first by the sanitizer; stable order keeps
    # the packaging report deterministic without retaining any path in it.
    return tuple(dict.fromkeys(value for value in values if value))


def _encode_sanitized_text(
    *, original: bytes, original_text: str, cleaned_text: str, encoding: str
) -> bytes:
    if cleaned_text == original_text:
        return original
    try:
        return cleaned_text.encode(encoding)
    except UnicodeEncodeError:
        return cleaned_text.encode("utf-8")


def _sanitize_bytes(
    data: bytes,
    path: str,
    media_type: str,
    *,
    known_paths: Iterable[object] = (),
) -> _SanitizedArtifactData:
    suffix = PurePosixPath(path).suffix.casefold()
    decoded = _decode_text(data, path, media_type)
    # raw_to_current.diff is a LaTeX source diff.  A broad plain-text path
    # scrubber cannot distinguish legitimate mathematics such as
    # ``V:\\lvert`` from a Windows path, so route diffs through the same
    # evidence-backed, span-producing sanitizer as TeX and include them in
    # the post-packaging conservation gate.
    is_tex = _is_tex_payload(path, media_type) or suffix == ".diff"
    if decoded is None:
        return _SanitizedArtifactData(data=data, is_tex=is_tex)
    text, encoding = decoded
    media = str(media_type or "").casefold()
    if is_tex:
        result = sanitize_tex_text_with_spans(text, known_paths)
        packaged = _encode_sanitized_text(
            original=data,
            original_text=text,
            cleaned_text=result.text,
            encoding=encoding,
        )
        return _SanitizedArtifactData(
            data=packaged,
            changes=len(result.spans),
            tex_spans=result.spans,
            is_tex=True,
        )
    if suffix == ".json" or "application/json" in media:
        cleaned = sanitize_json_text(text, known_paths)
    elif suffix == ".log" or "log" in media:
        cleaned = sanitize_log_text(text, known_paths)
    else:
        cleaned = sanitize_plain_text(text, known_paths)
    packaged = _encode_sanitized_text(
        original=data,
        original_text=text,
        cleaned_text=cleaned,
        encoding=encoding,
    )
    return _SanitizedArtifactData(
        data=packaged,
        changes=int(packaged != data),
        is_tex=False,
    )


def _sanitize_jsonish(value: Any, *, redact_sensitive: bool = True) -> Any:
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            normalized_key = str(key)
            if redact_sensitive and _is_sensitive_metadata_key(normalized_key):
                result[normalized_key] = "<REDACTED>"
            else:
                result[normalized_key] = _sanitize_jsonish(
                    item, redact_sensitive=redact_sensitive
                )
        return result
    if isinstance(value, (list, tuple)):
        return [
            _sanitize_jsonish(item, redact_sensitive=redact_sensitive) for item in value
        ]
    if isinstance(value, str):
        return (
            _redact_text(value)[0]
            if redact_sensitive
            else _redact_local_paths(value)[0]
        )
    return value


def _source_preview_has_notice(data: bytes) -> bool:
    try:
        import fitz  # type: ignore

        document = fitz.open(stream=data, filetype="pdf")
        try:
            if document.page_count:
                first = document.load_page(0).get_text().upper()
                return (
                    "NOT A LATEX COMPILED RESULT" in first
                    or "不是 LATEX 编译结果" in first
                )
        finally:
            document.close()
    except (ImportError, RuntimeError, ValueError):
        return False
    return False


def _ensure_source_preview_notice(data: bytes) -> bytes:
    if not data.startswith(b"%PDF-"):
        decoded = _decode_text(data, "source-preview.txt", "text/plain")
        if decoded is not None and decoded[0].lstrip().upper().startswith(
            "SOURCE_PREVIEW: NOT A LATEX COMPILED RESULT."
        ):
            return data
        return (_SOURCE_NOTICE + "\n\n").encode("utf-8") + data
    if _source_preview_has_notice(data):
        return data
    try:
        import fitz  # type: ignore

        original = fitz.open(stream=data, filetype="pdf")
        output = fitz.open()
        try:
            notice = output.new_page(width=595, height=842)
            notice.insert_textbox(
                fitz.Rect(54, 72, 541, 770),
                _SOURCE_NOTICE
                + "\n\nThis preview is a readable fallback rendered from source text. "
                "It must not be used as evidence that LaTeX compilation succeeded.",
                fontsize=15,
                lineheight=1.5,
            )
            output.insert_pdf(original)
            rendered = output.tobytes(garbage=4, deflate=True)
        finally:
            output.close()
            original.close()
    except (ImportError, RuntimeError, ValueError) as exc:
        raise ValueError(
            "SOURCE_PREVIEW PDF has no first-page non-compilation notice and cannot be repaired"
        ) from exc
    if not _source_preview_has_notice(rendered):
        raise ValueError("failed to create the required SOURCE_PREVIEW first-page notice")
    return rendered


@dataclass
class _MutablePackagedArtifact:
    artifact_id: str
    artifact_role: str
    path: str
    data: bytes
    media_type: str
    parent_artifact_ids: tuple[str, ...]
    preview_status: str | None
    aliases: list[dict[str, object]]
    source_bytes_sha256: str
    redacted: bool
    metadata: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _TexGateCandidate:
    original: bytes
    packaged: bytes
    artifact_id: str
    artifact_role: str
    path: str
    authorized_spans: tuple[SanitizationSpan, ...]
    known_paths: tuple[object, ...]


def _select_and_package_artifacts(
    snapshot: RunSnapshot,
    request: AuditSubmissionRequest,
) -> tuple[
    list[_MutablePackagedArtifact],
    dict[str, bytes],
    int,
    list[dict[str, object]],
    list[_TexGateCandidate],
]:
    selected = [
        item for item in snapshot.artifacts if _role_is_included(item.artifact_role, request)
    ]
    used_paths = sorted(CONTROL_PATHS)
    files: dict[str, bytes] = {}
    packaged: list[_MutablePackagedArtifact] = []
    by_digest: dict[str, _MutablePackagedArtifact] = {}
    redaction_count = 0
    skipped_sensitive_project_files: list[dict[str, object]] = []
    known_paths = _snapshot_known_paths(snapshot)
    tex_gate_candidates: list[_TexGateCandidate] = []

    transformed: list[
        tuple[AuditArtifact, _SanitizedArtifactData, str, str]
    ] = []
    for item in selected:
        if request.sanitize_sensitive and item.artifact_role == ArtifactRole.PROJECT_FILE:
            portable_path = _safe_bundle_path(item.path)
            reason = _sensitive_project_file_reason(portable_path)
            if reason:
                skipped_sensitive_project_files.append({
                    "artifact_id": item.artifact_id,
                    "artifact_role": item.artifact_role,
                    "path": portable_path,
                    "reason": reason,
                })
                continue
        sanitized = _SanitizedArtifactData(
            data=item.data,
            is_tex=_is_tex_payload(item.path, item.media_type),
        )
        packaged_media_type = item.media_type
        if item.preview_status in {COMPILED, PARTIAL_COMPILED} and not item.data.startswith(b"%PDF-"):
            raise ValueError(
                f"{item.preview_status} preview must contain a real PDF artifact"
            )
        if request.sanitize_sensitive:
            sanitized = _sanitize_bytes(
                item.data,
                item.path,
                item.media_type,
                known_paths=known_paths,
            )
        data = sanitized.data
        if item.preview_status == SOURCE_PREVIEW:
            data = _ensure_source_preview_notice(data)
            sanitized = replace(sanitized, data=data)
            item_name = PurePosixPath(item.path.replace("\\", "/")).name.casefold()
            if "compiled" in item_name:
                # The canonical replacement below is host-determined and cannot
                # retain a misleading caller filename.
                requested = canonical_artifact_path(
                    item.artifact_role, preview_status=SOURCE_PREVIEW
                )
            else:
                requested = item.path
            if not data.startswith(b"%PDF-") and PurePosixPath(requested).suffix.casefold() == ".pdf":
                requested = PurePosixPath(requested).with_suffix(".txt").as_posix()
            if not data.startswith(b"%PDF-"):
                packaged_media_type = "text/plain; charset=utf-8"
        else:
            requested = item.path
        transformed.append((item, sanitized, requested, packaged_media_type))
        redaction_count += sanitized.changes

    for item, sanitized, requested_path, packaged_media_type in transformed:
        data = sanitized.data
        requested = _safe_bundle_path(requested_path)
        digest = hashlib.sha256(data).hexdigest()
        parents = item.parent_artifact_ids
        metadata = thaw_json(item.metadata)
        metadata = _sanitize_jsonish(
            metadata, redact_sensitive=request.sanitize_sensitive
        )
        existing = by_digest.get(digest)
        if existing is not None:
            logical_path = _allocate_path(requested, used_paths)
            used_paths.append(logical_path)
            existing.aliases.append({
                "logical_path": logical_path,
                "artifact_role": item.artifact_role,
                "artifact_id": item.artifact_id,
                "source_bytes_sha256": item.bytes_sha256,
                "parent_artifact_ids": list(parents),
                "preview_status": item.preview_status,
                "redacted": sanitized.changes > 0,
                **(
                    {"requested_logical_path": requested}
                    if logical_path != requested else {}
                ),
            })
            if sanitized.is_tex:
                tex_gate_candidates.append(_TexGateCandidate(
                    original=item.data,
                    packaged=data,
                    artifact_id=item.artifact_id,
                    artifact_role=item.artifact_role,
                    path=logical_path,
                    authorized_spans=sanitized.tex_spans,
                    known_paths=known_paths,
                ))
            continue
        allocated = _allocate_path(requested, used_paths)
        if item.preview_status == SOURCE_PREVIEW and "compiled" in PurePosixPath(allocated).name.casefold():
            raise ValueError("SOURCE_PREVIEW package filename cannot contain 'compiled'")
        used_paths.append(allocated)
        files[allocated] = data
        record = _MutablePackagedArtifact(
            artifact_id=item.artifact_id,
            artifact_role=item.artifact_role,
            path=allocated,
            data=data,
            media_type=packaged_media_type,
            parent_artifact_ids=parents,
            preview_status=item.preview_status,
            aliases=[],
            source_bytes_sha256=item.bytes_sha256,
            redacted=sanitized.changes > 0 or data != item.data,
            metadata=metadata,
        )
        packaged.append(record)
        by_digest[digest] = record
        if sanitized.is_tex:
            tex_gate_candidates.append(_TexGateCandidate(
                original=item.data,
                packaged=data,
                artifact_id=item.artifact_id,
                artifact_role=item.artifact_role,
                path=allocated,
                authorized_spans=sanitized.tex_spans,
                known_paths=known_paths,
            ))
    return (
        packaged,
        files,
        redaction_count,
        skipped_sensitive_project_files,
        tex_gate_candidates,
    )


def _manifest_records(
    packaged: Iterable[_MutablePackagedArtifact],
) -> list[AuditManifestArtifact]:
    records = []
    for item in packaged:
        records.append(AuditManifestArtifact(
            artifact_id=item.artifact_id,
            artifact_role=item.artifact_role,
            path=item.path,
            bytes_sha256=hashlib.sha256(item.data).hexdigest(),
            byte_count=len(item.data),
            media_type=item.media_type,
            parent_artifact_ids=item.parent_artifact_ids,
            preview_status=item.preview_status,
            aliases=tuple(item.aliases),
            source_bytes_sha256=item.source_bytes_sha256,
            redacted=item.redacted,
            metadata=item.metadata,
        ))
    return records


def _control_record(
    role: str,
    path: str,
    data: bytes | None = None,
    media_type: str = "text/plain; charset=utf-8",
) -> AuditManifestArtifact:
    digest = hashlib.sha256(data).hexdigest() if data is not None else None
    return AuditManifestArtifact(
        artifact_id=f"sha256:{digest}" if digest else f"control:{role.lower()}",
        artifact_role=role,
        path=path,
        bytes_sha256=digest,
        byte_count=len(data) if data is not None else None,
        media_type=media_type,
    )


def _logical_roles(records: Iterable[AuditManifestArtifact]) -> set[str]:
    roles: set[str] = set()
    for item in records:
        roles.add(item.artifact_role)
        roles.update(
            str(alias.get("artifact_role") or "")
            for alias in item.aliases
            if str(alias.get("artifact_role") or "")
        )
    return roles


def _manifest_stage_map(
    snapshot: RunSnapshot,
    records: Iterable[AuditManifestArtifact],
) -> dict[str, AuditStageExecution]:
    records = tuple(records)
    role_candidates = {
        "ocr": (ArtifactRole.RAW_OCR_TEX,),
        "analysis": (ArtifactRole.AI_ANALYZED_TEX, ArtifactRole.RULE_ANALYZED_TEX),
        "review": (ArtifactRole.AI_REVIEWED_TEX,),
        "template": (ArtifactRole.TEMPLATE_MANIFEST,),
    }
    result: dict[str, AuditStageExecution] = {}
    for name, execution in snapshot.stages.items():
        canonical_id = execution.canonical_artifact_id
        deduplicated = execution.deduplicated
        if execution.status is StageExecutionStatus.COMPLETED:
            match: tuple[str, bool] | None = None
            for record in records:
                if record.artifact_role in role_candidates.get(name, ()):
                    match = (record.artifact_id, False)
                    break
                for alias in record.aliases:
                    if str(alias.get("artifact_role") or "") in role_candidates.get(name, ()):
                        match = (record.artifact_id, True)
                        break
                if match is not None:
                    break
            if match is not None:
                canonical_id, deduplicated = match
        result[name] = AuditStageExecution(
            status=execution.status,
            reason=execution.reason,
            checked=execution.checked,
            canonical_artifact_id=canonical_id,
            deduplicated=deduplicated,
            metadata=thaw_json(execution.metadata),
        )
    return result


def _missing_role_reason(snapshot: RunSnapshot, role: str) -> str:
    stage_for_role = {
        ArtifactRole.RAW_OCR_TEX: "ocr",
        ArtifactRole.AI_ANALYZED_TEX: "analysis",
        ArtifactRole.RULE_ANALYZED_TEX: "analysis",
        ArtifactRole.AI_REVIEWED_TEX: "review",
        ArtifactRole.TEMPLATE_MANIFEST: "template",
    }.get(role)
    if stage_for_role:
        execution = snapshot.stages.get(stage_for_role)
        if execution is not None:
            if execution.reason:
                return execution.reason
            if execution.status is StageExecutionStatus.SKIPPED:
                return f"{stage_for_role} stage was skipped"
            if execution.status is StageExecutionStatus.NOT_REQUESTED:
                return f"{stage_for_role} stage was not requested"
            if execution.status is not StageExecutionStatus.COMPLETED:
                return f"{stage_for_role} stage status is {execution.status.value}"
    if role == ArtifactRole.RAW_OCR_PREVIEW:
        status = str(snapshot.machine_verification.get("raw_preview_state") or "")
        if status:
            return f"machine verification declared raw preview {status}, but its bytes are unavailable"
    if role == ArtifactRole.CURRENT_PREVIEW:
        status = str(snapshot.machine_verification.get("preview_state") or "")
        if status:
            return f"machine verification declared current preview {status}, but its bytes are unavailable"
    if role == ArtifactRole.OUTLINE:
        return "no non-empty host-derived PDF outline evidence was available"
    if role == ArtifactRole.COMPILE_INPUT_MANIFEST:
        return "the exact captured compile-input inventory is unavailable"
    if role == ArtifactRole.TEMPLATE_MANIFEST:
        return "the captured template asset inventory is unavailable"
    return "the terminal RunSnapshot contains no selected physical or deduplicated logical artifact"


def _build_manifest(
    snapshot: RunSnapshot,
    request: AuditSubmissionRequest,
    records: Iterable[AuditManifestArtifact],
    *,
    submission_id: str,
    generated_at: str,
    audit_focus: str,
    redaction_count: int,
    skipped_sensitive_project_files: Iterable[Mapping[str, object]] = (),
    packaging_status: PackagingStatus = PackagingStatus.SUCCESS,
    audit_package_status: AuditPackageStatus = AuditPackageStatus.VALID,
    extra_missing_details: Iterable[Mapping[str, object]] = (),
) -> AuditSubmissionManifest:
    record_list = tuple(records)
    available_roles = _logical_roles(record_list)
    expected = {
        role for role in _EXPECTED_ROLES[snapshot.workflow] if _role_is_included(role, request)
    }
    if request.depth is not AuditDepth.QUICK:
        expected.update(_MACHINE_REPORT_ROLES)
    if (
        snapshot.workflow in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}
        and ArtifactRole.SOURCE_IMAGE in available_roles
    ):
        # OCR accepts either a PDF or a single source image.  Do not claim the
        # PDF role is missing when the host authoritatively recorded an image.
        expected.discard(ArtifactRole.SOURCE_PDF)
    if snapshot.terminal_status is TerminalStatus.FAILED:
        expected.add(ArtifactRole.ERROR_LOG)
    missing_set = set(expected - available_roles)
    missing_details = [
        {"role": role, "reason": _missing_role_reason(snapshot, role)}
        for role in sorted(missing_set)
    ]
    missing_details.extend(dict(item) for item in extra_missing_details)
    normalized_missing_details: list[dict[str, object]] = []
    seen_missing_details: set[tuple[str, str]] = set()
    for detail in missing_details:
        role = normalize_artifact_role(detail.get("role"))
        reason = str(detail.get("reason") or _missing_role_reason(snapshot, role))
        key = (role, reason)
        if key in seen_missing_details:
            continue
        seen_missing_details.add(key)
        detail_status = str(detail.get("status") or "").upper()
        if role not in available_roles or detail_status in {"INVALID", "INCONSISTENT"}:
            missing_set.add(role)
        normalized_missing_details.append({
            "role": role,
            "reason": reason,
            **({"status": str(detail.get("status"))} if detail.get("status") else {}),
        })
    logical_ids = {
        item.artifact_id for item in record_list
    }
    logical_ids.update(
        str(alias.get("artifact_id") or "")
        for item in record_list
        for alias in item.aliases
        if str(alias.get("artifact_id") or "")
    )
    referenced_parents = {
        str(parent)
        for item in record_list
        for parent in item.parent_artifact_ids
    }
    referenced_parents.update(
        str(parent)
        for item in record_list
        for alias in item.aliases
        for parent in (alias.get("parent_artifact_ids") or ())
    )
    unavailable_parents = tuple(sorted(referenced_parents - logical_ids))
    cleaner = _redact_text if request.sanitize_sensitive else _redact_local_paths
    project_id = cleaner(str(snapshot.project_id))[0]
    run_id = cleaner(str(snapshot.run_id))[0]
    model = cleaner(str(snapshot.model))[0]
    template = cleaner(str(snapshot.template))[0]
    page_range = cleaner(str(snapshot.page_range))[0]
    blockers = tuple(
        _sanitize_jsonish(
            item.to_dict(), redact_sensitive=request.sanitize_sensitive
        )
        for item in snapshot.structured_blockers
    )
    skipped_project_files = tuple(
        _sanitize_jsonish(item, redact_sensitive=request.sanitize_sensitive)
        for item in skipped_sensitive_project_files
    )
    return AuditSubmissionManifest(
        submission_id=submission_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_fingerprint=snapshot.current_fingerprint,
        generated_at=generated_at,
        workflow=snapshot.workflow,
        terminal_status=snapshot.terminal_status,
        verification_status=snapshot.verification_status,
        depth=request.depth,
        audit_focus=audit_focus,
        project_id=project_id,
        run_id=run_id,
        model=model,
        app_version=cleaner(str(snapshot.app_version))[0],
        template=template,
        page_range=page_range,
        blockers=blockers,
        missing_expected_roles=tuple(sorted(missing_set)),
        missing_expected_role_details=tuple(normalized_missing_details),
        unavailable_parent_artifact_ids=unavailable_parents,
        artifacts=tuple(sorted(record_list, key=lambda item: item.path.casefold())),
        privacy={
            "payload_sensitive_data_sanitized": request.sanitize_sensitive,
            "payload_replacement_count": redaction_count,
            "sensitive_project_file_policy": (
                "exclude_credential_like_filenames"
                if request.sanitize_sensitive
                else "disabled_by_explicit_opt_out"
            ),
            "skipped_sensitive_project_file_count": len(skipped_project_files),
            "skipped_sensitive_project_files": skipped_project_files,
            "manifest_local_paths_sanitized": True,
            "local_absolute_paths_in_manifest": False,
            "binary_payloads": "preserved; package paths never expose source locations",
        },
        packaging_status=packaging_status,
        audit_package_status=audit_package_status,
        stages=_manifest_stage_map(snapshot, record_list),
        source_pdf=(snapshot.source_pdf.to_dict() if snapshot.source_pdf else None),
        provenance=_sanitize_jsonish(
            snapshot.provenance.to_dict(),
            redact_sensitive=request.sanitize_sensitive,
        ),
    )


def _artifact_record_for_role(
    records: Iterable[AuditManifestArtifact], role: str
) -> tuple[AuditManifestArtifact, Mapping[str, object] | None] | None:
    for record in records:
        if record.artifact_role == role:
            return record, None
        for alias in record.aliases:
            if str(alias.get("artifact_role") or "") == role:
                return record, alias
    return None


def _record_preview_status(
    binding: tuple[AuditManifestArtifact, Mapping[str, object] | None] | None,
) -> str | None:
    if binding is None:
        return None
    record, alias = binding
    if alias is not None:
        return str(alias.get("preview_status") or "") or record.preview_status
    return record.preview_status


def _json_payload_for_role(
    records: Iterable[AuditManifestArtifact],
    files: Mapping[str, bytes],
    role: str,
) -> tuple[Mapping[str, object] | None, str | None]:
    binding = _artifact_record_for_role(records, role)
    if binding is None:
        return None, "artifact role is missing"
    try:
        value = json.loads(files[binding[0].path].decode("utf-8-sig"))
    except (KeyError, UnicodeDecodeError, TypeError, ValueError):
        return None, "artifact is not a readable JSON document"
    if not isinstance(value, Mapping):
        return None, "artifact JSON root is not an object"
    return value, None


@dataclass(frozen=True, slots=True)
class _ResolvedLogicalPayload:
    physical_path: str
    data: bytes
    logical_path: str
    artifact_id: str
    artifact_role: str
    parent_artifact_ids: tuple[str, ...]


def _resolve_logical_payload(
    records: Iterable[AuditManifestArtifact],
    files: Mapping[str, bytes],
    *,
    path: object = "",
    artifact_id: object = "",
) -> _ResolvedLogicalPayload | None:
    """Resolve a physical payload without treating alias logical_path as a member."""
    requested_path = str(path or "")
    requested_id = str(artifact_id or "")
    if not requested_path and not requested_id:
        return None
    for record in records:
        canonical_matches = (
            (not requested_path or requested_path == record.path)
            and (not requested_id or requested_id == record.artifact_id)
        )
        if canonical_matches:
            data = files.get(record.path)
            return (
                _ResolvedLogicalPayload(
                    physical_path=record.path,
                    data=data,
                    logical_path=record.path,
                    artifact_id=record.artifact_id,
                    artifact_role=record.artifact_role,
                    parent_artifact_ids=record.parent_artifact_ids,
                )
                if data is not None
                else None
            )
        for alias in record.aliases:
            alias_matches = (
                (
                    not requested_path
                    or requested_path == str(alias.get("logical_path") or "")
                )
                and (
                    not requested_id
                    or requested_id == str(alias.get("artifact_id") or "")
                )
            )
            if alias_matches:
                data = files.get(record.path)
                return (
                    _ResolvedLogicalPayload(
                        physical_path=record.path,
                        data=data,
                        logical_path=str(alias.get("logical_path") or ""),
                        artifact_id=str(alias.get("artifact_id") or ""),
                        artifact_role=str(alias.get("artifact_role") or ""),
                        parent_artifact_ids=tuple(
                            str(parent)
                            for parent in (alias.get("parent_artifact_ids") or ())
                        ),
                    )
                    if data is not None
                    else None
                )
    return None


def _compile_manifest_failures(
    payload: Mapping[str, object],
    *,
    records: Iterable[AuditManifestArtifact],
    files: Mapping[str, bytes],
    main_role: str,
    preview_role: str,
) -> list[str]:
    failures: list[str] = []
    source_files = payload.get("files")
    packaged_files = payload.get("packaged_files")
    if not isinstance(source_files, list) or not source_files:
        return ["compile-input manifest has no source file inventory"]
    if not isinstance(packaged_files, list) or not packaged_files:
        return ["compile-input manifest has no packaged file inventory"]
    if payload.get("complete") is not True:
        failures.append("manifest does not declare a complete captured closure")
    if payload.get("file_count") != len(source_files):
        failures.append("file_count does not match the source file inventory")
    claimed_manifest_hash = str(payload.get("manifest_sha256") or "")
    if claimed_manifest_hash != compile_input_manifest_sha256(payload):
        failures.append("manifest_sha256 is not recomputable from the source inventory")
    recorded_hash = str(payload.get("recorded_compile_input_sha256") or "")
    if not recorded_hash:
        failures.append("recorded compile input hash is missing")
    elif recorded_hash != claimed_manifest_hash:
        failures.append("recorded compile input hash does not match manifest_sha256")

    preview = _artifact_record_for_role(records, preview_role)
    if preview is None:
        failures.append("compiled preview artifact is missing")
    elif str(payload.get("preview_artifact_sha256") or "") != str(
        preview[0].bytes_sha256 or ""
    ):
        failures.append("preview_artifact_sha256 does not bind the packaged PDF")

    main = _artifact_record_for_role(records, main_role)
    main_ids: set[str] = set()
    if main is not None:
        main_ids.add(main[0].artifact_id)
        if main[1] is not None:
            main_ids.add(str(main[1].get("artifact_id") or ""))
    if not main_ids or str(payload.get("main_artifact_id") or "") not in main_ids:
        failures.append("main_artifact_id does not bind the packaged main TeX")

    by_relative: dict[str, Mapping[str, object]] = {}
    for index, row in enumerate(packaged_files, 1):
        if not isinstance(row, Mapping):
            failures.append(f"packaged file row {index} is not an object")
            continue
        relative = str(row.get("path") or "")
        if not relative or relative in by_relative:
            failures.append(f"packaged file row {index} has an empty or duplicate path")
            continue
        by_relative[relative] = row

    source_paths: set[str] = set()
    for index, source_row in enumerate(source_files, 1):
        if not isinstance(source_row, Mapping):
            failures.append(f"source file row {index} is not an object")
            continue
        relative = str(source_row.get("path") or "")
        if not relative or relative in source_paths:
            failures.append(f"source file row {index} has an empty or duplicate path")
            continue
        source_paths.add(relative)
        packaged_row = by_relative.get(relative)
        if packaged_row is None:
            failures.append(f"source compile input has no packaged mapping: {relative}")
            continue
        expected_hash = str(source_row.get("sha256") or "")
        if str(packaged_row.get("bytes_sha256") or "") != expected_hash:
            failures.append(f"compile inventory hashes disagree: {relative}")
        if packaged_row.get("required_for_compile") is not True:
            failures.append(f"compile input is not marked required: {relative}")
        packaged_path = str(packaged_row.get("packaged_path") or "")
        packaged_artifact_id = str(packaged_row.get("artifact_id") or "")
        if not packaged_path:
            failures.append(f"compile input has no packaged_path: {relative}")
        if not packaged_artifact_id:
            failures.append(f"compile input has no artifact_id: {relative}")
        resolved = _resolve_logical_payload(
            records,
            files,
            path=packaged_path,
            artifact_id=packaged_artifact_id,
        )
        if resolved is None:
            failures.append(f"required compile input is missing: {relative}")
            continue
        data = resolved.data
        claimed_role = str(packaged_row.get("artifact_role") or "")
        if not claimed_role:
            failures.append(f"compile input has no artifact_role: {relative}")
        elif claimed_role != resolved.artifact_role:
            failures.append(f"compile input artifact_role mismatch: {relative}")
        claimed_parents = packaged_row.get("parent_artifact_ids")
        if not isinstance(claimed_parents, list | tuple):
            failures.append(f"compile input has no parent_artifact_ids: {relative}")
        elif tuple(str(parent) for parent in claimed_parents) != (
            resolved.parent_artifact_ids
        ):
            failures.append(f"compile input parent_artifact_ids mismatch: {relative}")
        if hashlib.sha256(data).hexdigest() != expected_hash:
            failures.append(f"compile input hash mismatch: {relative}")
        expected_bytes = source_row.get("bytes")
        if expected_bytes is not None and expected_bytes != len(data):
            failures.append(f"compile input byte count mismatch: {relative}")
    if set(by_relative) != source_paths:
        failures.append("packaged file inventory does not exactly match source files")
    return failures


def _template_manifest_failures(
    payload: Mapping[str, object],
    *,
    records: Iterable[AuditManifestArtifact],
    files: Mapping[str, bytes],
) -> list[str]:
    failures: list[str] = []
    if str(payload.get("asset_manifest_sha256") or "") != template_manifest_sha256(
        payload
    ):
        failures.append("asset_manifest_sha256 is not recomputable")
    assets = payload.get("assets")
    if not isinstance(assets, list) or not assets:
        return [*failures, "template manifest has no assets"]
    elegantbook_rows = []
    for index, row in enumerate(assets, 1):
        if not isinstance(row, Mapping):
            failures.append(f"template asset row {index} is not an object")
            continue
        relative = str(row.get("path") or "")
        artifact_path = str(
            row.get("artifact_path") or row.get("packaged_path") or ""
        )
        artifact_id = str(row.get("artifact_id") or "")
        if not artifact_path:
            failures.append(f"template asset has no artifact path: {relative or index}")
        if not artifact_id:
            failures.append(f"template asset has no artifact_id: {relative or index}")
        resolved = _resolve_logical_payload(
            records,
            files,
            path=artifact_path,
            artifact_id=artifact_id,
        )
        if resolved is None:
            failures.append(f"template asset is missing: {artifact_path or relative}")
            continue
        data = resolved.data
        claimed_role = str(row.get("artifact_role") or row.get("role") or "")
        if not claimed_role:
            failures.append(f"template asset has no artifact role: {artifact_path or relative}")
        elif claimed_role != resolved.artifact_role:
            failures.append(f"template asset role mismatch: {artifact_path or relative}")
        claimed_parents = row.get("parent_artifact_ids")
        if not isinstance(claimed_parents, list | tuple):
            failures.append(
                f"template asset has no parent_artifact_ids: {artifact_path or relative}"
            )
        elif tuple(str(parent) for parent in claimed_parents) != (
            resolved.parent_artifact_ids
        ):
            failures.append(
                f"template asset parent_artifact_ids mismatch: {artifact_path or relative}"
            )
        if row.get("required_for_compile") is not True:
            failures.append(
                f"template asset is not marked required_for_compile: {artifact_path or relative}"
            )
        claimed_hash = str(row.get("bytes_sha256") or row.get("sha256") or "")
        if not claimed_hash or hashlib.sha256(data).hexdigest() != claimed_hash:
            failures.append(f"template asset hash mismatch: {artifact_path or relative}")
        if relative.casefold().endswith("elegantbook.cls"):
            elegantbook_rows.append(row)
    if str(payload.get("template_id") or "").casefold() == "elegantbook" or elegantbook_rows:
        if not elegantbook_rows:
            failures.append("ElegantBook template manifest has no elegantbook.cls asset")
        for row in elegantbook_rows:
            license_path = str(row.get("license_path") or "")
            if not license_path or _resolve_logical_payload(
                records, files, path=license_path
            ) is None:
                failures.append("ElegantBook class asset has no packaged license")
    return failures


def _pdf_page_count(data: bytes) -> int:
    import fitz  # type: ignore

    document = fitz.open(stream=data, filetype="pdf")
    try:
        return int(document.page_count)
    finally:
        document.close()


def _rewrite_packaged_json(
    packaged: Iterable[_MutablePackagedArtifact],
    files: dict[str, bytes],
    role: str,
    transform,
) -> None:
    for item in packaged:
        if item.artifact_role != role:
            continue
        try:
            payload = json.loads(item.data.decode("utf-8-sig"))
        except (UnicodeDecodeError, TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        updated = transform(dict(payload))
        if not isinstance(updated, Mapping):
            raise TypeError("audit JSON enrichment must return a mapping")
        original_data = item.data
        data = _json_bytes(updated)
        item.data = data
        item.redacted = item.redacted or data != original_data
        item.metadata = {
            **dict(item.metadata),
            "packager_enriched": True,
        }
        files[item.path] = data


def _annotate_quick_dependency_manifests(
    packaged: Iterable[_MutablePackagedArtifact], files: dict[str, bytes]
) -> None:
    physical_paths = set(files)

    def annotate_compile(payload: dict[str, object]) -> dict[str, object]:
        included: list[str] = []
        omitted: list[str] = []
        for row in payload.get("packaged_files") or ():
            if not isinstance(row, Mapping):
                continue
            packaged_path = str(row.get("packaged_path") or "")
            if not packaged_path and str(row.get("path") or "") == "main.tex":
                packaged_path = str(payload.get("main_artifact_path") or "")
            if not packaged_path:
                continue
            (included if packaged_path in physical_paths else omitted).append(packaged_path)
        payload["package_materialization"] = {
            "depth": "quick",
            "complete": not omitted,
            "included_paths": included,
            "omitted_paths": omitted,
            "reason": (
                "quick audit depth omits non-essential dependency payloads"
                if omitted else None
            ),
        }
        return payload

    def annotate_template(payload: dict[str, object]) -> dict[str, object]:
        included: list[str] = []
        omitted: list[str] = []
        for row in payload.get("assets") or ():
            if not isinstance(row, Mapping):
                continue
            path = str(row.get("packaged_path") or row.get("artifact_path") or "")
            if path:
                (included if path in physical_paths else omitted).append(path)
        payload["package_materialization"] = {
            "depth": "quick",
            "complete": not omitted,
            "included_paths": included,
            "omitted_paths": omitted,
            "reason": (
                "quick audit depth includes manifests but may omit template assets"
                if omitted else None
            ),
        }
        return payload

    _rewrite_packaged_json(
        packaged, files, ArtifactRole.COMPILE_INPUT_MANIFEST, annotate_compile
    )
    _rewrite_packaged_json(
        packaged, files, ArtifactRole.RAW_COMPILE_INPUT_MANIFEST, annotate_compile
    )
    _rewrite_packaged_json(
        packaged, files, ArtifactRole.TEMPLATE_MANIFEST, annotate_template
    )


def _completeness_issues(
    snapshot: RunSnapshot,
    request: AuditSubmissionRequest,
    records: Iterable[AuditManifestArtifact],
    files: Mapping[str, bytes],
) -> list[dict[str, object]]:
    records = tuple(records)
    roles = _logical_roles(records)
    issues: list[dict[str, object]] = []

    def missing(role: str, reason: str, *, status: str = "MISSING") -> None:
        issues.append({"role": role, "reason": reason, "status": status})

    preview_specs = (
        (
            "raw_preview_state",
            "compile_before",
            ArtifactRole.RAW_OCR_PREVIEW,
            "compile_raw_status",
            "raw OCR",
        ),
        (
            "preview_state",
            "compile_after",
            ArtifactRole.CURRENT_PREVIEW,
            "compile_current_status",
            "current",
        ),
    )
    preview_facts: dict[str, tuple[str, ...]] = {}
    for top_key, nested_key, role, metric_key, label in preview_specs:
        declared_facts: list[str] = []
        top_level = str(snapshot.machine_verification.get(top_key) or "").upper()
        if top_level:
            declared_facts.append(top_level)
        nested = snapshot.machine_verification.get(nested_key)
        if isinstance(nested, Mapping):
            nested_status = str(nested.get("preview_status") or "").upper()
            if nested_status:
                declared_facts.append(nested_status)
        binding = _artifact_record_for_role(records, role)
        artifact_status = str(_record_preview_status(binding) or "").upper()
        if artifact_status:
            declared_facts.append(artifact_status)
        distinct_facts = tuple(dict.fromkeys(declared_facts))
        preview_facts[metric_key] = distinct_facts
        if len(distinct_facts) > 1:
            missing(
                role,
                f"{label} preview status facts contradict each other: "
                + ", ".join(distinct_facts),
                status="INCONSISTENT",
            )
        machine_declared = tuple(
            value for value in (top_level, nested_status if isinstance(nested, Mapping) else "")
            if value
        )
        if (
            any(value in {COMPILED, PARTIAL_COMPILED} for value in machine_declared)
            and role not in roles
        ):
            missing(
                role,
                f"machine verification declared {label} preview "
                f"{machine_declared[0]}, but the PDF bytes are missing",
                status=machine_declared[0],
            )

    logical_ids = {
        record.artifact_id
        for record in records
    }
    logical_ids.update(
        str(alias.get("artifact_id") or "")
        for record in records
        for alias in record.aliases
        if str(alias.get("artifact_id") or "")
    )
    snapshot_artifacts = {artifact.artifact_id: artifact for artifact in snapshot.artifacts}
    child_lineage = [
        (record.artifact_role, record.artifact_id, record.parent_artifact_ids)
        for record in records
    ]
    child_lineage.extend(
        (
            str(alias.get("artifact_role") or record.artifact_role),
            str(alias.get("artifact_id") or record.artifact_id),
            tuple(str(parent) for parent in (alias.get("parent_artifact_ids") or ())),
        )
        for record in records
        for alias in record.aliases
    )
    for child_role, child_id, parents in child_lineage:
        for parent_id in parents:
            if parent_id in logical_ids:
                continue
            source_parent = snapshot_artifacts.get(parent_id)
            if source_parent is not None and not _role_is_included(
                source_parent.artifact_role, request
            ):
                # A quick depth or an explicit include_* option may deliberately
                # omit a parent.  The manifest still exposes it through
                # unavailable_parent_artifact_ids, but that is not corruption.
                continue
            missing(
                child_role,
                f"artifact {child_id} references unavailable parent_artifact_id "
                f"{parent_id} that was not omitted by the selected audit depth/options",
                status="INCONSISTENT",
            )

    outline_payload: Mapping[str, object] | None = None
    metrics_payload: Mapping[str, object] | None = None
    report_payload: Mapping[str, object] | None = None
    if request.depth is not AuditDepth.QUICK:
        for role in sorted(_MACHINE_REPORT_ROLES):
            if role not in roles:
                missing(role, "standard/full audit depth requires this machine-readable report")
        if snapshot.workflow in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}:
            if ArtifactRole.OUTLINE not in roles:
                missing(
                    ArtifactRole.OUTLINE,
                    "no real host-derived PDF outline evidence was captured; an empty substitute was not generated",
                )
            else:
                outline_payload, error = _json_payload_for_role(
                    records, files, ArtifactRole.OUTLINE
                )
                outline_failures = (
                    [str(error)] if error else outline_evidence_errors(outline_payload)
                )
                if outline_failures:
                    missing(
                        ArtifactRole.OUTLINE,
                        "; ".join(outline_failures),
                        status="INVALID",
                    )

        report_payload, report_error = _json_payload_for_role(
            records, files, ArtifactRole.REPORT_JSON
        )
        if ArtifactRole.REPORT_JSON in roles:
            report_failures = [str(report_error)] if report_error else []
            if report_payload is not None:
                if report_payload.get("schema_version") != "latexstruct-audit-report-v2":
                    report_failures.append("report has an unsupported or missing schema_version")
                if str(report_payload.get("source_run_status") or "") != (
                    snapshot.source_run_status.value
                ):
                    report_failures.append("source_run_status contradicts the RunSnapshot")
                if str(report_payload.get("verification_status") or "") != (
                    snapshot.verification_status.value
                ):
                    report_failures.append("verification_status contradicts the RunSnapshot")
                if report_payload.get("blocker_count") != len(snapshot.structured_blockers):
                    report_failures.append("blocker_count contradicts the manifest blockers")
                reported_stages = report_payload.get("stages")
                if isinstance(reported_stages, Mapping):
                    for name, execution in snapshot.stages.items():
                        reported = reported_stages.get(name)
                        reported_status = (
                            reported.get("status")
                            if isinstance(reported, Mapping)
                            else reported
                        )
                        if str(reported_status or "") != execution.status.value:
                            report_failures.append(
                                f"reported stage status contradicts RunSnapshot: {name}"
                            )
                else:
                    report_failures.append("report has no structured stage map")
            if report_failures:
                missing(
                    ArtifactRole.REPORT_JSON,
                    "; ".join(report_failures),
                    status="INVALID",
                )

        metrics_payload, metrics_error = _json_payload_for_role(
            records, files, ArtifactRole.METRICS
        )
        if ArtifactRole.METRICS in roles:
            metric_failures = [str(metrics_error)] if metrics_error else []
            if metrics_payload is not None:
                required_metric_keys = {
                    "source_pages", "selected_pages", "outline_total",
                    "outline_accepted", "outline_rejected", "formal_total",
                    "formal_structured", "formal_residual", "proof_total",
                    "proof_structured", "equation_number_sequence",
                    "bibliography_count", "compile_raw_status",
                    "compile_current_status", "body_text_conservation",
                    "math_token_conservation", "packaging_integrity",
                }
                if metrics_payload.get("schema_version") != (
                    "latexstruct-audit-metrics-v1"
                ):
                    metric_failures.append(
                        "metrics has an unsupported or missing schema_version"
                    )
                missing_metric_keys = required_metric_keys - set(metrics_payload)
                if missing_metric_keys:
                    metric_failures.append(
                        "metrics omits required fields: "
                        + ", ".join(sorted(missing_metric_keys))
                    )
                if snapshot.source_pdf is not None:
                    if metrics_payload.get("source_pages") != snapshot.source_pdf.page_count:
                        metric_failures.append("source_pages contradicts source_pdf.page_count")
                    if list(metrics_payload.get("selected_pages") or ()) != list(
                        snapshot.source_pdf.selected_page_range.pages
                    ):
                        metric_failures.append("selected_pages contradicts source_pdf")
                if outline_payload is not None and not outline_evidence_errors(
                    outline_payload
                ):
                    expected_outline = {
                        "outline_total": len(outline_payload.get("source_outline") or ()),
                        "outline_accepted": int(outline_payload.get("accepted_count") or 0),
                        "outline_rejected": int(outline_payload.get("rejected_count") or 0),
                    }
                    for key, expected_value in expected_outline.items():
                        if metrics_payload.get(key) != expected_value:
                            metric_failures.append(f"{key} contradicts outline evidence")
                allowed_compile_statuses = {
                    "NOT_RUN",
                    COMPILED,
                    PARTIAL_COMPILED,
                    SOURCE_PREVIEW,
                }
                for key, facts in preview_facts.items():
                    metric_value = str(metrics_payload.get(key) or "").upper()
                    if metric_value not in allowed_compile_statuses:
                        metric_failures.append(f"{key} has an unsupported preview status")
                    if facts and any(metric_value != expected for expected in facts):
                        metric_failures.append(
                            f"{key} contradicts packaged preview or machine verification"
                        )
                    elif not facts and metric_value != "NOT_RUN":
                        metric_failures.append(
                            f"{key} claims a preview without packaged or machine evidence"
                        )
            if metric_failures:
                missing(
                    ArtifactRole.METRICS,
                    "; ".join(metric_failures),
                    status="INVALID",
                )

        if ArtifactRole.ISSUES_CSV in roles:
            issue_binding = _artifact_record_for_role(records, ArtifactRole.ISSUES_CSV)
            issue_failures: list[str] = []
            reader: csv.DictReader | None = None
            try:
                issue_text = files[issue_binding[0].path].decode("utf-8-sig")
                reader = csv.DictReader(io.StringIO(issue_text))
                issue_rows = list(reader)
            except (KeyError, UnicodeDecodeError, TypeError, ValueError):
                issue_rows = []
                issue_failures.append("issues.csv is unreadable")
            required_columns = {
                "id", "severity", "module", "candidate_id", "source_page",
                "source_line", "expected", "actual", "evidence",
                "recommended_fix", "acceptance",
            }
            if reader is None or reader.fieldnames is None or set(reader.fieldnames) != required_columns:
                issue_failures.append("issues.csv columns do not match the audit schema")
            blocker_ids = {item.id for item in snapshot.structured_blockers}
            row_ids = {str(row.get("id") or "") for row in issue_rows}
            if not blocker_ids.issubset(row_ids):
                issue_failures.append("issues.csv omits one or more manifest blockers")
            if issue_failures:
                missing(
                    ArtifactRole.ISSUES_CSV,
                    "; ".join(issue_failures),
                    status="INVALID",
                )

        if report_payload is not None and metrics_payload is not None:
            embedded = report_payload.get("metrics")
            if not isinstance(embedded, Mapping) or dict(embedded) != dict(metrics_payload):
                missing(
                    ArtifactRole.REPORT_JSON,
                    "embedded report metrics contradict audit/metrics.json",
                    status="INVALID",
                )
        resource_capture = snapshot.machine_verification.get(
            "audit_resource_capture"
        )
        if (
            isinstance(resource_capture, Mapping)
            and resource_capture.get("complete") is False
        ):
            missing(
                ArtifactRole.EVIDENCE,
                "host-declared OCR resources failed byte/hash validation during snapshot capture",
                status="INVALID",
            )

        stage_role = {
            ArtifactRole.RAW_OCR_TEX: "ocr",
            ArtifactRole.AI_ANALYZED_TEX: "analysis",
            ArtifactRole.RULE_ANALYZED_TEX: "analysis",
            ArtifactRole.AI_REVIEWED_TEX: "review",
            ArtifactRole.TEMPLATE_MANIFEST: "template",
        }
        expected_physical = {
            role
            for role in _EXPECTED_ROLES[snapshot.workflow]
            if _role_is_included(role, request)
        }
        if ArtifactRole.SOURCE_IMAGE in roles:
            expected_physical.discard(ArtifactRole.SOURCE_PDF)
        if ArtifactRole.RULE_ANALYZED_TEX in roles:
            expected_physical.discard(ArtifactRole.AI_ANALYZED_TEX)
        for role in sorted(expected_physical - roles):
            stage_name = stage_role.get(role)
            execution = snapshot.stages.get(stage_name) if stage_name else None
            # An output cannot be required from a stage the host truthfully says
            # did not complete.  In particular, review SKIPPED is not package
            # corruption and must not be turned into a false review claim.
            if execution is not None and execution.status is not StageExecutionStatus.COMPLETED:
                continue
            if role == ArtifactRole.COMPILE_CURRENT_LOG and (
                ArtifactRole.CURRENT_PREVIEW not in roles
            ):
                continue
            if role == ArtifactRole.COMPILE_RAW_LOG and (
                ArtifactRole.RAW_OCR_PREVIEW not in roles
            ):
                continue
            if role in _MACHINE_REPORT_ROLES or role == ArtifactRole.OUTLINE:
                continue
            missing(
                role,
                "standard/full audit depth is missing an expected physical run artifact",
            )

    current_preview = _artifact_record_for_role(records, ArtifactRole.CURRENT_PREVIEW)
    compiled_current = bool(
        current_preview
        and _record_preview_status(current_preview) in {COMPILED, PARTIAL_COMPILED}
    )
    current_compile_payload: Mapping[str, object] | None = None
    if request.depth is not AuditDepth.QUICK and compiled_current:
        if ArtifactRole.COMPILE_INPUT_MANIFEST not in roles:
            missing(
                ArtifactRole.COMPILE_INPUT_MANIFEST,
                "compiled current PDF has no captured compile-input manifest",
            )
        else:
            current_compile_payload, error = _json_payload_for_role(
                records, files, ArtifactRole.COMPILE_INPUT_MANIFEST
            )
            failures = [str(error)] if error else _compile_manifest_failures(
                current_compile_payload,
                records=records,
                files=files,
                main_role=ArtifactRole.CURRENT_TEX,
                preview_role=ArtifactRole.CURRENT_PREVIEW,
            )
            if failures:
                missing(
                    ArtifactRole.COMPILE_INPUT_MANIFEST,
                    "; ".join(failures),
                    status="INVALID",
                )

    raw_preview = _artifact_record_for_role(records, ArtifactRole.RAW_OCR_PREVIEW)
    if (
        request.depth is not AuditDepth.QUICK
        and raw_preview
        and _record_preview_status(raw_preview) in {COMPILED, PARTIAL_COMPILED}
    ):
        if ArtifactRole.RAW_COMPILE_INPUT_MANIFEST not in roles:
            missing(
                ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
                "compiled/partial raw OCR PDF has no captured raw compile-input manifest",
            )
        else:
            raw_payload, error = _json_payload_for_role(
                records, files, ArtifactRole.RAW_COMPILE_INPUT_MANIFEST
            )
            failures = [str(error)] if error else _compile_manifest_failures(
                raw_payload,
                records=records,
                files=files,
                main_role=ArtifactRole.RAW_OCR_TEX,
                preview_role=ArtifactRole.RAW_OCR_PREVIEW,
            )
            if failures:
                missing(
                    ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
                    "; ".join(failures),
                    status="INVALID",
                )

    template_stage = snapshot.stages.get("template")
    template_required = bool(
        current_compile_payload
        and any(
            str(row.get("path") or "").casefold().endswith(
                (".cls", ".sty", ".def", ".cfg", ".clo")
            )
            for row in current_compile_payload.get("packaged_files") or ()
            if isinstance(row, Mapping)
        )
    )
    if (
        request.depth is not AuditDepth.QUICK
        and (
            template_required
            or (
                template_stage is not None
                and template_stage.status is StageExecutionStatus.COMPLETED
            )
        )
        and ArtifactRole.TEMPLATE_MANIFEST not in roles
    ):
        missing(
            ArtifactRole.TEMPLATE_MANIFEST,
            "completed template stage has no captured template asset manifest",
        )
    elif request.depth is not AuditDepth.QUICK and ArtifactRole.TEMPLATE_MANIFEST in roles:
        template_payload, error = _json_payload_for_role(
            records, files, ArtifactRole.TEMPLATE_MANIFEST
        )
        failures = [str(error)] if error else _template_manifest_failures(
            template_payload,
            records=records,
            files=files,
        )
        if failures:
            missing(
                ArtifactRole.TEMPLATE_MANIFEST,
                "; ".join(failures),
                status="INVALID",
            )

    source_pdf_binding = _artifact_record_for_role(records, ArtifactRole.SOURCE_PDF)
    if (
        request.depth is not AuditDepth.QUICK
        and snapshot.workflow
        in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}
        and source_pdf_binding is not None
        and snapshot.source_pdf is None
    ):
        missing(
            ArtifactRole.SOURCE_PDF,
            "packaged OCR source PDF has no structured source_pdf page-count/range facts",
            status="INCONSISTENT",
        )
    if snapshot.source_pdf is not None:
        if snapshot.source_pdf.page_count is None:
            missing(
                ArtifactRole.SOURCE_PDF,
                "structured source_pdf facts omit the total PDF page_count",
                status="INCONSISTENT",
            )
        selected = snapshot.source_pdf.selected_page_range.pages
        if not selected:
            missing(
                ArtifactRole.SOURCE_PDF,
                "structured source_pdf facts omit the selected page set",
                status="INCONSISTENT",
            )
        if (
            snapshot.source_pdf.page_count is not None
            and selected
            and any(page > snapshot.source_pdf.page_count for page in selected)
        ):
            missing(
                ArtifactRole.SOURCE_PDF,
                "selected page range exceeds the recorded source PDF page count",
                status="INCONSISTENT",
            )
        if source_pdf_binding is None:
            missing(
                ArtifactRole.SOURCE_PDF,
                "structured source_pdf facts have no packaged source PDF bytes",
            )
        else:
            try:
                actual_pages = _pdf_page_count(files[source_pdf_binding[0].path])
            except (ImportError, KeyError, RuntimeError, TypeError, ValueError):
                missing(
                    ArtifactRole.SOURCE_PDF,
                    "source PDF page count cannot be independently read",
                    status="INVALID",
                )
            else:
                if (
                    snapshot.source_pdf.page_count is not None
                    and actual_pages != snapshot.source_pdf.page_count
                ):
                    missing(
                        ArtifactRole.SOURCE_PDF,
                        "source_pdf.page_count contradicts the packaged source PDF",
                        status="INCONSISTENT",
                    )
    return issues


def _enrich_metrics_status(
    packaged: Iterable[_MutablePackagedArtifact],
    files: dict[str, bytes],
    *,
    packaging_status: PackagingStatus,
    audit_package_status: AuditPackageStatus,
) -> None:
    status_payload = {
        "packaging_status": packaging_status.value,
        "audit_package_status": audit_package_status.value,
    }

    def transform(payload: dict[str, object]) -> dict[str, object]:
        payload["packaging_integrity"] = status_payload
        return payload

    _rewrite_packaged_json(packaged, files, ArtifactRole.METRICS, transform)
    updated_metrics: Mapping[str, object] | None = None
    for item in packaged:
        if item.artifact_role != ArtifactRole.METRICS:
            continue
        try:
            candidate = json.loads(item.data.decode("utf-8-sig"))
        except (UnicodeDecodeError, TypeError, ValueError):
            break
        if isinstance(candidate, Mapping):
            updated_metrics = candidate
        break
    if updated_metrics is not None:
        _rewrite_packaged_json(
            packaged,
            files,
            ArtifactRole.REPORT_JSON,
            lambda payload: {**payload, "metrics": dict(updated_metrics)},
        )


class _AuditZipSizeLimitExceeded(ValueError):
    pass


class _SizeLimitedBytesIO(io.BytesIO):
    def __init__(self, maximum_bytes: int):
        super().__init__()
        self.maximum_bytes = int(maximum_bytes)

    def write(self, data: bytes) -> int:
        if self.tell() + len(data) > self.maximum_bytes:
            raise _AuditZipSizeLimitExceeded
        return super().write(data)


def _fixed_zip(
    files: Mapping[str, bytes],
    *,
    maximum_bytes: int,
) -> bytes:
    maximum_bytes = int(maximum_bytes)
    if maximum_bytes <= 0:
        raise ValueError("audit ZIP maximum size must be positive")
    output = _SizeLimitedBytesIO(maximum_bytes)
    try:
        with zipfile.ZipFile(
            output,
            "w",
            zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                info.create_system = 3
                archive.writestr(info, data)
    except _AuditZipSizeLimitExceeded as exc:
        raise ValueError(
            f"audit ZIP exceeds configured maximum of {maximum_bytes} bytes"
        ) from exc
    payload = output.getvalue()
    if len(payload) > maximum_bytes:  # pragma: no cover - defensive invariant
        raise ValueError(
            f"audit ZIP exceeds configured maximum of {maximum_bytes} bytes"
        )
    return payload


def build_audit_submission(
    snapshot: RunSnapshot,
    request: AuditSubmissionRequest | None = None,
    *,
    submission_id: str | None = None,
    generated_at: str | None = None,
    include_zip: bool = True,
) -> AuditSubmissionResult:
    """Build one package solely from an immutable terminal ``RunSnapshot``.

    The function never calls an analysis/review model.  Missing stage files are
    recorded rather than fabricated, so failed and cancelled runs remain
    packageable with whatever evidence was captured.
    """
    if not isinstance(snapshot, RunSnapshot):
        raise TypeError("build_audit_submission requires an immutable RunSnapshot")
    request = request or AuditSubmissionRequest()
    if not isinstance(request, AuditSubmissionRequest):
        raise TypeError("request must be AuditSubmissionRequest")
    submission_id = str(submission_id or f"audit-{uuid.uuid4().hex[:20]}")
    if not _SUBMISSION_ID_RE.fullmatch(submission_id):
        raise ValueError("submission_id must be a portable opaque identifier")
    generated_at = str(generated_at or _now_iso())
    audit_focus = request.audit_focus
    if request.sanitize_sensitive:
        audit_focus = _redact_text(audit_focus)[0]
    else:
        audit_focus = _redact_local_paths(audit_focus)[0]

    (
        packaged,
        files,
        redaction_count,
        skipped_sensitive_project_files,
        tex_gate_candidates,
    ) = _select_and_package_artifacts(snapshot, request)

    gate = AuditPackagingIntegrityGate()
    gate_exception = ""
    try:
        for item in tex_gate_candidates:
            gate.check_tex_artifact(
                item.original,
                item.packaged,
                artifact_id=item.artifact_id,
                artifact_role=item.artifact_role,
                path=item.path,
                authorized_spans=item.authorized_spans,
                known_paths=item.known_paths,
            )
        gate_result = gate.finalize()
        integrity_payload = gate_result.to_dict()
    except Exception as exc:  # noqa: BLE001 - a broken gate itself must fail closed
        gate_exception = sanitize_log_text(
            f"{type(exc).__name__}: {exc}", _snapshot_known_paths(snapshot)
        )
        integrity_payload = {
            "schema_version": "latexstruct-audit-packaging-integrity-v1",
            "packaging_status": PackagingStatus.FAILED.value,
            "audit_package_status": AuditPackageStatus.INVALID.value,
            "valid": False,
            "checked_tex_artifact_count": len(gate.artifacts),
            "failed_tex_artifact_count": len(tex_gate_candidates),
            "artifacts": [item.to_dict() for item in gate.artifacts],
            "failures": [{
                "artifact_id": "packaging-integrity-gate",
                "path": PACKAGING_INTEGRITY_PATH,
                "code": "integrity_gate_exception",
            }],
            "gate_exception": gate_exception,
        }

    if integrity_payload.get("valid") is not True:
        failed_ids = {
            str(item.get("artifact_id") or "")
            for item in integrity_payload.get("failures") or ()
            if isinstance(item, Mapping)
        }
        if gate_exception:
            failed_ids.update(item.artifact_id for item in tex_gate_candidates)
        safe_packaged: list[_MutablePackagedArtifact] = []
        safe_files: dict[str, bytes] = {}
        for item in packaged:
            if item.artifact_id in failed_ids or item.path == "audit/error.log":
                continue
            item.aliases = [
                alias
                for alias in item.aliases
                if str(alias.get("artifact_id") or "") not in failed_ids
            ]
            safe_packaged.append(item)
            safe_files[item.path] = item.data

        integrity_payload.update({
            "packaging_status": PackagingStatus.FAILED.value,
            "audit_package_status": AuditPackageStatus.INVALID.value,
            "valid": False,
        })
        integrity_bytes = _json_bytes(integrity_payload)
        failure_codes = [
            str(item.get("code") or "unknown_packaging_failure")
            for item in integrity_payload.get("failures") or ()
            if isinstance(item, Mapping)
        ]
        packaging_error = {
            "schema_version": "latexstruct-audit-packaging-error-v1",
            "source_run_status": snapshot.source_run_status.value,
            "verification_status": snapshot.verification_status.value,
            "packaging_status": PackagingStatus.FAILED.value,
            "audit_package_status": AuditPackageStatus.INVALID.value,
            "failure_codes": failure_codes,
            "damaged_or_unverifiable_artifact_ids": sorted(failed_ids),
            "normal_audit_package_suppressed": True,
            "message": (
                "Post-sanitization TeX conservation failed; only a minimal "
                "failure bundle and independently safe artifacts were retained."
            ),
        }
        packaging_error_bytes = _json_bytes(packaging_error)
        error_text = (
            "LaTeXStruct audit packaging failed closed.\n"
            f"source_run_status={snapshot.source_run_status.value}\n"
            f"verification_status={snapshot.verification_status.value}\n"
            "packaging_status=FAILED\n"
            "audit_package_status=INVALID\n"
            f"failure_codes={','.join(failure_codes) or 'unknown_packaging_failure'}\n"
            + (f"gate_exception={gate_exception}\n" if gate_exception else "")
        ).encode("utf-8")
        safe_files.update({
            PACKAGING_INTEGRITY_PATH: integrity_bytes,
            PACKAGING_ERROR_PATH: packaging_error_bytes,
            "audit/error.log": error_text,
        })
        safe_records = _manifest_records(safe_packaged)
        generated_records = [
            _control_record(
                ArtifactRole.PACKAGING_INTEGRITY,
                PACKAGING_INTEGRITY_PATH,
                integrity_bytes,
                "application/json; charset=utf-8",
            ),
            _control_record(
                ArtifactRole.PACKAGING_ERROR,
                PACKAGING_ERROR_PATH,
                packaging_error_bytes,
                "application/json; charset=utf-8",
            ),
            _control_record(ArtifactRole.ERROR_LOG, "audit/error.log", error_text),
        ]
        placeholder_controls = [
            _control_record(ArtifactRole.README, README_PATH),
            _control_record(
                ArtifactRole.SUBMISSION_MANIFEST,
                MANIFEST_PATH,
                media_type="application/json; charset=utf-8",
            ),
        ]
        failure_details = [
            {
                "role": item.artifact_role,
                "reason": "post-sanitization TeX conservation failed; damaged payload was suppressed",
                "status": "INVALID",
            }
            for item in tex_gate_candidates
            if item.artifact_id in failed_ids
        ]
        provisional = _build_manifest(
            snapshot,
            request,
            [*safe_records, *generated_records, *placeholder_controls],
            submission_id=submission_id,
            generated_at=generated_at,
            audit_focus=audit_focus,
            redaction_count=redaction_count,
            skipped_sensitive_project_files=skipped_sensitive_project_files,
            packaging_status=PackagingStatus.FAILED,
            audit_package_status=AuditPackageStatus.INVALID,
            extra_missing_details=failure_details,
        )
        readme_bytes = render_readme(provisional).encode("utf-8")
        safe_files[README_PATH] = readme_bytes
        final_controls = [
            _control_record(
                ArtifactRole.README,
                README_PATH,
                readme_bytes,
                "text/markdown; charset=utf-8",
            ),
            _control_record(
                ArtifactRole.SUBMISSION_MANIFEST,
                MANIFEST_PATH,
                media_type="application/json; charset=utf-8",
            ),
        ]
        manifest = _build_manifest(
            snapshot,
            request,
            [*safe_records, *generated_records, *final_controls],
            submission_id=submission_id,
            generated_at=generated_at,
            audit_focus=audit_focus,
            redaction_count=redaction_count,
            skipped_sensitive_project_files=skipped_sensitive_project_files,
            packaging_status=PackagingStatus.FAILED,
            audit_package_status=AuditPackageStatus.INVALID,
            extra_missing_details=failure_details,
        )
        safe_files[MANIFEST_PATH] = _json_bytes(manifest.to_dict())
        validate_archive_namespace([(name, False) for name in safe_files])
        zip_bytes = (
            _fixed_zip(safe_files, maximum_bytes=MAX_AUDIT_ZIP_BYTES)
            if include_zip else b""
        )
        return AuditSubmissionResult(
            submission_id=submission_id,
            snapshot_id=snapshot.snapshot_id,
            snapshot_fingerprint=snapshot.current_fingerprint,
            generated_at=generated_at,
            manifest=manifest,
            files=safe_files,
            zip_bytes=zip_bytes,
            zip_sha256=hashlib.sha256(zip_bytes).hexdigest() if zip_bytes else "",
        )

    if request.depth is AuditDepth.QUICK:
        _annotate_quick_dependency_manifests(packaged, files)
    preliminary_records = _manifest_records(packaged)
    completeness = _completeness_issues(
        snapshot, request, preliminary_records, files
    )
    packaging_status = (
        PackagingStatus.PARTIAL if completeness else PackagingStatus.SUCCESS
    )
    audit_package_status = (
        AuditPackageStatus.INCOMPLETE if completeness else AuditPackageStatus.VALID
    )
    _enrich_metrics_status(
        packaged,
        files,
        packaging_status=packaging_status,
        audit_package_status=audit_package_status,
    )
    payload_records = _manifest_records(packaged)
    integrity_payload.update({
        "packaging_status": packaging_status.value,
        "audit_package_status": audit_package_status.value,
        "valid": audit_package_status is AuditPackageStatus.VALID,
        "tex_content_gate_valid": True,
        "completeness_failures": completeness,
    })
    integrity_bytes = _json_bytes(integrity_payload)
    files[PACKAGING_INTEGRITY_PATH] = integrity_bytes
    integrity_record = _control_record(
        ArtifactRole.PACKAGING_INTEGRITY,
        PACKAGING_INTEGRITY_PATH,
        integrity_bytes,
        "application/json; charset=utf-8",
    )
    placeholder_controls = [
        _control_record(ArtifactRole.README, README_PATH),
        _control_record(ArtifactRole.PROMPT_SHORT, SHORT_PROMPT_PATH),
        _control_record(ArtifactRole.PROMPT_FULL, FULL_PROMPT_PATH),
        _control_record(
            ArtifactRole.SUBMISSION_MANIFEST,
            MANIFEST_PATH,
            media_type="application/json; charset=utf-8",
        ),
        _control_record(ArtifactRole.SHA256SUMS, SHA256SUMS_PATH),
    ]
    provisional = _build_manifest(
        snapshot,
        request,
        [*payload_records, integrity_record, *placeholder_controls],
        submission_id=submission_id,
        generated_at=generated_at,
        audit_focus=audit_focus,
        redaction_count=redaction_count,
        skipped_sensitive_project_files=skipped_sensitive_project_files,
        packaging_status=packaging_status,
        audit_package_status=audit_package_status,
        extra_missing_details=completeness,
    )
    full_bytes = render_full_prompt(provisional).encode("utf-8")
    short_bytes = (render_short_prompt(provisional) + "\n").encode("utf-8")
    readme_bytes = render_readme(provisional).encode("utf-8")
    files.update({
        README_PATH: readme_bytes,
        SHORT_PROMPT_PATH: short_bytes,
        FULL_PROMPT_PATH: full_bytes,
    })
    final_controls = [
        _control_record(
            ArtifactRole.README,
            README_PATH,
            readme_bytes,
            "text/markdown; charset=utf-8",
        ),
        _control_record(ArtifactRole.PROMPT_SHORT, SHORT_PROMPT_PATH, short_bytes),
        _control_record(
            ArtifactRole.PROMPT_FULL,
            FULL_PROMPT_PATH,
            full_bytes,
            "text/markdown; charset=utf-8",
        ),
        _control_record(
            ArtifactRole.SUBMISSION_MANIFEST,
            MANIFEST_PATH,
            media_type="application/json; charset=utf-8",
        ),
        _control_record(ArtifactRole.SHA256SUMS, SHA256SUMS_PATH),
    ]
    manifest = _build_manifest(
        snapshot,
        request,
        [*payload_records, integrity_record, *final_controls],
        submission_id=submission_id,
        generated_at=generated_at,
        audit_focus=audit_focus,
        redaction_count=redaction_count,
        skipped_sensitive_project_files=skipped_sensitive_project_files,
        packaging_status=packaging_status,
        audit_package_status=audit_package_status,
        extra_missing_details=completeness,
    )
    files[MANIFEST_PATH] = _json_bytes(manifest.to_dict())
    validate_archive_namespace(
        [(name, False) for name in files], additions=(SHA256SUMS_PATH,)
    )
    sums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        for name, data in sorted(files.items())
    ).encode("utf-8")
    files[SHA256SUMS_PATH] = sums
    zip_bytes = (
        _fixed_zip(files, maximum_bytes=MAX_AUDIT_ZIP_BYTES)
        if include_zip else b""
    )
    return AuditSubmissionResult(
        submission_id=submission_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_fingerprint=snapshot.current_fingerprint,
        generated_at=generated_at,
        manifest=manifest,
        files=files,
        zip_bytes=zip_bytes,
        zip_sha256=hashlib.sha256(zip_bytes).hexdigest() if zip_bytes else "",
    )


def build_lightweight_audit_files(
    snapshot: RunSnapshot,
    *,
    audit_focus: str = "",
) -> AuditSubmissionResult:
    """Build a truthful four-file control set without claiming payload exists."""
    if not isinstance(snapshot, RunSnapshot):
        raise TypeError("build_lightweight_audit_files requires RunSnapshot")
    request = AuditSubmissionRequest(depth=AuditDepth.STANDARD, audit_focus=audit_focus)
    submission_id = f"audit-{uuid.uuid4().hex[:20]}"
    generated_at = _now_iso()
    cleaned_focus = request.audit_focus
    if request.sanitize_sensitive:
        cleaned_focus = _redact_text(cleaned_focus)[0]
    placeholders = [
        _control_record(ArtifactRole.README, README_PATH),
        _control_record(ArtifactRole.PROMPT_SHORT, SHORT_PROMPT_PATH),
        _control_record(ArtifactRole.PROMPT_FULL, FULL_PROMPT_PATH),
        _control_record(
            ArtifactRole.SUBMISSION_MANIFEST,
            MANIFEST_PATH,
            media_type="application/json; charset=utf-8",
        ),
    ]
    provisional = _build_manifest(
        snapshot,
        request,
        placeholders,
        submission_id=submission_id,
        generated_at=generated_at,
        audit_focus=cleaned_focus,
        redaction_count=0,
        packaging_status=PackagingStatus.PARTIAL,
        audit_package_status=AuditPackageStatus.INCOMPLETE,
    )
    full_bytes = render_full_prompt(provisional).encode("utf-8")
    short_bytes = (render_short_prompt(provisional) + "\n").encode("utf-8")
    readme_bytes = render_readme(provisional).encode("utf-8")
    controls = [
        _control_record(ArtifactRole.README, README_PATH, readme_bytes, "text/markdown; charset=utf-8"),
        _control_record(ArtifactRole.PROMPT_SHORT, SHORT_PROMPT_PATH, short_bytes),
        _control_record(ArtifactRole.PROMPT_FULL, FULL_PROMPT_PATH, full_bytes, "text/markdown; charset=utf-8"),
        _control_record(
            ArtifactRole.SUBMISSION_MANIFEST,
            MANIFEST_PATH,
            media_type="application/json; charset=utf-8",
        ),
    ]
    manifest = _build_manifest(
        snapshot,
        request,
        controls,
        submission_id=submission_id,
        generated_at=generated_at,
        audit_focus=cleaned_focus,
        redaction_count=0,
        packaging_status=PackagingStatus.PARTIAL,
        audit_package_status=AuditPackageStatus.INCOMPLETE,
    )
    files = {
        README_PATH: readme_bytes,
        SHORT_PROMPT_PATH: short_bytes,
        FULL_PROMPT_PATH: full_bytes,
        MANIFEST_PATH: _json_bytes(manifest.to_dict()),
    }
    return AuditSubmissionResult(
        submission_id=submission_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_fingerprint=snapshot.current_fingerprint,
        generated_at=generated_at,
        manifest=manifest,
        files=files,
    )


def write_audit_submission_atomic(
    snapshot: RunSnapshot,
    destination: str | os.PathLike[str],
    request: AuditSubmissionRequest | None = None,
    *,
    submission_id: str | None = None,
    generated_at: str | None = None,
) -> AuditSubmissionResult:
    """Atomically replace ``destination`` with a completely built ZIP."""
    target = Path(destination)
    if target.suffix.casefold() != ".zip":
        raise ValueError("audit submission destination must end in .zip")
    target.parent.mkdir(parents=True, exist_ok=True)
    result = build_audit_submission(
        snapshot,
        request,
        submission_id=submission_id,
        generated_at=generated_at,
        include_zip=True,
    )
    temporary = target.parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(result.zip_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return replace(result, zip_path=str(target))


def snapshot_fingerprint_from_hashes(
    *,
    current_tex_sha256: str = "",
    current_pdf_sha256: str = "",
    decisions_sha256: str = "",
    verification_sha256: str = "",
) -> str:
    """Compute the stale-check value used by server/UI state transitions."""
    pairs = [
        (ArtifactRole.CURRENT_TEX, current_tex_sha256),
        (ArtifactRole.CURRENT_PREVIEW, current_pdf_sha256),
        (ArtifactRole.DECISIONS, decisions_sha256),
        (ArtifactRole.VERIFICATION, verification_sha256),
    ]
    present = sorted((role, str(digest)) for role, digest in pairs if str(digest))
    canonical = json.dumps(present, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

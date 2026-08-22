# -*- coding: utf-8 -*-
"""Build portable, privacy-cleaned AI audit submission packages."""

from __future__ import annotations

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
from .audit_schema import (
    ArtifactRole,
    AuditArtifact,
    AuditDepth,
    AuditManifestArtifact,
    AuditSubmissionManifest,
    AuditSubmissionRequest,
    AuditSubmissionResult,
    AuditWorkflow,
    RunSnapshot,
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
MAX_AUDIT_ZIP_BYTES = 500 * 1024 * 1024

CONTROL_PATHS = frozenset({
    README_PATH,
    SHORT_PROMPT_PATH,
    FULL_PROMPT_PATH,
    MANIFEST_PATH,
    SHA256SUMS_PATH,
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
}

_EXPECTED_ROLES = {
    AuditWorkflow.ANALYSIS_REVIEW_ONLY: {
        ArtifactRole.SOURCE_TEX,
        ArtifactRole.STAGE_SOURCE_TEX,
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
            PARTIAL_COMPILED: "raw-ocr-partial-compiled.pdf",
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


def _sanitize_bytes(data: bytes, path: str, media_type: str) -> tuple[bytes, int]:
    decoded = _decode_text(data, path, media_type)
    if decoded is None:
        return data, 0
    text, encoding = decoded
    if PurePosixPath(path).suffix.lower() == ".json" or "application/json" in media_type.lower():
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            pass
        else:
            cleaned_value = _sanitize_jsonish(parsed, redact_sensitive=True)
            if cleaned_value == parsed:
                return data, 0
            # JSON is a structured audit record, so sanitize decoded values and
            # re-serialize instead of applying UNC regexes to JSON escape bytes.
            return _json_bytes(cleaned_value), 1
    cleaned, count = _redact_text(text)
    if not count:
        return data, 0
    try:
        return cleaned.encode(encoding), count
    except UnicodeEncodeError:
        return cleaned.encode("utf-8"), count


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


def _select_and_package_artifacts(
    snapshot: RunSnapshot,
    request: AuditSubmissionRequest,
) -> tuple[
    list[_MutablePackagedArtifact],
    dict[str, bytes],
    int,
    list[dict[str, object]],
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

    transformed: list[tuple[AuditArtifact, bytes, int, str, str]] = []
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
        data = item.data
        changes = 0
        packaged_media_type = item.media_type
        if item.preview_status in {COMPILED, PARTIAL_COMPILED} and not data.startswith(b"%PDF-"):
            raise ValueError(
                f"{item.preview_status} preview must contain a real PDF artifact"
            )
        if request.sanitize_sensitive:
            data, changes = _sanitize_bytes(data, item.path, item.media_type)
        if item.preview_status == SOURCE_PREVIEW:
            data = _ensure_source_preview_notice(data)
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
        transformed.append((item, data, changes, requested, packaged_media_type))
        redaction_count += changes

    for item, data, changes, requested_path, packaged_media_type in transformed:
        requested = _safe_bundle_path(requested_path)
        digest = hashlib.sha256(data).hexdigest()
        parents = item.parent_artifact_ids
        metadata = thaw_json(item.metadata)
        metadata = _sanitize_jsonish(
            metadata, redact_sensitive=request.sanitize_sensitive
        )
        existing = by_digest.get(digest)
        if existing is not None:
            alias_path = _allocate_path(requested, used_paths)
            used_paths.append(alias_path)
            existing.aliases.append({
                "path": alias_path,
                "artifact_role": item.artifact_role,
                "artifact_id": item.artifact_id,
                "source_bytes_sha256": item.bytes_sha256,
                "parent_artifact_ids": list(parents),
                "preview_status": item.preview_status,
                **({"requested_path": requested} if alias_path != requested else {}),
            })
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
            redacted=changes > 0 or data != item.data,
            metadata=metadata,
        )
        packaged.append(record)
        by_digest[digest] = record
    return packaged, files, redaction_count, skipped_sensitive_project_files


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
) -> AuditSubmissionManifest:
    available_roles = {item.artifact_role for item in snapshot.artifacts}
    expected = {
        role for role in _EXPECTED_ROLES[snapshot.workflow] if _role_is_included(role, request)
    }
    if (
        snapshot.workflow in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}
        and ArtifactRole.SOURCE_IMAGE in available_roles
    ):
        # OCR accepts either a PDF or a single source image.  Do not claim the
        # PDF role is missing when the host authoritatively recorded an image.
        expected.discard(ArtifactRole.SOURCE_PDF)
    if snapshot.terminal_status is TerminalStatus.FAILED:
        expected.add(ArtifactRole.ERROR_LOG)
    missing = tuple(sorted(expected - available_roles))
    record_list = tuple(records)
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
    blockers = tuple(cleaner(item)[0] for item in snapshot.blockers)
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
        missing_expected_roles=missing,
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
    ) = _select_and_package_artifacts(snapshot, request)
    payload_records = _manifest_records(packaged)
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
        [*payload_records, *placeholder_controls],
        submission_id=submission_id,
        generated_at=generated_at,
        audit_focus=audit_focus,
        redaction_count=redaction_count,
        skipped_sensitive_project_files=skipped_sensitive_project_files,
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
        _control_record(ArtifactRole.README, README_PATH, readme_bytes, "text/markdown; charset=utf-8"),
        _control_record(ArtifactRole.PROMPT_SHORT, SHORT_PROMPT_PATH, short_bytes),
        _control_record(ArtifactRole.PROMPT_FULL, FULL_PROMPT_PATH, full_bytes, "text/markdown; charset=utf-8"),
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
        [*payload_records, *final_controls],
        submission_id=submission_id,
        generated_at=generated_at,
        audit_focus=audit_focus,
        redaction_count=redaction_count,
        skipped_sensitive_project_files=skipped_sensitive_project_files,
    )
    manifest_bytes = _json_bytes(manifest.to_dict())
    files[MANIFEST_PATH] = manifest_bytes
    validate_archive_namespace([(name, False) for name in files], additions=(SHA256SUMS_PATH,))
    sums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        for name, data in sorted(files.items())
    ).encode("utf-8")
    files[SHA256SUMS_PATH] = sums
    zip_bytes = (
        _fixed_zip(files, maximum_bytes=MAX_AUDIT_ZIP_BYTES)
        if include_zip
        else b""
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

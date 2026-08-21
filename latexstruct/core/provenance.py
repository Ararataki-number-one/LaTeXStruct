# -*- coding: utf-8 -*-
"""Pure helpers for self-describing TEX export provenance.

The stored project remains byte-for-byte unchanged.  Provenance is attached
only to downloaded artifacts, and hashes always describe the *unstamped* TEX
body.  This makes a downloaded file independently auditable without letting a
comment alter the commit marker that authorized the export.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping


PROVENANCE_SCHEMA_VERSION = "latexstruct-export-provenance-v2"
PROVENANCE_MANIFEST_NAME = "LATEXSTRUCT-PROVENANCE.json"
RAW_ARTIFACT_PACKAGE_PATH = "LATEXSTRUCT-RAW-SOURCE.tex"
PROVENANCE_BEGIN = "% LaTeXStruct-Provenance-Begin"
PROVENANCE_END = "% LaTeXStruct-Provenance-End"

VERIFIED_SCOPE = (
    "structural_safety_and_recorded_compile_checks_only;"
    "not_ocr_text_math_or_semantic_accuracy"
)
UNVERIFIED_SCOPE = "snapshot_only;safety_or_publication_verification_not_established"
RAW_OCR_SCOPE = "raw_ocr_snapshot_only;structure_and_publication_not_verified"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+:-]{0,159}")
_TEX_MAGIC_LINE_RE = re.compile(r"%(?:&\S.*|\s*!\s*TeX\b.*)", re.IGNORECASE)
_FIELD_ORDER = (
    "schema_version",
    "artifact_kind",
    "verification_status",
    "verification_scope",
    "app_version",
    "build_id",
    "commit",
    "prompt_version",
    "source_sha256",
    "body_sha256",
    "raw_sha256",
    "result_sha256",
    # The legacy identity fields above remain aliases for the producer.  The
    # explicit fields below prevent a newer exporter from impersonating the
    # build that actually produced a stored result.
    "producer_app_version",
    "producer_build_id",
    "producer_commit",
    "producer_prompt_version",
    "exporter_app_version",
    "exporter_build_id",
    "exporter_commit",
    # ``raw_sha256`` remains the byte-hash alias.  These fields state exactly
    # which companion artifact it describes and how to recompute its canonical
    # text hash without confusing CRLF/LF normalization with byte identity.
    "raw_artifact_role",
    "raw_artifact_path",
    "raw_bytes_sha256",
    "raw_normalized_text_sha256",
    "raw_normalization_pipeline",
)


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 of an immutable byte artifact."""
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_lf_normalized_text(data: bytes) -> str:
    """Hash decoded TEX text after newline normalization and UTF-8 encoding.

    The byte hash remains authoritative for artifact identity.  This secondary
    digest is deliberately narrow and reproducible: decode with LaTeXStruct's
    existing TEX decoder, map CRLF/CR to LF, then encode as UTF-8 without a BOM.
    """
    from .project import decode_tex_bytes

    text = decode_tex_bytes(bytes(data)).text
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return sha256_bytes(normalized.encode("utf-8"))


def _identity(value: object, *, default: str = "unknown") -> str:
    text = str(value or "").strip()
    return text if _SAFE_IDENTITY_RE.fullmatch(text) else default


def _hash_or_unknown(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if _SHA256_RE.fullmatch(text) else "unknown"


def _identity_record(
    value: Mapping[str, object] | None,
    *,
    fallback: Mapping[str, object] | None = None,
) -> dict[str, str]:
    """Return a bounded build identity without consulting ambient runtime state."""
    source = value if isinstance(value, Mapping) else (fallback or {})
    return {
        "app_version": _identity(source.get("app_version")),
        "build_id": _identity(source.get("build_id")),
        "commit": _identity(source.get("commit")),
        "prompt_version": _identity(source.get("prompt_version")),
    }


def make_provenance_record(
    *,
    body: bytes,
    verified: bool,
    verification_scope: str,
    artifact_kind: str,
    app_version: str,
    build_id: str = "unknown",
    commit: str = "unknown",
    prompt_version: str = "unknown",
    source_sha256: str = "unknown",
    raw_sha256: str = "unknown",
    result_sha256: str = "unknown",
    producer_identity: Mapping[str, object] | None = None,
    exporter_identity: Mapping[str, object] | None = None,
    raw_artifact_role: str = "unknown",
    raw_artifact_path: str = "unknown",
    raw_bytes_sha256: str = "unknown",
    raw_normalized_text_sha256: str = "unknown",
    raw_normalization_pipeline: str = "unknown",
) -> dict[str, str]:
    """Build one bounded, JSON-safe record without reading external state."""
    status = "VERIFIED" if verified else "UNVERIFIED"
    scope = str(verification_scope or "").strip()
    if not scope or any(char in scope for char in "\r\n") or len(scope) > 240:
        scope = VERIFIED_SCOPE if verified else UNVERIFIED_SCOPE
    # The comment must remain representable in legacy TEX encodings, so every
    # identity and scope value is deliberately ASCII-only.
    try:
        scope.encode("ascii")
    except UnicodeEncodeError:
        scope = VERIFIED_SCOPE if verified else UNVERIFIED_SCOPE
    legacy_identity = {
        "app_version": app_version,
        "build_id": build_id,
        "commit": commit,
        "prompt_version": prompt_version,
    }
    producer = _identity_record(producer_identity, fallback=legacy_identity)
    exporter = _identity_record(exporter_identity, fallback=legacy_identity)
    raw_bytes = _hash_or_unknown(raw_bytes_sha256)
    if raw_bytes == "unknown":
        raw_bytes = _hash_or_unknown(raw_sha256)
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "artifact_kind": _identity(artifact_kind),
        "verification_status": status,
        "verification_scope": scope,
        # Backward-compatible aliases.  Their meaning is now unambiguously the
        # producer identity; a legacy stored result therefore stays unknown.
        "app_version": producer["app_version"],
        "build_id": producer["build_id"],
        "commit": producer["commit"],
        "prompt_version": producer["prompt_version"],
        "source_sha256": _hash_or_unknown(source_sha256),
        "body_sha256": sha256_bytes(body),
        "raw_sha256": raw_bytes,
        "result_sha256": _hash_or_unknown(result_sha256),
        "producer_app_version": producer["app_version"],
        "producer_build_id": producer["build_id"],
        "producer_commit": producer["commit"],
        "producer_prompt_version": producer["prompt_version"],
        "exporter_app_version": exporter["app_version"],
        "exporter_build_id": exporter["build_id"],
        "exporter_commit": exporter["commit"],
        "raw_artifact_role": _identity(raw_artifact_role),
        "raw_artifact_path": _identity(raw_artifact_path),
        "raw_bytes_sha256": raw_bytes,
        "raw_normalized_text_sha256": _hash_or_unknown(
            raw_normalized_text_sha256
        ),
        "raw_normalization_pipeline": _identity(raw_normalization_pipeline),
    }


def render_provenance_comment(record: Mapping[str, object], newline: str = "\n") -> str:
    """Render a deterministic ASCII TEX comment from a provenance record."""
    if newline not in {"\n", "\r\n", "\r"}:
        newline = "\n"
    fields = []
    for key in _FIELD_ORDER:
        value = str(record.get(key, "unknown"))
        if any(char in value for char in "\r\n"):
            raise ValueError(f"provenance field contains a newline: {key}")
        value.encode("ascii")
        fields.append(f"% {key}: {value}")
    return newline.join((PROVENANCE_BEGIN, *fields, PROVENANCE_END, ""))


def _format_for_tex_bytes(data: bytes) -> tuple[bytes, str, str]:
    """Return BOM, encoding and newline without changing any body bytes."""
    from .project import decode_tex_bytes

    fmt = decode_tex_bytes(data)
    return fmt.bom, fmt.encoding, fmt.newline or "\n"


def _tex_magic_prefix_length(payload: bytes, encoding: str, newline: str) -> int:
    """Keep first-line format/engine directives ahead of provenance comments."""
    separator = newline.encode(encoding)
    cursor = 0
    while cursor < len(payload):
        end = payload.find(separator, cursor)
        if end < 0:
            line_bytes = payload[cursor:]
            next_cursor = len(payload)
        else:
            line_bytes = payload[cursor:end]
            next_cursor = end + len(separator)
        try:
            line = line_bytes.decode(encoding)
        except UnicodeDecodeError:
            break
        if not _TEX_MAGIC_LINE_RE.fullmatch(line):
            break
        # A provenance block needs its own line.  A final magic directive with
        # no terminator cannot be moved or extended without changing the body.
        if end < 0:
            return 0
        cursor = next_cursor
    return cursor


def strip_tex_provenance(data: bytes) -> bytes:
    """Remove one leading LaTeXStruct provenance block, preserving all else."""
    raw = bytes(data)
    bom, encoding, newline = _format_for_tex_bytes(raw)
    payload = raw[len(bom):]
    prefix_end = _tex_magic_prefix_length(payload, encoding, newline)
    begin = (PROVENANCE_BEGIN + newline).encode(encoding)
    if not payload.startswith(begin, prefix_end):
        return raw
    end = (PROVENANCE_END + newline).encode(encoding)
    end_at = payload.find(end, prefix_end + len(begin))
    if end_at < 0:
        # A malformed user comment is not silently removed.
        return raw
    return bom + payload[:prefix_end] + payload[end_at + len(end):]


def stamp_tex_provenance(data: bytes, record: Mapping[str, object]) -> bytes:
    """Attach one canonical leading comment; repeated calls are idempotent."""
    body = strip_tex_provenance(bytes(data))
    expected = str(record.get("body_sha256") or "").lower()
    if expected != sha256_bytes(body):
        raise ValueError("provenance body_sha256 does not match the TEX body")
    bom, encoding, newline = _format_for_tex_bytes(body)
    comment = render_provenance_comment(record, newline).encode(encoding)
    payload = body[len(bom):]
    prefix_end = _tex_magic_prefix_length(payload, encoding, newline)
    return bom + payload[:prefix_end] + comment + payload[prefix_end:]


def parse_tex_provenance(data: bytes) -> dict[str, str]:
    """Parse a leading canonical block; return an empty dict when absent."""
    raw = bytes(data)
    bom, encoding, newline = _format_for_tex_bytes(raw)
    payload = raw[len(bom):]
    prefix_end = _tex_magic_prefix_length(payload, encoding, newline)
    begin = (PROVENANCE_BEGIN + newline).encode(encoding)
    if not payload.startswith(begin, prefix_end):
        return {}
    end = (PROVENANCE_END + newline).encode(encoding)
    end_at = payload.find(end, prefix_end + len(begin))
    if end_at < 0:
        return {}
    block = payload[prefix_end + len(begin):end_at].decode(encoding)
    result: dict[str, str] = {}
    for line in block.splitlines():
        match = re.fullmatch(r"% ([a-z0-9_]+): (.*)", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result

# -*- coding: utf-8 -*-
"""Portable, traceable filenames for AI-audit submission ZIPs."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from enum import Enum


# ``save_unique_download`` keeps stems to 120 characters.  Building the audit
# name to the same bound means its required workflow/run/status suffix is never
# silently cut off when the desktop copy is saved.
MAX_AUDIT_ZIP_FILENAME_CHARS = 124
_INVALID_COMPONENT_RE = re.compile(r"[^0-9A-Za-z\u4e00-\u9fff._ -]+")
_WHITESPACE_RE = re.compile(r"\s+")
_MULTI_HYPHEN_RE = re.compile(r"-{2,}")
_DOUBLE_UNDERSCORE_RE = re.compile(r"_{2,}")


def _enum_text(value: object) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value or "")


def _safe_component(value: object, *, fallback: str) -> str:
    """Return one filename component without consuming the ``__`` delimiter."""
    text = unicodedata.normalize("NFC", _enum_text(value)).strip()
    text = _INVALID_COMPONENT_RE.sub("-", text)
    text = _WHITESPACE_RE.sub("-", text)
    text = _DOUBLE_UNDERSCORE_RE.sub("-", text)
    text = _MULTI_HYPHEN_RE.sub("-", text).strip(" .-_")
    return text or fallback


def _utc_timestamp(moment: datetime | None = None) -> str:
    value = moment or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_audit_zip_filename(
    *,
    project_name: object,
    workflow: object,
    run_id: object,
    source_status: object,
    generated_at: datetime | None = None,
) -> str:
    """Build ``project__workflow__UTC__run__status.zip``.

    Workflow and source status are normalized to upper case enum spellings.
    The run ID is preserved apart from filename-unsafe character replacement;
    in particular, no OCR/analysis/review prefix is added or removed.
    """
    project = _safe_component(project_name, fallback="LaTeXStruct")
    workflow_text = _safe_component(workflow, fallback="UNKNOWN_WORKFLOW").upper()
    run_text = _safe_component(run_id, fallback="unknown-run")
    status_text = _safe_component(source_status, fallback="UNVERIFIED").upper()
    timestamp = _utc_timestamp(generated_at)

    required_tail = (
        f"__{workflow_text}__{timestamp}__{run_text}__{status_text}.zip"
    )
    project_budget = MAX_AUDIT_ZIP_FILENAME_CHARS - len(required_tail)
    if project_budget < 1:
        raise ValueError("audit run ID is too long for a portable ZIP filename")
    project = project[:project_budget].rstrip(" .-_") or "L"
    return f"{project}{required_tail}"


__all__ = ["MAX_AUDIT_ZIP_FILENAME_CHARS", "build_audit_zip_filename"]

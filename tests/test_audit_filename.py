# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest
from fastapi.responses import FileResponse

from latexstruct.core.audit_schema import AuditWorkflow, TerminalStatus
from latexstruct.server.audit_filename import (
    MAX_AUDIT_ZIP_FILENAME_CHARS,
    build_audit_zip_filename,
)
from latexstruct.server.audit_store import AuditSubmissionStore
from latexstruct.server.downloads import safe_download_filename, save_unique_download


def test_audit_zip_filename_matches_v127_contract_exactly():
    filename = build_audit_zip_filename(
        project_name="Sharp Bounds",
        workflow=AuditWorkflow.OCR_ANALYSIS_REVIEW,
        generated_at=datetime(2026, 8, 22, 13, 34, 8, tzinfo=timezone.utc),
        run_id="c955db229541",
        source_status=TerminalStatus.UNVERIFIED,
    )

    assert filename == (
        "Sharp-Bounds__OCR_ANALYSIS_REVIEW__20260822T133408Z__"
        "c955db229541__UNVERIFIED.zip"
    )
    assert filename.count("OCR_ANALYSIS_REVIEW") == 1
    assert "c955db229541" in filename


def test_audit_zip_filename_preserves_chinese_and_converts_time_to_utc():
    filename = build_audit_zip_filename(
        project_name="中文 Ramsey／样本",
        workflow="OCR_ONLY",
        generated_at=datetime(
            2026,
            8,
            22,
            21,
            34,
            8,
            tzinfo=timezone(timedelta(hours=8)),
        ),
        run_id="ocr-c955db229541",
        source_status="PARTIAL",
    )

    assert filename == (
        "中文-Ramsey-样本__OCR_ONLY__20260822T133408Z__"
        "ocr-c955db229541__PARTIAL.zip"
    )
    # No synthetic OCR tag is inserted; the workflow and the real run ID are
    # each represented exactly once.
    assert filename.count("OCR_ONLY") == 1
    assert filename.count("ocr-c955db229541") == 1


def test_audit_zip_filename_is_bounded_without_cutting_lineage_suffix():
    filename = build_audit_zip_filename(
        project_name="很长的中文项目名" * 30,
        workflow="OCR_ANALYSIS_REVIEW",
        generated_at=datetime(2026, 8, 22, tzinfo=timezone.utc),
        run_id="ocr-analysis-start-c955db229541-acde1234",
        source_status="CANCELLED",
    )

    assert len(filename) <= MAX_AUDIT_ZIP_FILENAME_CHARS
    assert filename.endswith(
        "__OCR_ANALYSIS_REVIEW__20260822T000000Z__"
        "ocr-analysis-start-c955db229541-acde1234__CANCELLED.zip"
    )
    assert safe_download_filename(filename) == filename
    assert AuditSubmissionStore._safe_zip_filename(filename) == filename


def test_audit_zip_filename_rejects_run_id_that_cannot_fit_portably():
    with pytest.raises(ValueError, match="run ID is too long"):
        build_audit_zip_filename(
            project_name="样本",
            workflow="OCR_ANALYSIS_REVIEW",
            generated_at=datetime(2026, 8, 22, tzinfo=timezone.utc),
            run_id="r" * 200,
            source_status="UNVERIFIED",
        )


def test_audit_zip_same_name_never_overwrites_and_content_disposition_is_utf8(
    tmp_path,
):
    filename = build_audit_zip_filename(
        project_name="中文样本",
        workflow="ANALYSIS_REVIEW_ONLY",
        generated_at=datetime(2026, 8, 22, 13, 34, 8, tzinfo=timezone.utc),
        run_id="run-123",
        source_status="SUCCESS",
    )
    first = save_unique_download(b"first", filename, root=tmp_path)
    second = save_unique_download(b"second", filename, root=tmp_path)

    assert first.name == filename
    assert second.name != first.name
    assert re.fullmatch(r".+ \(1\)\.zip", second.name)
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"second"

    response = FileResponse(first, media_type="application/zip", filename=filename)
    disposition = response.headers["content-disposition"]
    marker = "filename*=utf-8''"
    assert marker in disposition.lower()
    encoded = disposition[disposition.lower().index(marker) + len(marker):]
    assert unquote(encoded) == filename

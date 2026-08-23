# -*- coding: utf-8 -*-
"""Server boundary tests for the compile/render/visual quality loop."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

pymupdf = pytest.importorskip("pymupdf")
pytest.importorskip("fastapi")
try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover - older Starlette installations
    from starlette.testclient import TestClient

import latexstruct.server.app as srv
from latexstruct.config import AppConfig
from latexstruct.core.audit_schema import (
    ArtifactRole,
    AuditWorkflow,
    RunSnapshot,
    TerminalStatus,
)
from latexstruct.core.audit_submission import make_audit_artifact
from latexstruct.server.audit_store import AuditSubmissionStore


def _pdf_bytes(page_count: int) -> bytes:
    document = pymupdf.open()
    try:
        for page_number in range(1, page_count + 1):
            page = document.new_page(width=300, height=420)
            page.insert_text((36, 54), f"immutable source page {page_number}")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _source_record(data: bytes, *, pages: int, start: int, end: int) -> dict:
    return {
        "available": True,
        "path": "ocr-source.pdf",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "source_type": "pdf",
        "source_pages": pages,
        "selected_start": start,
        "selected_end": end,
        "immutable_evidence": True,
        "reason": "",
    }


def _persist_ocr_page_count_authority(
    project_dir: Path,
    data: bytes,
    *,
    project_id: str | None = None,
    page_count: int = 17,
    start: int = 1,
    end: int = 17,
    workflow: AuditWorkflow = AuditWorkflow.OCR_ANALYSIS_REVIEW,
    artifact_data: bytes | None = None,
    include_source_pdf: bool = True,
    source_metadata_overrides: dict | None = None,
) -> RunSnapshot:
    """Persist the same hash-verified latest snapshot used by legacy migration."""
    frozen_pdf = data if artifact_data is None else artifact_data
    source_metadata = _source_record(
        frozen_pdf,
        pages=1,
        start=start,
        end=end,
    )
    source_metadata.update(source_metadata_overrides or {})
    source = make_audit_artifact(
        ArtifactRole.SOURCE_PDF,
        frozen_pdf,
        filename="source.pdf",
        media_type="application/pdf",
        metadata=source_metadata,
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"\\documentclass{article}\n\\begin{document}OCR\\end{document}\n",
        parent_artifact_ids=(source.artifact_id,),
    )
    source_pdf = None
    if include_source_pdf:
        source_pdf = {
            "page_count": page_count,
            "selected_page_range": {
                "start": start,
                "end": end,
                "pages": list(range(start, end + 1)),
            },
        }
    snapshot = RunSnapshot(
        project_id=project_id or project_dir.name,
        run_id="legacy-page-count-authority",
        workflow=workflow,
        terminal_status=TerminalStatus.FAILED,
        captured_at="2026-08-23T09:32:09Z",
        artifacts=(source, raw),
        machine_verification={"safe_to_export": False},
        blockers=("legacy page-count preflight failure",),
        metadata={"project_kind": "ocr"},
        source_pdf=source_pdf,
    )
    AuditSubmissionStore(project_dir).persist_terminal_snapshot(snapshot)
    return snapshot


def _png_bytes() -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=240, height=320)
        page.insert_text((24, 40), "immutable source image")
        return page.get_pixmap(alpha=False).tobytes("png")
    finally:
        document.close()


def test_ai_ocr_quality_loop_uses_hash_bound_pdf_and_page_range(tmp_path: Path):
    data = _pdf_bytes(4)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=4, start=2, end=3),
    }

    provenance = {}
    enabled, source, page_range = srv._quality_loop_inputs(
        tmp_path,
        project,
        mode="ai",
        provenance_out=provenance,
    )

    assert enabled is True
    assert source == data
    assert page_range == (2, 3)
    digest = hashlib.sha256(data).hexdigest()
    assert provenance["original_upload_sha256"] == digest
    assert provenance["visual_pdf_sha256"] == digest
    assert provenance["visual_pdf_is_derived"] is False
    assert provenance["derivation_id"] == srv.PDF_IDENTITY_VISUAL_DERIVATION_ID


def test_ai_ocr_quality_loop_rejects_changed_source(tmp_path: Path):
    data = _pdf_bytes(2)
    record = _source_record(data, pages=2, start=1, end=2)
    (tmp_path / "ocr-source.pdf").write_bytes(data + b"changed")

    with pytest.raises(ValueError, match="大小校验失败|哈希校验失败"):
        srv._quality_loop_inputs(
            tmp_path,
            {"kind": "ocr", "ocr_source": record},
            mode="ai",
        )


@pytest.mark.parametrize(
    "invalid_kind",
    ["boolean", "equal_float", "truncating_float", "equal_string"],
)
def test_ai_ocr_quality_loop_rejects_noninteger_source_size(
    tmp_path: Path,
    invalid_kind: str,
):
    data = _pdf_bytes(2)
    record = _source_record(data, pages=2, start=1, end=2)
    record["bytes"] = {
        "boolean": True,
        "equal_float": float(len(data)),
        "truncating_float": len(data) + 0.9,
        "equal_string": str(len(data)),
    }[invalid_kind]
    (tmp_path / "ocr-source.pdf").write_bytes(data)

    with pytest.raises(ValueError, match="大小校验失败"):
        srv._quality_loop_inputs(
            tmp_path,
            {"kind": "ocr", "ocr_source": record},
            mode="ai",
        )


def test_ai_ocr_quality_loop_rejects_page_metadata_mismatch(tmp_path: Path):
    data = _pdf_bytes(3)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=4, start=1, end=3),
    }

    with pytest.raises(ValueError, match="页数与不可变快照不一致"):
        srv._quality_loop_inputs(tmp_path, project, mode="ai")


@pytest.mark.parametrize(
    "workflow",
    [AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW],
)
def test_legacy_v128_page_count_bug_requires_matching_audit_authority(
    tmp_path: Path,
    workflow: AuditWorkflow,
):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    authority = _persist_ocr_page_count_authority(
        tmp_path,
        data,
        workflow=workflow,
    )

    repaired = srv._repair_legacy_ocr_source_page_count(tmp_path, project)

    assert repaired is not None
    assert repaired["source_pages"] == 17
    assert repaired["page_count_schema"] == srv.OCR_SOURCE_PAGE_COUNT_SCHEMA
    assert repaired["page_count_source"] == (
        "host_reparsed_hash_bound_pdf_and_immutable_run_snapshot"
    )
    assert repaired["legacy_page_count_repair"] == {
        "migration_id": srv.OCR_LEGACY_PAGE_COUNT_REPAIR_ID,
        "from": 1,
        "to": 17,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "authority_snapshot_id": authority.snapshot_id,
    }


def test_legacy_page_count_is_not_repaired_without_audit_authority(tmp_path: Path):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None
    assert not (tmp_path / "audit-submissions").exists()


def test_legacy_page_count_rejects_unstructured_snapshot_authority(tmp_path: Path):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        include_source_pdf=False,
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


def test_legacy_page_count_rejects_snapshot_page_count_conflict(tmp_path: Path):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=16),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        page_count=16,
        start=1,
        end=16,
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


def test_legacy_page_count_rejects_snapshot_source_hash_conflict(tmp_path: Path):
    data = _pdf_bytes(17)
    different_bytes = data + b"\n% different immutable snapshot bytes\n"
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        artifact_data=different_bytes,
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


def test_legacy_page_count_rejects_snapshot_selected_range_conflict(tmp_path: Path):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        start=2,
        end=17,
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


def test_legacy_page_count_rejects_snapshot_project_conflict(tmp_path: Path):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        project_id="different-project",
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


def test_legacy_page_count_rejects_non_ocr_snapshot_workflow(tmp_path: Path):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        workflow=AuditWorkflow.TEMPLATE_CONVERSION,
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


@pytest.mark.parametrize(
    ("field", "authority_start", "authority_end"),
    [
        ("source_pages", 1, 17),
        ("selected_start", 1, 17),
        ("selected_end", 1, 1),
    ],
)
def test_legacy_page_count_rejects_boolean_page_metadata(
    tmp_path: Path,
    field: str,
    authority_start: int,
    authority_end: int,
):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    source = _source_record(
        data,
        pages=1,
        start=authority_start,
        end=authority_end,
    )
    source[field] = True
    project = {"id": tmp_path.name, "kind": "ocr", "ocr_source": source}
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        start=authority_start,
        end=authority_end,
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_pages", 1.0),
        ("selected_start", 1.0),
        ("selected_end", 17.0),
    ],
)
def test_legacy_page_count_rejects_fractional_page_metadata(
    tmp_path: Path,
    field: str,
    value: float,
):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    source = _source_record(data, pages=1, start=1, end=17)
    source[field] = value
    project = {"id": tmp_path.name, "kind": "ocr", "ocr_source": source}
    _persist_ocr_page_count_authority(tmp_path, data)

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("page_count_schema", ""),
        ("page_count_schema", 0),
        ("page_count_schema", False),
        ("legacy_page_count_repair", {}),
    ],
)
def test_legacy_page_count_repair_requires_schema_and_repair_keys_to_be_absent(
    tmp_path: Path,
    field: str,
    value: object,
):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    source = _source_record(data, pages=1, start=1, end=17)
    source[field] = value
    project = {"id": tmp_path.name, "kind": "ocr", "ocr_source": source}
    _persist_ocr_page_count_authority(tmp_path, data)

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("page_count_schema", ""),
        ("page_count_schema", 0),
        ("page_count_schema", False),
        ("legacy_page_count_repair", {}),
    ],
)
def test_legacy_page_count_repair_rejects_nonmissing_frozen_schema_keys(
    tmp_path: Path,
    field: str,
    value: object,
):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=1, start=1, end=17),
    }
    _persist_ocr_page_count_authority(
        tmp_path,
        data,
        source_metadata_overrides={field: value},
    )

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_pages", 17.0, "总页数记录无效"),
        ("selected_start", 1.0, "起始页记录无效"),
        ("selected_end", 17.0, "结束页记录无效"),
    ],
)
def test_ai_ocr_quality_loop_rejects_fractional_page_metadata(
    tmp_path: Path,
    field: str,
    value: float,
    message: str,
):
    data = _pdf_bytes(17)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    source = _source_record(data, pages=17, start=1, end=17)
    source["page_count_schema"] = srv.OCR_SOURCE_PAGE_COUNT_SCHEMA
    source[field] = value

    with pytest.raises(ValueError, match=message):
        srv._quality_loop_inputs(
            tmp_path,
            {"kind": "ocr", "ocr_source": source},
            mode="ai",
        )


def test_nonlegacy_page_count_mismatch_is_never_auto_repaired(tmp_path: Path):
    data = _pdf_bytes(3)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "id": tmp_path.name,
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=2, start=1, end=2),
    }

    assert srv._repair_legacy_ocr_source_page_count(tmp_path, project) is None
    with pytest.raises(ValueError, match="页数与不可变快照不一致"):
        srv._quality_loop_inputs(tmp_path, project, mode="ai")


def test_ai_ocr_quality_loop_rejects_missing_immutable_source(tmp_path: Path):
    with pytest.raises(ValueError, match="来源证据缺失"):
        srv._quality_loop_inputs(
            tmp_path,
            {"kind": "ocr", "ocr_source": {}},
            mode="ai",
        )


def test_non_ocr_ai_run_never_invents_source_pdf(tmp_path: Path):
    enabled, source, page_range = srv._quality_loop_inputs(
        tmp_path,
        {
            "kind": "tex",
            "ocr_source": {
                "available": True,
                "path": "C:/private/should-not-be-read.pdf",
            },
        },
        mode="ai",
    )

    assert enabled is True
    assert source == b""
    assert page_range is None


def test_rule_mode_legacy_ocr_can_run_without_visual_source(tmp_path: Path):
    enabled, source, page_range = srv._quality_loop_inputs(
        tmp_path,
        {"kind": "ocr", "ocr_source": {}},
        mode="rule",
    )

    assert enabled is False
    assert source == b""
    assert page_range is None


def test_ai_image_ocr_is_wrapped_as_one_immutable_visual_page(tmp_path: Path):
    data = _png_bytes()
    (tmp_path / "ocr-source.png").write_bytes(data)
    record = _source_record(data, pages=1, start=1, end=1)
    record.update({"path": "ocr-source.png", "source_type": "image"})

    provenance = {}
    enabled, source_pdf, page_range = srv._quality_loop_inputs(
        tmp_path,
        {"kind": "ocr", "ocr_source": record},
        mode="ai",
        provenance_out=provenance,
    )

    assert enabled is True
    assert source_pdf.startswith(b"%PDF-")
    assert page_range == (1, 1)
    assert provenance["original_upload_sha256"] == hashlib.sha256(data).hexdigest()
    assert provenance["visual_pdf_sha256"] == hashlib.sha256(source_pdf).hexdigest()
    assert provenance["original_upload_bytes"] == len(data)
    assert provenance["visual_pdf_bytes"] == len(source_pdf)
    assert provenance["visual_pdf_is_derived"] is True
    assert provenance["derivation_id"] == srv.IMAGE_TO_VISUAL_PDF_DERIVATION_ID
    document = pymupdf.open(stream=source_pdf, filetype="pdf")
    try:
        assert document.page_count == 1
    finally:
        document.close()


def test_process_wires_ocr_source_range_and_visual_client(tmp_path: Path):
    old_store = srv._store
    old_config = srv._config
    srv._process_jobs.clear()
    with srv._project_locks_guard:
        srv._project_locks.clear()
    srv._store = srv.ProjectStore(root=str(tmp_path / "projects"))
    srv._config = AppConfig(
        analysis_backend="api",
        ocr_base_url="https://vision.example.invalid/v1",
        ocr_model="vision-model",
        ocr_api_key="test-secret",
    )
    visual_client = object()
    captured = {}
    real_pipeline = srv.run_pipeline
    unavailable = {
        "available": False,
        "ok": None,
        "pages": 0,
        "errors": [],
        "log": "",
    }
    try:
        with TestClient(srv.create_app()) as client:
            response = client.post(
                "/api/projects",
                json={
                    "text": "\\documentclass{article}\n\\begin{document}\nHello.\n\\end{document}\n",
                    "name": "quality-loop-boundary",
                    "mode": "ai",
                },
            )
            assert response.status_code == 200, response.text
            pid = response.json()["id"]
            project_dir = Path(srv.get_store()._dir(pid))
            data = _pdf_bytes(3)
            (project_dir / "ocr-source.pdf").write_bytes(data)
            meta_path = project_dir / "meta.json"
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta.update({
                "kind": "ocr",
                # v1.2.8 accidentally persisted the fallback 1 because its
                # private import snapshot omitted source_total.
                "ocr_source": _source_record(data, pages=1, start=2, end=3),
                "ocr_resources": {"assets": []},
            })
            meta_path.write_text(
                json.dumps(meta, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            authority = _persist_ocr_page_count_authority(
                project_dir,
                data,
                project_id=pid,
                page_count=3,
                start=2,
                end=3,
            )

            def capture_pipeline(*args, **kwargs):
                captured.update(kwargs)
                safe_kwargs = dict(kwargs)
                safe_kwargs.update({
                    "mode": "rule",
                    "ai_config": None,
                    "quality_loop": False,
                    "visual_client": None,
                })
                return real_pipeline(*args, **safe_kwargs)

            with (
                patch.object(
                    srv,
                    "_build_ocr_client",
                    return_value=(visual_client, "vision-model", "api"),
                ),
                patch.object(srv, "run_pipeline", side_effect=capture_pipeline),
                patch(
                    "latexstruct.core.compilecheck.compile_latex",
                    return_value=unavailable,
                ),
            ):
                processed = client.post(f"/api/projects/{pid}/process")

        assert processed.status_code == 200, processed.text
        assert captured["quality_loop"] is True
        # The stored project kind is authoritative even though the submitted
        # TEX above deliberately contains no LaTeXStruct OCR metadata marker.
        assert captured["ocr_project"] is True
        assert captured["source_pdf_bytes"] == data
        assert captured["source_pdf_page_range"] == (2, 3)
        migrated_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert migrated_meta["ocr_source"]["source_pages"] == 3
        assert (
            migrated_meta["ocr_source"]["legacy_page_count_repair"]["migration_id"]
            == srv.OCR_LEGACY_PAGE_COUNT_REPAIR_ID
        )
        audit_store = AuditSubmissionStore(project_dir)
        authority_submissions = [
            child.name
            for child in (audit_store.root / "submissions").iterdir()
            if child.is_dir()
            and audit_store.get_submission(child.name).snapshot_id == authority.snapshot_id
        ]
        assert len(authority_submissions) == 1
        assert audit_store.get_submission(authority_submissions[0]).stale is True
        provenance = captured["source_visual_provenance"]
        assert provenance["original_upload_sha256"] == hashlib.sha256(data).hexdigest()
        assert provenance["visual_pdf_sha256"] == hashlib.sha256(data).hexdigest()
        assert provenance["visual_pdf_is_derived"] is False
        assert captured["visual_client"] is visual_client
    finally:
        srv._store = old_store
        srv._config = old_config
        srv._process_jobs.clear()
        with srv._project_locks_guard:
            srv._project_locks.clear()

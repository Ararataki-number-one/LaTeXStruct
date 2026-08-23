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


def test_ai_ocr_quality_loop_rejects_page_metadata_mismatch(tmp_path: Path):
    data = _pdf_bytes(3)
    (tmp_path / "ocr-source.pdf").write_bytes(data)
    project = {
        "kind": "ocr",
        "ocr_source": _source_record(data, pages=4, start=1, end=3),
    }

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
                "ocr_source": _source_record(data, pages=3, start=2, end=3),
                "ocr_resources": {"assets": []},
            })
            meta_path.write_text(
                json.dumps(meta, ensure_ascii=False, indent=2),
                encoding="utf-8",
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

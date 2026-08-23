from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pymupdf
from fastapi.testclient import TestClient

from latexstruct.core.ocr_runtime import OcrRunSnapshot, OcrRunStore, make_run_snapshot
from latexstruct.core.ocr_sources import (
    build_multi_image_source,
    extract_multi_image_bytes,
    verify_multi_image_source,
)
from latexstruct.server import app as srv
from latexstruct.store import ProjectStore


def _png(color: int, width: int = 3, height: int = 4) -> bytes:
    pixmap = pymupdf.Pixmap(
        pymupdf.csRGB, pymupdf.IRect(0, 0, width, height), False,
    )
    pixmap.clear_with(color)
    return pixmap.tobytes("png")


def test_multi_image_source_preserves_chinese_names_order_bytes_and_hashes():
    first = _png(0xFF0000)
    second = _png(0x0000FF, 5, 2)

    source = build_multi_image_source([
        ("第二章 中文.png", first),
        ("第1章.png", second),
    ])
    checked = verify_multi_image_source(
        source.bundle_bytes,
        expected_images=source.image_entries,
        expected_visual_sha256=hashlib.sha256(source.visual_pdf_bytes).hexdigest(),
    )

    assert [row["original_filename"] for row in checked["images"]] == [
        "第二章 中文.png", "第1章.png",
    ]
    assert [row["order"] for row in checked["images"]] == [1, 2]
    extracted = extract_multi_image_bytes(source.bundle_bytes, source.manifest)
    assert [payload for _row, payload in extracted] == [first, second]
    assert [row["sha256"] for row, _payload in extracted] == [
        hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest(),
    ]
    with zipfile.ZipFile(io.BytesIO(source.bundle_bytes)) as archive:
        assert archive.namelist() == [
            "images/000001.png", "images/000002.png", "source-manifest.json",
        ]
    with pymupdf.open(stream=source.visual_pdf_bytes, filetype="pdf") as document:
        assert document.page_count == 2


def test_multi_image_snapshot_and_store_survive_restart_without_absolute_paths(tmp_path):
    source = build_multi_image_source([
        ("第一页.png", _png(0x00FF00)),
        ("末页.png", _png(0xABCDEF)),
    ])
    snapshot = make_run_snapshot(
        source_bytes=source.bundle_bytes,
        source_type="images",
        original_filename="2-images.zip",
        source_total_pages=2,
        selected_pages=(1, 2),
        ocr_model="vision-test",
        api_backend="api",
        app_version="2.0.0",
        source_images=source.image_entries,
        visual_source_bytes=source.visual_pdf_bytes,
        run_id="c" * 32,
    )
    root = tmp_path / "中文 OCR 恢复"
    OcrRunStore(root).initialize(
        snapshot, source.bundle_bytes, visual_source_bytes=source.visual_pdf_bytes,
    )

    restarted = OcrRunStore(root)
    loaded = restarted.load_snapshot(snapshot.run_id)
    assert loaded == OcrRunSnapshot.from_dict(snapshot.to_dict())
    assert restarted.verify_source(snapshot.run_id).name == "source.zip"
    assert restarted.verify_visual_source(snapshot.run_id).name == "visual-source.pdf"
    manifest = json.loads(
        (restarted.run_dir(snapshot.run_id) / "source-images-manifest.json").read_text("utf-8")
    )
    assert [row["original_filename"] for row in manifest["images"]] == [
        "第一页.png", "末页.png",
    ]
    serialized = json.dumps(loaded.to_dict(), ensure_ascii=False)
    assert str(tmp_path) not in serialized


def test_inspect_accepts_ordered_same_field_images_and_keeps_single_image_compatible(tmp_path):
    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()
    client = TestClient(srv.create_app())
    first = _png(0x112233)
    second = _png(0x445566)
    created_ids: list[str] = []
    try:
        multi = client.post(
            "/api/ocr/inspect",
            files=[
                ("file", ("中文二.png", first, "image/png")),
                ("file", ("中文一.png", second, "image/png")),
            ],
        )
        assert multi.status_code == 200, multi.text
        info = multi.json()
        created_ids.append(info["id"])
        assert info["source_type"] == "images"
        assert info["total_pages"] == 2
        state = client.get(f"/api/ocr/jobs/{info['id']}")
        assert state.status_code == 200
        assert str(tmp_path) not in state.text
        with srv._ocr_jobs_lock:
            job = srv._ocr_jobs[info["id"]]
            assert [row["original_filename"] for row in job["source_images"]] == [
                "中文二.png", "中文一.png",
            ]
            assert [row["sha256"] for row in job["source_images"]] == [
                hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest(),
            ]
            assert job["target"].endswith("scan.zip")
            assert job["visual_target"].endswith("visual-source.pdf")

        single = client.post(
            "/api/ocr/inspect",
            files={"file": ("单页.png", first, "image/png")},
        )
        assert single.status_code == 200, single.text
        created_ids.append(single.json()["id"])
        assert single.json()["source_type"] == "image"
        assert single.json()["total_pages"] == 1
    finally:
        for job_id in created_ids:
            client.delete(f"/api/ocr/jobs/{job_id}")
        with srv._ocr_jobs_lock:
            srv._ocr_jobs.clear()

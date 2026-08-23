from __future__ import annotations

from pathlib import Path

import pytest

from latexstruct.core.ocr_artifacts import available_ocr_artifacts, resolve_ocr_artifact
from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunStore,
    OcrStoreError,
    make_run_snapshot,
)


def _frozen_run(tmp_path: Path) -> tuple[OcrRunStore, str]:
    source = b"%PDF-1.4\n% test\n"
    snapshot = make_run_snapshot(
        source_bytes=source,
        source_type="pdf",
        original_filename="中文 原稿.pdf",
        source_total_pages=1,
        selected_pages=[1],
        ocr_model="vision-test",
        api_backend="test",
        app_version="2.0.0",
        run_id="a" * 32,
    )
    store = OcrRunStore(tmp_path / "ocr-runs")
    store.initialize(snapshot, source)
    raw = {"pages": [{"page_id": "ocr-p000001", "latex": "Hello", "figures": [], "unresolved_regions": []}]}
    record = OcrPageRecord.pending(1, 1)
    record = record.transition(OcrPageStatus.RENDERING, dpi=200)
    record = record.transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256="1" * 64,
        dpi=200,
        model="vision-test",
        call_index=1,
    )
    record = record.transition(OcrPageStatus.VALIDATING)
    import hashlib, json

    raw_bytes = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    record = record.transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_tex="Hello",
        cleaned_tex="Hello",
    )
    store.persist_record(snapshot.run_id, record, raw_response=raw)
    store.freeze_raw_ocr(snapshot.run_id)
    store.save_compile_baseline(
        snapshot.run_id,
        baseline_tex="Hello",
        compile_log="two passes",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.4\ncompiled\n",
    )
    return store, snapshot.run_id


def test_resolves_allowlisted_artifacts_and_preserves_chinese_filename(tmp_path: Path):
    store, run_id = _frozen_run(tmp_path)
    source = resolve_ocr_artifact(store, run_id, "source")
    assert source.filename == "中文 原稿.pdf"
    assert source.path.read_bytes().startswith(b"%PDF-")
    baseline = resolve_ocr_artifact(store, run_id, "baseline-pdf")
    assert baseline.filename == "baseline.pdf"
    assert baseline.media_type == "application/pdf"
    assert {"source", "raw-ocr", "baseline-tex", "baseline-pdf", "compile-log"} <= set(
        available_ocr_artifacts(store, run_id)
    )


def test_rejects_unknown_role_and_tampered_bytes(tmp_path: Path):
    store, run_id = _frozen_run(tmp_path)
    with pytest.raises(ValueError):
        resolve_ocr_artifact(store, run_id, "../../secret")
    artifact = store.run_dir(run_id) / "artifacts" / "baseline.tex"
    artifact.write_text("tampered", encoding="utf-8")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        resolve_ocr_artifact(store, run_id, "baseline-tex")
    assert "baseline-tex" not in available_ocr_artifacts(store, run_id)

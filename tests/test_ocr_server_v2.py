from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    OcrPreviewStatus,
    OcrRunStore,
    OcrStoreError,
    make_page_id,
    make_run_snapshot,
)
from latexstruct.core.ocr_baseline import OcrBaselineResult
from latexstruct.core.ocr_recovery import (
    AttemptOutcome,
    OcrRecoveryEvidenceStore,
    RecoveryEvidenceError,
    RecoveryImageInput,
    RecoveryImageRole,
    RecoveryStage,
)
from latexstruct.server import app as srv
from latexstruct.store import ProjectStore


def _persist_result(
    store: OcrRunStore,
    run_id: str,
    task_index: int,
    source_page: int,
    *,
    success: bool,
) -> None:
    image = b"\x89PNG\r\n\x1a\n" + f"rendered-page-{source_page}".encode()
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    record = OcrPageRecord.pending(task_index, source_page)
    record = record.transition(OcrPageStatus.RENDERING, dpi=200)
    record = record.transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=200,
        model="vision-test",
        call_index=1,
        started_at=started_at,
    )
    store.persist_page_image(run_id, record, image)
    if not success:
        store.persist_record(
            run_id,
            record.transition(
                OcrPageStatus.FAILED,
                ended_at=datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                ),
                error_reason="provider interrupted",
            ),
        )
        return
    raw = {
        "page_id": record.page_id,
        "latex": f"Recovered page {source_page}.",
        "figures": [],
        "unresolved_regions": [],
    }
    raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    record = record.transition(OcrPageStatus.VALIDATING)
    record = record.transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_tex=raw["latex"],
        cleaned_tex=raw["latex"],
        ended_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    store.persist_record(run_id, record, raw_response=raw)


def _setup_store(tmp_path: Path, pages: tuple[int, ...]) -> tuple[OcrRunStore, str]:
    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nrestart evidence\n"
    run_id = "b" * 32
    snapshot = make_run_snapshot(
        source_bytes=source,
        source_type="pdf",
        original_filename="中文恢复.pdf",
        source_total_pages=max(pages),
        selected_pages=pages,
        ocr_model="vision-test",
        api_backend="api",
        app_version="2.0.0",
        run_id=run_id,
    )
    store = OcrRunStore(tmp_path / "ocr-runs")
    store.initialize(snapshot, source)
    return store, run_id


def _single_visual_classification(source: bytes, candidate_tex: str):
    from latexstruct.core.ocr_pipeline import SourceClassification
    from latexstruct.core.ocr_schema import (
        DocumentStrategy,
        PageBlock,
        PageBlockType,
        PageClassification,
        PageFeatures,
        PageStrategy,
    )

    page_id = make_page_id(1)
    block_hash = hashlib.sha256(candidate_tex.encode("utf-8")).hexdigest()
    features = PageFeatures(
        page_width=612,
        page_height=792,
        rotation=0,
        has_text_objects=True,
        text_character_count=len(candidate_tex),
        printable_character_ratio=1,
        unicode_replacement_ratio=0,
        garbled_character_ratio=0,
        font_mapping_health=1,
        text_block_count=1,
        image_count=0,
        image_coverage_ratio=0,
        single_full_page_image=False,
        math_symbol_density=0,
        formula_region_count=0,
        double_column_likelihood=0,
        text_pixel_alignment_confidence=1,
        reading_order_confidence=1,
    )
    block = PageBlock(
        block_id=f"{page_id}-block-0001-{block_hash[:12]}",
        block_type=PageBlockType.TEXT,
        bbox=(72, 72, 540, 220),
        reading_order=1,
        plain_text=candidate_tex,
        style_features={},
        math_likelihood=0,
        source_object_hash=block_hash,
        candidate_latex=candidate_tex,
    )
    page = PageClassification(
        page_id=page_id,
        source_page_number=1,
        selected_index=1,
        strategy=PageStrategy.BORN_DIGITAL_CLEAN,
        features=features,
        blocks=(block,),
        source_page_object_hash=hashlib.sha256(b"single-visual-page").hexdigest(),
        source_text_layer_sha256=hashlib.sha256(
            candidate_tex.encode("utf-8")
        ).hexdigest(),
        candidate_tex=candidate_tex,
    )
    return SourceClassification(
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_type="pdf",
        document_strategy=DocumentStrategy.BORN_DIGITAL_FAST,
        pages=(page,),
    ), block


def _one_page_png(label: str) -> bytes:
    import pymupdf

    document = pymupdf.open()
    page = document.new_page(width=120, height=120)
    page.insert_text((12, 20), label)
    payload = page.get_pixmap(alpha=False).tobytes("png")
    document.close()
    return payload


def _persist_recovery_attempt(
    store: OcrRunStore,
    run_id: str,
    task_index: int,
    source_page: int,
    *,
    outcome: AttemptOutcome,
    total_tokens: int,
) -> Path:
    image = b"\x89PNG\r\n\x1a\n" + f"rendered-page-{source_page}".encode()
    recovery_root = store.run_dir(run_id) / "recovery-evidence"
    recovery = OcrRecoveryEvidenceStore(recovery_root)
    recovery.record_attempt(
        run_id=run_id,
        page_id=make_page_id(task_index),
        source_page=source_page,
        task_index=task_index,
        stage=RecoveryStage.INITIAL_READ,
        outcome=outcome,
        base_dpi=200,
        dpi=200,
        model="vision-test",
        backend="api",
        model_context_id=f"context-{task_index}",
        images=(RecoveryImageInput(
            role=RecoveryImageRole.FULL_PAGE,
            content=image,
            dpi=200,
            width_pixels=1200,
            height_pixels=1800,
        ),),
        raw_response=json.dumps({"page": source_page, "outcome": outcome.value}),
        duration_ms=10,
        usage={
            "prompt_tokens": total_tokens - 1,
            "completion_tokens": 1,
            "total_tokens": total_tokens,
        },
        error=("provider interrupted" if outcome is AttemptOutcome.FAILED else None),
        tex_sha256=(
            hashlib.sha256(f"Recovered page {source_page}.".encode()).hexdigest()
            if outcome is AttemptOutcome.PASSED else ""
        ),
    )
    return recovery_root


def test_status_reconstructs_partial_run_from_immutable_snapshot(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (4, 5))
    _persist_result(store, run_id, 1, 4, success=True)
    _persist_result(store, run_id, 2, 5, success=False)
    recovery_root = _persist_recovery_attempt(
        store, run_id, 1, 4,
        outcome=AttemptOutcome.PASSED,
        total_tokens=11,
    )
    _persist_recovery_attempt(
        store, run_id, 2, 5,
        outcome=AttemptOutcome.FAILED,
        total_tokens=13,
    )
    evidence_before = {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in recovery_root.rglob("*") if path.is_file()
    }
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()
    response = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}")
    assert response.status_code == 200
    state = response.json()
    assert state["status"] == "partial"
    assert state["recovered_after_restart"] is True
    assert state["can_resume"] is True
    assert state["pages"]["4"]["status"] == "done"
    assert state["pages"]["5"]["status"] == "error"
    assert state["usage"]["calls"] == 2
    assert state["usage"]["total_tokens"] == 24
    assert state["usage_revision"] == 2
    assert state["pages"]["4"]["recovery_attempt_count"] == 1
    assert state["pages"]["5"]["recovery_status"] == "FAILED"
    assert state["progress_metrics"]["attempt_progress"] == 1.0
    assert state["progress_metrics"]["recognition_progress"] == 0.5
    assert state["progress_metrics"]["merge_complete"] is False
    assert state["progress"] < 0.5
    assert state["progress"] < 1.0
    assert str(tmp_path) not in response.text
    assert evidence_before == {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in recovery_root.rglob("*") if path.is_file()
    }


def test_partial_raw_preview_does_not_unlock_merge_progress(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (4, 5))
    _persist_result(store, run_id, 1, 4, success=True)
    _persist_result(store, run_id, 2, 5, success=False)
    snapshot = store.load_snapshot(run_id)
    job = {
        "id": run_id,
        "status": "partial",
        "selected_pages": [4, 5],
        "pages": {
            4: {"status": "done", "task_index": 1},
            5: {"status": "error", "task_index": 2},
        },
        "raw_tex": "% Page 4\nRecovered page 4.",
        # This legacy field intentionally means a partial preview is available.
        "raw_ready": True,
        "raw_frozen": False,
        "_v2_store": store,
        "_v2_snapshot": snapshot,
        "current_concurrency_limit": 3,
    }

    state = srv._public_ocr_job(job)

    assert state["raw_ready"] is True
    assert state["progress_metrics"]["recognition_progress"] == 0.5
    assert state["progress_metrics"]["merge_complete"] is False
    assert state["progress"] < 0.5


def test_codex_v2_prefers_host_validator_and_retries_equation_gate(
    tmp_path: Path,
):
    """Codex v2 must not bypass the host's publisher-quality validators."""
    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    calls: list[str] = []

    class HostValidatedCodex:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="gpt-5.4", api_key="")
            self.last_usage: dict[str, int] = {}

        def chat_vision_json_bytes(self, *_args, **_kwargs):
            raise AssertionError("generic JSON OCR bypassed the host validator")

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("generic batch OCR bypassed the host validator")

        def chat_vision_structured_bytes(self, _system, user, _image):
            calls.append(user)
            total = 10 if len(calls) == 1 else 12
            self.last_usage = {
                "prompt_tokens": total - 2,
                "completion_tokens": 2,
                "total_tokens": total,
            }
            tag = "" if len(calls) == 1 else r" \tag{1}"
            return {
                "latex": (
                    "```latex\n"
                    "A sufficiently long faithful paragraph precedes "
                    rf"\begin{{equation}}x=1{tag}\end{{equation}}."
                    "\n```"
                ),
                "figures": [],
                "framed_insets": [],
            }

    fake_codex = HostValidatedCodex()
    equation_region = {
        "evidence_id": "p1-equation-tag-1",
        "label_hint": "1",
        "bbox_normalized": [0.848, 0.20, 0.883, 0.22],
        "source": "isolated_right_margin_pdf_word_geometry",
    }

    import pymupdf

    image_document = pymupdf.open()
    image_page = image_document.new_page(width=120, height=120)
    image_page.insert_text((12, 20), "x = 1                                      (1)")
    page_png = image_page.get_pixmap(alpha=False).tobytes("png")
    image_document.close()

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    baseline = OcrBaselineResult(
        tex="twice compiled equation baseline",
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled equation baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    http = TestClient(srv.create_app())
    jid = ""
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("equation.pdf", b"%PDF-1.7\nfake", "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(fake_codex, "gpt-5.4", "codex_cli"),
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch(
                "latexstruct.ocr.pdf_page_text_hint",
                return_value="A sufficiently long faithful equation x = 1 (1).",
            ),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch(
                "latexstruct.ocr.pdf_page_equation_tag_regions",
                return_value=[equation_region],
            ),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
            patch("latexstruct.server.app._ocr_retry_wait", return_value=None),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(400):
                state = http.get(f"/api/ocr/jobs/{jid}").json()
                if state.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

        assert state["status"] == "done", json.dumps(
            {"state": state, "calls": calls}, ensure_ascii=False, indent=2
        )
        assert state["compile_status"] == "COMPILED"
        assert state["pages"]["1"]["attempts"] == 2
        assert state["pages"]["1"]["can_retry"] is False
        assert state["usage"]["calls"] == 2
        assert state["usage"]["total_tokens"] == 22
        assert len(calls) == 2
        assert "publisher_equation_tag_evidence" in calls[0]
        assert "retry_correction" in calls[1]
        cleanup_dirs = []
        with srv._ocr_jobs_lock:
            internal_page = dict(srv._ocr_jobs[jid]["pages"][1])
            v2_store = srv._ocr_jobs[jid]["_v2_store"]
            v2_snapshot = srv._ocr_jobs[jid]["_v2_snapshot"]
            cleanup_dirs.append(str(srv._ocr_jobs[jid].get("dir") or ""))
            page_usage = list(
                srv._ocr_jobs[jid]["_v2_page_usage"][internal_page["page_id"]]
            )
        assert [entry["usage"]["total_tokens"] for entry in page_usage] == [10, 12]
        assert internal_page["quality_flags"] == [{
            "type": "equation_tag_integrity_evidence",
            "status": "source_geometry_and_active_match",
            "needs_review": False,
            "evidence_id": "p1-equation-tag-1",
            "label": "1",
            "bbox_normalized": [0.848, 0.20, 0.883, 0.22],
            "source": "isolated_right_margin_pdf_word_geometry",
            "verifier": "pdf_geometry_plus_full_page_visual_and_active_latex",
        }]
        record = v2_store.load_record(v2_snapshot.run_id, internal_page["page_id"])
        assert record.raw_tex.startswith("```latex\n")
        assert "```" not in record.cleaned_tex
        assert record.raw_tex != record.cleaned_tex
        response_envelope = v2_store.load_raw_response(v2_snapshot.run_id, record)
        assert response_envelope["model_raw_latex"] == record.raw_tex
        assert response_envelope["model_raw_response"]["latex"] == record.raw_tex
        assert response_envelope["transport_response"]["latex"] == record.cleaned_tex
        source_evidence = v2_store.load_page_source_evidence(
            v2_snapshot.run_id, record
        )
        assert source_evidence["equation_tag_regions"] == [equation_region]
        assert record.to_dict()["host_quality_flags"] == internal_page["quality_flags"]

        # Simulate a process restart: inventories and trusted host flags must
        # come back from their hash-bound sidecars, not from runtime issues.
        with srv._ocr_jobs_lock:
            srv._ocr_jobs.pop(jid, None)
        restored = http.get(f"/api/ocr/jobs/{jid}").json()
        assert restored["status"] == "done"
        assert restored["quality_report"]["counts"]["equation_tags_expected"] == 1
        assert restored["quality_report"]["counts"]["equation_tags_verified"] == 1
        with srv._ocr_jobs_lock:
            restored_page = dict(srv._ocr_jobs[jid]["pages"][1])
            cleanup_dirs.append(str(srv._ocr_jobs[jid].get("dir") or ""))
        assert restored_page["equation_tag_regions"] == [equation_region]
        assert restored_page["quality_flags"] == internal_page["quality_flags"]
        frozen_retry = http.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
        assert frozen_retry.status_code == 409
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs = locals().get("cleanup_dirs", [])
            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


def test_visual_fast_path_cleans_boundary_folio_before_freeze(tmp_path: Path):
    """A verified object candidate must use the same host cleanup as full OCR."""
    from latexstruct.core.ocr_pipeline import SourceClassification
    from latexstruct.core.ocr_schema import (
        DocumentStrategy,
        PageBlock,
        PageBlockType,
        PageClassification,
        PageFeatures,
        PageStrategy,
    )

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nvisual fast-path folio regression\n"
    page_id = make_page_id(1)
    body = (
        "A sufficiently long bibliography paragraph is preserved exactly, "
        "including its final verified email address."
    )
    raw_math = "x ≤ y"
    patched_math = r"\[x \le y\]"
    candidate_tex = f"{raw_math}\n\n{body}\n\n37"
    math_hash = hashlib.sha256(raw_math.encode("utf-8")).hexdigest()
    body_hash = hashlib.sha256(f"{body}\n\n37".encode("utf-8")).hexdigest()
    features = PageFeatures(
        page_width=612,
        page_height=792,
        rotation=0,
        has_text_objects=True,
        text_character_count=len(candidate_tex),
        printable_character_ratio=1,
        unicode_replacement_ratio=0,
        garbled_character_ratio=0,
        font_mapping_health=1,
        text_block_count=1,
        image_count=0,
        image_coverage_ratio=0,
        single_full_page_image=False,
        math_symbol_density=0,
        formula_region_count=0,
        double_column_likelihood=0,
        text_pixel_alignment_confidence=1,
        reading_order_confidence=1,
    )
    math_block = PageBlock(
        block_id=f"{page_id}-block-0001-{math_hash[:12]}",
        block_type=PageBlockType.DISPLAY_MATH,
        bbox=(72, 72, 540, 140),
        reading_order=1,
        plain_text=raw_math,
        style_features={},
        math_likelihood=0.95,
        source_object_hash=math_hash,
        candidate_latex=raw_math,
    )
    body_block = PageBlock(
        block_id=f"{page_id}-block-0002-{body_hash[:12]}",
        block_type=PageBlockType.TEXT,
        bbox=(72, 160, 540, 730),
        reading_order=2,
        plain_text=f"{body}\n\n37",
        style_features={},
        math_likelihood=0,
        source_object_hash=body_hash,
        candidate_latex=f"{body}\n\n37",
    )
    page_classification = PageClassification(
        page_id=page_id,
        source_page_number=37,
        selected_index=1,
        strategy=PageStrategy.BORN_DIGITAL_CLEAN,
        features=features,
        blocks=(math_block, body_block),
        source_page_object_hash=hashlib.sha256(b"source-page-37").hexdigest(),
        source_text_layer_sha256=hashlib.sha256(
            candidate_tex.encode("utf-8")
        ).hexdigest(),
        candidate_tex=candidate_tex,
    )
    classification = SourceClassification(
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_type="pdf",
        document_strategy=DocumentStrategy.BORN_DIGITAL_FAST,
        pages=(page_classification,),
    )

    class VisualVerifier:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="gpt-5.4", api_key="")
            self.last_usage: dict[str, int] = {}
            self.calls = 0

        def chat_vision_json_bytes(self, _system, user, _image, _schema):
            self.calls += 1
            request = json.loads(user)
            page_request = request["pages"][0]
            is_retry = bool(page_request.get("local_patch_retry"))
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": page_id,
                    "verdict": "PATCH" if is_retry else "PASS",
                    "reading_order_ok": True,
                    "coverage_ok": True,
                    "block_findings": ([{
                        "block_id": math_block.block_id,
                        "issue_type": "MATH_MISMATCH",
                        "severity": "HIGH",
                        "replacement_latex": patched_math,
                        "evidence_region": [0.1, 0.08, 0.9, 0.2],
                        "confidence": 0.99,
                    }] if is_retry else []),
                    "missing_regions": [],
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("single-page verifier must not use a batch image call")

        def chat_vision_structured_bytes(self, *_args, **_kwargs):
            raise AssertionError("verified object page must not fall through to full OCR")

    verifier = VisualVerifier()
    import pymupdf

    image_document = pymupdf.open()
    image_page = image_document.new_page(width=120, height=120)
    image_page.insert_text((12, 20), "Verified bibliography page 37")
    page_png = image_page.get_pixmap(alpha=False).tobytes("png")
    image_document.close()

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [37]
        yield 37, page_png

    baseline = OcrBaselineResult(
        tex="twice compiled visual fast-path baseline",
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled visual fast-path baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 37, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("folio.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(verifier, "gpt-5.4", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=candidate_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "37",
                    "end_page": "37",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(400):
                state = http.get(f"/api/ocr/jobs/{jid}").json()
                if state.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

        assert state["status"] == "done", json.dumps(
            state, ensure_ascii=False, indent=2
        )
        assert state["raw_frozen"] is True
        assert state["compile_status"] == "COMPILED"
        assert verifier.calls == 2
        with srv._ocr_jobs_lock:
            live_job = srv._ocr_jobs[jid]
            store = live_job["_v2_store"]
            snapshot = live_job["_v2_snapshot"]
            internal_tex = live_job["pages"][37]["tex"]
            cleanup_dirs.append(str(live_job.get("dir") or ""))
        record = store.load_record(snapshot.run_id, page_id)
        assert record.raw_tex == candidate_tex
        expected_cleaned = f"{patched_math}\n\n{body}"
        assert record.cleaned_tex == expected_cleaned
        assert internal_tex == expected_cleaned
        transport = store.verify_saved_response(snapshot.run_id, record)
        assert transport["latex"] == expected_cleaned
        assets, figure_manifest = store.materialize_figure_assets(snapshot.run_id)
        assert assets == {}
        assert figure_manifest["figures"] == []
        evidence_tex = (
            store.run_dir(snapshot.run_id)
            / "pages"
            / "page-000001"
            / "page.tex"
        ).read_text(encoding="utf-8")
        assert evidence_tex == expected_cleaned
        frozen_tex = (
            store.run_dir(snapshot.run_id) / "artifacts" / "raw-ocr.tex"
        ).read_text(encoding="utf-8")
        assert "\n37\n" not in frozen_tex
        from latexstruct.core.ocrstruct import parse_ocr_metadata

        assert frozen_tex.count("% LaTeXStruct-OCR-Metadata:") == 1
        assert parse_ocr_metadata(frozen_tex)["pages"] == [37]
        assert body in frozen_tex

        with srv._ocr_jobs_lock:
            srv._ocr_jobs.pop(jid, None)
        restored = http.get(f"/api/ocr/jobs/{jid}").json()
        assert restored["status"] == "done"
        assert restored["raw_frozen"] is True
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize(
    ("crash_point", "crash_call_kind", "calls_before_restart"),
    [
        ("INITIAL_RESULT", "INITIAL", 1),
        ("LOCAL_PATCH_RESULT", "LOCAL_PATCH", 2),
        ("TERMINAL_ROUTE", "", 1),
        ("CONSUMED_MARKER", "", 1),
        ("FULL_ROUTE_CONSUMED", "", 1),
        ("TAMPER_RESULT", "INITIAL", 1),
        ("TAMPER_CONSUMED", "", 1),
    ],
)
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_visual_result_crash_resume_never_replays_provider(
    tmp_path: Path,
    crash_point: str,
    crash_call_kind: str,
    calls_before_restart: int,
):
    """A returned initial/PATCH verifier response is never bought twice."""

    from latexstruct.core.ocr_lane_routes import OcrLaneOwner, OcrLaneRouteStore
    from latexstruct.core import ocr_lane_scheduler as lane_scheduler_module
    from latexstruct.core.ocr_page_evidence import (
        PageEvidenceIntegrityError,
        PageEvidenceStore,
    )
    import threading

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nvisual response crash evidence\n"
    candidate_tex = (
        "A sufficiently long host-owned object-layer paragraph is checked "
        "against its rendered page before it can be frozen."
    )
    classification, block = _single_visual_classification(source, candidate_tex)
    page_id = classification.pages[0].page_id
    patched_tex = candidate_tex.replace("checked", "strictly checked")

    class CrashVerifier:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="gpt-5.4-mini", api_key="")
            self.last_usage: dict[str, int] = {}
            self.calls = 0
            self.full_calls = 0

        def chat_vision_json_bytes(self, _system, user, _image, _schema):
            self.calls += 1
            request = json.loads(user)
            is_retry = bool(request["pages"][0].get("local_patch_retry"))
            local_patch_case = crash_point == "LOCAL_PATCH_RESULT"
            full_route_case = crash_point == "FULL_ROUTE_CONSUMED"
            if full_route_case:
                verdict = "FULL_OCR_REQUIRED"
                replacement = None
            elif local_patch_case and not is_retry:
                verdict = "FULL_OCR_REQUIRED"
                replacement = ""
            elif local_patch_case:
                verdict = "PATCH"
                replacement = patched_tex
            else:
                verdict = "PASS"
                replacement = None
            findings = []
            if replacement is not None:
                findings.append({
                    "block_id": block.block_id,
                    "issue_type": "TEXT_MISMATCH",
                    "severity": "HIGH",
                    "replacement_latex": replacement,
                    "evidence_region": [0.1, 0.1, 0.9, 0.3],
                    "confidence": 0.99,
                })
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": page_id,
                    "verdict": verdict,
                    "reading_order_ok": True,
                    "coverage_ok": not full_route_case,
                    "block_findings": findings,
                    "missing_regions": (
                        [[0.0, 0.0, 1.0, 1.0]] if full_route_case else []
                    ),
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("single page must not use batch visual transport")

        def chat_vision_structured_bytes(self, *_args, **_kwargs):
            if crash_point != "FULL_ROUTE_CONSUMED":
                raise AssertionError("visual crash case must not enter full OCR")
            self.full_calls += 1
            usage = {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12}
            self.last_usage = usage
            return {
                "latex": candidate_tex,
                "figures": [],
                "framed_insets": [],
            }

    verifier = CrashVerifier()
    page_png = _one_page_png("visual crash candidate")

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    baseline = OcrBaselineResult(
        tex="twice compiled visual crash retry baseline",
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled visual crash retry baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )

    class SyntheticProcessLoss(BaseException):
        pass

    original_persist_result = PageEvidenceStore.persist_visual_call_result
    original_persist_consumed = PageEvidenceStore.persist_visual_call_consumed
    original_route_transition = OcrLaneRouteStore.transition
    original_lane_scheduler = lane_scheduler_module.run_overlapping_ocr_lanes
    crash_enabled = {"value": True}
    crash_observed = threading.Event()
    crashed_call_id = {"value": ""}

    def persist_then_crash(self, selected_page_id, call_id, **kwargs):
        result = original_persist_result(
            self, selected_page_id, call_id, **kwargs
        )
        intent = self.load_visual_call_intent(selected_page_id, call_id)
        if (
            crash_enabled["value"]
            and crash_point.endswith("_RESULT")
            and intent["call_kind"] == crash_call_kind
        ):
            crashed_call_id["value"] = call_id
            crash_observed.set()
            raise SyntheticProcessLoss("synthetic visual result commit crash")
        return result

    def crash_before_terminal_route(self, selected_page_id, owner, **kwargs):
        if (
            crash_enabled["value"]
            and crash_point == "TERMINAL_ROUTE"
            and owner is OcrLaneOwner.TERMINAL_VISUAL
        ):
            crash_observed.set()
            raise SyntheticProcessLoss("synthetic terminal route commit crash")
        return original_route_transition(
            self, selected_page_id, owner, **kwargs
        )

    def crash_before_consumed_marker(self, selected_page_id, call_id, **kwargs):
        if crash_enabled["value"] and crash_point in {
            "CONSUMED_MARKER",
            "FULL_ROUTE_CONSUMED",
        }:
            crash_observed.set()
            raise SyntheticProcessLoss("synthetic visual consumed marker crash")
        result = original_persist_consumed(
            self, selected_page_id, call_id, **kwargs
        )
        if crash_enabled["value"] and crash_point == "TAMPER_CONSUMED":
            crashed_call_id["value"] = call_id
            crash_observed.set()
            raise SyntheticProcessLoss("synthetic post-consumed process loss")
        return result

    def isolate_full_route_crash(initial_page_ids, **kwargs):
        if (
            crash_point != "FULL_ROUTE_CONSUMED"
            or not crash_enabled["value"]
        ):
            return original_lane_scheduler(initial_page_ids, **kwargs)
        assert not initial_page_ids
        queued_page_ids: list[str] = []
        # Model an actual process loss after the visual lane has durably moved
        # the page to FULL_OCR_QUEUED, but before the full-lane coordinator can
        # claim it.  The consumed-marker fault below terminates this call.
        kwargs["run_visual_lane"](queued_page_ids.append)
        raise AssertionError("synthetic process loss must stop the visual lane")

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("visual-crash.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(verifier, "gpt-5.4-mini", "codex_cli"),
            ),
            patch.object(
                PageEvidenceStore,
                "persist_visual_call_result",
                new=persist_then_crash,
            ),
            patch.object(
                OcrLaneRouteStore,
                "transition",
                new=crash_before_terminal_route,
            ),
            patch.object(
                PageEvidenceStore,
                "persist_visual_call_consumed",
                new=crash_before_consumed_marker,
            ),
            patch.object(
                lane_scheduler_module,
                "run_overlapping_ocr_lanes",
                new=isolate_full_route_crash,
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=candidate_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            pending = ()
            for _ in range(500):
                with srv._ocr_jobs_lock:
                    live_job = srv._ocr_jobs[jid]
                    run_store = live_job.get("_v2_store")
                    snapshot = live_job.get("_v2_snapshot")
                    evidence_store = live_job.get("_v2_page_evidence_store")
                    cleanup_dirs.append(str(live_job.get("dir") or ""))
                if (
                    verifier.calls >= calls_before_restart
                    and isinstance(evidence_store, PageEvidenceStore)
                ):
                    try:
                        pending = evidence_store.pending_visual_calls(page_id)
                    except Exception:
                        pending = ()
                    if crash_point == "TAMPER_CONSUMED" and crash_observed.is_set():
                        break
                    if (
                        len(pending) >= calls_before_restart
                        and pending[-1]["intent"]["call_kind"]
                        == (crash_call_kind or "INITIAL")
                        and pending[-1]["result"] is not None
                    ):
                        break
                time.sleep(0.01)
            assert verifier.calls == calls_before_restart
            if crash_point == "TAMPER_CONSUMED":
                assert crash_observed.wait(timeout=5.0)
                pending = evidence_store.pending_visual_calls(page_id)
            assert len(pending) == (
                0 if crash_point == "TAMPER_CONSUMED" else calls_before_restart
            )
            if crash_point == "LOCAL_PATCH_RESULT":
                assert [
                    item["intent"]["call_kind"] for item in pending
                ] == ["INITIAL", "LOCAL_PATCH"]
                assert (
                    pending[1]["intent"]["parent_result_sha256"]
                    == pending[0]["result_sha256"]
                )
                assert pending[1]["intent"]["required_block_ids"] == [
                    block.block_id
                ]
            assert run_store is not None and snapshot is not None
            assert crash_observed.wait(timeout=5.0)
            time.sleep(0.1)

            if crash_point in {"TAMPER_RESULT", "TAMPER_CONSUMED"}:
                call_id = crashed_call_id["value"]
                assert call_id
                artifact_name = (
                    "result.json"
                    if crash_point == "TAMPER_RESULT"
                    else "consumed.json"
                )
                artifact = (
                    evidence_store.page_dir(page_id)
                    / "visual-calls"
                    / call_id
                    / artifact_name
                )
                artifact_value = json.loads(artifact.read_text(encoding="utf-8"))
                artifact_value["page_id"] = "ocr-page-999999"
                artifact.write_text(
                    json.dumps(
                        artifact_value,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n",
                    encoding="utf-8",
                )

            # Emulate process loss by discarding only volatile job state.
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)
            crash_enabled["value"] = False
            restored = http.get(f"/api/ocr/jobs/{jid}")
            assert restored.status_code == 200, restored.text
            resumed = http.post(f"/api/ocr/jobs/{jid}/resume")
            assert resumed.status_code == 200, resumed.text
            for _ in range(500):
                state = http.get(f"/api/ocr/jobs/{jid}").json()
                if state.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

            assert verifier.calls == calls_before_restart
            record = run_store.load_record(snapshot.run_id, page_id)
            route = srv._ocr_jobs[jid]["_v2_lane_route_store"].load(page_id)
            if crash_point in {"TAMPER_RESULT", "TAMPER_CONSUMED"}:
                assert state["status"] in {"partial", "error"}
                assert state["status"] != "done"
                with pytest.raises(PageEvidenceIntegrityError):
                    evidence_store.pending_visual_calls(page_id)
                if crash_point == "TAMPER_RESULT":
                    assert record.status is OcrPageStatus.FAILED
                    assert route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED
                else:
                    assert record.status is OcrPageStatus.SUCCESS
                    assert route.owner is OcrLaneOwner.TERMINAL_VISUAL
            else:
                assert evidence_store.pending_visual_calls(page_id) == ()
            if crash_point in {
                "TERMINAL_ROUTE",
                "CONSUMED_MARKER",
                "FULL_ROUTE_CONSUMED",
            }:
                for _ in range(500):
                    state = http.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] == "done":
                        break
                    time.sleep(0.01)
                assert state["status"] == "done", json.dumps(
                    state, ensure_ascii=False, indent=2
                )
                assert record.status is OcrPageStatus.SUCCESS
                assert route.owner is (
                    OcrLaneOwner.TERMINAL_FULL_OCR
                    if crash_point == "FULL_ROUTE_CONSUMED"
                    else OcrLaneOwner.TERMINAL_VISUAL
                )
                assert verifier.full_calls == (
                    1 if crash_point == "FULL_ROUTE_CONSUMED" else 0
                )
            elif crash_point not in {"TAMPER_RESULT", "TAMPER_CONSUMED"}:
                assert state["status"] == "partial"
                assert state["pages"]["1"]["status"] == "error"
                with srv._ocr_jobs_lock:
                    internal_page = dict(srv._ocr_jobs[jid]["pages"][1])
                assert internal_page["visual_replay_blocked"] is True
                assert record.status is OcrPageStatus.FAILED
                assert route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED

                explicit_retry = http.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
                assert explicit_retry.status_code == 200, explicit_retry.text
                assert explicit_retry.json()["ok"] is True
                assert verifier.calls == calls_before_restart * 2
                retried = run_store.load_record(snapshot.run_id, page_id)
                assert retried.status is OcrPageStatus.SUCCESS
                assert evidence_store.pending_visual_calls(page_id) == ()
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


def test_malformed_visual_batch_is_not_split_or_replayed(tmp_path: Path):
    """A paid batch that returned malformed coverage fails every page closed."""

    from dataclasses import replace as dc_replace

    from latexstruct.core.ocr_lane_routes import OcrLaneOwner
    from latexstruct.core.ocr_pipeline import SourceClassification
    from latexstruct.core.ocr_page_evidence import PageEvidenceStore

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nmalformed visual batch\n"
    candidate_tex = (
        "A sufficiently long object-layer paragraph is intentionally repeated "
        "on two pages for one malformed batch response."
    )
    single, block_one = _single_visual_classification(source, candidate_tex)
    page_one = single.pages[0]
    page_two_id = make_page_id(2)
    block_two = dc_replace(
        block_one,
        block_id=(
            f"{page_two_id}-block-0001-"
            f"{hashlib.sha256((candidate_tex + '2').encode()).hexdigest()[:12]}"
        ),
        source_object_hash=hashlib.sha256(
            (candidate_tex + "2").encode()
        ).hexdigest(),
    )
    page_two = dc_replace(
        page_one,
        page_id=page_two_id,
        source_page_number=2,
        selected_index=2,
        blocks=(block_two,),
        source_page_object_hash=hashlib.sha256(b"visual-page-two").hexdigest(),
    )
    classification = SourceClassification(
        source_sha256=single.source_sha256,
        source_type=single.source_type,
        document_strategy=single.document_strategy,
        pages=(page_one, page_two),
    )

    class MalformedBatchVerifier:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="gpt-5.4-mini", api_key="")
            self.last_usage: dict[str, int] = {}
            self.batch_calls = 0
            self.single_calls = 0

        def chat_vision_json_images_bytes(self, _system, user, _images, _schema):
            self.batch_calls += 1
            request = json.loads(user)
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            # Deliberately omit page two after the paid transport returned.
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": page_one.page_id,
                    "verdict": "PASS",
                    "reading_order_ok": True,
                    "coverage_ok": True,
                    "block_findings": [],
                    "missing_regions": [],
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_bytes(self, *_args, **_kwargs):
            self.single_calls += 1
            raise AssertionError("returned malformed batch must not be split and repurchased")

        def chat_vision_structured_bytes(self, *_args, **_kwargs):
            raise AssertionError("malformed visual batch must not enter full OCR")

    verifier = MalformedBatchVerifier()
    page_png = _one_page_png("malformed visual batch")

    def fake_render(_path, pages, _dpi):
        assert list(pages) in ([1], [2])
        for page_no in pages:
            yield page_no, page_png

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 2, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("batch.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(verifier, "gpt-5.4-mini", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=candidate_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                side_effect=AssertionError("unresolved batch must not compile"),
            ),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "2",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(500):
                state = http.get(f"/api/ocr/jobs/{jid}").json()
                if state.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

        assert state["status"] == "partial"
        assert verifier.batch_calls == 1
        assert verifier.single_calls == 0
        with srv._ocr_jobs_lock:
            live_job = srv._ocr_jobs[jid]
            run_store = live_job["_v2_store"]
            snapshot = live_job["_v2_snapshot"]
            evidence_store = live_job["_v2_page_evidence_store"]
            route_store = live_job["_v2_lane_route_store"]
            cleanup_dirs.append(str(live_job.get("dir") or ""))
        assert isinstance(evidence_store, PageEvidenceStore)
        for page_id in (page_one.page_id, page_two.page_id):
            assert run_store.load_record(
                snapshot.run_id, page_id
            ).status is OcrPageStatus.FAILED
            assert route_store.load(
                page_id
            ).owner is OcrLaneOwner.TERMINAL_UNRESOLVED
            assert evidence_store.pending_visual_calls(page_id) == ()
            consumed = list(
                (evidence_store.page_dir(page_id) / "visual-calls").glob(
                    "visual-*/consumed.json"
                )
            )
            assert len(consumed) == 1
            assert json.loads(consumed[0].read_text(encoding="utf-8"))[
                "disposition"
            ] == "FAIL_CLOSED"
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize(
    "failure_kind",
    ["model_full_local", "local_syntax", "local_schema_exception"],
)
def test_visual_fast_path_never_promotes_local_failure_to_full_ocr(
    tmp_path: Path,
    failure_kind: str,
):
    """Provider misrouting and local host errors must terminate in review."""
    from latexstruct.core.ocr_lane_routes import OcrLaneOwner
    from latexstruct.core.ocr_pipeline import SourceClassification
    from latexstruct.core.ocr_schema import (
        DocumentStrategy,
        PageBlock,
        PageBlockType,
        PageClassification,
        PageFeatures,
        PageStrategy,
    )

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nlocal full OCR guard\n"
    page_id = make_page_id(1)
    candidate_tex = (
        "A sufficiently long host-owned object-layer paragraph remains a "
        "bounded candidate for local review."
    )
    if failure_kind == "local_syntax":
        candidate_tex += " {"
    elif failure_kind == "local_schema_exception":
        candidate_tex += r" \includegraphics{missing-local-evidence.png}"
    block_hash = hashlib.sha256(candidate_tex.encode("utf-8")).hexdigest()
    features = PageFeatures(
        page_width=612,
        page_height=792,
        rotation=0,
        has_text_objects=True,
        text_character_count=len(candidate_tex),
        printable_character_ratio=1,
        unicode_replacement_ratio=0,
        garbled_character_ratio=0,
        font_mapping_health=1,
        text_block_count=1,
        image_count=0,
        image_coverage_ratio=0,
        single_full_page_image=False,
        math_symbol_density=0,
        formula_region_count=0,
        double_column_likelihood=0,
        text_pixel_alignment_confidence=1,
        reading_order_confidence=1,
    )
    block = PageBlock(
        block_id=f"{page_id}-block-0001-{block_hash[:12]}",
        block_type=PageBlockType.TEXT,
        bbox=(72, 72, 540, 220),
        reading_order=1,
        plain_text=candidate_tex,
        style_features={},
        math_likelihood=0,
        source_object_hash=block_hash,
        candidate_latex=candidate_tex,
    )
    page_classification = PageClassification(
        page_id=page_id,
        source_page_number=1,
        selected_index=1,
        strategy=PageStrategy.BORN_DIGITAL_CLEAN,
        features=features,
        blocks=(block,),
        source_page_object_hash=hashlib.sha256(b"guard-source-page").hexdigest(),
        source_text_layer_sha256=hashlib.sha256(
            candidate_tex.encode("utf-8")
        ).hexdigest(),
        candidate_tex=candidate_tex,
    )
    classification = SourceClassification(
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_type="pdf",
        document_strategy=DocumentStrategy.BORN_DIGITAL_FAST,
        pages=(page_classification,),
    )

    class GuardVerifier:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="gpt-5.4-mini", api_key="")
            self.last_usage: dict[str, int] = {}
            self.verifier_calls = 0
            self.full_ocr_calls = 0

        def chat_vision_json_bytes(self, _system, user, _image, _schema):
            self.verifier_calls += 1
            request = json.loads(user)
            finding = []
            verdict = "PASS"
            if failure_kind == "model_full_local":
                verdict = "FULL_OCR_REQUIRED"
                finding = [{
                    "block_id": block.block_id,
                    "issue_type": "TEXT_MISMATCH",
                    "severity": "HIGH",
                    "replacement_latex": "",
                    "evidence_region": [0.1, 0.1, 0.9, 0.3],
                    "confidence": 0.99,
                }]
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": page_id,
                    "verdict": verdict,
                    "reading_order_ok": True,
                    "coverage_ok": True,
                    "block_findings": finding,
                    "missing_regions": [],
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("single page must not use batch image verification")

        def chat_vision_structured_bytes(self, *_args, **_kwargs):
            self.full_ocr_calls += 1
            raise AssertionError("local failure must never enter full-page OCR")

    verifier = GuardVerifier()
    import pymupdf

    image_document = pymupdf.open()
    image_page = image_document.new_page(width=120, height=120)
    image_page.insert_text((12, 20), "Local guard candidate")
    page_png = image_page.get_pixmap(alpha=False).tobytes("png")
    image_document.close()

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("guard.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(verifier, "gpt-5.4-mini", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=candidate_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                side_effect=AssertionError("unresolved OCR must not compile"),
            ),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(400):
                state = http.get(f"/api/ocr/jobs/{jid}").json()
                if state.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

        assert state["status"] == "partial", state
        assert verifier.verifier_calls == (
            2 if failure_kind == "model_full_local" else 1
        )
        assert verifier.full_ocr_calls == 0
        assert state["pages"]["1"]["needs_review"] is True
        with srv._ocr_jobs_lock:
            live_job = srv._ocr_jobs[jid]
            store = live_job["_v2_store"]
            snapshot = live_job["_v2_snapshot"]
            internal_page = dict(live_job["pages"][1])
            cleanup_dirs.append(str(live_job.get("dir") or ""))
        route = live_job["_v2_lane_route_store"].load(page_id)
        assert route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED
        assert internal_page["lane_owner"] == OcrLaneOwner.TERMINAL_UNRESOLVED.value
        assert internal_page["candidate_strategy"] == "OBJECT_LAYER_LOCAL_REVIEW"
        record = store.load_record(snapshot.run_id, page_id)
        assert record.status is OcrPageStatus.NEEDS_REVIEW
        if failure_kind == "local_syntax":
            with (
                patch("latexstruct.ocr.iter_pdf_pages", fake_render),
                patch(
                    "latexstruct.ocr.pdf_page_text_hint",
                    return_value=candidate_tex,
                ),
                patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
                patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
                patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
                patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
                patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
                patch(
                    "latexstruct.server.app._prepare_page_formula_evidence",
                    return_value=[],
                ),
            ):
                retry_response = http.post(
                    f"/api/ocr/jobs/{jid}/pages/1/retry"
                )
            assert retry_response.status_code == 200, retry_response.text
            assert retry_response.json()["ok"] is False
            assert verifier.verifier_calls == 2, retry_response.text
            assert verifier.full_ocr_calls == 0
            retried_route = live_job["_v2_lane_route_store"].load(page_id)
            assert retried_route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED
            assert [event.owner for event in retried_route.history][-3:] == [
                OcrLaneOwner.TERMINAL_UNRESOLVED,
                OcrLaneOwner.VISUAL,
                OcrLaneOwner.TERMINAL_UNRESOLVED,
            ]
            retry_dirs = list(
                (
                    store.run_dir(snapshot.run_id)
                    / "pages"
                    / "page-000001"
                    / "retries"
                ).glob("retry-*/record.json")
            )
            assert len(retry_dirs) == 1
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


def test_restart_reconciles_committed_full_ocr_without_second_provider_call(
    tmp_path: Path,
):
    """A crash after the page commit must not buy the full-OCR call twice."""
    from latexstruct.core.ocr_lane_routes import (
        OcrLaneOwner,
        OcrLaneRouteStore,
    )
    from latexstruct.core.ocr_pipeline import (
        visual_strict_fallback_classification,
    )

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nterminal route crash window\n"
    classification = visual_strict_fallback_classification(
        source_type="pdf",
        source_bytes=source,
        selected_pages=(1,),
    )
    latex = (
        "A sufficiently long faithful full-page transcription survives the "
        "terminal scheduler crash without another provider request."
    )

    class CountingClient:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage: dict[str, int] = {}
            self.calls = 0

        def chat_vision_structured_bytes(self, _system, _user, _image):
            self.calls += 1
            usage = {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12}
            self.last_usage = usage
            return {
                "latex": latex,
                "figures": [],
                "framed_insets": [],
            }

    client_instance = CountingClient()
    import pymupdf

    image_document = pymupdf.open()
    image_page = image_document.new_page(width=120, height=120)
    image_page.insert_text((12, 20), "Terminal route crash window")
    page_png = image_page.get_pixmap(alpha=False).tobytes("png")
    image_document.close()

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    baseline = OcrBaselineResult(
        tex=latex,
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled crash-window baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    original_reconcile = OcrLaneRouteStore.reconcile_terminal
    injected = {"raised": False}

    def crash_once(route_store, page_id, owner, **kwargs):
        if (
            owner is OcrLaneOwner.TERMINAL_FULL_OCR
            and not injected["raised"]
        ):
            injected["raised"] = True
            raise RuntimeError("synthetic crash after terminal page persistence")
        return original_reconcile(route_store, page_id, owner, **kwargs)

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("crash.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(client_instance, "vision-test", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=latex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
            patch.object(OcrLaneRouteStore, "reconcile_terminal", crash_once),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(400):
                first = http.get(f"/api/ocr/jobs/{jid}").json()
                if first.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)
            assert first["status"] == "partial", first
            assert client_instance.calls == 1, (
                first.get("error"), first.get("errors"), first.get("pages")
            )
            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                store = live_job["_v2_store"]
                snapshot = live_job["_v2_snapshot"]
                cleanup_dirs.append(str(live_job.get("dir") or ""))
            record = store.load_record(snapshot.run_id, make_page_id(1))
            assert record.status is OcrPageStatus.SUCCESS
            interrupted_route = live_job["_v2_lane_route_store"].load(record.page_id)
            assert interrupted_route.owner is OcrLaneOwner.FULL_OCR_IN_FLIGHT

            resumed = http.post(f"/api/ocr/jobs/{jid}/resume")
            assert resumed.status_code == 200, resumed.text
            for _ in range(500):
                final = http.get(f"/api/ocr/jobs/{jid}").json()
                if final.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

        assert client_instance.calls == 1
        terminal_route = live_job["_v2_lane_route_store"].load(record.page_id)
        assert terminal_route.owner is OcrLaneOwner.TERMINAL_FULL_OCR
        assert [event.owner for event in terminal_route.history] == [
            OcrLaneOwner.FULL_OCR_QUEUED,
            OcrLaneOwner.FULL_OCR_IN_FLIGHT,
            OcrLaneOwner.TERMINAL_FULL_OCR,
        ]
        assert final["status"] == "done", final
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize("lane", ["visual", "full"])
def test_restart_repairs_absent_initial_terminal_evidence_without_provider_replay(
    tmp_path: Path,
    lane: str,
):
    """A terminal runtime record plus an absent marker is repaired exactly once."""
    from latexstruct.core.ocr_lane_routes import OcrLaneOwner
    from latexstruct.core.ocr_page_evidence import PageEvidenceStore
    from latexstruct.core.ocr_pipeline import visual_strict_fallback_classification

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\ninitial evidence crash window\n"
    candidate_tex = (
        "A sufficiently long host-owned object-layer transcription remains "
        "stable across an evidence-marker crash and restart."
    )
    if lane == "visual":
        classification, _block = _single_visual_classification(source, candidate_tex)
    else:
        classification = visual_strict_fallback_classification(
            source_type="pdf",
            source_bytes=source,
            selected_pages=(1,),
        )
    full_tex = (
        "A sufficiently long full-page OCR transcription remains stable across "
        "an evidence-marker crash and restart."
    )

    class CountingClient:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage: dict[str, int] = {}
            self.visual_calls = 0
            self.full_calls = 0

        def chat_vision_json_bytes(self, _system, user, _image, _schema):
            self.visual_calls += 1
            request = json.loads(user)
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": make_page_id(1),
                    "verdict": "PASS",
                    "reading_order_ok": True,
                    "coverage_ok": True,
                    "block_findings": [],
                    "missing_regions": [],
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("one visual page must use the single-image verifier")

        def chat_vision_structured_bytes(self, _system, _user, _image):
            self.full_calls += 1
            usage = {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12}
            self.last_usage = usage
            return {"latex": full_tex, "figures": [], "framed_insets": []}

    client_instance = CountingClient()
    page_png = _one_page_png(f"{lane} terminal evidence crash")

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    baseline = OcrBaselineResult(
        tex=candidate_tex if lane == "visual" else full_tex,
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled initial repair baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    original_persist = PageEvidenceStore.persist_page_bundle
    injected = {"raised": False}

    def crash_before_marker(evidence_store, *args, **kwargs):
        if not injected["raised"]:
            injected["raised"] = True
            raise RuntimeError("synthetic crash before terminal evidence marker")
        return original_persist(evidence_store, *args, **kwargs)

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": (f"{lane}.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(client_instance, "vision-test", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=candidate_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
            patch.object(PageEvidenceStore, "persist_page_bundle", crash_before_marker),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(400):
                first = http.get(f"/api/ocr/jobs/{jid}").json()
                if first.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)
            assert first["status"] in {"error", "partial"}, first
            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                store = live_job["_v2_store"]
                snapshot = live_job["_v2_snapshot"]
                evidence_store = live_job["_v2_page_evidence_store"]
                route_store = live_job["_v2_lane_route_store"]
                cleanup_dirs.append(str(live_job.get("dir") or ""))
                # Simulate the actual process crash: the runtime-only error
                # state disappears and the immutable run is reconstructed.
                srv._ocr_jobs.pop(jid, None)
            record = store.load_record(snapshot.run_id, make_page_id(1))
            assert record.status is OcrPageStatus.SUCCESS
            assert evidence_store.base_commit_marker_exists(record.page_id) is False
            calls_before_resume = (
                client_instance.visual_calls,
                client_instance.full_calls,
            )
            restored = http.get(f"/api/ocr/jobs/{jid}").json()
            assert restored["status"] == "partial", restored

            resumed = http.post(f"/api/ocr/jobs/{jid}/resume")
            assert resumed.status_code == 200, resumed.text
            for _ in range(500):
                final = http.get(f"/api/ocr/jobs/{jid}").json()
                if final.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

        assert (
            client_instance.visual_calls,
            client_instance.full_calls,
        ) == calls_before_resume
        assert calls_before_resume == ((1, 0) if lane == "visual" else (0, 1))
        assert evidence_store.base_commit_marker_exists(record.page_id) is True
        terminal = evidence_store.verify_terminal_page_artifacts(
            record.page_id,
            raw_response=store.load_raw_response(snapshot.run_id, record),
            page_tex=record.cleaned_tex,
        )
        assert terminal["retry_id"] is None
        route = route_store.load(record.page_id)
        assert route.owner is (
            OcrLaneOwner.TERMINAL_VISUAL
            if lane == "visual"
            else OcrLaneOwner.TERMINAL_FULL_OCR
        )
        assert final["status"] == "done", final
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize("tamper_journal", [False, True])
def test_restart_blocks_replay_after_terminal_journal_before_runtime_commit(
    tmp_path: Path,
    tamper_journal: bool,
):
    """A paid terminal journal is never replayed after its runtime-commit crash."""
    from latexstruct.core.ocr_lane_routes import OcrLaneOwner
    from latexstruct.core.ocr_pipeline import visual_strict_fallback_classification

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nterminal journal before runtime commit\n"
    classification = visual_strict_fallback_classification(
        source_type="pdf",
        source_bytes=source,
        selected_pages=(1,),
    )
    final_tex = (
        "A sufficiently long full-page result was paid and journaled before "
        "the runtime terminal record could be committed."
    )
    page_png = _one_page_png("journal before runtime terminal")

    class CountingClient:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage: dict[str, int] = {}
            self.calls = 0

        def chat_vision_structured_bytes(self, _system, _user, _image):
            self.calls += 1
            self.last_usage = {
                "prompt_tokens": 9,
                "completion_tokens": 3,
                "total_tokens": 12,
            }
            return {"latex": final_tex, "figures": [], "framed_insets": []}

    client_instance = CountingClient()

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    original_persist_record = OcrRunStore.persist_record
    injected = {"raised": False}

    def crash_before_runtime_terminal(run_store, run_id, record, **kwargs):
        if (
            record.status in {OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW}
            and kwargs.get("raw_response") is not None
            and not injected["raised"]
        ):
            injected["raised"] = True
            raise RuntimeError("synthetic crash before runtime terminal commit")
        return original_persist_record(run_store, run_id, record, **kwargs)

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("journal.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(client_instance, "vision-test", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=final_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch.object(
                OcrRunStore,
                "persist_record",
                crash_before_runtime_terminal,
            ),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(500):
                first = http.get(f"/api/ocr/jobs/{jid}").json()
                if first["status"] in {"error", "partial"}:
                    break
                time.sleep(0.01)
            assert injected["raised"] is True
            assert client_instance.calls == 1
            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                store = live_job["_v2_store"]
                snapshot = live_job["_v2_snapshot"]
                cleanup_dirs.append(str(live_job.get("dir") or ""))
            page_id = make_page_id(1)
            interrupted = store.load_record(snapshot.run_id, page_id)
            assert interrupted.status is OcrPageStatus.OCR_RUNNING
            recovery_root = store.run_dir(snapshot.run_id) / "recovery-evidence"
            attempt_paths = sorted(recovery_root.glob(
                f"*/pages/{page_id}/attempts/*.json"
            ))
            assert len(attempt_paths) == 1
            if tamper_journal:
                attempt_payload = json.loads(
                    attempt_paths[0].read_text(encoding="utf-8")
                )
                attempt_payload["previous_attempt_sha256"] = "0" * 64
                attempt_paths[0].write_text(
                    json.dumps(attempt_payload, sort_keys=True),
                    encoding="utf-8",
                )

            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)
            restored = http.get(f"/api/ocr/jobs/{jid}")
            assert restored.status_code == 200, restored.text
            resumed = http.post(f"/api/ocr/jobs/{jid}/resume")
            assert resumed.status_code == 200, resumed.text
            for _ in range(500):
                final = http.get(f"/api/ocr/jobs/{jid}").json()
                if final["status"] in {"error", "partial"}:
                    break
                time.sleep(0.01)

        assert client_instance.calls == 1
        blocked = store.load_record(snapshot.run_id, page_id)
        assert blocked.status is OcrPageStatus.FAILED
        with srv._ocr_jobs_lock:
            restored_job = srv._ocr_jobs[jid]
            route = restored_job["_v2_lane_route_store"].load(page_id)
        assert route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED
        assert final["status"] in {"error", "partial"}
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


def test_failed_page_visual_retry_repairs_absent_retry_marker_without_replay(
    tmp_path: Path,
):
    """A later retry keeps base evidence and repairs its own durable head."""
    from latexstruct.core.ocr_page_evidence import PageEvidenceStore

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nmanual retry crash window\n"
    candidate_tex = (
        "A sufficiently long host-owned candidate enters local syntax review "
        "because this final brace remains open {"
    )
    repaired_tex = (
        "A sufficiently long host-owned candidate leaves local syntax review "
        "after a bounded visual patch."
    )
    classification, block = _single_visual_classification(source, candidate_tex)

    class RetryVerifier:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage: dict[str, int] = {}
            self.calls = 0

        def chat_vision_json_bytes(self, _system, user, _image, _schema):
            self.calls += 1
            request = json.loads(user)
            is_retry = self.calls > 1
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": make_page_id(1),
                    "verdict": "PATCH" if is_retry else "PASS",
                    "reading_order_ok": True,
                    "coverage_ok": True,
                    "block_findings": ([{
                        "block_id": block.block_id,
                        "issue_type": "TEXT_MISMATCH",
                        "severity": "HIGH",
                        "replacement_latex": repaired_tex,
                        "evidence_region": [0.1, 0.1, 0.9, 0.3],
                        "confidence": 0.99,
                    }] if is_retry else []),
                    "missing_regions": [],
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("one visual retry must use the single-image verifier")

        def chat_vision_structured_bytes(self, *_args, **_kwargs):
            raise AssertionError("bounded visual retry must not enter full OCR")

    verifier = RetryVerifier()
    page_png = _one_page_png("manual visual retry evidence crash")

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    baseline = OcrBaselineResult(
        tex=repaired_tex,
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled manual retry baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    original_retry_persist = PageEvidenceStore.persist_retry_bundle
    injected = {"raised": False}

    def crash_before_retry_marker(evidence_store, page_id, retry_id, **kwargs):
        request = kwargs.get("request") or {}
        if (
            request.get("schema_version")
            == "latexstruct-ocr-page-retry-intent-v1"
            and not injected["raised"]
        ):
            injected["raised"] = True
            raise RuntimeError("synthetic crash before retry record marker")
        return original_retry_persist(
            evidence_store, page_id, retry_id, **kwargs
        )

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("manual.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(verifier, "vision-test", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=candidate_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                return_value=[],
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(400):
                initial = http.get(f"/api/ocr/jobs/{jid}").json()
                if initial.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)
            assert initial["status"] == "partial", initial
            assert verifier.calls == 1
            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                store = live_job["_v2_store"]
                snapshot = live_job["_v2_snapshot"]
                evidence_store = live_job["_v2_page_evidence_store"]
                cleanup_dirs.append(str(live_job.get("dir") or ""))
            page_id = make_page_id(1)
            base_record = store.load_record(snapshot.run_id, page_id)
            assert base_record.status is OcrPageStatus.NEEDS_REVIEW
            evidence_store.verify_terminal_page_artifacts(
                page_id,
                raw_response=store.load_raw_response(snapshot.run_id, base_record),
                page_tex=base_record.cleaned_tex,
            )
            base_bytes = {
                name: (evidence_store.page_dir(page_id) / name).read_bytes()
                for name in (
                    "source.json",
                    "candidate.json",
                    "verification.json",
                    "raw-response.json",
                    "page.tex",
                )
            }

            # Crash after the append-only manual intent but before the provider.
            # Ordinary resume must close this state without silently paying for
            # the visual verifier.
            with patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                side_effect=RuntimeError("synthetic pre-provider retry crash"),
            ):
                interrupted = http.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
            assert interrupted.status_code == 200, interrupted.text
            assert verifier.calls == 1
            interrupted_record = store.load_record(snapshot.run_id, page_id)
            assert interrupted_record.status is OcrPageStatus.FAILED
            pending = evidence_store.pending_retry_intents(page_id)
            assert len(pending) == 1
            assert pending[0]["intended_call_index"] == base_record.call_index + 1
            assert {
                name: (evidence_store.page_dir(page_id) / name).read_bytes()
                for name in base_bytes
            } == base_bytes

            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)
            restored = http.get(f"/api/ocr/jobs/{jid}").json()
            assert restored["status"] == "partial", restored
            resumed_without_replay = http.post(f"/api/ocr/jobs/{jid}/resume")
            assert resumed_without_replay.status_code == 200, resumed_without_replay.text
            for _ in range(500):
                fail_closed = http.get(f"/api/ocr/jobs/{jid}").json()
                if fail_closed["status"] in {"partial", "error"}:
                    break
                time.sleep(0.01)
            assert verifier.calls == 1
            assert fail_closed["status"] == "partial", fail_closed
            failed = store.load_record(snapshot.run_id, page_id)
            assert failed.status is OcrPageStatus.FAILED
            route = live_job["_v2_lane_route_store"].load(page_id)
            assert route.owner.value == "TERMINAL_UNRESOLVED"

            with patch.object(
                PageEvidenceStore,
                "persist_retry_bundle",
                crash_before_retry_marker,
            ):
                retried = http.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
                assert retried.status_code == 200, retried.text
                assert verifier.calls == 2
                terminal_record = store.load_record(snapshot.run_id, page_id)
                assert terminal_record.status is OcrPageStatus.SUCCESS, (
                    terminal_record.to_dict(), retried.json()
                )
                envelope = store.load_raw_response(snapshot.run_id, terminal_record)
                facts = envelope["terminal_evidence_facts"]
                retry_id = str(facts["retry_id"])
                assert facts["evidence_head"] == "RETRY"
                assert evidence_store.retry_commit_marker_exists(
                    page_id, retry_id
                ) is False
                assert {
                    name: (evidence_store.page_dir(page_id) / name).read_bytes()
                    for name in base_bytes
                } == base_bytes
                calls_before_resume = verifier.calls

                with srv._ocr_jobs_lock:
                    srv._ocr_jobs.pop(jid, None)
                restored = http.get(f"/api/ocr/jobs/{jid}").json()
                assert restored["status"] == "partial", restored
                resumed = http.post(f"/api/ocr/jobs/{jid}/resume")
                assert resumed.status_code == 200, resumed.text
                for _ in range(500):
                    final = http.get(f"/api/ocr/jobs/{jid}").json()
                    if final.get("terminal_epoch") is not None:
                        break
                    time.sleep(0.01)

                assert verifier.calls == calls_before_resume
                assert final["status"] == "done", final
            assert evidence_store.retry_commit_marker_exists(page_id, retry_id) is True
            terminal = evidence_store.verify_terminal_page_artifacts(
                page_id,
                raw_response=envelope,
                page_tex=terminal_record.cleaned_tex,
            )
            assert terminal["retry_id"] == retry_id
            assert {
                name: (evidence_store.page_dir(page_id) / name).read_bytes()
                for name in base_bytes
            } == base_bytes
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


def test_manual_full_ocr_crop_retry_repairs_absent_marker_without_replay(
    tmp_path: Path,
):
    """A crop-backed manual FULL retry is repaired from exact private evidence."""
    from latexstruct.core.ocr_lane_routes import OcrLaneOwner
    from latexstruct.core.ocr_page_evidence import PageEvidenceStore
    from latexstruct.core.ocr_pipeline import visual_strict_fallback_classification

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    source = b"%PDF-1.7\nmanual full crop crash window\n"
    classification = visual_strict_fallback_classification(
        source_type="pdf",
        source_bytes=source,
        selected_pages=(1,),
    )
    retryable_tex = (
        "A sufficiently long full-page retry remains syntactically incomplete {"
    )
    final_tex = (
        "A sufficiently long crop-backed full-page transcription passes every "
        "host check without semantic rewriting."
    )
    page_png = _one_page_png("manual full OCR crop crash")
    crop_png = _one_page_png("formula crop x squared plus y squared")
    crop_sha256 = hashlib.sha256(crop_png).hexdigest()

    class CropRetryClient:
        backend = "codex_cli"

        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage: dict[str, int] = {}
            self.structured_calls = 0
            self.multi_calls = 0
            self.manual_phase = False
            self.initial_provider_calls = 0
            self.initial_structured_calls = 0
            self.initial_multi_calls = 0
            self.initial_multi_image_counts: list[int] = []
            self.manual_provider_calls = 0
            self.manual_structured_calls = 0
            self.manual_multi_calls = 0
            self.manual_multi_image_counts: list[int] = []

        def _usage(self):
            usage = {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12}
            self.last_usage = usage
            return usage

        def chat_vision_structured_bytes(self, _system, _user, _image):
            self.structured_calls += 1
            if self.manual_phase:
                self.manual_provider_calls += 1
                self.manual_structured_calls += 1
            else:
                self.initial_provider_calls += 1
                self.initial_structured_calls += 1
            self._usage()
            return {
                "latex": retryable_tex,
                "figures": [],
                "framed_insets": [],
            }

        def chat_vision_structured_images_bytes(self, _system, _user, images):
            self.multi_calls += 1
            if self.manual_phase:
                self.manual_provider_calls += 1
                self.manual_multi_calls += 1
                self.manual_multi_image_counts.append(len(images))
                latex = (
                    final_tex
                    if self.manual_provider_calls == 4
                    else retryable_tex
                )
            else:
                self.initial_provider_calls += 1
                self.initial_multi_calls += 1
                self.initial_multi_image_counts.append(len(images))
                latex = retryable_tex
            self._usage()
            return {
                "latex": latex,
                "figures": [],
                "framed_insets": [],
            }

        def chat_vision_json_bytes(self, *_args, **_kwargs):
            raise AssertionError("full OCR must retain the host-validated adapter")

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("crop OCR must retain the host-validated adapter")

    client_instance = CropRetryClient()

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    def fake_formula_evidence(job, page_no):
        assert page_no == 1
        evidence_root = Path(job["dir"]) / "formula-evidence"
        evidence_root.mkdir(parents=True, exist_ok=True)
        crop_path = evidence_root / "p0001-f001.png"
        if not crop_path.exists():
            crop_path.write_bytes(crop_png)
        return [{
            "id": "p0001-f001",
            "target_bbox_normalized_in_crop": [0.1, 0.1, 0.9, 0.9],
            "source_bbox_points": [20.0, 20.0, 80.0, 70.0],
            "crop_bbox_points": [10.0, 10.0, 90.0, 80.0],
            "crop_sha256": crop_sha256,
            "dpi": 420,
            "image_size_pixels": [120, 120],
            "crop_path": str(crop_path),
        }]

    baseline = OcrBaselineResult(
        tex=final_tex,
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\ncompiled manual full crop baseline\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    original_retry_persist = PageEvidenceStore.persist_retry_bundle
    injected = {"raised": False}

    def crash_before_retry_marker(evidence_store, page_id, retry_id, **kwargs):
        request = kwargs.get("request") or {}
        if (
            request.get("schema_version")
            == "latexstruct-ocr-page-retry-intent-v1"
            and not injected["raised"]
        ):
            injected["raised"] = True
            raise RuntimeError("synthetic crop retry crash before record marker")
        return original_retry_persist(
            evidence_store,
            page_id,
            retry_id,
            **kwargs,
        )

    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("manual-crop.pdf", source, "application/pdf")},
            )
        assert inspected.status_code == 200, inspected.text
        jid = inspected.json()["id"]
        with (
            patch.object(
                srv,
                "_build_ocr_client",
                return_value=(client_instance, "vision-test", "codex_cli"),
            ),
            patch(
                "latexstruct.core.ocr_pipeline.classify_source_pages",
                return_value=classification,
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_text_hint", return_value=final_tex),
            patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
            patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
            patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch(
                "latexstruct.server.app._prepare_page_formula_evidence",
                side_effect=fake_formula_evidence,
            ),
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                return_value=baseline,
            ),
            patch("latexstruct.server.app._ocr_retry_wait", return_value=None),
        ):
            started = http.post(
                f"/api/ocr/jobs/{jid}/start",
                data={
                    "start_page": "1",
                    "end_page": "1",
                    "dpi": "200",
                    "quality_profile": "publication",
                    "quality_tier": "high",
                    "output_template": "faithfulbook",
                },
            )
            assert started.status_code == 200, started.text
            for _ in range(500):
                initial = http.get(f"/api/ocr/jobs/{jid}").json()
                if initial.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)
            assert initial["status"] == "partial", initial
            assert client_instance.initial_provider_calls == 5
            assert client_instance.initial_structured_calls == 4
            assert client_instance.initial_multi_calls == 1
            assert client_instance.initial_multi_image_counts == [2]

            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                store = live_job["_v2_store"]
                snapshot = live_job["_v2_snapshot"]
                evidence_store = live_job["_v2_page_evidence_store"]
                route_store = live_job["_v2_lane_route_store"]
                cleanup_dirs.append(str(live_job.get("dir") or ""))
            page_id = make_page_id(1)
            base_record = store.load_record(snapshot.run_id, page_id)
            assert base_record.status is OcrPageStatus.NEEDS_REVIEW
            base_head = evidence_store.latest_committed_coverage_head(page_id)
            assert base_head["retry_id"] is None
            assert route_store.load(page_id).owner is OcrLaneOwner.TERMINAL_UNRESOLVED
            client_instance.manual_phase = True

            with patch.object(
                PageEvidenceStore,
                "persist_retry_bundle",
                crash_before_retry_marker,
            ):
                retried = http.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
                assert retried.status_code == 200, retried.text
                assert injected["raised"] is True
                terminal_record = store.load_record(snapshot.run_id, page_id)
                assert terminal_record.status is OcrPageStatus.SUCCESS, retried.json()
                assert client_instance.manual_provider_calls == 4
                assert client_instance.manual_structured_calls == 3
                assert client_instance.manual_multi_calls == 1
                assert client_instance.manual_multi_image_counts == [2]

                envelope = store.load_raw_response(snapshot.run_id, terminal_record)
                facts = envelope["terminal_evidence_facts"]
                retry_id = str(facts["retry_id"])
                assert facts["evidence_head"] == "RETRY"
                assert facts["visual_mode"] == "FULL_OCR_WITH_CROPS"
                assert facts["full_ocr_performed"] is True
                assert facts["full_ocr_with_crops"] is True
                assert facts["crop_input_sha256s"] == [crop_sha256]
                assert evidence_store.retry_commit_marker_exists(
                    page_id,
                    retry_id,
                ) is False

                recovery = OcrRecoveryEvidenceStore(
                    store.run_dir(snapshot.run_id) / "recovery-evidence"
                )
                attempts, recovery_state = recovery.recover_page(
                    str(facts["recovery_run_id"]),
                    page_id,
                    crops_available=True,
                    independent_second_read=True,
                    repair=False,
                )
                crop_attempt = attempts[-1]
                assert crop_attempt.stage is RecoveryStage.PAGE_WITH_CROPS
                assert crop_attempt.record_sha256 == facts[
                    "recovery_attempt_sha256"
                ]
                assert recovery_state.last_attempt_sha256 == facts[
                    "recovery_attempt_sha256"
                ]
                assert recovery_state.evidence_chain_sha256 == facts[
                    "recovery_chain_sha256"
                ]
                assert [item.role for item in crop_attempt.images] == [
                    RecoveryImageRole.FULL_PAGE,
                    RecoveryImageRole.CROP,
                ]
                full_image, crop_image = crop_attempt.images
                assert full_image.blob.sha256 == terminal_record.image_sha256
                assert crop_image.blob.sha256 == crop_sha256
                for image in crop_attempt.images:
                    blob_path = (
                        recovery.root
                        / str(facts["recovery_run_id"])
                        / Path(image.blob.storage_key)
                    )
                    blob_bytes = blob_path.read_bytes()
                    assert hashlib.sha256(blob_bytes).hexdigest() == image.blob.sha256
                assert (
                    recovery.root
                    / str(facts["recovery_run_id"])
                    / Path(crop_image.blob.storage_key)
                ).read_bytes() == crop_png

                # The same strict journal loader used by terminal-call binding
                # must reject a modified link before restart repair can trust it.
                attempt_paths = sorted((
                    recovery.root
                    / str(facts["recovery_run_id"])
                    / "pages"
                    / page_id
                    / "attempts"
                ).glob("*.json"))
                last_attempt_path = attempt_paths[-1]
                last_attempt_bytes = last_attempt_path.read_bytes()
                tampered_attempt = json.loads(last_attempt_bytes)
                tampered_attempt["previous_attempt_sha256"] = "0" * 64
                try:
                    last_attempt_path.write_text(
                        json.dumps(tampered_attempt, sort_keys=True),
                        encoding="utf-8",
                    )
                    with pytest.raises(RecoveryEvidenceError):
                        recovery.recover_page(
                            str(facts["recovery_run_id"]),
                            page_id,
                            repair=False,
                        )
                finally:
                    last_attempt_path.write_bytes(last_attempt_bytes)
                restored_attempts, restored_state = recovery.recover_page(
                    str(facts["recovery_run_id"]),
                    page_id,
                    repair=False,
                )
                assert restored_attempts[-1].record_sha256 == facts[
                    "recovery_attempt_sha256"
                ]
                assert restored_state.evidence_chain_sha256 == facts[
                    "recovery_chain_sha256"
                ]

                calls_before_resume = (
                    client_instance.structured_calls,
                    client_instance.multi_calls,
                )
                with srv._ocr_jobs_lock:
                    srv._ocr_jobs.pop(jid, None)
                restored = http.get(f"/api/ocr/jobs/{jid}").json()
                assert restored["status"] == "partial", restored
                resumed = http.post(f"/api/ocr/jobs/{jid}/resume")
                assert resumed.status_code == 200, resumed.text
                for _ in range(600):
                    final = http.get(f"/api/ocr/jobs/{jid}").json()
                    if final.get("terminal_epoch") is not None:
                        break
                    time.sleep(0.01)

            assert (
                client_instance.structured_calls,
                client_instance.multi_calls,
            ) == calls_before_resume
            assert final["status"] == "done", final
            assert evidence_store.retry_commit_marker_exists(page_id, retry_id) is True
            retry_record = json.loads(
                (
                    evidence_store.page_dir(page_id)
                    / "retries"
                    / retry_id
                    / "record.json"
                ).read_text(encoding="utf-8")
            )
            assert (
                retry_record["schema_version"]
                == "latexstruct-ocr-page-retry-record-v2"
            )
            assert retry_record["parent_artifact_hashes"] == dict(
                base_head["artifact_hashes"]
            )
            terminal = evidence_store.verify_terminal_page_artifacts(
                page_id,
                raw_response=envelope,
                page_tex=terminal_record.cleaned_tex,
            )
            assert terminal["retry_id"] == retry_id
            assert route_store.load(page_id).owner is OcrLaneOwner.TERMINAL_FULL_OCR
            assert store.verify_saved_response(
                snapshot.run_id,
                terminal_record,
            )["latex"] == final_tex
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)


def test_restart_resume_retries_only_failed_page_and_second_resume_freezes(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1, 2))
    _persist_result(store, run_id, 1, 1, success=True)
    _persist_result(store, run_id, 2, 2, success=False)
    recovery_root = _persist_recovery_attempt(
        store, run_id, 1, 1,
        outcome=AttemptOutcome.PASSED,
        total_tokens=17,
    )
    _persist_recovery_attempt(
        store, run_id, 2, 2,
        outcome=AttemptOutcome.FAILED,
        total_tokens=19,
    )
    original_chain = {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (recovery_root / run_id).rglob("*") if path.is_file()
    }
    successful_before = store.load_record(run_id, make_page_id(1)).to_dict()
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    calls: list[int] = []
    systems: list[str] = []

    class ResumeClient:
        def __init__(self):
            self.cfg = SimpleNamespace(model="vision-test", api_key="configured")
            self.last_usage = {}

        def chat_vision_json_bytes(self, system, user, _image, _schema, **_kwargs):
            request = json.loads(user)["page_requests"][0]
            source_page = int(request["source_page"])
            calls.append(source_page)
            systems.append(system)
            if len(calls) == 1:
                raise RuntimeError("synthetic permanent resume failure")
            usage = {
                "prompt_tokens": 22,
                "completion_tokens": 3,
                "total_tokens": 25,
            }
            self.last_usage = usage
            return ({"pages": [{
                "page_id": request["page_id"],
                "latex": "Recovered failed page two after the fixed prompt.\n\n2",
                "figures": [],
                "unresolved_regions": [],
            }]}, usage)

    client_instance = ResumeClient()

    def fake_render(_path, pages, _dpi):
        source_page = int(pages[0])
        yield source_page, b"\x89PNG\r\n\x1a\n" + bytes([source_page]) * 32

    baseline = OcrBaselineResult(
        tex="twice compiled resumed baseline",
        log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\nresumed compiled\n",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    fixed_prompt = "FIXED OCR PROMPT WITH CURRENT image_size_pixels"
    app = srv.create_app()
    http = TestClient(app)
    restored = http.get(f"/api/ocr/jobs/{run_id}").json()
    assert restored["usage"]["calls"] == 2
    assert restored["usage"]["total_tokens"] == 36

    with (
        patch.object(
            srv,
            "_build_ocr_client",
            return_value=(client_instance, "vision-test", "api"),
        ),
        patch.object(srv, "OCR_TRANSCRIPTION_SYSTEM_PROMPT", fixed_prompt),
        patch("latexstruct.ocr.iter_pdf_pages", fake_render),
        patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
        patch("latexstruct.server.app._prepare_page_formula_evidence", return_value=[]),
        patch("latexstruct.core.ocr_baseline.compile_ocr_baseline", return_value=baseline),
    ):
        first_resume = http.post(f"/api/ocr/jobs/{run_id}/resume")
        assert first_resume.status_code == 200, first_resume.text
        for _ in range(200):
            first_terminal = http.get(f"/api/ocr/jobs/{run_id}").json()
            if first_terminal["status"] == "partial" and first_terminal.get("terminal_epoch"):
                break
            time.sleep(0.01)
        assert first_terminal["status"] == "partial", first_terminal
        assert calls == [2], first_terminal
        assert first_terminal["pages"]["1"]["status"] == "done"

        second_resume = http.post(f"/api/ocr/jobs/{run_id}/resume")
        assert second_resume.status_code == 200, second_resume.text
        for _ in range(300):
            final = http.get(f"/api/ocr/jobs/{run_id}").json()
            if final["status"] == "done":
                break
            time.sleep(0.01)

    assert final["status"] == "done", final
    assert final["raw_frozen"] is True
    assert final["compile_status"] == "COMPILED"
    assert final["baseline_compile"]["successful_passes"] == 2
    assert final["usage"]["calls"] == 3
    assert final["usage"]["total_tokens"] == 61
    assert calls == [2, 2]
    assert systems == [fixed_prompt, fixed_prompt]
    assert store.load_record(run_id, make_page_id(1)).to_dict() == successful_before
    resumed_record = store.load_record(run_id, make_page_id(2))
    assert resumed_record.raw_tex.endswith("\n\n2")
    assert resumed_record.cleaned_tex == "Recovered failed page two after the fixed prompt."
    assert original_chain == {
        path.relative_to(recovery_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (recovery_root / run_id).rglob("*") if path.is_file()
    }
    recovery_runs = [
        path for path in recovery_root.iterdir()
        if path.is_dir() and path.name != run_id
    ]
    assert len(recovery_runs) == 2


def test_completed_run_restores_and_serves_only_hash_verified_artifacts(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    store.freeze_raw_ocr(run_id)
    store.save_compile_baseline(
        run_id,
        baseline_tex="Recovered page 1.",
        compile_log="two successful passes",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.7\ncompiled\n",
    )
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()
    client = TestClient(srv.create_app())
    state = client.get(f"/api/ocr/jobs/{run_id}").json()
    assert state["status"] == "done"
    assert state["quality_report"]["counts"]["missing_provenance_pages"] == 0
    assert state["quality_report"]["resources"]["source_pages"] == 1
    assert state["pages"]["1"]["visual_input_persisted"] is True
    assert state["progress_metrics"]["elapsed_frozen"] is True
    assert state["artifacts"]["baseline_pdf"]["available"] is True
    assert client.get(f"/api/ocr/jobs/{run_id}/pages/1").status_code == 200
    raw = client.get(f"/api/ocr/jobs/{run_id}/artifacts/raw-ocr")
    assert raw.status_code == 200
    assert hashlib.sha256(raw.content).hexdigest() == raw.headers["x-latexstruct-sha256"]
    bad = client.get(f"/api/ocr/jobs/{run_id}/artifacts/../../secret")
    assert bad.status_code in {404, 405}


def test_open_creates_verified_baseline_project_without_starting_analysis(
    tmp_path: Path,
):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    store.freeze_raw_ocr(run_id)
    baseline_tex = "Syntax repaired baseline that is safe to open."
    store.save_compile_baseline(
        run_id,
        baseline_tex=baseline_tex,
        compile_log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.7\ncompiled\n",
    )
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    client = TestClient(srv.create_app())
    restored = client.get(f"/api/ocr/jobs/{run_id}")
    assert restored.status_code == 200, restored.text
    assert restored.json()["status"] == "done"

    with (
        patch(
            "latexstruct.ocr.image_pixel_size",
            return_value=(1200, 1800),
        ),
        patch("latexstruct.ocr.pdf_page_count_bytes", return_value=1),
        patch.object(
            srv._process_jobs,
            "create",
            side_effect=AssertionError("opening an OCR baseline started analysis"),
        ) as create_process,
    ):
        opened = client.post(f"/api/ocr/jobs/{run_id}/open")

    assert opened.status_code == 200, opened.text
    payload = opened.json()
    assert payload["analysis_started"] is False
    assert payload["processed"] is False
    assert payload["process"] is None
    assert payload["ocr_snapshot_id"]
    create_process.assert_not_called()

    pid = payload["id"]
    project = client.get(f"/api/projects/{pid}")
    assert project.status_code == 200, project.text
    assert project.json()["kind"] == "ocr"
    assert project.json()["mode"] == "rule"
    assert client.get(f"/api/projects/{pid}/source").text == baseline_tex
    assert srv._process_jobs.active(pid) is None
    assert srv._process_jobs.latest(pid) is None
    with srv._ocr_jobs_lock:
        job = srv._ocr_jobs[run_id]
        assert job["baseline_project_id"] == pid
        assert job["imported_project_id"] == pid
        assert job["imported_processed"] is False


def test_analysis_entry_uses_only_hash_verified_twice_compiled_baseline(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    store.freeze_raw_ocr(run_id)
    store.save_compile_baseline(
        run_id,
        baseline_tex="Syntax repaired baseline.",
        compile_log="pass 1 exit 0\npass 2 exit 0",
        preview_status=OcrPreviewStatus.COMPILED,
        exit_code=0,
        successful_passes=2,
        pdf_bytes=b"%PDF-1.7\ncompiled\n",
    )
    runtime = {
        "_v2_store": store,
        "_v2_snapshot": store.load_snapshot(run_id),
        "raw_tex": "uncompiled raw",
    }

    baseline, lineage = srv._verified_v2_baseline_for_analysis(runtime)

    assert baseline == "Syntax repaired baseline."
    assert lineage["verified"] is True
    assert lineage["successful_passes"] == 2
    assert lineage["source"] == "twice_compiled_syntax_baseline"
    baseline_path = store.run_dir(run_id) / "artifacts" / "baseline.tex"
    baseline_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(OcrStoreError, match="SHA-256"):
        srv._verified_v2_baseline_for_analysis(runtime)


def test_restore_does_not_promote_missing_persisted_visual_evidence(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    _persist_result(store, run_id, 1, 1, success=True)
    for page_image in (store.run_dir(run_id) / "page-images").iterdir():
        page_image.unlink()
    store.freeze_raw_ocr(run_id)
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    state = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}").json()

    assert state["status"] == "partial"
    assert state["pages"]["1"]["visual_input_persisted"] is False
    assert state["quality_report"]["counts"]["missing_provenance_pages"] == 1
    assert state["quality_report"]["resources"]["source_pages"] == 0


def test_restart_keeps_needs_review_page_retryable_and_unfrozen(tmp_path: Path):
    store, run_id = _setup_store(tmp_path, (1,))
    image = b"\x89PNG\r\n\x1a\nreview-page"
    record = store.load_record(run_id, make_page_id(1))
    record = record.transition(OcrPageStatus.RENDERING, dpi=300).transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=hashlib.sha256(image).hexdigest(),
        image_size_pixels=(1200, 1800),
        dpi=300,
        model="vision-test",
        call_index=2,
    )
    store.persist_record(run_id, record)
    store.persist_page_image(run_id, record, image)
    raw = {
        "page_id": record.page_id,
        "latex": "Visible content that still needs confirmation.",
        "figures": [],
        "unresolved_regions": [{
            "type": "formula",
            "reason": "operator is not legible",
            "bbox_normalized": [0.2, 0.2, 0.4, 0.3],
        }],
    }
    raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    record = record.transition(OcrPageStatus.VALIDATING).transition(
        OcrPageStatus.NEEDS_REVIEW,
        raw_response_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_tex=raw["latex"],
        cleaned_tex=raw["latex"],
        unresolved_regions=tuple(raw["unresolved_regions"]),
    )
    store.persist_record(run_id, record, raw_response=raw)
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()

    state = TestClient(srv.create_app()).get(f"/api/ocr/jobs/{run_id}").json()

    assert state["status"] == "partial"
    assert state["raw_frozen"] is False
    assert state["pages"]["1"]["needs_review"] is True
    assert state["can_resume"] is True


def test_bundle_snapshot_exports_page_telemetry_without_local_paths():
    source = b"%PDF-1.7\ntelemetry\n"
    runtime_snapshot = make_run_snapshot(
        source_bytes=source,
        source_type="pdf",
        original_filename="中文证据.pdf",
        source_total_pages=1,
        selected_pages=(1,),
        ocr_model="vision-test",
        api_backend="codex_cli",
        app_version="2.0.0",
        run_id="c" * 32,
    )
    image_sha = hashlib.sha256(b"page-image").hexdigest()
    raw_response_sha = hashlib.sha256(b"response").hexdigest()
    record = OcrPageRecord(
        page_id="ocr-page-000001",
        source_page=1,
        task_index=1,
        status=OcrPageStatus.SUCCESS,
        image_sha256=image_sha,
        image_size_pixels=(1200, 1800),
        dpi=300,
        model="vision-test",
        call_index=2,
        raw_response_sha256=raw_response_sha,
        raw_tex="Telemetry page.",
        cleaned_tex="Telemetry page.",
        started_at="2026-08-24T00:00:00Z",
        ended_at="2026-08-24T00:00:12Z",
        elapsed_seconds=12.0,
        retry_count=1,
        quality_issues=({"code": "OCR_RETRY_SCHEDULED"},),
        usage={"attempts": [{"usage": {"total_tokens": 123}}]},
    )
    live_job = {
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "source_outline": [],
        "_source_sha256": runtime_snapshot.source_sha256,
        "target": "C:/private/source.pdf",
        "status": "done",
        "quality_profile": "standard",
        "backend": "codex_cli",
        "model": "vision-test",
        "reasoning_effort": "low",
        "dpi": 200,
        "raw_ready": True,
        "raw_frozen": True,
        "compile_status": "COMPILED",
        "_v2_snapshot": runtime_snapshot,
        "current_concurrency_limit": 3,
        "pages": {
            1: {
                "status": "done",
                "attempts": 2,
                "image_size_pixels": [1200, 1800],
                "visual_input_sha256": image_sha,
                "visual_input_persisted": True,
            }
        },
    }

    frozen = srv._snapshot_ocr_bundle_job(live_job, v2_records=[record])
    manifest_page = srv._ocr_manifest_page_records(frozen)[0]

    assert frozen["performance_metrics"]["counts"]["success"] == 1
    assert frozen["ocr_run_snapshot"]["concurrency_limit"] == 3
    exported_telemetry = json.dumps({
        "run_snapshot": frozen["ocr_run_snapshot"],
        "performance_metrics": frozen["performance_metrics"],
        "page": manifest_page,
    }, ensure_ascii=False)
    assert "C:/private" not in exported_telemetry
    assert manifest_page["telemetry"] == {
        "page_id": "ocr-page-000001",
        "status": "SUCCESS",
        "task_index": 1,
        "dpi": 300,
        "model": "vision-test",
        "call_index": 2,
        "batch_call": False,
        "batch_id": "",
        "started_at": "2026-08-24T00:00:00Z",
        "ended_at": "2026-08-24T00:00:12Z",
        "elapsed_seconds": 12.0,
        "retry_count": 1,
        "raw_response_sha256": raw_response_sha,
        "tex_sha256": record.tex_sha256,
        "usage": {"attempts": [{"usage": {"total_tokens": 123}}]},
        "quality_issues": [{"code": "OCR_RETRY_SCHEDULED"}],
        "unresolved_regions": [],
        "terminal_error": "",
        "recovery": {
            "run_id": "",
            "stage": "",
            "status": "",
            "attempt_count": 0,
            "evidence_chain_sha256": "",
        },
    }


def test_recovery_json_evidence_is_preserved_and_hash_verified_without_host_path(
    tmp_path: Path,
):
    root = tmp_path / "private-recovery-root"
    page = root / ("a" * 32) / "pages" / "ocr-page-000001"
    attempts = page / "attempts"
    attempts.mkdir(parents=True)
    attempt = {
        "schema_version": "latexstruct-ocr-recovery-attempt-v2",
        "record_sha256": "b" * 64,
    }
    (attempts / "000001-attempt01.json").write_text(
        json.dumps(attempt), encoding="utf-8"
    )
    (page / "state.json").write_text(
        json.dumps({"status": "SUCCESS"}), encoding="utf-8"
    )
    (root / ("a" * 32) / "blobs").mkdir()
    (root / ("a" * 32) / "blobs" / "secret").write_bytes(b"not packaged")

    project = tmp_path / "project"
    project.mkdir()
    rows = srv._preserve_ocr_recovery_evidence(
        {"_recovery_evidence_root": str(root)}, project
    )
    files = srv._verified_ocr_recovery_resource_bytes(
        project, {"recovery_evidence": rows}
    )

    assert len(rows) == 2
    assert all(str(tmp_path) not in json.dumps(row) for row in rows)
    assert all(path.startswith("evidence/ocr-recovery/") for path in files)
    assert not any("blobs" in path for path in files)
    tampered = project / Path(rows[0]["path"])
    tampered.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="校验失败"):
        srv._verified_ocr_recovery_resource_bytes(
            project, {"recovery_evidence": rows}
        )


def test_ocr_bundle_contains_recovery_journal_without_host_paths(tmp_path: Path):
    source = tmp_path / "中文原始输入.pdf"
    source.write_bytes(b"%PDF-1.7\nimmutable source\n")
    recovery_root = tmp_path / "private-recovery-root"
    page = recovery_root / ("d" * 32) / "pages" / "ocr-page-000001"
    attempts = page / "attempts"
    attempts.mkdir(parents=True)
    attempt_bytes = json.dumps({
        "schema_version": "latexstruct-ocr-recovery-attempt-v2",
        "record_sha256": "e" * 64,
    }).encode("utf-8")
    (attempts / "000001-attempt01.json").write_bytes(attempt_bytes)
    state_bytes = json.dumps({"status": "NEEDS_REVIEW"}).encode("utf-8")
    (page / "state.json").write_bytes(state_bytes)

    source_bytes = source.read_bytes()
    bundle, manifest = srv._ocr_bundle_bytes({
        "target": str(source),
        "_source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "_recovery_evidence_root": str(recovery_root),
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "pages": {},
        "status": "partial",
    }, "Recovered page 1.")

    assert len(manifest["recovery_evidence"]) == 2
    assert all(
        item["path"].startswith("evidence/ocr-recovery/")
        for item in manifest["recovery_evidence"]
    )
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        names = set(archive.namelist())
        for item in manifest["recovery_evidence"]:
            assert item["path"] in names
            assert hashlib.sha256(archive.read(item["path"])).hexdigest() == item["sha256"]
        manifest_bytes = archive.read("OCR-MANIFEST.json")
    assert str(tmp_path).encode("utf-8") not in bundle
    assert str(tmp_path).encode("utf-8") not in manifest_bytes


def test_ocr_bundle_manifest_redacts_historical_page_record_errors(tmp_path: Path):
    source = tmp_path / "source.pdf"
    source_bytes = b"%PDF-1.7\nimmutable source\n"
    source.write_bytes(source_bytes)
    runtime_snapshot = make_run_snapshot(
        source_bytes=source_bytes,
        source_type="pdf",
        original_filename="source.pdf",
        source_total_pages=1,
        selected_pages=(1,),
        ocr_model="vision-test",
        api_backend="api",
        app_version="2.0.0",
        run_id="f" * 32,
    )
    secret = "super-secret-token-123456"
    windows_path = r"C:\Users\ZQY\private\ocr.log"
    posix_path = "/home/zqy/private/ocr.log"
    unsafe = (
        f"Authorization: Bearer {secret} failed at {windows_path}; "
        f"trace {posix_path}"
    )
    record = OcrPageRecord(
        page_id=make_page_id(1),
        source_page=1,
        task_index=1,
        status=OcrPageStatus.FAILED,
        quality_issues=({
            "code": "OCR_CALL_FAILED",
            "message": unsafe,
            "Authorization": secret,
        },),
        unresolved_regions=({"reason": unsafe},),
        usage={"provider_error": unsafe, "api_key": secret},
        error_reason=unsafe,
    )
    frozen = srv._snapshot_ocr_bundle_job({
        "source_type": "pdf",
        "source_total": 1,
        "selected_start": 1,
        "selected_end": 1,
        "selected_pages": [1],
        "_source_sha256": runtime_snapshot.source_sha256,
        "target": str(source),
        "status": "partial",
        "backend": "api",
        "model": "vision-test",
        "_v2_snapshot": runtime_snapshot,
        "pages": {1: {"status": "error", "error": unsafe}},
    }, v2_records=[record])

    bundle, manifest = srv._ocr_bundle_bytes(frozen, "Recovered page.")

    manifest_text = json.dumps(manifest, ensure_ascii=False)
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        archived_manifest = archive.read("OCR-MANIFEST.json").decode("utf-8")
    for payload in (manifest_text, archived_manifest):
        assert secret not in payload
        assert windows_path not in payload
        assert posix_path not in payload
        assert "<REDACTED>" in payload
        assert "<LOCAL_PATH>" in payload

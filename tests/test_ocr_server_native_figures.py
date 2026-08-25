"""Server closure for host-owned native PDF figure objects."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pymupdf
import pytest
from fastapi.testclient import TestClient

from latexstruct.core.ocr_baseline import OcrBaselineResult
from latexstruct.core.ocr_extraction import extract_pdf_pages
from latexstruct.core.ocr_lane_routes import OcrLaneOwner
from latexstruct.core.ocr_native_figures import NATIVE_FIGURE_SOURCE
from latexstruct.core.ocr_pipeline import SourceClassification
from latexstruct.core.ocr_runtime import (
    OcrPageStatus,
    OcrPreviewStatus,
    OcrStoreError,
)
from latexstruct.core.ocr_schema import DocumentStrategy, PageBlockType
from latexstruct.server import app as srv
from latexstruct.store import ProjectStore


def _native_vector_pdf() -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=400, height=600)
        nodes = ((120, 120), (200, 90), (280, 120), (160, 200), (240, 200))
        edges = ((0, 1), (1, 2), (0, 3), (1, 3), (1, 4), (2, 4), (3, 4))
        for first, second in edges:
            page.draw_line(nodes[first], nodes[second], color=(0, 0, 0), width=2)
        for index, center in enumerate(nodes):
            page.draw_circle(center, 12, color=(0, 0, 0), width=1.5)
            page.insert_text(
                (center[0] - 4, center[1] + 4),
                chr(65 + index),
                fontsize=9,
            )
        page.insert_text((105, 230), "Figure 1. Native vector graph.", fontsize=10)
        page.insert_text(
            (40, 285),
            "This sufficiently long body paragraph remains faithful to the source ",
            fontsize=10,
        )
        page.insert_text(
            (40, 305),
            "while the host preserves the bounded vector diagram as one crop.",
            fontsize=10,
        )
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _render_pdf_page(payload: bytes) -> bytes:
    document = pymupdf.open(stream=payload, filetype="pdf")
    try:
        return document[0].get_pixmap(matrix=pymupdf.Matrix(2, 2), alpha=False).tobytes(
            "png"
        )
    finally:
        document.close()


@pytest.mark.parametrize(
    "mutation",
    [None, "valid_patch", "missing", "tampered"],
)
def test_visual_native_figure_transport_is_closed_and_retryable(
    tmp_path: Path,
    mutation: str | None,
) -> None:
    """PASS materializes the crop; a changed ref retains the host candidate."""

    source = _native_vector_pdf()
    page_classification = extract_pdf_pages(source, extraction_workers=1)[0]
    figure_blocks = tuple(
        block
        for block in page_classification.blocks
        if block.block_type is PageBlockType.FIGURE
        and dict(block.style_features).get("host_figure_path")
    )
    assert len(figure_blocks) == 1
    figure = figure_blocks[0]
    text_block = next(
        block
        for block in page_classification.blocks
        if block.block_type is PageBlockType.TEXT
    )
    figure_path = "figures/page_0001_figure_01.png"
    assert dict(figure.style_features)["host_figure_path"] == figure_path
    assert figure_path in page_classification.candidate_tex
    classification = SourceClassification(
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_type="pdf",
        document_strategy=DocumentStrategy.BORN_DIGITAL_FAST,
        pages=(page_classification,),
    )

    class NativeFigureVerifier:
        backend = "codex_cli"

        def __init__(self) -> None:
            self.cfg = SimpleNamespace(model="gpt-5.4-mini", api_key="")
            self.last_usage: dict[str, int] = {}
            self.verifier_calls = 0
            self.full_ocr_calls = 0

        def chat_vision_json_bytes(self, _system, user, _image, _schema):
            self.verifier_calls += 1
            request = json.loads(user)
            invalid_mutation = mutation in {"missing", "tampered"}
            mutate_now = mutation is not None and self.verifier_calls == 1
            findings = []
            if mutate_now:
                if mutation == "valid_patch":
                    target_block = text_block
                    replacement = (
                        text_block.candidate_latex
                        + " Host-verified local correction."
                    )
                else:
                    target_block = figure
                    replacement = (
                        "The diagram reference was incorrectly removed by the verifier."
                        if mutation == "missing"
                        else figure.candidate_latex.replace(
                            "figure_01.png", "figure_02.png"
                        )
                    )
                findings = [{
                    "block_id": target_block.block_id,
                    "issue_type": (
                        "STYLE_ERROR" if invalid_mutation else "TEXT_MISMATCH"
                    ),
                    "severity": "HIGH",
                    "replacement_latex": replacement,
                    "evidence_region": [0.15, 0.10, 0.85, 0.45],
                    "confidence": 0.99,
                }]
            usage = {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}
            self.last_usage = usage
            return ({
                "batch_id": request["batch_id"],
                "pages": [{
                    "page_id": page_classification.page_id,
                    "verdict": "PATCH" if mutate_now else "PASS",
                    "reading_order_ok": True,
                    "coverage_ok": True,
                    "block_findings": findings,
                    "missing_regions": [],
                    "unresolved_regions": [],
                }],
            }, usage)

        def chat_vision_json_images_bytes(self, *_args, **_kwargs):
            raise AssertionError("one native page must use the single-image verifier")

        def chat_vision_structured_bytes(self, *_args, **_kwargs):
            self.full_ocr_calls += 1
            raise AssertionError("a local figure-reference mismatch cannot buy full OCR")

    verifier = NativeFigureVerifier()
    page_png = _render_pdf_page(source)

    def fake_render(_path, pages, _dpi):
        assert list(pages) == [1]
        yield 1, page_png

    compile_calls: list[dict[str, object]] = []

    def fake_compile(tex, *, extra_files=None, selected_pages=None, **_kwargs):
        compile_calls.append({
            "tex": tex,
            "extra_files": dict(extra_files or {}),
            "selected_pages": tuple(selected_pages or ()),
        })
        return OcrBaselineResult(
            tex=tex,
            log="pass 1 exit 0\npass 2 exit 0",
            preview_status=OcrPreviewStatus.COMPILED,
            pdf_bytes=b"%PDF-1.7\ncompiled native figure baseline\n",
            exit_code=0,
            successful_passes=2,
            syntax_repairs=(),
            error_lines=(),
            engine="xelatex",
        )

    srv._store = ProjectStore(root=str(tmp_path / "projects"))
    srv._config = None
    http = TestClient(srv.create_app())
    jid = ""
    cleanup_dirs: list[str] = []
    initial_envelope = None
    initial_route = None
    invalid_mutation = mutation in {"missing", "tampered"}
    try:
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ):
            inspected = http.post(
                "/api/ocr/inspect",
                files={"file": ("native-vector.pdf", source, "application/pdf")},
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
            patch(
                "latexstruct.ocr.pdf_page_text_hint",
                return_value=page_classification.candidate_tex,
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
            patch(
                "latexstruct.core.ocr_baseline.compile_ocr_baseline",
                side_effect=fake_compile,
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
                state = http.get(f"/api/ocr/jobs/{jid}").json()
                if state.get("terminal_epoch") is not None:
                    break
                time.sleep(0.01)

            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                store = live_job["_v2_store"]
                snapshot = live_job["_v2_snapshot"]
                internal_page = dict(live_job["pages"][1])
                cleanup_dirs.append(str(live_job.get("dir") or ""))

            if invalid_mutation:
                assert state["status"] == "partial", state
                assert state["pages"]["1"]["needs_review"] is True
                assert state["pages"]["1"]["can_retry"] is True
                assert compile_calls == []
                record = store.load_record(snapshot.run_id, page_classification.page_id)
                assert record.status is OcrPageStatus.NEEDS_REVIEW
                initial_envelope = store.load_raw_response(snapshot.run_id, record)
                retained_transport = store.verify_saved_response(
                    snapshot.run_id, record
                )
                assert retained_transport["latex"] == record.cleaned_tex
                assert figure_path in retained_transport["latex"]
                assert "figure_02.png" not in retained_transport["latex"]
                assert retained_transport["figures"][0]["source"] == (
                    NATIVE_FIGURE_SOURCE
                )
                assert retained_transport["figures"][0]["source_object_hash"] == (
                    figure.source_object_hash
                )
                assert internal_page["coverage_complete"] is False
                assert internal_page["coverage_record"]["final_status"] == (
                    OcrPageStatus.NEEDS_REVIEW.value
                )
                initial_route = live_job["_v2_lane_route_store"].load(
                    page_classification.page_id
                )
                assert initial_route.owner is OcrLaneOwner.TERMINAL_UNRESOLVED
                assert [event.owner for event in initial_route.history] == [
                    OcrLaneOwner.VISUAL,
                    OcrLaneOwner.TERMINAL_UNRESOLVED,
                ]
                assert all(
                    "FULL_OCR" not in event.owner.value
                    for event in initial_route.history
                )
                with pytest.raises(OcrStoreError, match="successful page"):
                    store.materialize_figure_assets(snapshot.run_id)

                retry = http.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
                assert retry.status_code == 200, retry.text
                assert retry.json()["ok"] is True
                state = http.get(f"/api/ocr/jobs/{jid}").json()

        assert state["status"] == "done", state
        assert state["compile_status"] == OcrPreviewStatus.COMPILED.value
        assert verifier.verifier_calls == (2 if invalid_mutation else 1)
        assert verifier.full_ocr_calls == 0
        assert compile_calls
        assert all(call["selected_pages"] == (1,) for call in compile_calls)
        assert all(figure_path in call["extra_files"] for call in compile_calls)
        assert all(
            call["extra_files"][figure_path].startswith(b"\x89PNG\r\n\x1a\n")
            for call in compile_calls
        )

        record = store.load_record(snapshot.run_id, page_classification.page_id)
        assert record.status is OcrPageStatus.SUCCESS
        transport = store.verify_saved_response(snapshot.run_id, record)
        assert transport["figures"][0]["source"] == NATIVE_FIGURE_SOURCE
        assert transport["figures"][0]["source_object_hash"] == (
            figure.source_object_hash
        )
        assert live_job["pages"][1]["figures"] == transport["figures"]
        if mutation == "valid_patch":
            assert "Host-verified local correction." in record.cleaned_tex
            envelope = store.load_raw_response(snapshot.run_id, record)
            assert envelope["patched_block_ids"] == [text_block.block_id]
        assets, figure_manifest = store.materialize_figure_assets(snapshot.run_id)
        assert set(assets) == {figure_path}
        assert assets[figure_path].startswith(b"\x89PNG\r\n\x1a\n")
        assert figure_manifest["figures"][0]["source"] == NATIVE_FIGURE_SOURCE
        assert figure_manifest["figures"][0]["source_object_hash"] == (
            figure.source_object_hash
        )
        route = live_job["_v2_lane_route_store"].load(page_classification.page_id)
        assert route.owner is OcrLaneOwner.TERMINAL_VISUAL
        if invalid_mutation:
            assert initial_envelope is not None
            assert initial_route is not None
            assert [event.owner for event in route.history] == [
                OcrLaneOwner.VISUAL,
                OcrLaneOwner.TERMINAL_UNRESOLVED,
                OcrLaneOwner.VISUAL,
                OcrLaneOwner.TERMINAL_VISUAL,
            ]
    finally:
        if jid:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {})
            import shutil

            cleanup_dirs.append(str(job.get("dir") or ""))
            for directory in set(cleanup_dirs):
                if directory:
                    shutil.rmtree(directory, ignore_errors=True)

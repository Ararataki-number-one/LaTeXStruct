from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from latexstruct.core.ocr_page_evidence import PageEvidenceStore
from latexstruct.core.ocr_page_evidence_bindings import (
    OcrPageEvidenceBindingsError,
    OcrPageTerminalMode,
    build_ocr_page_evidence_bindings_from_store,
    canonical_page_evidence_bindings_json_bytes,
    parse_ocr_page_evidence_bindings,
)
from latexstruct.core.ocr_runtime import (
    OcrPageStatus,
    OcrRunStore,
    make_run_snapshot,
)
from latexstruct.core.ocr_schema import (
    PageBlock,
    PageBlockType,
    PageCandidate,
    PageFeatures,
)
from latexstruct.core.ocr_visual import PageVisualVerification, VisualVerdict


RUN_ID = "d" * 32


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _runtime_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _candidate(index: int) -> PageCandidate:
    page_id = f"ocr-page-{index:06d}"
    object_hash = _sha(f"object-{index}".encode())
    block = PageBlock(
        block_id=f"{page_id}-block-0001-{object_hash[:12]}",
        block_type=PageBlockType.DISPLAY_MATH,
        bbox=(72, 100, 540, 150),
        reading_order=1,
        plain_text=f"private source text {index}",
        style_features={},
        math_likelihood=0.95,
        source_object_hash=object_hash,
        candidate_latex=f"x_{index} \\le y_{index}",
    )
    return PageCandidate(
        page_id=page_id,
        source_page_number=index,
        selected_index=index,
        features=PageFeatures(
            page_width=612,
            page_height=792,
            rotation=0,
            has_text_objects=True,
            text_character_count=25,
            printable_character_ratio=1,
            unicode_replacement_ratio=0,
            garbled_character_ratio=0,
            font_mapping_health=1,
            text_block_count=1,
            image_count=0,
            image_coverage_ratio=0,
            single_full_page_image=False,
            math_symbol_density=0.3,
            formula_region_count=1,
            double_column_likelihood=0,
            text_pixel_alignment_confidence=0.99,
            reading_order_confidence=0.99,
        ),
        blocks=(block,),
        source_page_object_hash=_sha(f"page-object-{index}".encode()),
        source_text_layer_sha256=_sha(f"text-layer-{index}".encode()),
        candidate_tex=f"private candidate x_{index} \\le y_{index}",
    )


def _visual_verification(candidate: PageCandidate) -> PageVisualVerification:
    return PageVisualVerification(
        page_id=candidate.page_id,
        verdict=VisualVerdict.PASS,
        reading_order_ok=True,
        coverage_ok=True,
    )


def _setup_store(tmp_path: Path) -> tuple[OcrRunStore, object, bytes]:
    source = b"%PDF-1.7\nprivate source payload\n"
    snapshot = make_run_snapshot(
        source_bytes=source,
        source_type="pdf",
        original_filename="private.pdf",
        source_total_pages=2,
        selected_pages=(1, 2),
        ocr_model="vision-test",
        api_backend="api",
        app_version="2.0.0",
        quality_tier="high",
        run_id=RUN_ID,
    )
    store = OcrRunStore(tmp_path / "ocr-runs")
    store.initialize(snapshot, source)
    return store, snapshot, source


def _persist_visual_page(
    store: OcrRunStore,
    snapshot: object,
    candidate: PageCandidate,
) -> str:
    record = store.load_record(snapshot.run_id, candidate.page_id)
    image = b"visual page pixels"
    record = record.transition(OcrPageStatus.RENDERING, dpi=160)
    evidence_sha = store.persist_page_source_evidence(
        snapshot.run_id, record, {"kind": "private object evidence"}
    )
    record = record.transition(
        OcrPageStatus.VERIFYING,
        image_sha256=_sha(image),
        image_size_pixels=(1200, 1600),
        source_evidence_sha256=evidence_sha,
        dpi=160,
        model="vision-test",
        call_index=1,
        started_at="2026-08-26T00:00:00Z",
    )
    verification = _visual_verification(candidate)
    # The terminal response may be the host's bounded local-retry wrapper,
    # rather than a provider batch at the top level.  The binding deliberately
    # treats it as opaque canonical response bytes.
    model_raw_response = {
        "schema_version": "latexstruct-ocr-visual-local-retry-chain-v1",
        "attempts": [{
            "batch_id": "ocr-visual-private-batch",
            "pages": [verification.to_dict()],
        }],
        "final_verification": verification.to_dict(),
    }
    verifier_response_sha = _sha(_runtime_json(model_raw_response))
    transport = {
        "page_id": candidate.page_id,
        "latex": candidate.candidate_tex,
        "figures": [],
        "unresolved_regions": [],
    }
    envelope = {
        "schema_version": "latexstruct-ocr-visual-response-v1",
        "page_id": candidate.page_id,
        "source_page": candidate.source_page_number,
        "task_index": candidate.selected_index,
        "call_index": record.call_index,
        "gate_applied": True,
        "source_evidence_sha256": evidence_sha,
        "candidate_tex": candidate.candidate_tex,
        "candidate_tex_sha256": _sha(candidate.candidate_tex.encode()),
        "verification_batch_id": "ocr-visual-private-batch",
        "verification_response_sha256": verifier_response_sha,
        "model_raw_response": model_raw_response,
        "verification_page": verification.to_dict(),
        "visual_mode": "VERIFIER",
        "patched_block_ids": [],
        "local_patch_block_ids": [],
        "needs_review": False,
        "transport_response": transport,
        "host_quality_flags": [],
    }
    record = record.transition(OcrPageStatus.VALIDATING)
    record = record.transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=_sha(_runtime_json(envelope)),
        raw_tex=candidate.candidate_tex,
        cleaned_tex=candidate.candidate_tex,
        ended_at="2026-08-26T00:00:01Z",
        host_quality_flags=(),
        unresolved_regions=(),
    )
    store.persist_record(snapshot.run_id, record, raw_response=envelope)
    PageEvidenceStore(
        store.root, snapshot.run_id, snapshot.source_sha256
    ).persist_page_bundle(
        candidate,
        verification={
            "page_id": candidate.page_id,
            "visual_mode": "VERIFIER",
            "visual_verification": verification.to_dict(),
            "syntax_checked": True,
        },
        raw_response=envelope,
        page_tex=candidate.candidate_tex,
    )
    return verifier_response_sha


def _persist_full_ocr_page(
    store: OcrRunStore,
    snapshot: object,
    candidate: PageCandidate,
) -> None:
    record = store.load_record(snapshot.run_id, candidate.page_id)
    image = b"full OCR page pixels"
    record = record.transition(OcrPageStatus.RENDERING, dpi=200)
    evidence_sha = store.persist_page_source_evidence(
        snapshot.run_id, record, {"kind": "private full OCR evidence"}
    )
    record = record.transition(
        OcrPageStatus.OCR_RUNNING,
        image_sha256=_sha(image),
        image_size_pixels=(1200, 1600),
        source_evidence_sha256=evidence_sha,
        dpi=200,
        model="vision-test",
        call_index=1,
        started_at="2026-08-26T00:00:00Z",
    )
    final_tex = "private full OCR terminal text"
    transport = {
        "page_id": candidate.page_id,
        "latex": final_tex,
        "figures": [],
        "unresolved_regions": [],
    }
    envelope = {
        "schema_version": "latexstruct-ocr-host-response-v1",
        "page_id": candidate.page_id,
        "source_page": candidate.source_page_number,
        "task_index": candidate.selected_index,
        "call_index": record.call_index,
        "gate_applied": True,
        "source_evidence_sha256": evidence_sha,
        "model_raw_latex": final_tex,
        "model_raw_response": transport,
        "transport_response": transport,
        "host_quality_flags": [],
        "formula_evidence": [],
        "batch_parent": None,
    }
    record = record.transition(OcrPageStatus.VALIDATING)
    record = record.transition(
        OcrPageStatus.SUCCESS,
        raw_response_sha256=_sha(_runtime_json(envelope)),
        raw_tex=final_tex,
        cleaned_tex=final_tex,
        ended_at="2026-08-26T00:00:01Z",
        host_quality_flags=(),
        unresolved_regions=(),
    )
    store.persist_record(snapshot.run_id, record, raw_response=envelope)
    PageEvidenceStore(
        store.root, snapshot.run_id, snapshot.source_sha256
    ).persist_page_bundle(
        candidate,
        verification={
            "page_id": candidate.page_id,
            "visual_mode": "FULL_OCR",
            "full_ocr_performed": True,
            "full_ocr_with_crops": False,
            "reading_order_checked": True,
            "text_coverage_checked": True,
            "math_region_coverage_checked": True,
            "syntax_checked": True,
            "unresolved_regions": [],
        },
        raw_response=envelope,
        page_tex=final_tex,
    )


def _complete_store(tmp_path: Path):
    store, snapshot, source = _setup_store(tmp_path)
    verifier_sha = _persist_visual_page(store, snapshot, _candidate(1))
    _persist_full_ocr_page(store, snapshot, _candidate(2))
    return store, snapshot, source, verifier_sha


def test_store_projection_is_canonical_hash_only_and_mode_safe(tmp_path):
    store, snapshot, _source, verifier_sha = _complete_store(tmp_path)

    data = build_ocr_page_evidence_bindings_from_store(store, RUN_ID)
    rows = parse_ocr_page_evidence_bindings(
        data,
        expected_run_id=RUN_ID,
        expected_source_sha256=snapshot.source_sha256,
        expected_selected_pages=(1, 2),
    )

    assert rows[0].terminal_mode is OcrPageTerminalMode.VISUAL
    assert rows[0].visual_verification_response_sha256 == verifier_sha
    assert rows[1].terminal_mode is OcrPageTerminalMode.FULL_OCR
    assert rows[1].visual_verification_response_sha256 is None
    assert b"private candidate" not in data
    assert b"private full OCR" not in data
    assert b"private source" not in data
    assert data.endswith(b"\n")


def test_projection_rejects_hash_tamper_noncanonical_and_plaintext_field(tmp_path):
    store, snapshot, _source, _verifier_sha = _complete_store(tmp_path)
    data = build_ocr_page_evidence_bindings_from_store(store, RUN_ID)
    value = json.loads(data)

    tampered = json.loads(data)
    tampered["pages"][0]["page_evidence_tex_sha256"] = "0" * 64
    with pytest.raises(OcrPageEvidenceBindingsError, match="page.tex"):
        parse_ocr_page_evidence_bindings(
            canonical_page_evidence_bindings_json_bytes(tampered),
            expected_run_id=RUN_ID,
            expected_source_sha256=snapshot.source_sha256,
            expected_selected_pages=(1, 2),
        )

    with pytest.raises(OcrPageEvidenceBindingsError, match="expected run/source"):
        parse_ocr_page_evidence_bindings(
            json.dumps(value, sort_keys=True).encode("utf-8"),
            expected_run_id=RUN_ID,
            expected_source_sha256=snapshot.source_sha256,
            expected_selected_pages=(1, 2),
        )

    leaked = json.loads(data)
    leaked["pages"][0]["candidate_tex"] = "private leaked TeX"
    with pytest.raises(OcrPageEvidenceBindingsError, match="keys mismatch"):
        parse_ocr_page_evidence_bindings(
            canonical_page_evidence_bindings_json_bytes(leaked),
            expected_run_id=RUN_ID,
            expected_source_sha256=snapshot.source_sha256,
            expected_selected_pages=(1, 2),
        )


def test_full_ocr_projection_rejects_visual_hash_semantics(tmp_path):
    store, snapshot, _source, _verifier_sha = _complete_store(tmp_path)
    value = json.loads(
        build_ocr_page_evidence_bindings_from_store(store, RUN_ID)
    )
    value["pages"][1]["visual_verification_response_sha256"] = "1" * 64

    with pytest.raises(
        OcrPageEvidenceBindingsError, match="must not claim a visual"
    ):
        parse_ocr_page_evidence_bindings(
            canonical_page_evidence_bindings_json_bytes(value),
            expected_run_id=RUN_ID,
            expected_source_sha256=snapshot.source_sha256,
            expected_selected_pages=(1, 2),
        )


def test_store_projection_fails_when_private_page_evidence_is_missing(tmp_path):
    store, snapshot, _source = _setup_store(tmp_path)
    _persist_visual_page(store, snapshot, _candidate(1))

    with pytest.raises((OcrPageEvidenceBindingsError, ValueError), match="terminal"):
        build_ocr_page_evidence_bindings_from_store(store, RUN_ID)


def test_store_projection_detects_private_raw_response_tamper(tmp_path):
    store, snapshot, _source, _verifier_sha = _complete_store(tmp_path)
    record = store.load_record(RUN_ID, "ocr-page-000001")
    response_path = (
        store.run_dir(RUN_ID)
        / "responses"
        / f"{record.page_id}-{record.raw_response_sha256}.json"
    )
    response_path.write_bytes(b'{"tampered":true}')

    with pytest.raises(Exception, match="SHA-256 mismatch"):
        build_ocr_page_evidence_bindings_from_store(store, RUN_ID)

# -*- coding: utf-8 -*-
"""Stable host page anchors and named-destination page maps."""

from __future__ import annotations

import hashlib
import json

import pymupdf
import pytest

from latexstruct.core.ocr_baseline import compile_ocr_baseline
from latexstruct.core.ocr_page_map import (
    OcrPageMapError,
    build_pdf_page_map,
    extract_page_anchors,
    inject_page_anchors,
    verify_page_map_json,
)
from latexstruct.core.ocr_runtime import OcrPreviewStatus


def _raw(*source_pages: int, line_ending: str = "\n") -> str:
    lines = [r"\documentclass{article}", r"\usepackage{hyperref}", r"\begin{document}"]
    for task_index, source_page in enumerate(source_pages, start=1):
        lines.extend([
            f"% Page {source_page}",
            "% LaTeXStruct-Page: "
            f"page_id=ocr-page-{task_index:06d} source_page={source_page}",
            f"Visible body for source page {source_page}.",
        ])
    lines.append(r"\end{document}")
    return line_ending.join(lines) + line_ending


def _pdf_with_destinations(
    page_count: int,
    destinations: dict[str, int | tuple[int, float]],
) -> bytes:
    document = pymupdf.open()
    try:
        for _ in range(page_count):
            document.new_page()
        values = []
        for name, destination in destinations.items():
            page_index, target_y = (
                destination if isinstance(destination, tuple) else (destination, 800.0)
            )
            page_reference = (
                f"{document.page_xref(page_index)} 0 R"
                if 0 <= page_index < page_count
                else "999999 0 R"
            )
            values.append(f"/{name} [{page_reference} /XYZ 0 {target_y} 0]")
        document.xref_set_key(document.pdf_catalog(), "Dests", f"<< {' '.join(values)} >>")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _compile_artifact(pdf: bytes, *, ok=True, code=0, log="real compiler log"):
    return {
        "engine": "xelatex.exe",
        "ok": ok,
        "exit_code": code,
        "passes_requested": 1,
        "passes_attempted": 1,
        "passes_completed": 1 if ok else 0,
        "pdf_bytes": pdf,
        "errors": [] if ok else ["compile failed"],
        "log": log,
    }


def test_injection_changes_only_syntax_candidate_and_preserves_raw_exactly():
    raw = _raw(4, 9, line_ending="\r\n")
    frozen_bytes = raw.encode("utf-8")

    injection = inject_page_anchors(raw, expected_selected_pages=(4, 9))

    assert raw.encode("utf-8") == frozen_bytes
    assert injection.raw_tex_sha256 == hashlib.sha256(frozen_bytes).hexdigest()
    assert injection.syntax_tex_sha256 == hashlib.sha256(
        injection.syntax_tex.encode("utf-8")
    ).hexdigest()
    assert [anchor.page_id for anchor in injection.anchors] == [
        "ocr-page-000001",
        "ocr-page-000002",
    ]
    assert [anchor.source_page for anchor in injection.anchors] == [4, 9]
    stripped = injection.syntax_tex
    for anchor in injection.anchors:
        assert f"{anchor.tex_marker}\r\n{anchor.hypertarget}\r\n" in stripped
        stripped = stripped.replace(anchor.hypertarget + "\r\n", "")
    assert stripped == raw


def test_legacy_input_remains_byte_identical_and_never_claims_anchors():
    raw = "\\documentclass{article}\n\\begin{document}legacy\\end{document}\n"
    injection = inject_page_anchors(raw, expected_selected_pages=(1, 2))

    assert injection.syntax_tex == raw
    assert injection.anchors == ()
    assert injection.raw_tex_sha256 == injection.syntax_tex_sha256


@pytest.mark.parametrize(
    ("raw", "selected", "message"),
    [
        (
            _raw(1).replace("ocr-page-000001", "ocr-page-000002"),
            (1,),
            "missing or out of task order",
        ),
        (
            _raw(1, 2).replace("ocr-page-000002", "ocr-page-000001"),
            (1, 2),
            "duplicate",
        ),
        (
            _raw(1, 2).replace("source_page=2", "source_page=1"),
            (1, 2),
            "duplicate",
        ),
        (
            _raw(1, 3),
            (1, 2),
            "outside selected_pages",
        ),
        (
            _raw(1).replace(
                "% LaTeXStruct-Page:", "% LaTeXStruct-Page: malformed",
            ),
            (1,),
            "malformed",
        ),
    ],
)
def test_missing_duplicate_out_of_range_and_malformed_markers_fail_closed(
    raw, selected, message,
):
    with pytest.raises(OcrPageMapError, match=message):
        inject_page_anchors(raw, expected_selected_pages=selected)


def test_raw_cannot_predeclare_a_reserved_hypertarget():
    raw = _raw(1).replace(
        "Visible body for source page 1.",
        r"\hypertarget{ocr-page-000001}{}Visible body for source page 1.",
    )
    with pytest.raises(OcrPageMapError, match="reserved"):
        extract_page_anchors(raw)


def test_real_pymupdf_named_destinations_generate_hash_bound_page_map():
    anchors = extract_page_anchors(_raw(4, 9), expected_selected_pages=(4, 9))
    pdf = _pdf_with_destinations(3, {
        "ocr-page-000001": 0,
        "ocr-page-000002": 2,
    })

    page_map = build_pdf_page_map(pdf, anchors)

    assert page_map.baseline_pdf_sha256 == hashlib.sha256(pdf).hexdigest()
    assert page_map.baseline_pdf_page_count == 3
    assert [entry.to_dict() for entry in page_map.entries] == [
        {
            "page_id": "ocr-page-000001",
            "source_page": 4,
            "task_index": 1,
            "tex_marker": (
                "% LaTeXStruct-Page: page_id=ocr-page-000001 source_page=4"
            ),
            "baseline_pdf_pages": [1, 2],
        },
        {
            "page_id": "ocr-page-000002",
            "source_page": 9,
            "task_index": 2,
            "tex_marker": (
                "% LaTeXStruct-Page: page_id=ocr-page-000002 source_page=9"
            ),
            "baseline_pdf_pages": [3],
        },
    ]
    payload = json.loads(page_map.to_json_bytes())
    assert payload["baseline_pdf_page_count"] == 3
    assert verify_page_map_json(page_map.to_json_bytes(), pdf, anchors) == page_map


def test_flowing_boundary_page_is_shared_when_next_anchor_begins_below_top():
    anchors = extract_page_anchors(_raw(1, 2))
    pdf = _pdf_with_destinations(2, {
        "ocr-page-000001": (0, 700.0),
        "ocr-page-000002": (1, 400.0),
    })

    page_map = build_pdf_page_map(pdf, anchors)

    assert page_map.entries[0].baseline_pdf_pages == (1, 2)
    assert page_map.entries[1].baseline_pdf_pages == (2,)


@pytest.mark.parametrize(
    ("destinations", "message"),
    [
        ({"ocr-page-000001": 0}, "missing"),
        (
            {
                "ocr-page-000001": 0,
                "ocr-page-000002": 1,
                "ocr-page-000003": 1,
            },
            "extra",
        ),
        (
            {"ocr-page-000001": 0, "ocr-page-000002": 99},
            "out of range",
        ),
        (
            {"ocr-page-000001": 1, "ocr-page-000002": 0},
            "out of source order",
        ),
    ],
)
def test_pdf_missing_extra_out_of_range_and_reversed_destinations_fail(
    destinations, message,
):
    anchors = extract_page_anchors(_raw(1, 2))
    pdf = _pdf_with_destinations(2, destinations)
    with pytest.raises(OcrPageMapError, match=message):
        build_pdf_page_map(pdf, anchors)


def test_page_map_json_tampering_fails_recomputation():
    anchors = extract_page_anchors(_raw(1))
    pdf = _pdf_with_destinations(1, {"ocr-page-000001": 0})
    page_map = build_pdf_page_map(pdf, anchors)
    payload = page_map.to_dict()
    payload["pages"][0]["baseline_pdf_pages"] = [99]
    tampered = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(OcrPageMapError, match="differs from the recomputed"):
        verify_page_map_json(tampered, pdf, anchors)


def test_baseline_compilation_uses_anchor_syntax_and_returns_strict_map(monkeypatch):
    raw = _raw(1, 2)
    frozen_hash = hashlib.sha256(raw.encode()).hexdigest()
    pdf = _pdf_with_destinations(2, {
        "ocr-page-000001": 0,
        "ocr-page-000002": 1,
    })
    seen = []

    def compile_once(candidate, **_kwargs):
        seen.append(candidate)
        return _compile_artifact(pdf)

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(raw, selected_pages=(1, 2))

    assert hashlib.sha256(raw.encode()).hexdigest() == frozen_hash
    assert len(seen) == 2
    assert all(r"\hypertarget{ocr-page-000001}{}" in candidate for candidate in seen)
    assert result.preview_status == OcrPreviewStatus.COMPILED
    assert len(result.page_anchors) == len(result.page_map_entries) == 2
    assert result.page_map_json
    assert json.loads(result.page_map_json)["pages"][1]["source_page"] == 2
    assert result.compile_invocations[0].input_tex_sha256 == hashlib.sha256(
        result.tex.encode()
    ).hexdigest()


def test_legacy_and_partial_baselines_do_not_fabricate_page_maps(monkeypatch):
    legacy = "\\documentclass{article}\n\\begin{document}legacy\\end{document}\n"
    invalid_but_magic_pdf = b"%PDF-1.7\npartial compiler output"
    monkeypatch.setattr(
        "latexstruct.core.ocr_baseline.compile_latex_artifact",
        lambda *_args, **_kwargs: _compile_artifact(
            invalid_but_magic_pdf,
            ok=False,
            code=1,
        ),
    )

    legacy_result = compile_ocr_baseline(legacy, selected_pages=(1,))
    marked_result = compile_ocr_baseline(_raw(1), selected_pages=(1,))

    assert legacy_result.preview_status == OcrPreviewStatus.PARTIAL_COMPILED
    assert legacy_result.page_anchors == ()
    assert legacy_result.page_map_entries == ()
    assert legacy_result.page_map_json == b""
    assert marked_result.preview_status == OcrPreviewStatus.PARTIAL_COMPILED
    assert len(marked_result.page_anchors) == 1
    assert marked_result.page_map_entries == ()
    assert marked_result.page_map_json == b""

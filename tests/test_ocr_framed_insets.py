# -*- coding: utf-8 -*-
"""Publisher text-frame fidelity gates for visual OCR."""

from pathlib import Path
import struct

import pytest

fitz = pytest.importorskip("fitz")

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402
from latexstruct.ocr import (  # noqa: E402
    OCR_PREAMBLE,
    OCR_SYSTEM_PROMPT,
    _OcrQualityGateError,
    _validate_framed_inset_integrity,
    pdf_page_framed_insets,
    transcribe_page_result,
)


PAGE_WIDTH = 439.37
PAGE_HEIGHT = 666.14
FRAME = (41.3, 54.2, 396.9, 520.0)


def _draw_frame(page, *, top=True, bottom=True):
    x0, y0, x1, y1 = FRAME
    if top:
        page.draw_line((x0, y0), (x1, y0), width=0.4)
    page.draw_line((x0, y0), (x0, y1), width=0.4)
    page.draw_line((x1, y0), (x1, y1), width=0.4)
    if bottom:
        page.draw_line((x0, y1), (x1, y1), width=0.4)


def _insert_title_and_body(page, title=None):
    if title:
        page.insert_text((53.5, 75.0), title, fontsize=10)
    body = (
        "This is substantive publisher inset text used to explain a proof "
        "technique. It remains searchable text rather than a raster figure. "
    ) * 4
    page.insert_textbox((53.5, 90.0, 388.0, 480.0), body, fontsize=9)


def _save_closed_or_negative(path: Path, kind: str):
    document = fitz.open()
    page = document.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
    if kind == "inset":
        _draw_frame(page)
        _insert_title_and_body(page, "PROOF TECHNIQUE: INDUCTION")
    elif kind == "table":
        _draw_frame(page)
        for y in (160.0, 260.0, 360.0):
            page.draw_line((FRAME[0], y), (FRAME[2], y), width=0.4)
        page.draw_line((210.0, FRAME[1]), (210.0, FRAME[3]), width=0.4)
        _insert_title_and_body(page, "TABLE 2.1")
    elif kind == "figure":
        _draw_frame(page)
        page.draw_circle((220.0, 260.0), 80.0, width=0.8)
        _insert_title_and_body(page, "FIGURE 2.1")
    else:
        _insert_title_and_body(page, "PROOF TECHNIQUE: INDUCTION")
    document.save(path)
    document.close()


def _save_cross_page(path: Path):
    document = fitz.open()
    first = document.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
    _draw_frame(first, top=True, bottom=False)
    _insert_title_and_body(first, "PROOF TECHNIQUE: EXTREMALITY")
    second = document.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
    _draw_frame(second, top=False, bottom=True)
    _insert_title_and_body(second)
    document.save(path)
    document.close()


def test_pdf_vector_frame_requires_substantive_heading_and_rejects_table_figure(tmp_path):
    inset = tmp_path / "inset.pdf"
    table = tmp_path / "table.pdf"
    figure = tmp_path / "figure.pdf"
    no_frame = tmp_path / "no-frame.pdf"
    for path, kind in (
        (inset, "inset"),
        (table, "table"),
        (figure, "figure"),
        (no_frame, "none"),
    ):
        _save_closed_or_negative(path, kind)

    records = pdf_page_framed_insets(str(inset), 1)
    assert len(records) == 1
    assert records[0]["position"] == "closed"
    assert records[0]["edge_presence"] == {
        "top": True, "left": True, "right": True, "bottom": True,
    }
    assert "PROOF TECHNIQUE" in records[0]["title"]
    assert records[0]["source"] == "pdf_vector_frame_plus_title_geometry"
    assert pdf_page_framed_insets(str(table), 1) == []
    assert pdf_page_framed_insets(str(figure), 1) == []
    assert pdf_page_framed_insets(str(no_frame), 1) == []


def test_cross_page_frame_segments_are_linked_and_each_page_is_semantically_closed(tmp_path):
    source = tmp_path / "cross-page.pdf"
    _save_cross_page(source)

    first = pdf_page_framed_insets(str(source), 1)
    second = pdf_page_framed_insets(str(source), 2)

    assert len(first) == len(second) == 1
    assert first[0]["position"] == "start"
    assert first[0]["title_visible"] is True
    assert first[0]["edge_presence"]["bottom"] is False
    assert second[0]["position"] == "end"
    assert second[0]["title_visible"] is False
    assert second[0]["edge_presence"]["top"] is False
    assert second[0]["title"] == first[0]["title"]
    assert second[0]["title_bbox_normalized"] == []


def _expected_region():
    return {
        "evidence_id": "p58-framed-inset-1",
        "title": "Proof Technique: Induction",
        "title_visible": True,
        "position": "closed",
        "bbox_normalized": [0.1, 0.08, 0.9, 0.7],
        "title_bbox_normalized": [0.12, 0.1, 0.45, 0.12],
        "edge_presence": {
            "top": True, "left": True, "right": True, "bottom": True,
        },
        "stroke_width_pt": 0.405,
        "title_font_evidence": "small_caps_font",
    }


def _structured_record():
    return {
        "index": 1,
        "title": "Proof Technique: Induction",
        "position": "closed",
        "environment": "lsframedinset",
        "bbox_normalized": [0.1, 0.08, 0.9, 0.7],
        "bbox_pixels": [100, 112, 900, 980],
    }


def test_structured_inset_gate_records_geometry_and_active_environment():
    latex = r"""\begin{lsframedinset}
\textsc{Proof Technique: Induction}
Substantive text.
\end{lsframedinset}"""
    flags = _validate_framed_inset_integrity(
        latex,
        58,
        [_structured_record()],
        (1000, 1400),
        [_expected_region()],
        structured=True,
    )
    assert flags == [{
        "type": "framed_inset_vector_evidence",
        "status": "source_geometry_and_active_match",
        "needs_review": False,
        "evidence_id": "p58-framed-inset-1",
        "title": "Proof Technique: Induction",
        "title_visible": True,
        "position": "closed",
        "environment": "lsframedinset",
        "frame_bbox_normalized": [0.1, 0.08, 0.9, 0.7],
        "model_bbox_normalized": [0.1, 0.08, 0.9, 0.7],
        "model_bbox_pixels": [100, 112, 900, 980],
        "title_bbox_normalized": [0.12, 0.1, 0.45, 0.12],
        "edge_presence": {
            "top": True, "left": True, "right": True, "bottom": True,
        },
        "stroke_width_pt": 0.405,
        "title_font_evidence": "small_caps_font",
        "verifier": "pdf_vector_geometry_plus_structured_codex_output",
    }]


def test_cross_page_continuation_keeps_chain_title_only_as_metadata():
    expected = _expected_region()
    expected.update({
        "position": "end",
        "title_visible": False,
        "title_bbox_normalized": [],
        "edge_presence": {
            "top": False, "left": True, "right": True, "bottom": True,
        },
    })
    record = _structured_record()
    record["position"] = "end"
    latex = r"""\begin{lsframedinset}
The proof continues here without repeating the previous page heading.
\end{lsframedinset}"""

    flags = _validate_framed_inset_integrity(
        latex,
        2,
        [record],
        (1000, 1400),
        [expected],
        structured=True,
    )

    assert flags[0]["title"] == "Proof Technique: Induction"
    assert flags[0]["title_visible"] is False
    invented = latex.replace(
        "The proof continues",
        r"\textsc{Proof Technique: Induction}" "\nThe proof continues",
    )
    with pytest.raises(_OcrQualityGateError, match="继承标题"):
        _validate_framed_inset_integrity(
            invented,
            2,
            [record],
            (1000, 1400),
            [expected],
            structured=True,
        )


@pytest.mark.parametrize(
    "latex,records,expected,message",
    [
        (
            "\\textsc{Proof Technique: Induction}\nSubstantive text.",
            [],
            [_expected_region()],
            "lsframedinset 数量",
        ),
        (
            "\\begin{lsframedinset}Invented\\end{lsframedinset}",
            [_structured_record()],
            [],
            "lsframedinset 数量",
        ),
        (
            "\\begin{lsframedinset}Wrong title\\end{lsframedinset}",
            [_structured_record()],
            [_expected_region()],
            "可见标题",
        ),
    ],
)
def test_inset_gate_fails_closed_for_missing_invented_or_wrong_title(
    latex,
    records,
    expected,
    message,
):
    with pytest.raises(_OcrQualityGateError, match=message) as raised:
        _validate_framed_inset_integrity(
            latex,
            58,
            records,
            (1000, 1400),
            expected,
            structured=True,
        )
    assert "framed_inset_expected" in raised.value.retry_state


def test_inset_gate_rejects_bbox_not_tied_to_source_vector_frame():
    bad = _structured_record()
    bad["bbox_normalized"] = [0.2, 0.2, 0.8, 0.6]
    bad["bbox_pixels"] = [200, 280, 800, 840]
    with pytest.raises(_OcrQualityGateError, match="PDF 矢量框"):
        _validate_framed_inset_integrity(
            "\\begin{lsframedinset}Proof Technique: Induction\\end{lsframedinset}",
            58,
            [bad],
            (1000, 1400),
            [_expected_region()],
            structured=True,
        )


def test_ocr_contract_and_preamble_support_semantic_text_insets():
    assert "publisher_framed_inset_evidence" in OCR_SYSTEM_PROMPT
    assert "\\begin{lsframedinset}" in OCR_SYSTEM_PROMPT
    assert "\\newtcolorbox{lsframedinset}" in OCR_PREAMBLE
    assert "breakable" in OCR_PREAMBLE


def test_scanner_treats_source_backed_inset_as_atomic_publisher_content():
    latex = r"""\begin{lsframedinset}
\textsc{Proof Technique: Induction}

Theorem 2.3 Every tournament has a directed Hamilton path.

Proof. Apply induction. \(\square\)
\end{lsframedinset}
"""

    assert scan(parse_latex(latex)).candidates == []


def test_page_transcription_retries_missing_frame_and_records_source_evidence():
    class FakeStructuredClient:
        backend = "codex_cli"

        def __init__(self):
            self.users = []
            self.responses = [
                {
                    "latex": r"\textsc{Proof Technique: Induction}\nSubstantive text.",
                    "figures": [],
                    "framed_insets": [],
                },
                {
                    "latex": (
                        r"\begin{lsframedinset}" "\n"
                        r"\textsc{Proof Technique: Induction}" "\n"
                        r"Substantive text." "\n"
                        r"\end{lsframedinset}"
                    ),
                    "figures": [],
                    "framed_insets": [_structured_record()],
                },
            ]

        def chat_vision_structured_bytes(self, _system, user, _image):
            self.users.append(user)
            return self.responses.pop(0)

    # The size reader only requires a valid PNG signature and IHDR dimensions.
    png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + struct.pack(
        ">II", 1000, 1400,
    )
    client = FakeStructuredClient()
    with pytest.raises(_OcrQualityGateError) as raised:
        transcribe_page_result(
            client,
            png,
            58,
            reference_framed_insets=[_expected_region()],
        )

    retry = raised.value
    result = transcribe_page_result(
        client,
        png,
        58,
        correction_feedback=retry.retry_instruction,
        quality_retry_state=retry.retry_state,
        reference_framed_insets=[_expected_region()],
    )

    assert "publisher_framed_inset_evidence" in client.users[0]
    assert "retry_correction" in client.users[1]
    assert result.figures == []
    assert result.quality_flags[0]["status"] == "corrected_after_controlled_retry"
    assert result.quality_flags[0]["evidence_id"] == "p58-framed-inset-1"

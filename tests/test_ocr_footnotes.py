# -*- coding: utf-8 -*-
"""Publisher-footnote source evidence and active-LaTeX gate tests."""

import json
import re
import struct
from pathlib import Path
from unittest.mock import patch

import pytest

from latexstruct.core.ai import LLMError
from latexstruct.ocr import (
    FOOTNOTE_VERIFY_SYSTEM_PROMPT,
    OcrConfig,
    OcrPageTranscription,
    _active_footnote_signatures,
    _footnote_digit_runs,
    _footnote_geometry_relation_backfill,
    _footnote_math_script_context,
    _page_request,
    _relation_occurrences,
    _validate_footnote_integrity,
    pdf_page_footnote_regions,
    pdf_page_relation_regions,
    pdf_page_text_hint,
    transcribe_page_result,
    transcribe_pdf,
)


def _digit_char(value, position, x0, *, size=7.97):
    return {
        "char": value,
        "bbox": [x0, 100.0, x0 + 4.2, 108.0],
        "size": size,
        "font": "CMR8",
        "line_position": position,
    }


def test_footnote_digit_runs_keep_two_digit_markers_and_reject_interior_subscripts():
    first = _digit_char("1", 0, 84.0)
    second = _digit_char("0", 1, 88.2)
    interior = _digit_char("4", 1, 80.4)
    lines = [
        {
            "characters": [first, second, {"char": "N", "bbox": [92.4, 100, 99, 110], "size": 9.96}],
        },
        {
            "characters": [
                {"char": "C", "bbox": [72, 100, 80.4, 112], "size": 11.96},
                interior,
                {"char": "-", "bbox": [84.6, 100, 88.5, 112], "size": 11.96},
            ],
        },
    ]

    runs = _footnote_digit_runs(lines)

    assert runs[0]["char"] == "10"
    assert runs[0]["first_nonspace_on_line"] is True
    assert runs[0]["line_position_end"] == 1
    assert runs[1]["char"] == "4"
    assert runs[1]["first_nonspace_on_line"] is False


def test_footnote_math_context_rejects_terminal_exponent_operator_digit():
    characters = [
        {"char": "C", "bbox": [316.1, 224.2, 324.5, 236.1], "size": 11.955, "font": "CMMI12"},
        {"char": "k", "bbox": [325.3, 224.2, 331.4, 236.1], "size": 11.955, "font": "CMMI12"},
        {"char": "ℓ", "bbox": [331.8, 222.9, 335.3, 230.9], "size": 7.97, "font": "CMMI8"},
        {"char": "−", "bbox": [335.3, 222.8, 341.9, 230.8], "size": 7.97, "font": "CMSY8"},
        {"char": "1", "bbox": [341.9, 222.9, 346.1, 230.9], "size": 7.97, "font": "CMR8"},
    ]
    candidate = {
        **characters[-1],
        "line_position": 4,
        "line_position_end": 4,
        "members": (characters[-1],),
    }

    assert _footnote_math_script_context(candidate, {"characters": characters}) is True


def test_footnote_math_context_keeps_raised_prose_reference():
    characters = [
        {"char": "s", "bbox": [261.0, 452.7, 265.7, 464.6], "size": 11.955, "font": "CMR12"},
        {"char": "1", "bbox": [265.6, 451.2, 269.9, 459.1], "size": 7.97, "font": "CMR8"},
        {"char": " ", "bbox": [269.9, 448.0, 273.8, 460.0], "size": 11.955, "font": "CMR12"},
        {"char": "t", "bbox": [273.8, 452.7, 278.3, 464.6], "size": 11.955, "font": "CMR12"},
    ]
    candidate = {
        **characters[1],
        "line_position": 1,
        "line_position_end": 1,
        "members": (characters[1],),
    }

    assert _footnote_math_script_context(candidate, {"characters": characters}) is False


def _sized_png(width=1000, height=1400):
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + struct.pack(
        ">II", width, height,
    ) + b"\x08\x02\x00\x00\x00"


def _p55_region():
    return {
        "evidence_id": "p55-footnote-1",
        "marker_hint": "1",
        "reference_count": 2,
        "reference_bboxes_normalized": [
            [0.717655, 0.194633, 0.726686, 0.205102],
            [0.545468, 0.468331, 0.554499, 0.4788],
        ],
        "definition_bbox_normalized": [0.105618, 0.864932, 0.740983, 0.895532],
        "bbox_normalized": [0.070194, 0.849921, 0.768294, 0.910544],
        "rule_present": True,
        "rule_bbox_normalized": [0.097506, 0.870013, 0.210884, 0.870013],
        "font_evidence": {
            "reference_pt": 6.974,
            "note_body_pt": 8.966,
            "reference_fonts": ["CMR7"],
            "note_fonts": ["CMR9", "CMMI9"],
        },
        "source": "pdf_text_font_geometry_plus_optional_vector_rule",
    }


def _p43_regions():
    return [
        {
            **_p55_region(),
            "evidence_id": "p43-footnote-1",
            "marker_hint": "1",
            "reference_count": 1,
            "reference_bboxes_normalized": [
                [0.437477, 0.668329, 0.446508, 0.678798],
            ],
            "definition_bbox_normalized": [0.105618, 0.793727, 0.904606, 0.842353],
            "bbox_normalized": [0.070194, 0.775653, 0.931918, 0.857364],
        },
        {
            **_p55_region(),
            "evidence_id": "p43-footnote-2",
            "marker_hint": "2",
            "reference_count": 1,
            "reference_bboxes_normalized": [
                [0.438009, 0.686271, 0.447041, 0.69674],
            ],
            "definition_bbox_normalized": [0.105618, 0.843082, 0.904547, 0.891713],
            "bbox_normalized": [0.070194, 0.775653, 0.931859, 0.906725],
        },
    ]


class FootnoteVisionClient:
    backend = "codex_cli"

    def __init__(self, page_outputs):
        self.page_outputs = list(page_outputs)
        self.page_users = []
        self.local_users = []
        self.last_usage = {}

    def chat_vision_structured_bytes(self, system, user, _image_bytes):
        self.last_usage = {"total_tokens": 7}
        if system == FOOTNOTE_VERIFY_SYSTEM_PROMPT:
            self.local_users.append(user)
            return {
                "latex": "FOOTNOTE_DEFINITION",
                "figures": [],
                "framed_insets": [],
            }
        self.page_users.append(user)
        return {
            "latex": self.page_outputs.pop(0),
            "figures": [],
            "framed_insets": [],
        }


def test_page_request_exposes_only_source_locations_not_footnote_answer():
    request = _page_request(
        55,
        (1000, 1400),
        "",
        reference_footnote_regions=[_p55_region()],
    )
    payload = json.loads(request[request.index("{"):])
    evidence = payload["publisher_footnote_evidence"][0]

    assert evidence["reference_bboxes_normalized"] == _p55_region()[
        "reference_bboxes_normalized"
    ]
    assert "marker_hint" not in evidence
    assert "marker" not in evidence
    assert "reference_count" not in evidence
    assert "body_text" not in json.dumps(payload, ensure_ascii=False)


def test_p55_manual_superscripts_retry_to_one_body_and_preserve_divider_rules():
    manual = "\n".join([
        r"First reference\textsuperscript{1} in the paragraph.",
        r"\begin{center}",
        r"\rule{0.12\linewidth}{0.4pt}\(\wr\wr\)\rule{0.12\linewidth}{0.4pt}",
        r"\end{center}",
        r"Second reference\textsuperscript{1} later in the page.",
        r"\rule{0.12\linewidth}{0.4pt}",
        r"\textsuperscript{1} Cauchy's inequality for real numbers.",
    ])
    semantic = "\n".join([
        r"First reference\footnote[1]{Cauchy's inequality for real numbers.}",
        r"\begin{center}",
        r"\rule{0.12\linewidth}{0.4pt}\(\wr\wr\)\rule{0.12\linewidth}{0.4pt}",
        r"\end{center}",
        r"Second reference\footnotemark[1] later in the page.",
    ])
    client = FootnoteVisionClient([manual, semantic])
    region = _p55_region()
    with patch(
        "latexstruct.ocr._crop_normalized_image_region",
        return_value=(b"\x89PNG\r\n\x1a\nfootnote-crop", [698, 221], "f" * 64),
    ):
        with pytest.raises(LLMError) as raised:
            transcribe_page_result(
                client,
                _sized_png(),
                55,
                reference_footnote_regions=[region],
            )
        retry = raised.value
        result = transcribe_page_result(
            client,
            _sized_png(),
            55,
            correction_feedback=retry.retry_instruction,
            quality_retry_state=retry.retry_state,
            reference_footnote_regions=[region],
        )

    assert "1" not in retry.retry_instruction
    assert "Cauchy" not in retry.retry_instruction
    assert len(client.local_users) == 1
    assert len(client.page_users) == 2
    assert r"\footnote[1]{" in result.tex
    assert result.tex.count(r"\footnotemark[1]") == 1
    assert result.tex.count(r"\rule") == 2
    assert r"\textsuperscript" not in result.tex
    flag = result.quality_flags[0]
    assert flag["status"] == "corrected_after_local_visual_retry"
    assert flag["source_reference_count"] == 2
    assert flag["active_reference_count"] == 2
    assert flag["active_body_count"] == 1
    assert flag["crop_sha256"] == "f" * 64


def test_p43_two_semantic_footnotes_pass_without_local_verifier():
    client = FootnoteVisionClient([
        r"One ref\footnote[1]{First note with {nested} braces.}" "\n"
        r"Two ref\footnote[2]{Second note.}",
    ])
    result = transcribe_page_result(
        client,
        _sized_png(),
        43,
        reference_footnote_regions=_p43_regions(),
    )

    assert client.local_users == []
    assert len(result.quality_flags) == 2
    assert all(
        flag["status"] == "source_geometry_and_active_match"
        for flag in result.quality_flags
    )
    assert [flag["marker"] for flag in result.quality_flags] == ["1", "2"]


@pytest.mark.parametrize(
    "latex, expected_references, expected_bodies, expected_legacy",
    [
        (r"A\footnote[1]{one} B\footnote[1]{duplicate}", 2, 2, 0),
        (r"A\footnote[1]{one}", 1, 1, 0),
        (r"A\textsuperscript{1} B\textsuperscript{1}", 0, 0, 2),
        (r"A\footnotemark[1] B\footnotemark[1]\footnotetext[1]{one}", 2, 1, 0),
        (r"% \footnote[1]{comment}\nA", 0, 0, 0),
    ],
)
def test_active_footnote_parser_rejects_duplicates_legacy_and_comments(
    latex, expected_references, expected_bodies, expected_legacy,
):
    signature = _active_footnote_signatures(latex).get("1", {})

    assert int(signature.get("active_reference_count") or 0) == expected_references
    assert int(signature.get("active_body_count") or 0) == expected_bodies
    assert int(signature.get("legacy_superscript_count") or 0) == expected_legacy


def test_real_bondy_p43_p55_probe_and_neighbor_negative_pages():
    source = (
        Path(__file__).resolve().parents[2]
        / "work"
        / "bondy-v1.2-e2e"
        / "source"
        / "bondy-graph-theory-2e.pdf"
    )
    if not source.exists():
        pytest.skip("formal Bondy source PDF is not present in this checkout")

    p43 = pdf_page_footnote_regions(str(source), 43)
    p55 = pdf_page_footnote_regions(str(source), 55)

    assert [(item["marker_hint"], item["reference_count"]) for item in p43] == [
        ("1", 1), ("2", 1),
    ]
    assert [(item["marker_hint"], item["reference_count"]) for item in p55] == [
        ("1", 2),
    ]
    assert p55[0]["reference_bboxes_normalized"] == [
        [0.717655, 0.194633, 0.726686, 0.205102],
        [0.545468, 0.468331, 0.554499, 0.4788],
    ]
    # The n^2 exponent on the same P55 baseline must not become a third reference.
    assert [0.758008, 0.468331, 0.767039, 0.4788] not in p55[0][
        "reference_bboxes_normalized"
    ]
    for page_no in (42, 44, 54, 56):
        assert pdf_page_footnote_regions(str(source), page_no) == []


def test_p55_chained_relations_do_not_need_footnote_backfill_or_duplicate():
    source = (
        Path(__file__).resolve().parents[2]
        / "work"
        / "bondy-v1.2-e2e"
        / "source"
        / "bondy-graph-theory-2e.pdf"
    )
    if not source.exists():
        pytest.skip("formal Bondy source PDF is not present in this checkout")

    reference = {}
    for item in _relation_occurrences(pdf_page_text_hint(str(source), 55), latex=False):
        reference.setdefault((item["left"], item["right"]), []).append(item)
    assert len(reference[("i", "1")]) == 3

    _footnote_geometry_relation_backfill(
        reference,
        pdf_page_relation_regions(str(source), 55),
        pdf_page_footnote_regions(str(source), 55),
    )

    assert [item["operator"] for item in reference[("i", "1")]] == ["=", "=", "="]


def test_footnote_relation_backfill_excludes_unverified_bottom_folio():
    reference = {}
    regions = [
        {
            "left": "i",
            "right": "1",
            "reference_operator": "=",
            "bbox_normalized": [0.20, 0.87, 0.30, 0.89],
        },
        {
            "left": "i",
            "right": "1",
            "reference_operator": "=",
            "bbox_normalized": [0.45, 0.965, 0.55, 0.985],
        },
    ]
    footnotes = [{"definition_bbox_normalized": [0.10, 0.86, 0.80, 0.90]}]

    _footnote_geometry_relation_backfill(reference, regions, footnotes)

    assert len(reference[("i", "1")]) == 1


def _formal_page(text, page_no):
    start_token = f"% Page {page_no}\n"
    end_token = f"% Page {page_no + 1}\n"
    start = text.index(start_token)
    end = text.index(end_token, start)
    return text[start:end]


def _semanticize_formal_footnote_page(page, markers):
    lines = page.splitlines()
    bodies = {}
    retained = []
    for line in lines:
        hit = next(
            (
                marker for marker in markers
                if line.startswith(rf"\noindent\textsuperscript{{{marker}}} ")
            ),
            None,
        )
        if hit is None:
            retained.append(line)
            continue
        body = line.split(rf"\textsuperscript{{{hit}}} ", 1)[1]
        bodies[hit] = body
    page = "\n".join(retained)
    for marker in markers:
        token = rf"\textsuperscript{{{marker}}}"
        page = page.replace(token, rf"\footnote[{marker}]{{{bodies[marker]}}}", 1)
        page = page.replace(token, rf"\footnotemark[{marker}]")
    return page


def test_formal_medium_p43_p55_semantic_result_passes_gate_and_faithfulbook_twice():
    from latexstruct.core.compilecheck import compile_latex
    from latexstruct.core.patch import Decision, apply_patches, validate_ops
    from latexstruct.core.template import FAITHFULBOOK, build_template_ops

    root = Path(__file__).resolve().parents[2] / "work" / "bondy-v1.2-e2e"
    preview = root / "full-run-v1.2.0" / "ocr-preview.tex"
    source_pdf = root / "source" / "bondy-graph-theory-2e.pdf"
    if not preview.exists() or not source_pdf.exists():
        pytest.skip("formal medium OCR artifacts are not present in this checkout")
    raw = preview.read_text(encoding="utf-8")
    p43 = _semanticize_formal_footnote_page(_formal_page(raw, 43), ("1", "2"))
    p55 = _semanticize_formal_footnote_page(_formal_page(raw, 55), ("1",))
    # Remove only the raw footnote rule on P55.  The separate centered
    # difficulty divider and both of its rule commands remain untouched.
    p55 = "\n".join(
        line for line in p55.splitlines()
        if not line.startswith(r"\noindent\rule{0.10\linewidth}{0.3pt}")
    )

    class NoCallClient:
        last_usage = {}

    flags43 = _validate_footnote_integrity(
        p43,
        43,
        NoCallClient(),
        b"",
        pdf_page_footnote_regions(str(source_pdf), 43),
    )
    flags55 = _validate_footnote_integrity(
        p55,
        55,
        NoCallClient(),
        b"",
        pdf_page_footnote_regions(str(source_pdf), 55),
    )
    assert len(flags43) == 2
    assert len(flags55) == 1
    assert p55.count(r"\footnote[1]") == 1
    assert p55.count(r"\footnotemark[1]") == 1
    assert p55.count(r"\rule") == 2
    assert r"\textsuperscript" not in p43 + p55

    # The P43 figure asset is outside this narrow compile probe; remove only
    # that already-tested figure block, not surrounding OCR text.
    p43_compile = re.sub(
        r"\\begin\{center\}\s*\\includegraphics.*?\\end\{center\}",
        "",
        p43,
        flags=re.S,
    )
    source = "\n".join([
        r"\documentclass[11pt]{book}",
        r"\usepackage{amsmath}",
        r"\usepackage{amssymb}",
        r"\begin{document}",
        r"\tableofcontents",
        r"\chapter{Semantic Footnote Probe}",
        p43_compile,
        p55,
        r"\end{document}",
    ])
    ops, _notes = build_template_ops(source, template=FAITHFULBOOK)
    planned, rejected = validate_ops(
        source.split("\n"),
        [(Decision(candidate_id="faithfulbook", action="none"), ops)],
    )
    assert rejected == []
    output_lines, applied, patch_rejected = apply_patches(source.split("\n"), planned)
    assert applied and patch_rejected == []
    compiled = compile_latex("\n".join(output_lines), timeout=240)
    if not compiled["available"]:
        pytest.skip("XeLaTeX is not available")
    # compile_latex deliberately executes two XeLaTeX passes when a contents
    # command is present, which is why this probe includes \tableofcontents.
    assert compiled["ok"], compiled["log"]
    assert compiled["pages"] >= 2


def test_direct_transcribe_pdf_forwards_footnote_source_evidence(tmp_path):
    pdf_path = tmp_path / "source.pdf"
    pdf_path.write_bytes(b"%PDF-1.7\nprobe")
    region = _p55_region()
    captured = {}

    def fake_transcribe(_client, _png, _page_no, **kwargs):
        captured.update(kwargs)
        return OcrPageTranscription(tex="% Page 1\nBody.")

    with (
        patch("latexstruct.ocr._pdf_page_count", return_value=1),
        patch(
            "latexstruct.ocr.render_pdf_pages",
            return_value=[(1, _sized_png())],
        ),
        patch("latexstruct.ocr.pdf_page_text_hint", return_value=""),
        patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
        patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
        patch("latexstruct.ocr.pdf_page_equation_tag_regions", return_value=[]),
        patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
        patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
        patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[region]),
        patch("latexstruct.ocr.transcribe_page_result", fake_transcribe),
        patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 1, "outline": []},
        ),
    ):
        result = transcribe_pdf(
            str(pdf_path),
            FootnoteVisionClient([]),
            OcrConfig(retries=0),
        )

    assert result.errors == []
    assert captured["reference_footnote_regions"] == [region]

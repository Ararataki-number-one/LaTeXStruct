# -*- coding: utf-8 -*-

from __future__ import annotations

import os
from pathlib import Path

import pytest

from latexstruct.core.ocrstyle import (
    build_document_lexicon,
    build_ocr_style_retry_feedback,
    classify_soft_line_break,
    extract_pdf_ocr_style_evidence,
    extract_rawdict_ocr_style_evidence,
    latex_visible_text,
    pdf_document_lexicon,
    validate_controlled_ocr_style_revision,
    validate_ocr_style_tex,
)


def _span(text, x0, x1, y, font="CMR10", *, size=10.0, flags=4):
    width = (x1 - x0) / max(1, len(text))
    chars = [
        {
            "c": character,
            "bbox": [x0 + index * width, y, x0 + (index + 1) * width, y + 10.0],
        }
        for index, character in enumerate(text)
    ]
    return {
        "font": font,
        "size": size,
        "flags": flags,
        "bbox": [x0, y, x1, y + 10.0],
        "chars": chars,
    }


def _line(spans, y):
    return {
        "dir": [1.0, 0.0],
        "bbox": [
            min(span["bbox"][0] for span in spans), y,
            max(span["bbox"][2] for span in spans), y + 10.0,
        ],
        "spans": spans,
    }


def _payload(*blocks):
    return {
        "width": 440.0,
        "height": 666.0,
        "blocks": [
            {"type": 0, "lines": list(lines)}
            for lines in blocks
        ],
    }


def _single_break_payload(left, right):
    return _payload([
        _line([_span(left, 50.0, 400.0, 100.0)], 100.0),
        _line([_span(right, 50.0, 260.0, 112.0)], 112.0),
    ])


def _style_evidence(payload, page=1):
    return extract_rawdict_ocr_style_evidence(payload, page, document_lexicon={})


def test_soft_break_join_keep_and_unknown_name_are_fail_closed():
    lexicon = build_document_lexicon(
        "representation representation representation "
        "vertex-transitive vertex-transitive edge-transitive edge-transitive"
    )
    assert classify_soft_line_break("rep", "resentation", lexicon)["decision"] == "join"
    assert classify_soft_line_break("vertex", "transitive", lexicon)["decision"] == "keep"
    assert classify_soft_line_break("Xqv", "rname", lexicon)["decision"] == "ambiguous"

    join_evidence = extract_rawdict_ocr_style_evidence(
        _single_break_payload("An exact representation needs a compact rep-", "resentation here."),
        17,
        document_lexicon=lexicon,
    )
    breaks = join_evidence["soft_line_breaks"]
    assert [(item["joined_text"], item["decision"]) for item in breaks] == [
        ("representation", "join"),
    ]
    bad = validate_ocr_style_tex(
        "An exact representation needs a compact rep-\nresentation here.", join_evidence,
    )
    assert bad["retry_required"] is True
    assert bad["issues"][0]["status"] == "soft_break_not_joined"
    assert build_ocr_style_retry_feedback(bad)["actions"] == [{
        "evidence_id": breaks[0]["evidence_id"],
        "action": "join_discretionary_line_break",
        "left_line_bbox_normalized": breaks[0]["left_line_bbox_normalized"],
        "right_line_bbox_normalized": breaks[0]["right_line_bbox_normalized"],
    }]
    assert validate_ocr_style_tex(
        "An exact representation needs a compact representation here.", join_evidence,
    )["ok"] is True

    keep_evidence = extract_rawdict_ocr_style_evidence(
        _single_break_payload("The graph is vertex-", "transitive."),
        31,
        document_lexicon=lexicon,
    )
    assert keep_evidence["soft_line_breaks"][0]["decision"] == "keep"
    assert validate_ocr_style_tex("The graph is vertex-transitive.", keep_evidence)["ok"]
    lost = validate_ocr_style_tex("The graph is vertextransitive.", keep_evidence)
    assert lost["retry_required"] is False
    assert lost["needs_review"] is True
    assert lost["issues"][0]["status"] == "lexical_hyphen_not_preserved"

    ambiguous = extract_rawdict_ocr_style_evidence(
        _single_break_payload("The author is Xqv-", "rname."),
        9,
        document_lexicon=lexicon,
    )
    assert ambiguous["soft_line_breaks"][0]["decision"] == "ambiguous"
    result = validate_ocr_style_tex("The author is Xqvrname.", ambiguous)
    assert result["retry_required"] is False
    assert result["needs_review"] is True

    cross_block = extract_rawdict_ocr_style_evidence(
        _payload(
            [_line([_span("The graph is edge-", 50.0, 400.0, 100.0)], 100.0)],
            [_line([_span("transitive.", 60.0, 260.0, 112.0)], 112.0)],
        ),
        46,
        document_lexicon=lexicon,
    )
    assert [item["hyphenated_text"] for item in cross_block["soft_line_breaks"]] == [
        "edge-transitive",
    ]


def test_headers_and_math_font_breaks_never_become_actionable_evidence():
    lexicon = build_document_lexicon("representation representation representation")
    header_only = _payload([_line([
        _span("1.1.16", 60, 105, 20, "CMBX10", flags=20),
        _span("Degree Sequence", 110, 220, 20, "CMCSC10"),
    ], 20)])
    header_evidence = extract_rawdict_ocr_style_evidence(
        header_only, 21, document_lexicon=lexicon,
    )
    assert header_evidence["style_runs"] == []
    assert header_evidence["soft_line_breaks"] == []

    math_break = _payload([_line([
        _span("rep-", 50, 400, 100, "CMMI10", flags=6),
    ], 100), _line([
        _span("resentation", 50, 260, 112, "CMMI10", flags=6),
    ], 112)])
    math_evidence = extract_rawdict_ocr_style_evidence(
        math_break, 17, document_lexicon=lexicon,
    )
    assert math_evidence["style_runs"] == []
    assert math_evidence["soft_line_breaks"] == []


def test_math_adjacent_italic_suffix_is_occurrence_exact_and_preserves_math():
    payload = _payload([_line([
        _span("A path is called a ", 50, 150, 100),
        _span("k", 150, 158, 100, "CMMI10", flags=6),
        _span("-path", 158, 192, 100, "CMTI10", flags=6),
        _span(" or ", 192, 218, 100),
        _span("k", 218, 226, 100, "CMMI10", flags=6),
        _span("-cycle", 226, 268, 100, "CMTI10", flags=6),
        _span(".", 268, 272, 100),
    ], 100)])
    evidence = _style_evidence(payload, 15)
    runs = [item for item in evidence["style_runs"] if item["actionable"]]
    assert [(item["source_text"], item["role"]) for item in runs] == [
        ("-path", "math_compound_suffix"),
        ("-cycle", "math_compound_suffix"),
    ]
    bad_tex = r"A path is called a \(k\)-path or \(k\)-cycle."
    bad = validate_ocr_style_tex(bad_tex, evidence)
    assert [item["status"] for item in bad["issues"]] == [
        "missing_style", "missing_style",
    ]

    corrected = r"A path is called a \(k\)\emph{-path} or \(k\)\emph{-cycle}."
    assert validate_ocr_style_tex(corrected, evidence)["ok"] is True
    assert validate_ocr_style_tex(corrected, evidence)["ok"] is True  # idempotent
    invariant = validate_controlled_ocr_style_revision(bad_tex, corrected, evidence)
    assert invariant["ok"] is True
    assert invariant["math_equal"] is True
    assert invariant["before_math_count"] == 2

    crosses_math = validate_ocr_style_tex(
        r"A path is called a \emph{\(k\)-path} or \(k\)\emph{-cycle}.", evidence,
    )
    assert crosses_math["retry_required"] is True
    assert crosses_math["issues"][0]["status"] == "style_crosses_math"

    changed_math = validate_controlled_ocr_style_revision(
        bad_tex,
        r"A path is called a \(q\)\emph{-path} or \(k\)\emph{-cycle}.",
        evidence,
    )
    assert changed_math["ok"] is False
    assert changed_math["math_equal"] is False
    arbitrary_style = validate_controlled_ocr_style_revision(
        bad_tex + " Ordinary.", corrected + r" \emph{Ordinary}.", evidence,
    )
    assert arbitrary_style["style_changes_allowed"] is False
    assert arbitrary_style["ok"] is False

    wrong_location = validate_ocr_style_tex(
        r"The prose has \emph{-path}; an unrelated \(k\) follows.", evidence,
    )
    assert wrong_location["retry_required"] is False
    assert wrong_location["needs_review"] is True
    assert wrong_location["issues"][0]["status"] in {
        "missing_alignment", "math_neighbor_mismatch",
    }


def test_controlled_revision_rejects_global_edits_controls_protected_text_and_math_order():
    lexicon = build_document_lexicon("representation representation representation")
    evidence = extract_rawdict_ocr_style_evidence(
        _single_break_payload("A compact rep-", "resentation follows."),
        17,
        document_lexicon=lexicon,
    )
    before = "A compact rep-\nresentation follows. Other rep-\nresentation."
    one_fix = "A compact representation follows. Other rep-\nresentation."
    global_fix = "A compact representation follows. Other representation."
    assert validate_controlled_ocr_style_revision(before, one_fix, evidence)["ok"]
    assert not validate_controlled_ocr_style_revision(before, global_fix, evidence)["ok"]

    empty_evidence = {"page": 1, "style_runs": [], "soft_line_breaks": []}
    assert not validate_controlled_ocr_style_revision(
        "Body", r"\input{Body}", empty_evidence,
    )["ok"]
    assert not validate_controlled_ocr_style_revision(
        r"\verb|safe|", r"\verb|EVIL|", empty_evidence,
    )["ok"]
    swapped = validate_controlled_ocr_style_revision(
        r"A \(x\) B \(y\)", r"A \(y\) B \(x\)", empty_evidence,
    )
    assert swapped["math_multiset_equal"] is True
    assert swapped["math_order_equal"] is False
    assert swapped["ok"] is False


def test_f_subgraph_suffix_targets_only_the_evidenced_occurrence():
    payload = _payload([_line([
        _span("Such a graph is an ", 50, 150, 100),
        _span("F", 150, 158, 100, "CMMI10", flags=6),
        _span("-subgraph", 158, 218, 100, "CMTI10", flags=6),
        _span(" of G.", 218, 255, 100),
    ], 100)])
    evidence = _style_evidence(payload, 50)
    run = next(item for item in evidence["style_runs"] if item["actionable"])
    assert run["source_text"] == "-subgraph"
    raw = r"Such a graph is an \(F\)-subgraph of G. Another subgraph remains roman."
    assert validate_ocr_style_tex(raw, evidence)["retry_required"]
    corrected = (
        r"Such a graph is an \(F\)\emph{-subgraph} of G. "
        r"Another subgraph remains roman."
    )
    assert validate_ocr_style_tex(corrected, evidence)["ok"]
    assert corrected.count(r"\emph") == 1


@pytest.mark.parametrize(
    ("number", "title"),
    [
        ("1.1.10", "-Partite Graph"),
        ("1.1.11", "Turán Graph"),
        ("1.1.16", "Degree Sequence"),
        ("1.1.17", "Complement of a Graph"),
        ("1.3.7", "Helly Property"),
        ("1.3.8", "Kneser Graph"),
    ],
)
def test_number_anchored_smallcaps_titles_are_actionable(number, title):
    prefix_spans = [_span(number, 60, 105, 100, "CMBX10", flags=20)]
    raw_prefix = rf"\textbf{{{number}}} "
    corrected_prefix = raw_prefix
    if title == "-Partite Graph":
        prefix_spans.append(_span("k", 110, 118, 100, "CMMI10", flags=6))
        raw_prefix += r"\(k\)"
        corrected_prefix += r"\(k\)"
    prefix_spans.append(_span(title, 118, 280, 100, "CMCSC10", flags=4))
    evidence = _style_evidence(_payload([_line(prefix_spans, 100)]), 21)
    actionable = [item for item in evidence["style_runs"] if item["actionable"]]
    assert len(actionable) == 1
    assert actionable[0]["role"] == "exercise_title"
    assert actionable[0]["source_text"] == title

    raw = raw_prefix + title
    assert validate_ocr_style_tex(raw, evidence)["retry_required"] is True
    corrected = corrected_prefix + rf"\textsc{{{title}}}"
    assert validate_ocr_style_tex(corrected, evidence)["ok"] is True
    if title == "-Partite Graph":
        assert r"\textsc{\(k\)" not in corrected


def test_smallcaps_credit_restores_only_source_case_pattern_and_keeps_initials():
    payload = _payload([_line([
        _span("(", 300, 305, 350),
        _span("L. Rédei", 305, 380, 350, "CMCSC10"),
        _span(")", 380, 385, 350),
    ], 350)])
    evidence = _style_evidence(payload, 64)
    run = next(item for item in evidence["style_runs"] if item["actionable"])
    assert run["role"] == "credit"
    assert run["source_text"] == "L. Rédei"

    raw = r"\hfill (L. RÉDEI)"
    assert validate_ocr_style_tex(raw, evidence)["retry_required"] is True
    wrong_case = r"\hfill (\textsc{L. RÉDEI})"
    result = validate_ocr_style_tex(wrong_case, evidence)
    assert result["issues"][0]["status"] == "case_pattern_mismatch"
    corrected = r"\hfill (\textsc{L. Rédei})"
    assert validate_ocr_style_tex(corrected, evidence)["ok"] is True
    assert validate_controlled_ocr_style_revision(raw, corrected, evidence)["ok"] is True
    tex_accented = r"\hfill (\textsc{L. R\'edei})"
    assert latex_visible_text(tex_accented).endswith("(L. Rédei)")
    assert validate_ocr_style_tex(tex_accented, evidence)["ok"] is True
    assert latex_visible_text(r"\textsc{P. Erd\H{o}s}") == "P. Erdős"
    unrelated_case_change = r"\hfill (\textsc{L. Rédei}) OTHER"
    assert validate_controlled_ocr_style_revision(
        raw + " other", unrelated_case_change, evidence,
    )["ok"] is False


def test_uppercase_without_smallcaps_ambiguous_duplicates_and_injection_do_not_retry():
    ordinary = _style_evidence(_payload([_line([
        _span("TSP", 60, 90, 100, "CMR10"),
    ], 100)]), 1)
    assert ordinary["style_runs"] == []

    acronym = _style_evidence(_payload([_line([
        _span("1.2.3", 60, 100, 100, "CMBX10", flags=20),
        _span("TSP", 105, 135, 100, "CMCSC10"),
    ], 100)]), 1)
    acronym_run = next(item for item in acronym["style_runs"] if item["source_text"] == "TSP")
    assert acronym_run["role"] == "exercise_title"
    assert acronym_run["actionable"] is False
    assert validate_ocr_style_tex("TSP", acronym)["ok"] is True

    title_payload = _payload([_line([
        _span("1.1.16", 60, 105, 100, "CMBX10", flags=20),
        _span("Degree Sequence", 110, 220, 100, "CMCSC10"),
    ], 100)])
    title_evidence = _style_evidence(title_payload, 21)
    record = next(item for item in title_evidence["style_runs"] if item["actionable"])
    record["context_before"] = ""
    record["context_after"] = ""
    duplicate = validate_ocr_style_tex(
        "Degree Sequence is followed by Degree Sequence.", title_evidence,
    )
    assert duplicate["retry_required"] is False
    assert duplicate["needs_review"] is True
    assert duplicate["issues"][0]["status"] == "ambiguous_alignment"

    injected = _style_evidence(_payload([_line([
        _span("1.2.3", 60, 100, 100, "CMBX10", flags=20),
        _span(r"\input{evil}", 105, 190, 100, "CMCSC10"),
    ], 100)]), 1)
    unsafe = next(item for item in injected["style_runs"] if item["style"] == "smallcaps")
    assert unsafe["safe_for_feedback"] is False
    assert unsafe["actionable"] is False
    validation = validate_ocr_style_tex(r"\input{evil}", injected)
    assert validation["retry_required"] is False
    assert build_ocr_style_retry_feedback(validation)["actions"] == []

    # Comments are inactive and cannot satisfy evidence alignment.
    assert "Degree Sequence" not in latex_visible_text("% Degree Sequence\nBody")
    assert latex_visible_text(
        r"Before\includegraphics[width=.5\linewidth]{evil.png}After",
    ) == "BeforeAfter"
    assert latex_visible_text(r"\section[Short]{Long Title}") == "Long Title"


def _bondy_pdf_path() -> Path:
    configured = os.environ.get("LATEXSTRUCT_BONDY_PDF", "").strip()
    if configured:
        return Path(configured)
    repo = Path(__file__).resolve().parents[1]
    return repo.parent / "work" / "bondy-v1.2-e2e" / "source" / "bondy-graph-theory-2e.pdf"


def test_real_bondy_occurrence_evidence_for_breaks_italics_smallcaps_and_credits():
    pytest.importorskip("fitz")
    source = _bondy_pdf_path()
    if not source.is_file():
        pytest.skip("local Bondy source PDF is not available")
    lexicon = pdf_document_lexicon(source)

    p17 = extract_pdf_ocr_style_evidence(source, 17, document_lexicon=lexicon)
    assert any(
        item["joined_text"].casefold() == "representation" and item["decision"] == "join"
        for item in p17["soft_line_breaks"]
    )

    p15 = extract_pdf_ocr_style_evidence(source, 15, document_lexicon=lexicon)
    p15_suffixes = {
        item["source_text"].casefold()
        for item in p15["style_runs"] if item["actionable"]
    }
    assert {"-path", "-cycle"} <= p15_suffixes

    p50 = extract_pdf_ocr_style_evidence(source, 50, document_lexicon=lexicon)
    assert any(
        item["source_text"].casefold() == "-subgraph" and item["actionable"]
        for item in p50["style_runs"]
    )

    p21 = extract_pdf_ocr_style_evidence(source, 21, document_lexicon=lexicon)
    p21_titles = {
        item["source_text"].casefold()
        for item in p21["style_runs"] if item["role"] == "exercise_title"
    }
    assert {"-partite graph", "turán graph", "degree sequence", "complement of a graph"} <= p21_titles

    p36 = extract_pdf_ocr_style_evidence(source, 36, document_lexicon=lexicon)
    p36_titles = {
        item["source_text"].casefold()
        for item in p36["style_runs"] if item["role"] == "exercise_title"
    }
    assert {"helly property", "kneser graph"} <= p36_titles

    p64 = extract_pdf_ocr_style_evidence(source, 64, document_lexicon=lexicon)
    credits = " ".join(
        item["source_text"] for item in p64["style_runs"] if item["role"] == "credit"
    ).casefold()
    assert "rédei" in credits
    assert "erdős" in credits

    p31 = extract_pdf_ocr_style_evidence(source, 31, document_lexicon=lexicon)
    p46 = extract_pdf_ocr_style_evidence(source, 46, document_lexicon=lexicon)
    kept = {
        item["hyphenated_text"].casefold()
        for page in (p31, p46)
        for item in page["soft_line_breaks"]
        if item["decision"] == "keep"
    }
    assert {"vertex-transitive", "edge-transitive"} <= kept

from __future__ import annotations

from latexstruct.core.ocrstruct import (
    build_ocr_structure_ops,
    check_ocr_structure,
    encode_ocr_metadata,
)
from latexstruct.core.patch import Decision, apply_patches, validate_ops


SHARP_TITLE = (
    "2. The number of independent sets in graphs with small "
    "nontrivial eigenvalues"
)


def _source(title: str, heading_lines: list[str]) -> str:
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": title, "page": 3}],
        "article",
        [3],
        False,
    )
    return "\n".join([
        r"\documentclass[11pt]{article}",
        r"\begin{document}",
        metadata,
        r"% Page 3",
        *heading_lines,
        "Opening paragraph must remain untouched.",
        r"\end{document}",
    ])


def _apply_structure_ops(text: str) -> tuple[str, list[dict]]:
    ops, notes = build_ocr_structure_ops(text)
    lines = text.split("\n")
    planned, rejected = validate_ops(
        lines,
        [(Decision(candidate_id="outline-span", action="none"), ops)],
    )
    assert rejected == []
    output, applied, rejected = apply_patches(lines, planned)
    assert applied and rejected == []
    return "\n".join(output), notes


def test_sharp_bounds_two_line_outline_heading_maps_to_complete_title():
    # Exact production failure: these were adjacent OCR lines 108--109 on page 3.
    source = _source(SHARP_TITLE, [
        "2. The number of independent sets in graphs with small",
        "nontrivial eigenvalues",
    ])

    repaired, notes = _apply_structure_ops(source)

    assert (
        r"\section{The number of independent sets in graphs with small "
        r"nontrivial eigenvalues}"
    ) in repaired
    assert "\nnontrivial eigenvalues\n" not in repaired
    assert "Opening paragraph must remain untouched." in repaired
    assert any(note["status"] == "mapped" for note in notes)
    assert check_ocr_structure(repaired)["ok"] is True


def test_three_line_outline_heading_group_maps_as_one_complete_title():
    title = "3. Sharp Bounds for Ramsey Numbers"
    source = _source(title, [
        r"\section*{3. Sharp",
        "Bounds for",
        "Ramsey Numbers}",
    ])

    repaired, _notes = _apply_structure_ops(source)

    assert r"\section{Sharp Bounds for Ramsey Numbers}" in repaired
    assert "\nBounds for\n" not in repaired
    assert "\nRamsey Numbers}\n" not in repaired
    assert "Opening paragraph must remain untouched." in repaired
    assert check_ocr_structure(repaired)["ok"] is True


def test_truncated_heading_without_confirmed_suffix_is_not_mapped():
    source = _source(SHARP_TITLE, [
        "2. The number of independent sets in graphs with small",
    ])

    operations, notes = build_ocr_structure_ops(source)

    assert not any(operation.kind == "replace_line" for operation in operations)
    assert any(note["status"] == "missing" for note in notes)
    gate = check_ocr_structure(source)
    assert gate["ok"] is False
    assert any("缺少 PDF 大纲标题" in issue["reason"] for issue in gate["issues"])


def test_truncated_command_with_isolated_suffix_fails_structure_gate():
    source = _source(SHARP_TITLE, [
        r"\section{The number of independent sets in graphs with small}",
        "This line separates the alleged heading continuation.",
        "nontrivial eigenvalues",
    ])

    gate = check_ocr_structure(source)

    assert gate["ok"] is False
    assert any("缺少 PDF 大纲标题" in issue["reason"] for issue in gate["issues"])


def test_outline_heading_span_never_crosses_a_pdf_page_boundary():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": SHARP_TITLE, "page": 3}],
        "article",
        [3, 4],
        False,
    )
    source = "\n".join([
        r"\documentclass[11pt]{article}",
        r"\begin{document}",
        metadata,
        r"% Page 3",
        "2. The number of independent sets in graphs with small",
        r"%=== PAGE BREAK === 2",
        r"% Page 4",
        "nontrivial eigenvalues",
        r"\end{document}",
    ])

    operations, notes = build_ocr_structure_ops(source)

    assert not any(operation.kind == "replace_line" for operation in operations)
    assert any(note["status"] == "missing" for note in notes)
    assert check_ocr_structure(source)["ok"] is False


def test_generic_same_page_outline_placeholder_is_explicitly_rejected():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Heading", "page": 1},
            {"level": 0, "title": "1. Introduction", "page": 1},
        ],
        "article",
        [1],
        False,
    )
    source = "\n".join([
        r"\documentclass[11pt]{article}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        "1. Introduction",
        "Opening paragraph.",
        r"\end{document}",
    ])

    repaired, notes = _apply_structure_ops(source)
    gate = check_ocr_structure(repaired)

    assert r"\section{Introduction}" in repaired
    assert any(note["status"] == "outline-noise-rejected" for note in notes)
    assert gate["ok"] is True
    assert gate["expected"] == gate["matched"] == 1
    assert gate["rejected_outline"] == [{
        "title": "Heading",
        "page": 1,
        "reason": "PDF 大纲中的通用占位书签，且同页已有可验证的真实标题",
    }]

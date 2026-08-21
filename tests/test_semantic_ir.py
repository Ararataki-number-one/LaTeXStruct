# -*- coding: utf-8 -*-
"""Focused regression tests for evidence-gated OCR semantic IR."""

from __future__ import annotations

import pytest

from latexstruct.core.ocrstruct import encode_ocr_metadata, parse_ocr_metadata
from latexstruct.core.patch import Decision, apply_patches, content_invariant, validate_ops
from latexstruct.core.pipeline import run_pipeline
from latexstruct.core.semantic_ir import build_ocr_semantic_ops
from latexstruct.core.template import build_template_ops

EVIDENCE_STATUS = "source_geometry_and_active_match"
EVIDENCE_VERIFIER = "pdf_geometry_plus_full_page_visual_and_active_latex"


def _evidence() -> list[dict]:
    pairs = [(2, "1", 0.20), (2, "2", 0.30), (3, "3", 0.20),
             (4, "4", 0.20), (4, "5", 0.30), (15, "6", 0.20)]
    return [{
        "page": page,
        "label": label,
        "evidence_id": f"p{page}-equation-tag-{index}",
        "bbox_normalized": [0.05, y, 0.10, y + 0.02],
        "source": "isolated_left_margin_pdf_word_geometry",
        "status": EVIDENCE_STATUS,
        "verifier": EVIDENCE_VERIFIER,
    } for index, (page, label, y) in enumerate(pairs, start=1)]


def _sharp_like_source(*, evidence: list[dict] | None | object = ...) -> str:
    outline = [
        {"level": 0, "title": "Introduction", "page": 1},
        {"level": 0, "title": "References", "page": 16},
    ]
    if evidence is ...:
        evidence = _evidence()
    if evidence is None:
        metadata = encode_ocr_metadata(outline, "article", range(1, 18), False)
    else:
        metadata = encode_ocr_metadata(
            outline,
            "article",
            range(1, 18),
            False,
            equation_tag_evidence=evidence,
        )
    references = []
    for number in range(1, 28):
        if number == 11:
            references.extend([
                r"\clearpage",
                r"%=== PAGE BREAK === 第 17 段",
                r"% Page 17",
                "",
            ])
        prefix = r"\noindent " if number >= 11 else ""
        spacer = r"\quad " if number >= 11 else " "
        references.extend([
            f"{prefix}[{number}]{spacer}Reference {number} payload.",
            "",
        ])
    return "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsmath}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\begin{center}",
        r"SHARP BOUNDS FOR A SAMPLE\\",
        r"A. AUTHOR",
        r"\end{center}",
        r"\section{Introduction}",
        "Opening text.",
        r"% Page 2",
        r"\[",
        r"\text{(1)}\qquad a_1=b_1.",
        r"\]",
        r"\[",
        r"\text{(2)}\qquad a_2=b_2.",
        r"\]",
        r"% Page 3",
        r"\begin{equation}",
        r"a_3=b_3.",
        r"\tag{3}",
        r"\end{equation}",
        r"% Page 4",
        r"\[",
        r"a_4=b_4.",
        r"\qquad (4)",
        r"\]",
        r"\[",
        r"a_5=b_5.",
        r"\qquad (5)",
        r"\]",
        r"% Page 15",
        r"\[",
        r"\text{(6)}\qquad a_6=b_6.",
        r"\]",
        r"% Page 16",
        r"\section*{References}",
        r"\addcontentsline{toc}{section}{References}",
        "",
        *references,
        r"\bigskip",
        r"\begin{minipage}{.45\linewidth}",
        "Author address.",
        r"\end{minipage}",
        r"\end{document}",
    ])


def _apply(source: str, operations):
    lines = source.split("\n")
    planned, rejected = validate_ops(
        lines,
        [(Decision(candidate_id="semantic-ir-test", action="none"), operations)],
    )
    assert rejected == []
    out, applied, rejected = apply_patches(lines, planned)
    assert rejected == []
    assert content_invariant(lines, out, applied) is True
    return "\n".join(out)


def test_metadata_v2_retains_only_full_source_equation_evidence():
    valid = _evidence()[0]
    invalid = {**valid, "evidence_id": "unverified", "verifier": "label_only"}
    encoded = encode_ocr_metadata(
        [], "article", [2], False, equation_tag_evidence=[valid, invalid],
    )

    parsed = parse_ocr_metadata(encoded)

    assert parsed["version"] == 2
    assert [(item["page"], item["label"]) for item in parsed["equation_tags"]] == [
        (2, "1")
    ]


def test_sharp_shape_normalizes_six_equations_and_27_references_reversibly():
    source = _sharp_like_source()

    operations, notes, before = build_ocr_semantic_ops(source)
    result = _apply(source, operations)
    second_ops, _second_notes, after = build_ocr_semantic_ops(result)

    equations = before["equations"]
    bibliography = before["bibliography"]
    assert before["ok"] is True
    assert equations["actual_pairs"] == [
        [2, "1"], [2, "2"], [3, "3"], [4, "4"], [4, "5"], [15, "6"],
    ]
    assert (equations["detected"], equations["literal"], equations["active"]) == (6, 5, 1)
    assert equations["rewritten"] == 5
    assert bibliography["detected"] == 27
    assert len(operations) == 48
    assert len(notes) == 7
    assert equations["tag_side"] == "left"
    assert equations["tag_side_option"] == "inserted_pass_options_leqno"
    assert result.startswith(
        "\\PassOptionsToPackage{leqno}{amsmath}\n\\documentclass{article}"
    )
    assert result.count(r"\tag{") == 6
    assert result.count(r"\bibitem{ref") == 27
    assert second_ops == []
    assert after["equations"]["status"] == "verified"
    assert after["bibliography"]["status"] == "already_structured"
    assert [item["payload_sha256"] for item in equations["inventory"]] == [
        item["payload_sha256"] for item in after["equations"]["inventory"]
    ]
    assert bibliography["payload_sha256"] == after["bibliography"]["payload_sha256"]
    assert before["frontmatter"]["inventory"][0]["kind"] == "title_page_center"


def test_left_equation_option_survives_later_elegantbook_class_rewrite():
    source = _sharp_like_source()
    semantic_ops, _notes, report = build_ocr_semantic_ops(source)
    normalized = _apply(source, semantic_ops)

    template_ops, template_notes = build_template_ops(
        normalized, template="elegantbook",
    )
    templated = _apply(normalized, template_ops)

    assert report["equations"]["tag_side"] == "left"
    assert not any(note.get("status") == "rejected" for note in template_notes)
    assert templated.startswith(r"\PassOptionsToPackage{leqno}{amsmath}")
    assert r"\documentclass[lang=en,11pt]{elegantbook}" in templated
    assert templated.index(r"\PassOptionsToPackage{leqno}{amsmath}") < templated.index(
        r"\documentclass[lang=en,11pt]{elegantbook}"
    )


def test_uniform_right_equation_evidence_keeps_default_ams_tag_side():
    evidence = _evidence()
    for item in evidence:
        _x0, y0, _x1, y1 = item["bbox_normalized"]
        item["bbox_normalized"] = [0.90, y0, 0.96, y1]
    source = _sharp_like_source(evidence=evidence)

    operations, _notes, report = build_ocr_semantic_ops(source)
    result = _apply(source, operations)

    assert report["ok"] is True
    assert report["equations"]["tag_side"] == "right"
    assert report["equations"]["tag_side_option"] == "none"
    assert r"\PassOptionsToPackage{leqno}{amsmath}" not in result
    assert result.count(r"\tag{") == 6


@pytest.mark.parametrize("side_case", ["mixed", "center"])
def test_ambiguous_equation_tag_side_rejects_the_whole_equation_class(side_case):
    evidence = _evidence()
    for index, item in enumerate(evidence):
        _x0, y0, _x1, y1 = item["bbox_normalized"]
        if side_case == "center":
            item["bbox_normalized"] = [0.45, y0, 0.52, y1]
        elif index % 2:
            item["bbox_normalized"] = [0.90, y0, 0.96, y1]
    source = _sharp_like_source(evidence=evidence)

    operations, _notes, report = build_ocr_semantic_ops(source)

    equations = report["equations"]
    assert report["ok"] is False
    assert equations["status"] == "rejected"
    assert equations["tag_side"] == ("unknown" if side_case == "center" else "mixed")
    assert all(operation.new != r"\PassOptionsToPackage{leqno}{amsmath}"
               for operation in operations)
    reference_line = source.splitlines().index(r"\section*{References}") + 1
    assert all(operation.line >= reference_line for operation in operations)


def test_legacy_metadata_inventories_literal_equations_but_does_not_rewrite_them():
    source = _sharp_like_source(evidence=None)

    operations, _notes, report = build_ocr_semantic_ops(source)
    result = _apply(source, operations)

    assert report["equations"]["status"] == "inventory_only"
    assert report["equations"]["detected"] == 6
    assert len(operations) == 29
    assert r"\text{(1)}\qquad" in result
    assert result.count(r"\tag{") == 1
    assert result.count(r"\bibitem{ref") == 27


def test_equation_inventory_mismatch_closes_the_whole_equation_edit_class():
    source = _sharp_like_source(evidence=_evidence()[:-1])

    operations, _notes, report = build_ocr_semantic_ops(source)

    assert report["ok"] is False
    assert report["equations"]["status"] == "rejected"
    assert report["equations"]["rewritten"] == 0
    # Bibliography remains an independently proven class; no equation line is
    # touched, and the pipeline-level gate will roll back all output.
    assert len(operations) == 29
    assert all(operation.line >= source.splitlines().index(r"\section*{References}") + 1
               for operation in operations)


@pytest.mark.parametrize(
    "entries,tail",
    [
        (["[1] First.", "", "[3] Third."], []),
        (["[1] First.", "", "[1] Duplicate."], []),
        (["[1] First."], ["", "Unclassified author note."]),
    ],
)
def test_bibliography_gap_duplicate_or_uncertain_boundary_fails_closed(entries, tail):
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "References", "page": 1}],
        "article", [1], False,
    )
    source = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\section*{References}",
        "",
        *entries,
        *tail,
        r"\end{document}",
    ])

    operations, _notes, report = build_ocr_semantic_ops(source)

    assert operations == []
    assert report["bibliography"]["status"] == "rejected"
    assert report["bibliography"]["ok"] is False


def _existing_bibliography_source(items: list[str]) -> str:
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "References", "page": 1}],
        "article", [1], False,
    )
    return "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\begin{thebibliography}{99}",
        *items,
        r"\end{thebibliography}",
        r"\end{document}",
    ])


@pytest.mark.parametrize(
    "items,active_count",
    [
        ([], 0),
        ([r"\bibitem{ref1} One.", r"\bibitem{ref1} Duplicate."], 2),
        ([r"\bibitem{ref1} One.", r"\bibitem{ref3} Gap."], 2),
        ([r"\bibitem{ref1} One.", r"\bibitem{source2} Extra key."], 2),
        ([r"\bibitem{ref1} One.", r"\bibitem ref2 Malformed."], 2),
        ([r"\bibitem{ref1} One.", r"\bibitem{ref2} Two.",
          r"\bibitem{ref99} Extra."], 3),
    ],
)
def test_existing_bibliography_requires_exact_active_ref_inventory(items, active_count):
    source = _existing_bibliography_source(items)

    operations, _notes, report = build_ocr_semantic_ops(source)

    bibliography = report["bibliography"]
    assert operations == []
    assert bibliography["status"] == "rejected"
    assert bibliography["ok"] is False
    assert bibliography["detected"] == active_count
    assert bibliography["active_bibitem_count"] == active_count


@pytest.mark.parametrize("display", ["2", "Author2020", "01"])
def test_existing_bibliography_rejects_noncanonical_optional_display(display):
    source = _existing_bibliography_source([
        rf"\bibitem[{display}]{{ref1}} First entry.",
        r"\bibitem{ref2} Second entry.",
    ])

    operations, _notes, report = build_ocr_semantic_ops(source)

    bibliography = report["bibliography"]
    assert operations == []
    assert bibliography["status"] == "rejected"
    assert bibliography["ok"] is False
    assert bibliography["detected"] == 2
    assert any("可选显示号" in issue["reason"] for issue in bibliography["issues"])


def test_existing_bibliography_ignores_commented_commands_and_hashes_full_body():
    source = _existing_bibliography_source([
        r"% \bibitem{not-active} This is only a comment.",
        r"\bibitem{ref1} First line.",
        "Continuation line whose content must be hashed.",
        "",
        r"\bibitem[2]{ref2}",
        "Second entry body on its following line.",
    ])

    operations, _notes, first = build_ocr_semantic_ops(source)
    changed = source.replace("whose content", "whose changed content")
    _changed_ops, _changed_notes, second = build_ocr_semantic_ops(changed)

    first_bibliography = first["bibliography"]
    second_bibliography = second["bibliography"]
    assert operations == []
    assert first_bibliography["ok"] is True
    assert first_bibliography["detected"] == 2
    assert len(first_bibliography["inventory"]) == 2
    assert first_bibliography["inventory"][0]["end_line"] > (
        first_bibliography["inventory"][0]["start_line"]
    )
    assert first_bibliography["inventory"][0]["payload_sha256"] != (
        second_bibliography["inventory"][0]["payload_sha256"]
    )
    assert first_bibliography["inventory"][1]["payload_sha256"] == (
        second_bibliography["inventory"][1]["payload_sha256"]
    )


def test_existing_bibliography_counts_commands_by_tex_backslash_parity():
    source = _existing_bibliography_source([
        r"\bibitem{ref1} First entry.",
        r"\\bibitem{not-a-command} Escaped command text.",
        r"\\\bibitem{ref2} Second active entry after a line-break command.",
    ])

    operations, _notes, report = build_ocr_semantic_ops(source)

    bibliography = report["bibliography"]
    assert operations == []
    assert bibliography["ok"] is True
    assert bibliography["detected"] == 2
    assert [item["number"] for item in bibliography["inventory"]] == [1, 2]


def test_pipeline_runs_semantic_stage_after_outline_and_keeps_it_reversible():
    source = _sharp_like_source()

    result = run_pipeline(source, mode="rule")

    assert result.ok is True
    assert result.verification["content_invariant"] is True
    assert result.verification["ocr_structure"]["ok"] is True
    assert result.verification["ocr_semantic_ir"]["ok"] is True
    assert result.verification["ocr_semantic_ir"]["equations"]["detected"] == 6
    assert result.verification["ocr_semantic_ir"]["bibliography"]["detected"] == 27
    assert result.result.count(r"\tag{") == 6
    assert result.result.count(r"\bibitem{ref") == 27

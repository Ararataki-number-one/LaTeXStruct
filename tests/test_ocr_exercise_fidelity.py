# -*- coding: utf-8 -*-
"""Evidence-driven exercise typography regressions from Bondy pp. 21/36/37/45."""

from __future__ import annotations

import re

from latexstruct.core.ocrstruct import (
    _add_pending_op_fail_safe,
    build_ocr_structure_ops,
    check_ocr_structure,
    encode_ocr_metadata,
)
from latexstruct.core.patch import (
    Decision,
    PendingOp,
    apply_patches,
    content_invariant,
)


def _metadata(*, outline=None, pages=(21, 36, 37, 45)) -> str:
    return encode_ocr_metadata(outline or [], "book", pages, False)


def _apply(source: str) -> tuple[str, list[dict], list]:
    operations, notes = build_ocr_structure_ops(source)
    if not operations:
        return source, notes, []
    decision = Decision(candidate_id="bondy-exercise-fidelity", action="none")
    out, applied, rejected = apply_patches(
        source.split("\n"), [(decision, operations)],
    )
    assert rejected == []
    assert content_invariant(source.split("\n"), out, applied) is True
    return "\n".join(out), notes, applied


def test_bondy_exercise_numbers_require_a_heading_star_or_bold_peer() -> None:
    source = "\n".join([
        _metadata(),
        r"% Page 21",
        r"\(\star\)1.1.10 \(k\)-Partite Graph",
        r"1.1.12",
        r"1.1.16 Degree Sequence",
        r"% Page 36",
        r"\textbf{1.3.9} Let \(G\) be a simple graph.",
        r"1.3.10",
        r"% Page 37",
        r"1.3.11",
        r"1.3.12 \textsc{Sperner's Lemma}",
        r"1.3.13 \textsc{Finite Projective Plane}",
        r"% Page 45",
        "Exercises",
        r"1.5.1 How many orientations are there?",
        r"\(\star\)1.5.2 Let \(D\) be a digraph.",
        r"1.5.3 Two digraphs are isomorphic.",
        # A lone three-part number has no exercise evidence and must stay plain.
        r"2.4.1 Genuine nested heading",
    ])

    result, notes, _applied = _apply(source)

    assert r"\(\star\)\textbf{1.1.10} \(k\)-Partite Graph" in result
    assert r"\textbf{1.1.12}" in result
    assert r"\textbf{1.1.16} Degree Sequence" in result
    assert r"\textbf{1.3.9} Let \(G\) be a simple graph." in result
    for number in ("1.3.10", "1.3.11", "1.3.12", "1.3.13"):
        assert rf"\textbf{{{number}}}" in result
    assert r"\textbf{Exercises}" in result
    for number in ("1.5.1", "1.5.2", "1.5.3"):
        assert rf"\textbf{{{number}}}" in result
    assert r"2.4.1 Genuine nested heading" in result
    assert r"\textbf{2.4.1}" not in result
    assert any(item["status"] == "normalized-exercise-heading" for item in notes)
    assert sum(
        item["status"] == "normalized-exercise-number" for item in notes
    ) == 10

    second_ops, second_notes = build_ocr_structure_ops(result)
    assert second_ops == []
    assert second_notes == []


def test_bondy_divider_repairs_only_the_exact_rule_anchored_corruption() -> None:
    broken = (
        r"\rule{0.14\linewidth}{0.4pt}\!"
        r"\mathrel{))}\!"
        r"\rule{0.14\linewidth}{0.4pt}"
    )
    source = "\n".join([
        _metadata(),
        r"\[",
        broken,
        r"\]",
        # Without two rule anchors the same token could be user mathematics.
        r"\[ A \mathrel{))} B \]",
    ])

    result, notes, _applied = _apply(source)

    assert (
        r"\rule{0.14\linewidth}{0.4pt}\!"
        r"\mathrel{\wr\wr}\!"
        r"\rule{0.14\linewidth}{0.4pt}"
    ) in result
    assert r"\[ A \mathrel{))} B \]" in result
    assert sum(
        item["status"] == "repaired-exercise-divider" for item in notes
    ) == 1


def test_missing_exercise_divider_is_never_invented_without_ocr_evidence() -> None:
    source = "\n".join([
        _metadata(),
        r"\noindent Exercise",
        "1.2.1 First exercise.",
        "1.2.2 Second exercise.",
        "1.2.3 Harder exercise, but no divider survived OCR.",
    ])

    result, _notes, _applied = _apply(source)

    assert r"\noindent \textbf{Exercise}" in result
    assert r"\textbf{1.2.3}" in result
    assert r"\rule" not in result
    assert r"\wr" not in result
    assert "LaTeXStruct-Exercise-Divider" not in result


def test_structure_gate_reports_unapplied_exercise_fidelity_repairs() -> None:
    metadata = _metadata(
        outline=[{"level": 0, "title": "1 Graphs", "page": 21}],
        pages=(21,),
    )
    source = "\n".join([
        r"\documentclass{book}",
        r"\begin{document}",
        metadata,
        r"% Page 21",
        r"\chapter{Graphs}",
        "Exercises",
        "1.5.1 First exercise.",
        "1.5.2 Second exercise.",
        r"\[",
        (
            r"\rule{0.14\linewidth}{0.4pt}\!"
            r"\mathrel{))}\!"
            r"\rule{0.14\linewidth}{0.4pt}"
        ),
        r"\]",
        r"\end{document}",
    ])

    before = check_ocr_structure(source)
    assert before["ok"] is False
    reasons = [item["reason"] for item in before["issues"]]
    assert "练习标题仍是普通字重，未保留源书层级" in reasons
    assert "有证据确认的练习编号仍未加粗" in reasons
    assert "练习难度分隔饰符仍含 OCR 错字 ))" in reasons

    repaired, _notes, _applied = _apply(source)
    after = check_ocr_structure(repaired)
    assert after["ok"] is True, after["issues"]


def test_true_exercise_headings_survive_running_header_cleanup_on_47_pages() -> None:
    """A repeated continuation header must not consume real block headings/markers."""
    metadata = _metadata(
        outline=[{"level": 0, "title": "1 Graphs", "page": 12}],
        pages=tuple(range(3, 50)),
    )
    bodies = {page: [f"Ordinary body on source page {page}."] for page in range(3, 50)}
    bodies[12] = ["1 Graphs", "Chapter opening."]
    bodies[20] = [r"\textbf{Exercises}", "1.1.1 First exercise."]
    # These are continuation-page furniture: the following exercise stem is
    # the same as the last preceding one, and the header repeats on two pages.
    bodies[21] = ["Exercises", "1.1.2 Continued exercise."]
    bodies[22] = [r"\noindent Exercises", "1.1.3 Continued exercise."]
    # A non-exercise repeated running title must still be removed.
    bodies[30] = ["Graph Theory", "Ordinary continuation text."]
    bodies[31] = [r"\noindent Graph Theory", "More continuation text."]
    bodies[35] = [r"\textbf{Exercises}", "1.3.1 First exercise."]
    bodies[42] = [r"\textbf{Exercises}", "1.4.1 First exercise."]
    bodies[44] = [r"\textbf{Exercises}", "1.5.1 First exercise."]
    # This is the exact formerly conflicting case: a plain true heading at the
    # top of physical page 48 must become bold without replacing its marker.
    bodies[48] = ["Exercises", "1.6.1 First exercise."]

    lines = [r"\documentclass{book}", r"\begin{document}", metadata]
    for index, page in enumerate(range(3, 50)):
        if index:
            lines.extend([r"\clearpage", f"%=== PAGE BREAK === {index + 1}"])
        lines.append(f"% Page {page}")
        lines.extend(bodies[page])
    lines.append(r"\end{document}")
    source = "\n".join(lines)

    operations, _planning_notes = build_ocr_structure_ops(source)
    by_line = {}
    for operation in operations:
        peers = by_line.setdefault(operation.line, [])
        assert not any(
            operation.kind == "delete_line" or peer.kind == "delete_line"
            for peer in peers
        ), (operation.line, peers, operation)
        assert not any(
            peer.kind != "insert_line" and operation.kind != "insert_line"
            for peer in peers
        ), (operation.line, peers, operation)
        peers.append(operation)

    result, notes, _applied = _apply(source)

    markers = [
        int(match.group(1))
        for match in re.finditer(r"(?m)^% Page (\d+)\s*$", result)
    ]
    assert markers == list(range(3, 50))
    assert result.count(r"\textbf{Exercises}") == 5
    assert "% Page 48\n\\textbf{Exercises}\n\\textbf{1.6.1}" in result
    assert not re.search(r"(?m)^\s*(?:\\noindent\s*)?Exercises\s*$", result)
    assert not re.search(r"(?mi)^\s*(?:\\noindent\s*)?Graph Theory\s*$", result)
    assert sum(item.get("status") == "removed-header" for item in notes) >= 4
    assert not any(item.get("status") == "conflict-preserved" for item in notes)
    assert check_ocr_structure(result)["ok"] is True


def test_destructive_op_conflict_fails_closed_but_legacy_precedence_remains() -> None:
    operations = {}
    blocked_lines = set()
    notes = []
    _add_pending_op_fail_safe(
        operations,
        blocked_lines,
        PendingOp(
            "replace_line", 48, old="Exercises", new=r"\textbf{Exercises}",
        ),
        notes,
    )
    _add_pending_op_fail_safe(
        operations,
        blocked_lines,
        PendingOp("delete_line", 48, old="Exercises"),
        notes,
    )
    assert operations == {}
    assert blocked_lines == {48}
    assert notes[-1]["status"] == "conflict-preserved"

    operations = {}
    blocked_lines = set()
    notes = []
    _add_pending_op_fail_safe(
        operations,
        blocked_lines,
        PendingOp("replace_line", 10, old="Contents", new=r"\chapter*{Contents}"),
        notes,
    )
    _add_pending_op_fail_safe(
        operations,
        blocked_lines,
        PendingOp("replace_line", 10, old="Contents", new=r"\tableofcontents"),
        notes,
    )
    assert list(operations.values()) == [
        PendingOp("replace_line", 10, old="Contents", new=r"\tableofcontents")
    ]

    _add_pending_op_fail_safe(
        operations,
        blocked_lines,
        PendingOp("insert_line", 20, new="% LaTeXStruct-Printed-Page: 1"),
        notes,
    )
    _add_pending_op_fail_safe(
        operations,
        blocked_lines,
        PendingOp("delete_line", 20, old="% Page 12"),
        notes,
    )
    assert {item.kind for item in operations.values() if item.line == 20} == {
        "insert_line", "delete_line",
    }

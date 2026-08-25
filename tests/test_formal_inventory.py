# -*- coding: utf-8 -*-
"""Full-document formal inventory and scanner reconciliation tests."""

from __future__ import annotations

from latexstruct.core.formal_inventory import inventory_document
from latexstruct.core.parser import parse_latex
from latexstruct.core.pipeline import run_pipeline
from latexstruct.core.scanner import scan


def test_inventory_api_is_stable_and_source_derived():
    source = (
        "Context remains in the same paragraph.\n"
        r"\textbf{Theorem 2.1.} Statement."
        "\n\n"
        r"\begin{proof}"
        "\nArgument.\n"
        r"\end{proof}"
    )
    first = inventory_document(parse_latex(source))
    second = inventory_document(parse_latex(source))

    assert first.schema == "latexstruct-formal-inventory-v1"
    assert first == second
    assert first.as_dict() == second.as_dict()
    assert len(first.anchors) == 1
    assert len(first.environments) == 1
    assert len(first.findings) == 1
    anchor = first.anchors[0]
    finding = first.findings[0]
    assert anchor.start_line == anchor.end_line == 2
    assert anchor.original_env == ""
    assert anchor.suggested_env == "theorem"
    assert anchor.number == "2.1"
    assert len(anchor.source_sha256) == 64
    assert finding.kind == "missing"
    assert finding.anchor_id == anchor.id
    assert finding.source_sha256 == anchor.source_sha256


def test_inventory_detects_only_bounded_wrapped_named_proof_titles():
    source = "\n".join([
        r"\textbf{Proof of \textcolor{cyan}{Theorem 2.1}.} Body.",
        r"\textit{Proof of the upper bound in Theorem 1.2.} More.",
        r"Proof of the upper bound for a heuristic. Ordinary discussion.",
        r"\href{https://example.invalid}{Proof of Theorem 9.9.} Not trusted.",
    ])

    inventory = inventory_document(parse_latex(source))
    proofs = [item for item in inventory.anchors if item.suggested_env == "proof"]

    assert len(proofs) == 2
    assert [item.start_line for item in proofs] == [1, 2]
    assert all(item.raw_text in source for item in proofs)


def test_scanner_reconciles_sharp_bounds_titles_beyond_paragraph_head():
    source = (
        "Lead-in for the first result.\n"
        "Theorem 2.1. First statement.\n\n"
        "Lead-in for the next result.\n"
        "Theorem 3.4. Second statement.\n\n"
        "Lead-in for the final result.\n"
        "Theorem 3.8. Third statement.\n"
    )
    result = scan(parse_latex(source))
    theorem_candidates = [
        candidate
        for candidate in result.candidates
        if candidate.kind == "theorem-like"
    ]

    assert [candidate.span.start_line for candidate in theorem_candidates] == [2, 5, 8]
    assert [candidate.payload["number"] for candidate in theorem_candidates] == [
        "2.1",
        "3.4",
        "3.8",
    ]
    assert all(
        candidate.rule_id == "formal-inventory-bare-title"
        for candidate in theorem_candidates
    )
    assert result.formal_inventory["counts"]["missing"] == 3


def test_macro_wrapped_box_heading_is_inventory_blocker_not_auto_patch():
    source = (
        r"\begin{tcolorbox}"
        "\n"
        r"\formalheading{\textbf{Remark.}} Body."
        "\n"
        r"\end{tcolorbox}"
    )
    result = scan(parse_latex(source))
    anchor = result.formal_inventory["anchors"][0]
    blockers = [
        candidate
        for candidate in result.candidates
        if candidate.kind == "formal-audit"
    ]

    assert anchor["in_box"] is True
    assert anchor["wrapper"] == "formalheading+textbf"
    assert not [
        candidate
        for candidate in result.candidates
        if candidate.kind in {"theorem-like", "proof"}
    ]
    assert len(blockers) == 1
    assert blockers[0].rule_id == "formal-inventory-missing"
    assert blockers[0].payload["source_sha256"] == anchor["source_sha256"]


def test_existing_environment_wrong_kind_is_reported_fail_closed():
    source = (
        r"\begin{lemma}"
        "\n"
        r"\textbf{Theorem 3.4.} Statement."
        "\n"
        r"\end{lemma}"
    )
    result = scan(parse_latex(source))
    wrong = [
        item
        for item in result.formal_inventory["findings"]
        if item["kind"] == "wrong-env"
    ]

    assert len(wrong) == 1
    assert wrong[0]["original_env"] == "lemma"
    assert wrong[0]["suggested_env"] == "theorem"
    assert any(
        candidate.kind == "formal-audit"
        and candidate.rule_id == "formal-inventory-wrong-env"
        for candidate in result.candidates
    )
    assert not [
        candidate
        for candidate in result.candidates
        if candidate.kind == "theorem-like"
    ]


def test_existing_environment_overwide_and_duplicate_are_reported():
    source = (
        r"\begin{theorem}[3.8]"
        "\nStatement. "
        r"\qed"
        "\nLater discussion.\n"
        r"\end{theorem}"
        "\n"
        r"\begin{theorem}[3.8]"
        "\nSecond statement.\n"
        r"\end{theorem}"
    )
    inventory = inventory_document(parse_latex(source))
    kinds = [finding.kind for finding in inventory.findings]

    assert "overwide" in kinds
    assert "duplicate" in kinds
    overwide = next(item for item in inventory.findings if item.kind == "overwide")
    duplicate = next(item for item in inventory.findings if item.kind == "duplicate")
    assert overwide.start_line == 1
    assert overwide.end_line == 4
    assert overwide.original_env == overwide.suggested_env == "theorem"
    assert duplicate.start_line == 5
    assert duplicate.end_line == 7
    assert len(duplicate.related_ids) == 2


def test_formal_audit_blocker_is_counted_as_unanswered_pipeline_candidate():
    source = (
        r"\begin{tcolorbox}"
        "\n"
        r"\formalheading{\textbf{Remark.}} Body."
        "\n"
        r"\end{tcolorbox}"
    )
    result = run_pipeline(source, mode="rule")
    coverage = result.verification["structure_decisions"]

    assert result.ok is False
    assert coverage["candidate_total"] == 1
    assert coverage["answered"] == 0
    assert coverage["coverage"] == 0.0
    assert coverage["missing_ids"] == ["c-0001"]

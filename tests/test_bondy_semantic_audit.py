# -*- coding: utf-8 -*-
"""Offline Bondy content/math audit tests; no model, API, or network is used."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.audit_bondy_semantics import (
    _critical_segment_diagnostics,
    _unexpected_confusables,
    audit_pdf_semantics,
    critical_segments,
    extract_math_tokens,
    main,
    math_alignment,
    reference_tokens,
    report_markdown,
    scan_unicode_confusables,
    sequence_alignment,
    unresolved_reference_markers,
)


FIXTURE = Path(__file__).parent / "tmp_pdf" / "ocr_page.pdf"


def _generic_manifest() -> dict:
    return {
        "source_range": [1, 1],
        "source_sha256": None,
        "expected_chapter_count": 1,
        "chapters": [
            {
                "number": 1,
                "title": "0.1 The Probabilistic Method",
                "source_start": 1,
                "source_end": 1,
                "figure_label_count": 0,
            }
        ],
        "path": None,
    }


def _write_text_pdf(path: Path, text: str) -> None:
    try:
        import pymupdf as fitz
    except ImportError:
        fitz = pytest.importorskip("fitz")
    document = fitz.open()
    page = document.new_page(width=440, height=620)
    result = page.insert_textbox(fitz.Rect(36, 36, 404, 584), text, fontsize=10)
    assert result >= 0
    document.save(str(path))
    document.close()


def test_sequence_alignment_reports_coverage_and_order_separately():
    reordered = sequence_alignment(["a", "b", "c", "d"], ["a", "c", "b", "d"])

    assert reordered["coverage_recall"] == 1.0
    assert reordered["multiset_f1"] == 1.0
    assert reordered["ordered_f1"] < 1.0
    assert reordered["order_preservation"] < 1.0


def test_math_tokens_cover_identifiers_greek_operators_and_numbering():
    tokens = extract_math_tokens("Theorem 2.3: G=(V,E), α≤β, d(v)=2 and x -> y.")
    keys = [token.key for token in tokens]

    assert "numbering:2.3" in keys
    assert "identifier:g" in keys
    assert "greek:α" in keys
    assert "greek:β" in keys
    assert "operator:≤" in keys
    assert "operator:→" in keys

    changed = math_alignment("α ≤ β in Theorem 2.3", "α ≥ β in Theorem 2.4")
    assert changed["accuracy"] < 1.0
    assert changed["categories"]["operator"]["accuracy"] < 1.0
    assert changed["categories"]["numbering"]["accuracy"] < 1.0


def test_critical_statement_operator_or_negation_change_is_fail_closed():
    source = (
        "Definition 1.1. A graph G is sparse if d(v) ≤ 2.\n"
        "Theorem 1.2. Every sparse graph is not complete.\n"
        "Proof. This is separate."
    )
    generated = (
        "Definition 1.1. A graph G is sparse if d(v) ≥ 2.\n"
        "Theorem 1.2. Every sparse graph is complete.\n"
        "Proof. This is separate."
    )

    segments = critical_segments(source)
    diagnostics = _critical_segment_diagnostics(
        source, generated, source_page=12, generated_page=10
    )

    assert [item["key"] for item in segments] == ["definition:1.1#1", "theorem:1.2#1"]
    assert all(item["suspected_meaning_change"] for item in diagnostics)
    assert "critical_operator_inventory_changed" in diagnostics[0]["reasons"]
    assert "critical_math_token_sequence_changed" in diagnostics[0]["reasons"]
    assert "critical_quantifier_or_negation_inventory_changed" in diagnostics[1]["reasons"]

    invented = _critical_segment_diagnostics(
        "Ordinary prose.",
        "Theorem 9.9. An invented statement.",
        source_page=12,
        generated_page=10,
    )
    assert invented[0]["reasons"] == ["unexpected_generated_critical_heading_or_statement"]


def test_confusable_unresolved_and_reference_extractors_are_explicit():
    text = "Theorem 1.2 cites Fig. 3.4; а) uses fullwidth Ａ, replacement �, and unresolved ??."

    confusables = scan_unicode_confusables(text, 17)
    markers = unresolved_reference_markers(text, 17)

    assert {(item["kind"], item["character"]) for item in confusables} == {
        ("cyrillic", "а"),
        ("fullwidth", "Ａ"),
        ("replacement_glyph", "�"),
    }
    assert confusables[0]["looks_like"] == "a"
    replacement = [item for item in confusables if item["kind"] == "replacement_glyph"]
    assert _unexpected_confusables(replacement, replacement) == replacement
    assert markers[0]["kind"] == "double_question_mark"
    assert reference_tokens(text) == ["theorem:1.2", "figure:3.4"]


def test_identical_pdf_passes_alignment_but_publication_gate_stays_unestablished():
    report = audit_pdf_semantics(
        FIXTURE,
        FIXTURE,
        manifest=_generic_manifest(),
        required_source_range=None,
    )

    assert report["gate"]["decision"] == "pass"
    assert report["gate"]["exit_code"] == 0
    assert report["gate"]["observed"]["normalized_text_accuracy"] == 1.0
    assert report["gate"]["observed"]["math_token_accuracy"] == 1.0
    assert report["gate"]["publication_readiness"] == "not_established"
    assert report["gate"]["mathematical_semantic_accuracy"] == "not_proven"
    assert report["gate"]["semantic_100_percent_claimed"] is False
    assert report["tool"]["model_invoked"] is False
    assert report["tool"]["network_used"] is False
    assert report["tool"]["blind_gold_used"] is False
    assert report["critical_structure"]["segment_count"] >= 2
    assert report["critical_structure"]["suspected_meaning_changes"] == []
    assert report["review_items"][0]["id"] == "independent_mathematical_semantic_review"

    markdown = report_markdown(report)
    assert "does not establish publication readiness" in markdown
    assert "Per-page normalized text and math alignment" in markdown
    assert "100% semantic accuracy" in markdown


def test_changed_critical_operator_reference_and_placeholder_fail_hard(tmp_path):
    source = tmp_path / "source.pdf"
    generated = tmp_path / "generated.pdf"
    source_text = (
        "Definition 1.1. A graph G=(V,E) is sparse if d(v) <= 2.\n"
        "Theorem 1.2. Every graph has at most 2 edges. See Fig. 1.3."
    )
    generated_text = (
        "Definition 1.1. A graph G=(V,E) is sparse if d(v) >= 2.\n"
        "Theorem 1.2. Every graph has at least 2 edges. See Fig. 1.4. ??"
    )
    _write_text_pdf(source, source_text)
    _write_text_pdf(generated, generated_text)

    report = audit_pdf_semantics(
        source,
        generated,
        manifest=_generic_manifest(),
        required_source_range=None,
    )

    assert report["gate"]["decision"] == "fail"
    failed = report["gate"]["failed_hard_gates"]
    assert "no_suspected_meaning_change_on_critical_structure_pages" in failed
    assert "no_unresolved_reference_markers" in failed
    assert "global_reference_inventory_match" in failed
    assert report["critical_structure"]["low_similarity_pages"]
    assert report["critical_structure"]["suspected_meaning_changes"]
    assert report["references"]["missing_from_generated"] == [
        {"token": "figure:1.3", "count": 1}
    ]
    assert report["references"]["extra_in_generated"] == [
        {"token": "figure:1.4", "count": 1}
    ]


def test_cli_rejects_non_bondy_scope_and_writes_fail_closed_reports(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "source_range": [1, 1],
                "expected_chapter_count": 1,
                "chapters": [
                    {
                        "number": 1,
                        "title": "Fixture",
                        "source_start": 1,
                        "source_end": 1,
                        "figure_label_count": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    json_out = tmp_path / "audit.json"
    markdown_out = tmp_path / "audit.md"

    exit_code = main(
        [
            str(FIXTURE),
            str(FIXTURE),
            "--manifest",
            str(manifest),
            "--quiet",
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ]
    )

    assert exit_code == 2
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["gate"]["decision"] == "error"
    assert report["gate"]["publication_readiness"] == "not_established"
    assert "fixed to physical source pages 3-473" in report["errors"][0]
    assert "Operational errors" in markdown_out.read_text(encoding="utf-8")

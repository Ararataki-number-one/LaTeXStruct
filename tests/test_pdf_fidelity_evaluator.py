# -*- coding: utf-8 -*-
"""Offline PDF fidelity gate tests; no model, API, or network is used."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.evaluate_pdf_fidelity import (
    EvaluationError,
    _caption_keys,
    _is_chapter_title,
    content_box,
    content_box_similarity,
    evaluate_pdf_fidelity,
    global_ssim,
    load_manifest,
    main,
    normalize_text,
    normalized_text_similarity,
    report_markdown,
)


FIXTURE = Path(__file__).parent / "tmp_pdf" / "ocr_page.pdf"
FIXTURE_TITLE = "0.1 The Probabilistic Method"


def _duplicate_fixture(output: Path) -> None:
    """Create a two-page PDF using whichever supported PDF backend is installed."""

    try:
        from pypdf import PdfReader, PdfWriter

        reader = PdfReader(str(FIXTURE))
        writer = PdfWriter()
        writer.add_page(reader.pages[0])
        writer.add_page(reader.pages[0])
        with output.open("wb") as handle:
            writer.write(handle)
        return
    except ImportError:
        pass
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
        except ImportError as exc:  # pragma: no cover - project server dependency supplies one
            raise RuntimeError("a supported PDF backend is required") from exc
    source = fitz.open(str(FIXTURE))
    target = fitz.open()
    target.insert_pdf(source)
    target.insert_pdf(source)
    target.save(str(output))
    target.close()
    source.close()


def test_text_normalization_keeps_math_symbols_and_similarity_is_bounded():
    normalized = normalize_text("  Théorème  x² ≤ y² — Proof. ")
    assert normalized == "théorèmex2≤y2proof"
    exact = normalized_text_similarity("A ∩ B = ∅", "A ∩ B = ∅")
    changed = normalized_text_similarity("A ∩ B = ∅", "A ∪ B = V")
    assert exact == {
        "combined": 1.0,
        "character_sequence": 1.0,
        "token_multiset_f1": 1.0,
    }
    assert 0.0 <= changed["combined"] < 1.0


def test_chapter_and_caption_detection_is_conservative():
    assert _is_chapter_title("17 Edge Colourings", outline_level=1)
    assert _is_chapter_title("Chapter XVII Edge Colourings")
    assert _is_chapter_title("第17章 边着色")
    assert not _is_chapter_title("17.2 Vizing's Theorem", outline_level=2)
    text = (
        "Figure 1.2 is a prose reference.\n"
        "Fig. 1.2. A real caption.\n"
        "Fig. 1.2a. A subfigure reference.\n"
        "See Fig. 2.1. Inline reference.\n"
        "Fig. 3-4. Noncanonical label.\n"
        "图 5.1。真正图题\n"
        "图 5.1a。子图引用"
    )
    assert _caption_keys(text) == ["figure:1.2", "figure:5.1"]


def test_identical_pdf_passes_mechanical_gate_but_never_claims_semantics():
    report = evaluate_pdf_fidelity(
        FIXTURE,
        FIXTURE,
        expected_chapter_count=1,
        expected_chapters=[FIXTURE_TITLE],
    )

    assert report["gate"]["decision"] == "pass"
    assert report["gate"]["exit_code"] == 0
    assert report["gate"]["score"] == 85.0  # optional rendered-layout 15 was not run
    assert report["gate"]["mathematical_semantic_accuracy"] == "unverified"
    assert report["gate"]["publication_readiness"] == "not_established"
    assert report["render_sampling"]["status"] == "not_run"
    assert any(
        item["id"] == "mathematical_semantic_accuracy"
        for item in report["unverified_items"]
    )
    assert report["chapter_diagnostics"][0]["title_preserved"] is True
    assert "must not be described as 98% mathematical accuracy" in report_markdown(report)


def test_page_count_mismatch_fails_hard_even_if_aligned_page_is_identical(tmp_path):
    generated = tmp_path / "two-pages.pdf"
    _duplicate_fixture(generated)

    report = evaluate_pdf_fidelity(
        FIXTURE,
        generated,
        expected_chapter_count=1,
        expected_chapters=[FIXTURE_TITLE],
    )

    assert report["gate"]["decision"] == "fail"
    assert report["gate"]["exit_code"] == 1
    assert "exact_page_count" in report["gate"]["failed_hard_gates"]
    assert "complete_page_inspection" in report["gate"]["failed_hard_gates"]
    assert report["page_diagnostics"][-1]["status"] == "extra_generated_page"

    json_out = tmp_path / "quality-fail.json"
    markdown_out = tmp_path / "quality-fail.md"
    exit_code = main(
        [
            str(FIXTURE),
            str(generated),
            "--expected-chapter-count", "1",
            "--chapter-title", FIXTURE_TITLE,
            "--quiet",
            "--json-out", str(json_out),
            "--markdown-out", str(markdown_out),
        ]
    )
    assert exit_code == 1
    assert json.loads(json_out.read_text(encoding="utf-8"))["gate"]["decision"] == "fail"
    assert "Decision: **FAIL**" in markdown_out.read_text(encoding="utf-8")


def test_same_file_source_slice_auto_aligns_and_explicit_self_compare_is_a_cli_gate(tmp_path):
    book = tmp_path / "two-pages.pdf"
    _duplicate_fixture(book)

    automatic = evaluate_pdf_fidelity(
        book,
        book,
        source_start=2,
        source_end=2,
        expected_chapter_count=1,
        expected_chapters=[FIXTURE_TITLE],
    )
    assert automatic["gate"]["decision"] == "pass"
    assert automatic["inputs"]["source_range"] == [2, 2]
    assert automatic["inputs"]["generated_range"] == [2, 2]
    assert automatic["inputs"]["range_alignment_mode"] == "automatic_same_pdf_source_range"
    assert automatic["page_diagnostics"][0]["source_page"] == 2
    assert automatic["page_diagnostics"][0]["generated_page"] == 2

    json_out = tmp_path / "self-check.json"
    markdown_out = tmp_path / "self-check.md"
    exit_code = main(
        [
            str(book),
            str(book),
            "--source-start", "2",
            "--source-end", "2",
            "--self-compare",
            "--expected-chapter-count", "1",
            "--chapter-title", FIXTURE_TITLE,
            "--quiet",
            "--json-out", str(json_out),
            "--markdown-out", str(markdown_out),
        ]
    )
    assert exit_code == 0
    explicit = json.loads(json_out.read_text(encoding="utf-8"))
    assert explicit["inputs"]["generated_range"] == [2, 2]
    assert explicit["inputs"]["range_alignment_mode"] == "explicit_self_compare"

    conflict_json = tmp_path / "self-check-conflict.json"
    conflict_md = tmp_path / "self-check-conflict.md"
    assert main(
        [
            str(book), str(book),
            "--source-start", "2", "--source-end", "2",
            "--self-compare", "--generated-start", "1",
            "--json-out", str(conflict_json),
            "--markdown-out", str(conflict_md),
            "--quiet",
        ]
    ) == 2
    assert json.loads(conflict_json.read_text(encoding="utf-8"))["gate"]["decision"] == "error"


def test_manifest_aliases_and_unsupported_external_gate_fail_closed(tmp_path):
    sha256 = hashlib.sha256(FIXTURE.read_bytes()).hexdigest().upper()
    manifest_path = tmp_path / "book-spec.json"
    manifest_path.write_text(
        json.dumps(
            {
                "source_sha256": sha256,
                "selected_start_page": 1,
                "selected_end_page": 1,
                "hard_gates": {
                    "chapter_count": 1,
                    "normalized_text_accuracy": 0.98,
                    "expected_figure_labels": 0,
                    "searchable_text": True,
                    "fonts_embedded": True,
                    "math_token_accuracy": 0.98,
                    "repeatable_compile": True,
                },
                "chapters": [
                    {
                        "number": 1,
                        "title": "0.1 The Probabilistic Method",
                        "start_page": 1,
                        "end_page": 1,
                        "figure_labels": 0,
                    }
                ],
                "representative_source_pages": [1],
            }
        ),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    assert manifest["source_range"] == [1, 1]
    assert manifest["normalized_text_threshold"] == 0.98
    assert manifest["chapters"][0]["figure_label_count"] == 0

    report = evaluate_pdf_fidelity(
        FIXTURE,
        FIXTURE,
        source_start=1,
        source_end=1,
        expected_chapter_count=1,
        manifest=manifest,
    )

    assert report["gate"]["decision"] == "fail"
    assert "manifest_external:math_token_accuracy" in report["gate"]["failed_hard_gates"]
    assert "manifest_external:repeatable_compile" in report["gate"]["failed_hard_gates"]
    assert report["manifest_evidence"]["source_sha256_observed"] == sha256
    assert any(
        item["id"] == "manifest_hard_gate:math_token_accuracy"
        for item in report["unverified_items"]
    )


def test_invalid_manifest_is_rejected_instead_of_weakening_expectations(tmp_path):
    manifest = tmp_path / "bad.json"
    manifest.write_text(
        json.dumps(
            {
                "source_sha256": "too-short",
                "chapter_ranges": [[12, 48], [50, 87]],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvaluationError):
        load_manifest(manifest)


def test_cli_operational_failure_writes_both_fail_closed_reports(tmp_path):
    json_out = tmp_path / "report.json"
    markdown_out = tmp_path / "report.md"

    exit_code = main(
        [
            str(tmp_path / "missing.pdf"),
            str(FIXTURE),
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
    assert report["gate"]["score"] == 0.0
    assert report["errors"]
    assert "Fail-closed" in markdown_out.read_text(encoding="utf-8")


def test_render_metrics_are_explicit_global_ssim_and_content_box_proxies():
    white = bytes([255] * 16)
    same = bytes([255] * 16)
    marked = bytearray(white)
    marked[5] = 0
    marked[6] = 0
    marked = bytes(marked)

    assert global_ssim(white, same) == pytest.approx(1.0)
    assert 0.0 <= global_ssim(white, marked) < 1.0
    assert content_box(white, 4, 4) is None
    assert content_box(marked, 4, 4) == [0.25, 0.25, 0.75, 0.5]
    assert content_box_similarity(None, None) == 1.0
    assert content_box_similarity(None, [0.1, 0.1, 0.9, 0.9]) == 0.0

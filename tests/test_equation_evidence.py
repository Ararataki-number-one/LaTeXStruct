# -*- coding: utf-8 -*-
"""Legacy equation evidence must be source-PDF-bound and fail closed."""

from __future__ import annotations

import hashlib

import pymupdf

from latexstruct.core.equation_evidence import (
    build_legacy_equation_evidence_ops,
)
from latexstruct.core.ocrstruct import encode_ocr_metadata, parse_ocr_metadata
from latexstruct.core.patch import Decision, apply_patches, validate_ops
from latexstruct.core.semantic_ir import build_ocr_semantic_ops


def _source_pdf(
    *labels: tuple[int, str, float],
    header: str = "Source page",
) -> bytes:
    document = pymupdf.open()
    try:
        page_count = max((page for page, _label, _y in labels), default=1)
        for page_number in range(1, page_count + 1):
            page = document.new_page(width=595, height=842)
            page.insert_text((110, 72), f"{header} {page_number}", fontsize=10)
            for expected_page, label, y in labels:
                if expected_page == page_number:
                    page.insert_text((20, y), f"({label})", fontsize=10)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _legacy_tex() -> str:
    metadata = encode_ocr_metadata([], "article", [1], False)
    return "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsmath}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\[",
        r"\text{(1)}\qquad x=y.",
        r"\]",
        r"\end{document}",
    ])


def _apply(text: str, operations):
    lines = text.split("\n")
    planned, rejected = validate_ops(
        lines,
        [(Decision(candidate_id="evidence", action="none"), operations)],
    )
    assert rejected == []
    out, _applied, rejected = apply_patches(lines, planned)
    assert rejected == []
    return "\n".join(out)


def test_legacy_metadata_upgrades_only_after_pdf_geometry_and_render_binding():
    source = _legacy_tex()
    pdf = _source_pdf((1, "1", 360))

    operations, result = build_legacy_equation_evidence_ops(source, pdf)
    assert result.ok is True
    assert result.upgraded is True
    assert len(operations) == 1
    upgraded = _apply(source, operations)
    metadata = parse_ocr_metadata(upgraded)
    assert metadata["version"] == 2
    assert [(item["page"], item["label"]) for item in metadata["equation_tags"]] == [
        (1, "1")
    ]
    evidence = metadata["equation_tags"][0]
    assert evidence["source_pdf_sha256"] == hashlib.sha256(pdf).hexdigest()
    assert len(evidence["page_render_sha256"]) == 64
    assert len(evidence["literal_inventory_sha256"]) == 64

    semantic_ops, _notes, report = build_ocr_semantic_ops(upgraded)
    assert report["equations"]["status"] == "normalized"
    normalized = _apply(upgraded, semantic_ops)
    assert r"\tag{1}" in normalized
    assert r"\text{(1)}\qquad" not in normalized
    assert r"\PassOptionsToPackage{leqno}{amsmath}" in normalized


def test_center_prose_number_is_not_accepted_as_equation_geometry():
    source = _legacy_tex()
    document = pymupdf.open()
    try:
        page = document.new_page(width=595, height=842)
        page.insert_text((280, 360), "(1)", fontsize=10)
        pdf = document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()

    operations, result = build_legacy_equation_evidence_ops(source, pdf)
    assert operations == []
    assert result.ok is False
    assert result.status == "source_geometry_mismatch"


def test_duplicate_outer_label_fails_closed():
    source = _legacy_tex()
    pdf = _source_pdf((1, "1", 300), (1, "1", 500))

    operations, result = build_legacy_equation_evidence_ops(source, pdf)
    assert operations == []
    assert result.ok is False
    assert result.status == "source_geometry_mismatch"


def test_existing_v2_metadata_is_rebound_to_the_current_source_pdf():
    source = _legacy_tex()
    pdf = _source_pdf((1, "1", 360))
    operations, migrated = build_legacy_equation_evidence_ops(source, pdf)
    assert migrated.ok is True
    upgraded = _apply(source, operations)

    operations, rebound = build_legacy_equation_evidence_ops(upgraded, pdf)
    assert operations == []
    assert rebound.ok is True
    assert rebound.status == "v2_source_reverified"
    assert rebound.source_pdf_sha256 == hashlib.sha256(pdf).hexdigest()
    assert rebound.evidence[0]["runtime_geometry_reverified"] is True

    changed_pdf = _source_pdf((1, "1", 420))
    operations, rejected = build_legacy_equation_evidence_ops(upgraded, changed_pdf)
    assert operations == []
    assert rejected.ok is False
    assert rejected.status == "v2_source_reverification_failed"


def test_existing_v2_metadata_rejects_different_pdf_with_same_tag_geometry():
    """Matching label coordinates cannot substitute for the bound PDF bytes."""

    source = _legacy_tex()
    bound_pdf = _source_pdf((1, "1", 360), header="Original source page")
    operations, migrated = build_legacy_equation_evidence_ops(source, bound_pdf)
    assert migrated.ok is True
    upgraded = _apply(source, operations)

    other_pdf = _source_pdf((1, "1", 360), header="Different source page")
    assert hashlib.sha256(other_pdf).hexdigest() != hashlib.sha256(bound_pdf).hexdigest()

    operations, rejected = build_legacy_equation_evidence_ops(upgraded, other_pdf)
    assert operations == []
    assert rejected.ok is False
    assert rejected.status == "v2_source_reverification_failed"
    assert rejected.source_pdf_sha256 == hashlib.sha256(other_pdf).hexdigest()


def test_legacy_document_without_numbered_equations_is_not_blocked():
    source = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        encode_ocr_metadata([], "article", [1], False),
        r"% Page 1",
        "A document without printed equation numbers.",
        r"\end{document}",
    ])
    pdf = _source_pdf()

    operations, result = build_legacy_equation_evidence_ops(source, pdf)

    assert operations == []
    assert result.checked is True
    assert result.ok is True
    assert result.upgraded is False
    assert result.status == "no_equation_tags"
    assert result.source_pdf_sha256 == hashlib.sha256(pdf).hexdigest()

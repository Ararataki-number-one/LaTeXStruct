# -*- coding: utf-8 -*-
"""OCR 结构失败的可恢复闭环测试。"""

from __future__ import annotations

import base64
import io
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from latexstruct.core.ocrstruct import (
    _manual_toc_entry_parts,
    build_ocr_structure_ops,
    check_ocr_structure,
    encode_ocr_metadata,
    parse_ocr_metadata,
)
from latexstruct.core.invariants import check_invariants
from latexstruct.core.patch import (
    Decision,
    apply_patches,
    content_invariant,
    validate_ops,
)
from latexstruct.core.verify import (
    check_display_tag_safety,
    check_env_balance,
    compare_env_balance,
    verification_failures,
)
from latexstruct.server.app import _ocr_bundle_bytes, _preserve_ocr_resources
import latexstruct.server.app as server_app
from latexstruct.server.process_jobs import ProcessJobManager
from latexstruct.store import ProjectStore


def _apply_structure_ops(text: str) -> str:
    ops, _notes = build_ocr_structure_ops(text)
    lines = text.split("\n")
    planned, rejected = validate_ops(
        lines,
        [(Decision(candidate_id="ocr-recovery", action="none"), ops)],
    )
    assert rejected == []
    out, applied, rejected = apply_patches(lines, planned)
    assert applied and rejected == []
    assert content_invariant(lines, out, applied) is True
    return "\n".join(out)


def _legacy_ocr_metadata(
    outline: list[dict],
    pages: list[int],
    *,
    source_has_toc: bool = False,
) -> str:
    """Encode a v1 token without the modern outline normalization step."""
    payload = {
        "version": 1,
        "kind": "book",
        "pages": pages,
        "source_has_toc": source_has_toc,
        "outline": outline,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return "% LaTeXStruct-OCR-Metadata: " + token


def _png_bytes(label: bytes = b"page") -> bytes:
    # Resource preservation identifies the actual raster format from its magic.
    return b"\x89PNG\r\n\x1a\n" + label


def test_ocr_structure_accepts_only_marked_faithfulbook_book_conversion():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "Overview", "page": 1}],
        "article",
        [1],
        False,
    )
    body = "\n".join([
        r"\documentclass[10pt,twoside,openany]{book}",
        r"% LaTeXStruct template: faithfulbook v1",
        r"\begin{document}",
        metadata,
        r"\chapter{Overview}",
        "Body.",
        r"\end{document}",
    ])

    assert check_ocr_structure(body)["ok"] is True
    assert check_ocr_structure(
        body.replace("% LaTeXStruct template: faithfulbook v1\n", "")
    )["ok"] is False


def test_duplicate_model_page_comment_does_not_corrupt_outline_or_manual_toc():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "First chapter", "page": 5},
            {"level": 1, "title": "Main method", "page": 5},
        ],
        "book",
        [1, 5],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 1",
            r"\section*{Contents}",
            r"1 \textbf{First chapter} \dotfill 5",
            r"\quad 1.1 Main method \dotfill 5",
            r"\vfill",
            r"\hbox{ii}",
            r"\clearpage",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 5",
            # 视觉模型偶尔会把印刷页码再次写成 Page 注释；这不是权威 PDF 页码。
            r"% Page 2",
            r"\section*{1 First chapter}",
            r"\subsection*{1.1 Main method}",
            "Body.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert r"\tableofcontents" in repaired
    assert r"\dotfill" not in repaired
    assert r"\chapter{First chapter}" in repaired
    assert r"\section{Main method}" in repaired
    assert check_ocr_structure(repaired)["ok"] is True


def test_publisher_outline_promotes_nested_numbered_chapters_and_split_number_line():
    """Front matter at L1 must not demote a consecutive L2 chapter run."""
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Preface", "page": 6},
            {"level": 0, "title": "Contents", "page": 10},
            {"level": 1, "title": "1 Graphs", "page": 12},
            {"level": 1, "title": "2 Subgraphs", "page": 49},
            {"level": 1, "title": "3 Connected Graphs", "page": 88},
        ],
        "book",
        [6, 10, 12, 49, 88],
        False,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 6",
            "Preface",
            r"\clearpage",
            r"%=== PAGE BREAK === 2",
            r"% Page 10",
            "Contents",
            r"\clearpage",
            r"%=== PAGE BREAK === 3",
            r"% Page 12",
            "1",
            "Graphs",
            "Opening text.",
            r"\clearpage",
            r"%=== PAGE BREAK === 4",
            r"% Page 49",
            "2 Subgraphs",
            "Second chapter.",
            r"\clearpage",
            r"%=== PAGE BREAK === 5",
            r"% Page 88",
            "3 Connected Graphs",
            "Third chapter.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert r"\chapter*{Preface}" in repaired
    assert r"\chapter*{Contents}" in repaired
    assert r"\chapter{Graphs}" in repaired
    assert r"\chapter{Subgraphs}" in repaired
    assert r"\chapter{Connected Graphs}" in repaired
    assert "\n1\n" not in repaired
    assert r"\section{Graphs}" not in repaired
    assert check_ocr_structure(repaired)["ok"] is True


def test_legacy_preencoded_partial_book_outline_is_normalized_when_parsed():
    metadata = _legacy_ocr_metadata(
        [
            {"level": 0, "title": "Preface", "page": 6},
            {"level": 0, "title": "Contents", "page": 10},
            {"level": 1, "title": "1 Graphs", "page": 12},
            {"level": 2, "title": "1.1 Graphs and Their Representation", "page": 12},
            {"level": 1, "title": "2 Subgraphs", "page": 49},
        ],
        [6, 10, 12, 49],
    )

    parsed = parse_ocr_metadata(metadata)

    assert [(item["title"], item["level"]) for item in parsed["outline"]] == [
        ("Preface", 0),
        ("Contents", 0),
        ("1 Graphs", 0),
        ("1.1 Graphs and Their Representation", 1),
        ("2 Subgraphs", 0),
    ]
    # New metadata encoding and legacy import share an idempotent normalizer.
    encoded_again = encode_ocr_metadata(
        parsed["outline"], "book", parsed["pages"], False,
    )
    assert parse_ocr_metadata(encoded_again)["outline"] == parsed["outline"]


def test_full_nested_book_outline_stops_before_appendix_and_back_matter():
    chapter_titles = [
        "Graphs",
        "Subgraphs",
        "Connected Graphs",
        "Trees",
        "Nonseparable Graphs",
        "Tree-Search Algorithms",
        "Flows in Networks",
        "Complexity of Algorithms",
        "Connectivity",
        "Planar Graphs",
        "The Four-Colour Problem",
        "Stable Sets and Cliques",
        "The Probabilistic Method",
        "Vertex Colourings",
        "Colourings of Maps",
        "Matchings",
        "Edge Colourings",
        "Hamilton Cycles",
        "Coverings and Packings in Directed Graphs",
        "Electrical Networks",
        "Integer Flows and Coverings",
    ]
    outline = [
        {"level": 0, "title": "Preface", "page": 6},
        {"level": 0, "title": "Contents", "page": 10},
    ]
    for number, title in enumerate(chapter_titles, start=1):
        page = 12 + (number - 1) * 30
        outline.extend([
            {"level": 1, "title": f"{number} {title}", "page": page},
            {"level": 2, "title": f"{number}.1 Opening Section", "page": page},
        ])
    outline.extend([
        {"level": 0, "title": "Appendix", "page": 650},
        {"level": 1, "title": "Tables", "page": 651},
        {"level": 0, "title": "References", "page": 660},
        {"level": 0, "title": "Index", "page": 690},
    ])
    metadata = _legacy_ocr_metadata(
        outline,
        sorted({int(item["page"]) for item in outline}),
    )

    normalized = parse_ocr_metadata(metadata)["outline"]
    levels = {item["title"]: item["level"] for item in normalized}

    for number, title in enumerate(chapter_titles, start=1):
        assert levels[f"{number} {title}"] == 0
        assert levels[f"{number}.1 Opening Section"] == 1
    assert levels["Appendix"] == 0
    assert levels["Tables"] == 1
    assert levels["References"] == 0
    assert levels["Index"] == 0


def test_nested_chapter_promotion_rejects_single_or_nonmonotonic_claims():
    single = _legacy_ocr_metadata(
        [{"level": 0, "title": "Preface", "page": 2},
         {"level": 1, "title": "1 Background", "page": 5}],
        [2, 5],
    )
    descending = _legacy_ocr_metadata(
        [{"level": 0, "title": "Contents", "page": 2},
         {"level": 1, "title": "1 One", "page": 5},
         {"level": 1, "title": "2 Two", "page": 4}],
        [2, 4, 5],
    )

    assert [item["level"] for item in parse_ocr_metadata(single)["outline"]] == [0, 1]
    assert [item["level"] for item in parse_ocr_metadata(descending)["outline"]] == [0, 1, 1]


def test_printed_toc_folio_accepts_only_closed_numeric_visual_wrappers():
    assert _manual_toc_entry_parts(
        r"1\quad Graphs . . . . . . . . . .\quad 1"
    ) == (r"1\quad Graphs", 1)
    assert _manual_toc_entry_parts(
        r"\textbf{1.2\quad Isomorphisms} ........ \textbf{12}"
    ) == (r"\textbf{1.2\quad Isomorphisms}", 12)
    assert _manual_toc_entry_parts(
        r"\textsc{Definitions} ........ \textit{7}"
    ) == (r"\textsc{Definitions}", 7)

    for unsafe_tail in (
        r"\textbf{12}\input{payload}",
        r"\textbf{\input{payload}}",
        r"\href{payload}{12}",
        r"\textbf{12\relax}",
        r"\textbf{0}",
    ):
        assert _manual_toc_entry_parts(
            rf"1.2 Isomorphisms ........ {unsafe_tail}"
        ) is None


def test_live_style_global_and_local_tocs_map_without_losing_page_markers():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Contents", "page": 10},
            {"level": 0, "title": "1 Graphs", "page": 12},
        ],
        "book",
        [10, 11, 12],
        True,
    )
    source = "\n".join([
        r"\documentclass[11pt]{book}",
        r"\begin{document}",
        metadata,
        r"% Page 10",
        "Contents",
        r"1\quad Graphs . . . . . . . . . . . . . . . .\quad 1",
        r"2\quad Subgraphs . . . . . . . . . . . . . .\quad 39",
        r"\clearpage",
        r"%=== PAGE BREAK === 2",
        r"% Page 11",
        r"\textbf{18\quad Hamilton Cycles} \dotfill 471",
        r"\textbf{References} \dotfill 593",
        r"\clearpage",
        r"%=== PAGE BREAK === 3",
        r"% Page 12",
        "1",
        r"\textbf{Graphs}",
        r"\textbf{Contents}",
        r"\textbf{1.1\quad First Section} ........ \textbf{1}",
        r"\textsc{First Topic} ................... 1",
        r"\textbf{1.2\quad Second Section} ....... \textbf{12}",
        r"\textbf{1.1 First Section}",
        r"\textsc{First Topic}",
        r"\textbf{1.2 Second Section}",
        "Body.",
        r"\end{document}",
    ])

    repaired = _apply_structure_ops(source)

    assert repaired.count(r"\tableofcontents") == 1
    assert "% LaTeXStruct-Local-Contents" in repaired
    assert r"\section{First Section}" in repaired
    assert r"\subsection*{First Topic}" in repaired
    assert r"\section{Second Section}" in repaired
    assert "Hamilton Cycles" not in repaired
    assert re.findall(r"(?m)^% Page (\d+)\s*$", repaired) == ["10", "11", "12"]
    assert check_ocr_structure(repaired)["ok"] is True


def test_multiphysical_page_printed_toc_is_replaced_until_next_outline_heading():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Contents", "page": 10},
            {"level": 0, "title": "1 Graphs", "page": 12},
        ],
        "book",
        [10, 11, 12],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 10",
            "Contents",
            r"1\quad Graphs ................................ 1",
            r"2\quad Subgraphs ............................. 39",
            r"\clearpage",
            r"%=== PAGE BREAK === 2",
            r"% Page 11",
            r"16\quad Matchings ............................ 413",
            r"17\quad Edge Colourings ...................... 451",
            r"18\quad Hamilton Cycles ...................... 471",
            r"\clearpage",
            r"%=== PAGE BREAK === 3",
            r"% Page 12",
            "1 Graphs",
            "Opening text.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert repaired.count(r"\tableofcontents") == 1
    assert "Hamilton Cycles" not in repaired
    assert r"\tableofcontents" + "\n" + r"\clearpage" in repaired
    assert r"\chapter{Graphs}" in repaired
    assert "Opening text." in repaired


def test_unnumbered_bookmark_uses_explicit_chapter_marker_as_toc_boundary():
    """An explicit ``Chapter N`` is safe even when the bookmark omits ``N``."""
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Contents", "page": 3},
            {"level": 0, "title": "Ramsey numbers", "page": 4},
        ],
        "book",
        [3, 4],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 3",
            "Contents",
            r"1 Ramsey numbers \dotfill 1",
            r"\clearpage",
            r"%=== PAGE BREAK === 2",
            r"% Page 4",
            "Chapter 1",
            "Ramsey numbers",
            "Opening text.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert r"\tableofcontents" in repaired
    assert r"\dotfill" not in repaired
    assert r"\chapter{Ramsey numbers}" in repaired
    assert "Chapter 1" not in repaired
    assert "Opening text." in repaired
    assert check_ocr_structure(repaired)["ok"] is True


def test_mismatched_numbered_bookmark_keeps_chapter_marker_and_fails_closed():
    """An explicit but contradictory bookmark number must not authorize deletion."""
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Contents", "page": 3},
            {"level": 0, "title": "2 Ramsey numbers", "page": 4},
        ],
        "book",
        [3, 4],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 3",
            "Contents",
            r"2 Ramsey numbers \dotfill 1",
            r"\clearpage",
            r"%=== PAGE BREAK === 2",
            r"% Page 4",
            "Chapter 1",
            "2 Ramsey numbers",
            "Opening text.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert r"\dotfill" in repaired
    assert r"\tableofcontents" not in repaired
    assert "Chapter 1" in repaired
    assert "Opening text." in repaired
    assert check_ocr_structure(repaired)["ok"] is False


def test_global_toc_preserves_printed_folios_when_blank_pages_are_omitted():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Contents", "page": 10},
            {"level": 0, "title": "1 Graphs", "page": 12},
            {"level": 0, "title": "2 Subgraphs", "page": 49},
            {"level": 0, "title": "3 Connected Graphs", "page": 88},
        ],
        "book",
        [10, 12, 49, 88],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 10",
            "Contents",
            r"1\quad Graphs ................................ 1",
            r"2\quad Subgraphs ............................. 39",
            r"3\quad Connected Graphs ...................... 79",
            r"\clearpage",
            r"%=== PAGE BREAK === 2",
            r"% Page 12",
            "1 Graphs",
            "First chapter.",
            r"\clearpage",
            r"%=== PAGE BREAK === 3",
            r"% Page 49",
            "2 Subgraphs",
            "Second chapter.",
            r"\clearpage",
            r"%=== PAGE BREAK === 4",
            r"% Page 88",
            "3 Connected Graphs",
            "Third chapter.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert "% LaTeXStruct-Printed-Page: 1\n\\chapter{Graphs}" in repaired
    assert "% LaTeXStruct-Printed-Page: 39\n\\chapter{Subgraphs}" in repaired
    assert "% LaTeXStruct-Printed-Page: 79\n\\chapter{Connected Graphs}" in repaired
    assert r"\tableofcontents" in repaired
    assert "2\\quad Subgraphs" not in repaired
    assert check_ocr_structure(repaired)["ok"] is True


def test_chapter_local_printed_toc_becomes_inert_template_marker():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "1 Graphs", "page": 12}],
        "book",
        [12],
        False,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 12",
            "1",
            "Graphs",
            "Contents",
            "1.1  Graphs and Their Representation .......... 1",
            r"\textsc{Definitions and Examples} ............ 1",
            "1.2  Isomorphisms and Automorphisms ........... 12",
            "1.1 Graphs and Their Representation",
            r"\textsc{Definitions and Examples}",
            "1.2 Isomorphisms and Automorphisms",
            "Real opening paragraph.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert r"\chapter{Graphs}" in repaired
    assert "% LaTeXStruct-Local-Contents" in repaired
    assert "Definitions and Examples} ........" not in repaired
    assert r"\section{Graphs and Their Representation}" in repaired
    assert r"\subsection*{Definitions and Examples}" in repaired
    assert r"\addcontentsline{toc}{subsection}{Definitions and Examples}" in repaired
    assert "Real opening paragraph." in repaired


def test_plain_local_toc_children_require_styled_body_and_keep_body_math():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "2 Subgraphs", "page": 49}],
        "book",
        [49],
        False,
    )
    source = "\n".join([
        r"\documentclass[11pt]{book}",
        r"\begin{document}",
        metadata,
        r"% Page 49",
        "2",
        "Subgraphs",
        r"\textbf{Contents}",
        "2.1  Subgraphs and Supergraphs ................. 40",
        "Edge and Vertex Deletion ........................ 40",
        "k-Connectivity .................................. 41",
        "2.1 Subgraphs and Supergraphs",
        r"\textsc{Edge and Vertex Deletion}",
        r"\textsc{\(k\)-Connectivity}",
        "Body paragraph.",
        r"\end{document}",
    ])

    repaired = _apply_structure_ops(source)

    assert "% LaTeXStruct-Local-Contents" in repaired
    assert r"\section{Subgraphs and Supergraphs}" in repaired
    assert r"\subsection*{Edge and Vertex Deletion}" in repaired
    assert r"\subsection*{\(k\)-Connectivity}" in repaired
    assert repaired.count(r"\(k\)") == source.count(r"\(k\)") == 1
    assert check_ocr_structure(repaired)["ok"] is True


@pytest.mark.parametrize("contents_line", [r"\textbf{Contents}", r"\section*{Contents}"])
def test_deferred_styled_local_contents_is_rejected_by_structure_gate(contents_line):
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "2 Subgraphs", "page": 49}],
        "book",
        [49],
        False,
    )
    source = "\n".join([
        r"\documentclass[11pt]{book}",
        r"\begin{document}",
        metadata,
        r"% Page 49",
        r"\chapter{Subgraphs}",
        contents_line,
        "2.1  Subgraphs and Supergraphs ................. 40",
        "Edge and Vertex Deletion ........................ 40",
        "Maximality and Minimality ....................... 41",
        r"\end{document}",
    ])

    gate = check_ocr_structure(source)

    assert gate["ok"] is False
    assert any(
        "章首手抄目录尚未完成正文标题全量匹配" in issue["reason"]
        for issue in gate["issues"]
    )


def test_partially_available_styled_local_toc_defers_every_heading_atomically():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "2 Subgraphs", "page": 49}],
        "book",
        [49, 50],
        False,
    )
    source = "\n".join([
        r"\documentclass[11pt]{book}",
        r"\begin{document}",
        metadata,
        r"% Page 49",
        "2",
        "Subgraphs",
        "Contents",
        r"\textbf{2.1\quad Subgraphs and Supergraphs} ......... 40",
        r"\textsc{Edge and Vertex Deletion} .................. 40",
        r"\textsc{Maximality and Minimality} ................. 41",
        r"\clearpage",
        r"%=== PAGE BREAK === 2",
        r"% Page 50",
        "2.1 Subgraphs and Supergraphs",
        r"\textsc{Edge and Vertex Deletion}",
        "Only two of three body headings are available.",
        r"\end{document}",
    ])

    repaired = _apply_structure_ops(source)

    assert r"\chapter{Subgraphs}" in repaired
    assert "% LaTeXStruct-Local-Contents" not in repaired
    assert r"\textbf{2.1\quad Subgraphs and Supergraphs} ......... 40" in repaired
    assert r"\textsc{Edge and Vertex Deletion} .................. 40" in repaired
    assert "2.1 Subgraphs and Supergraphs" in repaired
    assert r"\textsc{Edge and Vertex Deletion}" in repaired
    assert r"\section{Subgraphs and Supergraphs}" not in repaired
    assert r"\subsection*{Edge and Vertex Deletion}" not in repaired


def test_styled_proof_prefix_with_trailing_body_is_never_a_running_header():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "1 Graphs", "page": 1}],
        "book",
        [1, 2, 3],
        False,
    )
    proof_one = r"\textbf{Proof} Let \(G\) contain \(F\)."
    proof_two = r"\textbf{Proof} Suppose \(d(G)\geq 2k\)."
    source = "\n".join([
        r"\documentclass[11pt]{book}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        "1 Graphs",
        "Opening.",
        r"\clearpage",
        r"%=== PAGE BREAK === 2",
        r"% Page 2",
        proof_one,
        "Continuation.",
        r"\clearpage",
        r"%=== PAGE BREAK === 3",
        r"% Page 3",
        proof_two,
        "Continuation.",
        r"\end{document}",
    ])

    repaired = _apply_structure_ops(source)

    assert proof_one in repaired and proof_two in repaired
    assert check_invariants(source, repaired)["math"]["equal"] is True
    assert check_ocr_structure(repaired)["ok"] is True


def test_legacy_47_page_hierarchy_is_atomic_and_preserves_markers_and_math():
    metadata = _legacy_ocr_metadata(
        [
            {"level": 0, "title": "Preface", "page": 6},
            {"level": 0, "title": "Contents", "page": 10},
            {"level": 1, "title": "1 Graphs", "page": 12},
            {"level": 1, "title": "2 Subgraphs", "page": 49},
        ],
        list(range(3, 50)),
        source_has_toc=True,
    )
    lines = [r"\documentclass[11pt]{book}", r"\begin{document}", metadata]
    for index, page in enumerate(range(3, 50)):
        if index:
            lines.extend([r"\clearpage", f"%=== PAGE BREAK === {index + 1}"])
        lines.append(f"% Page {page}")
        if page == 6:
            lines.extend(["Preface", rf"Preface formula \({page}+x=y\)."])
        elif page == 10:
            lines.extend([
                "Contents",
                r"1\quad \textbf{Graphs} ........................ 1",
                r"2\quad \textbf{Subgraphs} ..................... 39",
            ])
        elif page == 11:
            lines.extend([
                r"\textbf{18\quad Hamilton Cycles} . . . . . . . 471",
                r"\textbf{References} . . . . . . . . . . . . . 593",
            ])
        elif page == 12:
            lines.extend([
                "1",
                "Graphs",
                "Contents",
                r"1.1\quad \textbf{First Section} ............... 1",
                r"\hspace*{2em}\textsc{First Topic} .............. 1",
                r"1.2\quad \textbf{Second Section} .............. 2",
                "1.1 First Section",
                r"\textsc{First Topic}",
                "First body paragraph.",
                "1.2 Second Section",
                rf"Chapter formula \({page}+x=y\).",
            ])
        elif page == 49:
            lines.extend([
                "2",
                "Subgraphs",
                "Contents",
                "2.1  Subgraphs and Supergraphs ................. 40",
                "Edge and Vertex Deletion ........................ 40",
                "Maximality and Minimality ....................... 41",
            ])
        else:
            lines.append(rf"Body formula on page {page}: \({page}+x=y\).")
    lines.append(r"\end{document}")
    source = "\n".join(lines)

    repaired = _apply_structure_ops(source)

    assert [
        int(match.group(1))
        for match in re.finditer(r"(?m)^% Page (\d+)\s*$", repaired)
    ] == list(range(3, 50))
    assert r"\tableofcontents" + "\n" + r"\clearpage" in repaired
    assert r"\chapter{Graphs}" in repaired
    assert r"\chapter{Subgraphs}" in repaired
    assert r"\section{Subgraphs}" not in repaired
    assert repaired.count("% LaTeXStruct-Local-Contents") == 1
    assert r"\section{First Section}" in repaired
    assert r"\section{\textbf{First Section}}" not in repaired
    assert r"\subsection*{First Topic}" in repaired
    assert r"\addcontentsline{toc}{subsection}{First Topic}" in repaired
    # Chapter 2 has no body pages yet, so its local TOC transaction is 0/3:
    # keep every row and old folio instead of deleting an incomplete outline.
    for source_row in (
        "2.1  Subgraphs and Supergraphs ................. 40",
        "Edge and Vertex Deletion ........................ 40",
        "Maximality and Minimality ....................... 41",
    ):
        assert source_row in repaired
    source_math = [line for line in source.splitlines() if r"\(" in line]
    repaired_math = [line for line in repaired.splitlines() if r"\(" in line]
    assert repaired_math == source_math
    gate = check_ocr_structure(repaired)
    assert gate["ok"] is False
    assert any(
        "章首手抄目录尚未完成正文标题全量匹配" in issue["reason"]
        for issue in gate["issues"]
    )


def test_ocr_structure_ops_repair_outer_environment_closed_inside_math():
    metadata = encode_ocr_metadata([], "book", [1], False)
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 1",
            r"\begin{theorem*}[1]",
            "A statement with a display:",
            r"\[",
            r"\end{theorem*}",
            r"x=y",
            r"\]",
            r"\begin{theorem*}[2]",
            r"\begin{equation}",
            r"a=b",
            r"\end{theorem*}",
            r"\tag{2}",
            r"\end{equation}",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert repaired.index(r"\]") < repaired.index(r"\end{theorem*}")
    first_end = repaired.index(r"\end{theorem*}")
    second_begin = repaired.index(r"\begin{theorem*}[2]")
    assert first_end < second_begin
    assert repaired.rindex(r"\end{equation}") < repaired.rindex(r"\end{theorem*}")
    assert check_env_balance(repaired)["ok"] is True
    assert check_display_tag_safety(repaired)["ok"] is True


def test_display_safety_allows_legal_matrix_environment_inside_brackets():
    text = "\n".join(
        [
            r"\[",
            r"A=\begin{pmatrix}1&0\\0&1\end{pmatrix}",
            r"\]",
        ]
    )
    assert check_display_tag_safety(text)["ok"] is True


def test_verification_failures_explain_actions_and_exact_relative_resources():
    failures = verification_failures(
        {
            "checks": [
                {"id": "outline", "label": "章节树与目录对应 PDF 大纲", "ok": False},
                {"id": "resources", "label": "图片资源真实存在且位于项目内", "ok": False},
                {"id": "compile", "label": "编译器可用时结果必须成功", "ok": False},
            ],
            "ocr_structure": {
                "issues": [{"line": 42, "reason": r"标题层级错误：应为 \section"}],
            },
            "resources": {
                "missing": ["images/page_08_01"],
                "unsafe": [],
            },
            "compile_after": {
                "errors": ["Missing $ inserted. @l.401"],
            },
        }
    )

    assert [item["id"] for item in failures] == ["outline", "resources", "compile"]
    assert failures[0]["details"][0]["line"] == 42
    assert "images/page_08_01" in failures[1]["summary"]
    assert "l.401" in failures[2]["summary"]
    assert all(item["action"] for item in failures)


def test_environment_failure_keeps_line_and_compile_error_redacts_only_local_path():
    compared = compare_env_balance(
        r"\begin{document}\end{document}",
        "\n".join([r"\begin{document}", r"\begin{theorem}", r"\end{document}"]),
    )
    failures = verification_failures(
        {
            "checks": [
                {"id": "environments", "label": "环境配平未恶化", "ok": False},
                {"id": "compile", "label": "编译器结果", "ok": False},
            ],
            "env_balance": compared,
            "compile_after": {
                "errors": [
                    r"C:\Users\Example\AppData\Local\Temp\job\main.tex:401: "
                    r"Missing $ inserted near \end{theorem}"
                ]
            },
        }
    )

    assert failures[0]["details"]
    assert failures[0]["details"][0]["line"] in {2, 3}
    assert "Example" not in failures[1]["summary"]
    assert "<local-file>:401" in failures[1]["summary"]
    assert r"\end{theorem}" in failures[1]["summary"]


def test_blocked_job_is_not_reported_done_and_keeps_last_structured_draft():
    manager = ProcessJobManager()
    job = manager.create("ocr-project", "original")
    manager.update(
        job["id"],
        "draft",
        0.84,
        "结构化草稿已生成",
        {"preview": "structured draft"},
    )
    manager.update(
        job["id"],
        "report",
        0.97,
        "安全检查未通过",
        {"preview": "original", "safe_to_export": False},
    )
    manager.update(
        job["id"],
        "ready",
        1.0,
        "安全检查完成，保留原文",
        {"preview": "original", "safe_to_export": False},
    )
    manager.complete(
        job["id"],
        {
            "ok": False,
            "failure_summary": "图片缺失：images/page_08_01",
            "failed_checks": ["resources"],
        },
    )

    public = manager.public(job)
    assert public["status"] == "blocked"
    assert public["phase"] == "verification_failed"
    assert public["message"] == "图片缺失：images/page_08_01"
    assert manager.preview(job) == "structured draft"
    assert "仅供检查" in public["preview_label"]


def test_pdf_resource_import_uses_physical_chunk_page_and_preserves_real_images():
    class FakePage:
        def __init__(self, xrefs):
            self.xrefs = xrefs

        def get_images(self, full=True):
            assert full is True
            return [(xref,) for xref in self.xrefs]

    class FakeDocument:
        page_count = 20

        def __getitem__(self, index):
            # 图片文件名中的 08/15 是书本印刷页码，权威物理页来自 OCR 段首。
            assert index in (10, 17)
            return FakePage([101, 102] if index == 10 else [201])

        def extract_image(self, xref):
            return {"ext": "png", "image": b"PNG" + str(xref).encode("ascii")}

        def close(self):
            pass

    class FakeFitz:
        @staticmethod
        def open(_path):
            return FakeDocument()

    raw = "\n".join(
        [
            r"% Page 11",
            r"% Page 8",  # 模型从页脚复制的印刷页码，不能覆盖物理页。
            r"\includegraphics{images/page_08_01}",
            r"\includegraphics{images/page_08_02}",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 18",
            r"% Page 15",
            r"\includegraphics{images/page_15_0}",
            # 页面 15 只有一张嵌入图但有两个引用；无 bbox 时
            # 无法证明这张图应绑定哪一个，两个都必须 unresolved。
            r"\includegraphics{images/page_15_1}",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {"fitz": FakeFitz}):
        target = Path(tmp, "source.pdf")
        target.write_bytes(b"%PDF-test")
        project = Path(tmp, "project")
        project.mkdir()
        result = _preserve_ocr_resources(
            {"source_type": "pdf", "target": str(target)},
            raw,
            project,
        )

        assert [item["path"] for item in result["assets"]] == [
            "images/page_08_01.png",
            "images/page_08_02.png",
        ]
        assert result["unresolved"] == ["images/page_15_0", "images/page_15_1"]
        assert Path(project, "images", "page_08_01.png").read_bytes() == b"PNG101"
        assert all("sha256" in item and item["bytes"] > 0 for item in result["assets"])
        assert [item["source_page"] for item in result["assets"]] == [11, 11]
        assert [item["printed_page"] for item in result["assets"]] == [8, 8]


def test_legacy_image_page_without_bbox_is_preview_only_not_figure_asset():
    raw = "\n".join(
        [
            r"% Page 1",
            r"\includegraphics{images/page_1_1.png}",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "source.png")
        source.write_bytes(_png_bytes(b"source"))
        page = Path(tmp, "page-1.img")
        page.write_bytes(_png_bytes(b"preview"))
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources(
            {
                "source_type": "image",
                "target": str(source),
                "selected_pages": [1],
                "pages": {1: {"png": str(page)}},
            },
            raw,
            project,
        )

        assert result["unresolved"] == ["images/page_1_1.png"]
        assert result["assets"] == []
        assert not Path(project, "images", "page_1_1.png.png").exists()
        assert not Path(project, "images", "page_1_1.png").exists()
        assert result["source_pages"][0]["path"] == "source-pages/page_0001.png"
        assert result["source_pages"][0]["sha256"] == hashlib.sha256(
            page.read_bytes()
        ).hexdigest()


def test_ocr_resource_scan_ignores_commented_and_verbatim_image_examples():
    raw = r"""% Page 1
% \includegraphics{figure.png}
\begin{verbatim}
\includegraphics{images/diagram}
\includegraphics{images/page_1_1.pdf}
\end{verbatim}
\verb|\includegraphics{also-not-active.png}|
Plain OCR text.
"""
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources({}, raw, project)

    assert result["unresolved"] == []
    assert result["assets"] == []


def test_missing_figure_keeps_source_preview_but_never_uses_whole_page_as_asset():
    raw = "\n".join(
        [
            r"% Page 3",
            r"\includegraphics{images/page_99_1}",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp, "page-3.img")
        page.write_bytes(_png_bytes(b"physical-page-3"))
        job = {
            "source_type": "pdf",
            "target": str(Path(tmp, "unavailable.pdf")),
            "status": "done",
            "selected_start": 3,
            "selected_end": 3,
            "selected_pages": [3],
            "raw_revision": 4,
            "usage_revision": 2,
            "page_revision": 5,
            "pages": {3: {"png": str(page)}},
        }
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources(job, raw, project)
        assert result["unresolved"] == ["images/page_99_1"]
        assert result["assets"] == []
        assert not Path(project, "images", "page_99_1.png").exists()
        assert Path(project, "source-pages", "page_0003.png").read_bytes() == page.read_bytes()

        bundle, manifest = _ocr_bundle_bytes(job, raw)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            from latexstruct.core.provenance import strip_tex_provenance

            assert strip_tex_provenance(archive.read("ocr.tex")).decode("utf-8") == raw
            assert "images/page_99_1.png" not in archive.namelist()
            assert archive.read("source-pages/page_0003.png") == page.read_bytes()
            disk_manifest = json.loads(archive.read("OCR-MANIFEST.json"))
        assert disk_manifest == manifest
        assert manifest["resources"]["assets"] == []
        assert manifest["resources"]["unresolved"] == ["images/page_99_1"]


def test_vector_only_pdf_uses_structured_bbox_high_dpi_crop_and_manifest():
    import fitz

    from latexstruct.ocr import image_pixel_size

    raw = "\n".join([
        r"% Page 1",
        r"\includegraphics[width=0.55\linewidth]{images/page_1_1}",
    ])
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "vector-only.pdf")
        document = fitz.open()
        page = document.new_page(width=400, height=600)
        page.insert_text((30, 18), "HEADER MUST STAY OUT")
        page.insert_text((30, 585), "FOOTER MUST STAY OUT")
        # Pure vector diagram: no embedded image xref exists.
        page.draw_circle((200, 270), 70, color=(0, 0, 0), width=2)
        page.draw_line((130, 270), (270, 270), color=(0, 0, 0), width=2)
        page.insert_text((190, 275), "v")
        assert page.get_images(full=True) == []
        document.save(source)
        document.close()

        page_preview = Path(tmp, "page-1.img")
        preview_document = fitz.open(source)
        preview_bytes = preview_document[0].get_pixmap(dpi=144, alpha=False).tobytes("png")
        preview_document.close()
        page_preview.write_bytes(preview_bytes)
        job = {
            "source_type": "pdf",
            "target": str(source),
            "status": "done",
            "selected_start": 1,
            "selected_end": 1,
            "selected_pages": [1],
            "raw_revision": 2,
            "usage_revision": 1,
            "page_revision": 3,
            "pages": {1: {
                "png": str(page_preview),
                "image_size_pixels": [800, 1200],
                "text_hint_chars": 44,
                "text_hint_sha256": "a" * 64,
                "figures": [{
                    "path": "images/page_1_1",
                    "index": 1,
                    "bbox_normalized": [0.28, 0.31, 0.72, 0.59],
                    "bbox_pixels": [224, 372, 576, 708],
                    "image_size_pixels": [800, 1200],
                    "source": "codex_vision",
                    "display_width_ratio": 0.55,
                }],
            }},
        }
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources(job, raw, project)

        assert result["unresolved"] == []
        assert len(result["assets"]) == 1
        asset = result["assets"][0]
        assert asset["kind"] == "bbox_crop"
        assert asset["bbox_source"] == "codex_vision"
        assert asset["render_dpi"] == 300
        assert asset["display_width_ratio"] == 0.55
        assert asset["bbox_normalized"] == [0.28, 0.31, 0.72, 0.59]
        # The clip stays far from header/footer and is materially smaller than
        # a 400x600pt full page rendered at 300 DPI (~1667x2500 px).
        assert asset["pdf_clip_points"][1] > 100
        assert asset["pdf_clip_points"][3] < 500
        crop_bytes = Path(project, asset["path"]).read_bytes()
        crop_width, crop_height = image_pixel_size(crop_bytes)
        assert crop_width < 1000 and crop_height < 1200
        assert crop_width > 400 and crop_height > 500

        bundle, manifest = _ocr_bundle_bytes(job, raw)
        assert manifest["pages"][0]["source_page"] == 1
        assert manifest["pages"][0]["figures"][0]["bbox_pixels"] == [
            224, 372, 576, 708,
        ]
        assert manifest["pages"][0]["figures"][0]["display_width_ratio"] == 0.55
        assert manifest["pages"][0]["reference_text"] == {
            "chars": 44,
            "sha256": "a" * 64,
        }
        assert manifest["resources"]["assets"][0]["kind"] == "bbox_crop"
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            from latexstruct.core.provenance import strip_tex_provenance

            assert strip_tex_provenance(archive.read("ocr.tex")).decode("utf-8") == raw
            packaged = archive.read(manifest["resources"]["assets"][0]["path"])
            assert image_pixel_size(packaged) == image_pixel_size(crop_bytes)


def test_vector_crop_refines_coarse_bbox_to_artwork_and_sparse_labels_only():
    import fitz

    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "coarse-vector-bbox.pdf")
        document = fitz.open()
        page = document.new_page(width=400, height=600)
        page.insert_text((40, 170), "preceding prose ending in j")
        page.insert_text((150, 205), "x1")
        page.draw_rect(fitz.Rect(100, 215, 300, 320), color=(0, 0, 0), width=1.5)
        page.draw_line((100, 215), (300, 320), color=(0, 0, 0), width=1.5)
        page.insert_text((190, 340), "A1")
        page.insert_text((125, 365), "Fig. 1. Synthetic vector diagram")
        page.insert_text((40, 400), "following body paragraph must stay outside")
        document.save(source)
        document.close()

        document = fitz.open(source)
        page = document[0]
        data, clip = server_app._pdf_clip_from_normalized_bbox(
            page,
            {"bbox_normalized": [0.08, 0.25, 0.92, 0.68]},
            dpi=300,
        )
        cropped_text = page.get_text("text", clip=clip)
        document.close()

    assert data and clip is not None
    assert "x1" in cropped_text and "A1" in cropped_text
    assert "preceding prose" not in cropped_text
    assert "Fig. 1." not in cropped_text
    assert "following body" not in cropped_text
    assert clip.y0 > 175
    assert clip.y1 < 350


def test_vector_crop_near_page_top_never_promotes_running_head_to_figure_label():
    import fitz

    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "top-vector-figure.pdf")
        document = fitz.open()
        page = document.new_page(width=400, height=600)
        page.insert_text((210, 38), "16.5 Running Header 445")
        page.draw_rect(fitz.Rect(50, 58, 350, 300), color=(0, 0, 0), width=1.2)
        page.insert_text((70, 78), "a")
        document.save(source)
        document.close()

        document = fitz.open(source)
        page = document[0]
        data, clip = server_app._pdf_clip_from_normalized_bbox(
            page,
            {"bbox_normalized": [0.10, 0.08, 0.90, 0.52]},
            dpi=240,
        )
        cropped_text = page.get_text("text", clip=clip)
        document.close()

    assert data and clip is not None
    assert "a" in cropped_text
    assert "Running Header" not in cropped_text and "445" not in cropped_text
    assert clip.y0 > 45


def test_custom_font_wordmark_uses_complete_glyph_bbox_without_following_body():
    import fitz

    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "text-glyph-wordmark.pdf")
        document = fitz.open()
        page = document.new_page(width=400, height=600)
        page.insert_text((70, 250), "Brand", fontsize=32)
        page.insert_text(
            (45, 315),
            "Following body paragraph must remain outside the logo crop.",
            fontsize=11,
        )
        document.save(source)
        document.close()

        document = fitz.open(source)
        page = document[0]
        brand_rect = next(
            fitz.Rect(line["bbox"])
            for block in (page.get_text("dict") or {}).get("blocks", [])
            if block.get("type") == 0
            for line in block.get("lines") or []
            if "Brand" in "".join(
                str(span.get("text") or "") for span in line.get("spans") or []
            )
        )
        # Deliberately stop the model bbox in the upper half of the glyph run.
        model_y1 = brand_rect.y0 + brand_rect.height * 0.40
        bbox = {
            "bbox_normalized": [
                max(0.0, (brand_rect.x0 - 3.0) / page.rect.width),
                max(0.0, (brand_rect.y0 - 3.0) / page.rect.height),
                min(1.0, (brand_rect.x1 + 3.0) / page.rect.width),
                model_y1 / page.rect.height,
            ],
        }
        data, clip = server_app._pdf_clip_from_normalized_bbox(page, bbox, dpi=240)
        cropped_text = page.get_text("text", clip=clip)
        document.close()

    assert data and clip is not None
    assert clip.y1 > brand_rect.y1
    assert "Brand" in cropped_text
    assert "Following body" not in cropped_text


def test_drawing_touching_model_bottom_admits_only_connected_lower_path():
    import fitz

    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "split-vector-logo.pdf")
        document = fitz.open()
        page = document.new_page(width=400, height=600)
        page.draw_rect(fitz.Rect(60, 200, 150, 235), color=(0, 0, 0), width=1.5)
        page.draw_rect(fitz.Rect(60, 238, 150, 260), color=(0, 0, 0), width=1.5)
        page.insert_text((45, 310), "Following body paragraph stays outside.")
        document.save(source)
        document.close()

        document = fitz.open(source)
        page = document[0]
        data, clip = server_app._pdf_clip_from_normalized_bbox(
            page,
            {"bbox_normalized": [0.14, 0.32, 0.39, 0.394]},
            dpi=240,
        )
        cropped_text = page.get_text("text", clip=clip)
        document.close()

    assert data and clip is not None
    assert clip.y1 > 260
    assert clip.y1 < 280
    assert "Following body" not in cropped_text


def test_bondy_real_vector_pages_exclude_prose_and_caption_but_keep_labels():
    """Workspace-only visual regression; CI skips when the licensed source is absent."""
    import fitz

    source = (
        Path(__file__).resolve().parents[2]
        / "work"
        / "bondy-v1.2-e2e"
        / "source"
        / "bondy-graph-theory-2e.pdf"
    )
    if not source.is_file():
        pytest.skip("Bondy real-page fixture is available only in the local fidelity workspace")

    document = fitz.open(source)
    try:
        page = document[2]
        data, clip = server_app._pdf_clip_from_normalized_bbox(
            page,
            {"bbox_normalized": [0.0916, 0.8158, 0.3105, 0.8615]},
            dpi=240,
        )
        cropped_text = page.get_text("text", clip=clip)
        assert data and clip is not None
        # The visible Springer horse + wordmark is one custom-font glyph run
        # whose searchable text happens to be “ABC”.  Its full PDF bbox ends at
        # y=603.134; the model bbox ended around y=574 and used to cut it in half.
        assert "ABC" in cropped_text
        assert clip.x1 > 152.73 and clip.y1 > 603.13
        assert clip.y1 < 620
        assert "Graph Theory" not in cropped_text

        page = document[193]
        page_194_cases = [
            ([0.1504, 0.1906, 0.8071, 0.3197], ("x1", "A1"), "vertex of Aj"),
            ([0.1512, 0.4411, 0.8064, 0.5639], ("Pij", "Aj"), "terminal vertex"),
            ([0.1489, 0.6454, 0.8079, 0.7814], ("P11", "A3"), "following figure"),
        ]
        for normalized, required, forbidden in page_194_cases:
            data, clip = server_app._pdf_clip_from_normalized_bbox(
                page, {"bbox_normalized": normalized}, dpi=240,
            )
            assert data and clip is not None
            cropped_text = page.get_text("text", clip=clip)
            assert all(label in cropped_text for label in required)
            assert forbidden not in cropped_text

        page = document[447]
        data, clip = server_app._pdf_clip_from_normalized_bbox(
            page,
            {"bbox_normalized": [0.1028, 0.0899, 0.8883, 0.7426]},
            dpi=240,
        )
        cropped_text = page.get_text("text", clip=clip)
        assert data and clip is not None
        assert "(g)" in cropped_text and "(h)" in cropped_text
        assert "Matching Algorithms" not in cropped_text and "445" not in cropped_text
        assert "Fig. 16.15" not in cropped_text
        assert "execution of APS" not in cropped_text
        assert clip.y0 > 50
        assert clip.y1 < 441.34
    finally:
        document.close()


def test_failed_attempt_does_not_replace_previous_verified_commit():
    with tempfile.TemporaryDirectory() as tmp:
        store = ProjectStore(tmp)
        pid = store.create("source", "safe")
        store.set_result(
            pid,
            "verified result",
            "verified report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        marker_before = Path(tmp, pid, "verification.json").read_bytes()

        store.record_failed_attempt(
            pid,
            "unsafe diagnostic draft",
            "failure report",
            {"verification": {"safe_to_export": False}, "failures": [{"id": "compile"}]},
        )

        assert store.read_result(pid) == "verified result"
        assert Path(tmp, pid, "verification.json").read_bytes() == marker_before
        failed = store.read_failed_attempt(pid)
        assert failed["details"]["failures"] == [{"id": "compile"}]
        assert failed["draft"] == "unsafe diagnostic draft"


def test_failed_draft_endpoint_survives_restart_but_never_replaces_export():
    from fastapi.testclient import TestClient

    with tempfile.TemporaryDirectory() as tmp:
        store = ProjectStore(tmp)
        pid = store.create("original source", "failed-recovery")
        verified_result = (
            r"\documentclass[lang=en,11pt]{elegantbook}"
            "\n"
            r"\begin{document}previous verified result\end{document}"
        )
        store.set_result(
            pid,
            verified_result,
            "previous verified report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        store.record_failed_attempt(
            pid,
            "latest unsafe draft",
            "actionable failure report",
            {
                "verification": {"safe_to_export": False},
                "failures": [{"id": "compile", "summary": "l.42"}],
            },
        )
        # 新建 app 模拟应用重启：进程内 job 已丢失，只依赖磁盘快照恢复。
        server_app._store = store
        server_app._process_jobs.clear()
        client = TestClient(server_app.create_app())

        response = client.get(f"/api/projects/{pid}/failed-draft")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        payload = response.json()
        assert payload["attempt"] == "blocked"
        assert payload["draft"] == "latest unsafe draft"
        assert payload["report"] == "actionable failure report"
        assert payload["details"]["failures"][0]["summary"] == "l.42"

        assert client.get(f"/api/projects/{pid}/result").text == verified_result
        exported = client.get(f"/api/projects/{pid}/export")
        assert exported.status_code == 200
        from latexstruct.core.provenance import (
            parse_tex_provenance,
            strip_tex_provenance,
        )

        assert strip_tex_provenance(exported.content).decode("utf-8") == verified_result

        current_tex = client.get(f"/api/projects/{pid}/export-current")
        assert current_tex.status_code == 200
        assert current_tex.headers["x-latexstruct-verified"] == "false"
        current_provenance = parse_tex_provenance(current_tex.content)
        assert current_provenance["verification_status"] == "UNVERIFIED"
        assert current_provenance["result_sha256"] == hashlib.sha256(
            b"latest unsafe draft"
        ).hexdigest()
        assert strip_tex_provenance(current_tex.content).decode("utf-8") == (
            "latest unsafe draft"
        )
        current_report = client.get(f"/api/projects/{pid}/export-current-report")
        assert current_report.status_code == 200
        assert current_report.headers["x-latexstruct-verified"] == "false"
        assert current_report.text == "actionable failure report"
        current_package = client.get(f"/api/projects/{pid}/export-current-package")
        assert current_package.status_code == 200
        assert current_package.headers["x-latexstruct-verified"] == "false"
        with zipfile.ZipFile(io.BytesIO(current_package.content)) as archive:
            assert strip_tex_provenance(archive.read("main.tex")) == b"latest unsafe draft"
            assert json.loads(archive.read("LATEXSTRUCT-PROVENANCE.json")) == (
                current_provenance
            )
            assert archive.read("LATEXSTRUCT-REPORT.md") == b"actionable failure report"
            assert "LATEXSTRUCT-UNVERIFIED.txt" in archive.namelist()

        native_dir = Path(tmp, "native-current")

        def save_current(data, filename):
            native_dir.mkdir()
            path = native_dir / filename
            path.write_bytes(data)
            return path

        for artifact, extension in (
            ("current", ".tex"),
            ("current-report", ".md"),
            ("current-package", ".zip"),
        ):
            with patch(
                "latexstruct.server.downloads.save_unique_download",
                save_current,
            ):
                native = client.post(f"/api/projects/{pid}/exports/{artifact}/save")
            assert native.status_code == 200
            assert native.json()["verified"] is False
            assert native.json()["filename"].endswith(extension)
            # Allow the next artifact helper invocation to create its isolated directory.
            for item in native_dir.iterdir():
                item.unlink()
            native_dir.rmdir()

        Path(tmp, pid, "last-failed-draft.tex").write_text(
            "tampered diagnostic", encoding="utf-8"
        )
        assert client.get(f"/api/projects/{pid}/failed-draft").status_code == 404
        assert client.get(f"/api/projects/{pid}/result").text == verified_result
        assert client.get(f"/api/projects/{pid}/export-current").status_code == 409


def test_ocr_package_contains_hash_verified_preserved_images():
    from fastapi.testclient import TestClient

    with tempfile.TemporaryDirectory() as tmp:
        store = ProjectStore(str(Path(tmp, "projects")))
        server_app._store = store
        server_app._process_jobs.clear()
        pid = store.create(
            r"\documentclass{book}\begin{document}source\end{document}",
            "ocr-assets",
            mode="ai",
            template="elegantbook",
            kind="ocr",
        )
        project_dir = Path(store._dir(pid))
        image = _png_bytes(b"real-png-resource")
        image_path = project_dir / "images" / "page_08_01.png"
        image_path.parent.mkdir(parents=True)
        image_path.write_bytes(image)
        meta_path = project_dir / "meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["ocr_resources"] = {
            "assets": [{
                "path": "images/page_08_01.png",
                "bytes": len(image),
                "sha256": hashlib.sha256(image).hexdigest(),
                "source_page": 8,
                "source_index": 1,
            }],
            "unresolved": [],
            "errors": [],
        }
        store._write_json(str(project_dir), "meta.json", meta)
        result = "\n".join(
            [
                r"\documentclass[lang=en,11pt]{elegantbook}",
                r"\usepackage{graphicx}",
                r"\begin{document}",
                r"\includegraphics{images/page_08_01}",
                r"\end{document}",
            ]
        )
        store.set_result(
            pid,
            result,
            "safe report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        client = TestClient(server_app.create_app())

        package = client.get(f"/api/projects/{pid}/export-package")
        assert package.status_code == 200, package.text
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            assert archive.read("images/page_08_01.png") == image

        current = client.get(f"/api/projects/{pid}/export-current")
        assert current.status_code == 200
        assert current.headers["x-latexstruct-verified"] == "true"
        current_package = client.get(f"/api/projects/{pid}/export-current-package")
        assert current_package.status_code == 200
        assert current_package.headers["x-latexstruct-verified"] == "true"
        with zipfile.ZipFile(io.BytesIO(current_package.content)) as archive:
            assert "LATEXSTRUCT-UNVERIFIED.txt" not in archive.namelist()

        image_path.write_bytes(b"tampered")
        blocked = client.get(f"/api/projects/{pid}/export-package")
        assert blocked.status_code == 409
        assert "校验失败" in blocked.json()["detail"]

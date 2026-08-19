# -*- coding: utf-8 -*-
"""Generic, source-faithful OCR book template tests (no model/network calls)."""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.faithfulbook import (  # noqa: E402
    FAITHFULBOOK_STYLE_MARKER,
    faithfulbook_style_asset_bytes,
    render_faithfulbook_style,
    resolve_faithfulbook_layout,
)
from latexstruct.core.patch import Decision, apply_patches, validate_ops  # noqa: E402
from latexstruct.core.template import (  # noqa: E402
    FAITHFULBOOK,
    build_template_ops,
    list_template_presets,
    normalize_template_id,
    uses_faithfulbook_style,
)


BOOK = r"""\documentclass[11pt]{book}
\usepackage{amsmath}
\begin{document}
% Page 21
\chapter{Graphs}
\section{Graphs and their representation}
Source text stays unchanged.
\clearpage
%=== PAGE BREAK === 第 2 段
% Page 22
\section{Subgraphs}
More source text.
\clearpage
%=== PAGE BREAK === 第 3 段
% Page 23
\chapter{Connected graphs}
Chapter-only text.
\end{document}
"""


def _apply(text=BOOK, context=None):
    ops, notes = build_template_ops(text, template=FAITHFULBOOK, context=context)
    planned, rejected = validate_ops(
        text.split("\n"),
        [(Decision(candidate_id="faithfulbook", action="none"), ops)],
    )
    assert not rejected, rejected[0].error if rejected else ""
    output, applied, patch_rejected = apply_patches(text.split("\n"), planned)
    assert not patch_rejected
    assert applied
    return "\n".join(output), notes


def test_faithfulbook_has_stable_public_template_id():
    assert normalize_template_id("faithfulbook") == FAITHFULBOOK
    assert FAITHFULBOOK in {item["id"] for item in list_template_presets()}
    preset = next(item for item in list_template_presets() if item["id"] == FAITHFULBOOK)
    assert preset["recommended_for"] == "ocr"


def test_faithfulbook_default_geometry_headers_and_source_page_boundaries():
    output, notes = _apply()

    assert output.startswith(r"\documentclass[10pt,twoside,openany]{book}")
    assert FAITHFULBOOK_STYLE_MARKER in output
    assert "paperwidth=155mm,paperheight=235mm" in output
    assert "inner=16mm,outer=14mm,top=15mm,bottom=17mm" in output
    assert r"\fontsize{10pt}{12pt}\selectfont" in output
    assert r"\begin{document}" + "\n" + r"\frontmatter" in output
    assert r"\LSMainMatter" + "\n" + r"\chapter{Graphs}" in output

    # Page breaks and inert source-page markers survive exactly; headers are
    # built from LaTeX marks/new pagination rather than copied OCR strings.
    assert output.count(r"\clearpage") == BOOK.count(r"\clearpage") == 2
    assert output.count("% Page ") == BOOK.count("% Page ") == 3
    assert r"\fancyhead[LO]" in output and r"\rightmark" in output
    assert r"\fancyhead[RE]" in output and r"\leftmark" in output
    header_block = output[output.index(r"\pagestyle{fancy}"):output.index(r"\titleformat{\chapter}")]
    assert "% Page" not in header_block
    assert "PAGE BREAK" not in header_block

    # Only the chapter with real section descendants gets a local TOC.
    assert output.count("\n\\LSChapterContents\n") == 1
    assert r"\localtableofcontents" in output
    assert any("完整保留 2 个源页" in item["reason"] for item in notes)
    assert any("不会把 OCR 页眉" in item["reason"] for item in notes)
    assert any("正文第 1 页" in item["reason"] for item in notes)


def test_faithfulbook_layout_uses_metadata_then_explicit_configuration():
    layout = resolve_faithfulbook_layout({
        "ocr_metadata": {
            "page_width_pt": 439.3700787,  # 155mm
            "page_height_pt": 666.1417323,  # 235mm
            "font_size_pt": 10,
            "margin_mm": 15,
        },
        "body_font_pt": 12,
        "layout": {
            "page_width_mm": 160,
            "inner_margin_mm": 17.5,
        },
    })

    assert layout.paper_width_mm == 160
    assert round(layout.paper_height_mm, 3) == 235
    assert layout.body_font_pt == 12
    assert layout.body_leading_pt == 14.4
    assert layout.inner_margin_mm == 17.5
    assert layout.outer_margin_mm == 15
    rendered = render_faithfulbook_style(layout)
    assert "paperwidth=160mm,paperheight=235mm" in rendered
    assert r"\fontsize{12pt}{14.4pt}\selectfont" in rendered
    assert "@@" not in rendered


def test_faithfulbook_rejects_invalid_or_injectable_numeric_layout():
    for context in (
        {"page_width_mm": r"155mm\input{bad}"},
        {"body_font_pt": 11},
        {"page_width_mm": 235, "page_height_mm": 155},
        {"margin_mm": 3},
    ):
        ops, notes = build_template_ops(BOOK, template=FAITHFULBOOK, context=context)
        assert ops == []
        assert notes[0]["status"] == "rejected"
        assert "faithfulbook" in notes[0]["reason"]


def test_faithfulbook_article_hierarchy_is_promoted_without_text_rewrite():
    article = r"""\documentclass{article}
\begin{document}
% Page 1
\section{First chapter}
\subsection{First section}
Body.
\clearpage
% Page 2
\section{Second chapter}
Body two.
\end{document}
"""
    output, _ = _apply(article)

    assert output.startswith(r"\documentclass[10pt,twoside,openany]{book}")
    assert r"\chapter{First chapter}" in output
    assert r"\section{First section}" in output
    assert r"\chapter{Second chapter}" in output
    assert output.count(r"\clearpage") == 1
    assert "Body." in output and "Body two." in output


def test_faithfulbook_consumes_verified_local_contents_marker_without_duplication():
    source = r"""\documentclass{book}
\begin{document}
\chapter{Graphs}

% LaTeXStruct-Local-Contents
Chapter lead text.
\clearpage
% Page 2
More text without parsed section commands yet.
\end{document}
"""
    output, notes = _apply(source)

    assert "% LaTeXStruct-Local-Contents" not in output
    assert output.count("\n\\LSChapterContents\n") == 1
    assert r"\localtableofcontents" in output
    assert output.count(r"\clearpage") == source.count(r"\clearpage")
    assert any("1 个章" in item["reason"] for item in notes)


def test_faithfulbook_frontmatter_is_roman_and_first_numbered_chapter_restarts_page_one():
    source = r"""\documentclass{book}
\begin{document}
\chapter*{Preface}
Front matter.
\tableofcontents
\clearpage
\chapter{Graphs}
\section{Foundations}
Body.
\end{document}
"""
    output, _ = _apply(source)

    assert output.index(r"\frontmatter") < output.index(r"\chapter*{Preface}")
    main_switch = output.index("\n\\LSMainMatter\n")
    assert main_switch < output.index(r"\chapter{Graphs}")
    assert main_switch > output.index(r"\tableofcontents")
    assert len(re.findall(r"(?m)^\\frontmatter$", output)) == 1
    assert len(re.findall(r"(?m)^\\LSMainMatter$", output)) == 1

    already = source.replace(
        r"\begin{document}",
        r"\begin{document}" + "\n" + r"\frontmatter",
    ).replace(r"\chapter{Graphs}", r"\mainmatter" + "\n" + r"\chapter{Graphs}")
    existing_output, _ = _apply(already)
    assert len(re.findall(r"(?m)^\\frontmatter$", existing_output)) == 1
    assert len(re.findall(r"(?m)^\\mainmatter$", existing_output)) == 1
    assert len(re.findall(r"(?m)^\\LSMainMatter$", existing_output)) == 0


def test_faithfulbook_consumes_safe_printed_page_markers_without_blank_pages():
    source = r"""\documentclass{book}
\begin{document}
Front title page.
\clearpage
% LaTeXStruct-Printed-Page: 1
\chapter{Graphs}
\section{Foundations}
First chapter.
\clearpage
% LaTeXStruct-Printed-Page: 451
\chapter{Edge Colourings}
Last chapter.
\end{document}
"""
    output, notes = _apply(source)

    assert "LaTeXStruct-Printed-Page" not in output
    assert output.count(r"\setcounter{page}{1}") == 1
    assert output.count(r"\setcounter{page}{451}") == 1
    assert output.count(r"\clearpage") == source.count(r"\clearpage") == 2
    assert (
        output.index(r"\LSMainMatter")
        < output.index(r"\setcounter{page}{1}")
        < output.index(r"\chapter{Graphs}")
    )
    assert (
        output.index(r"\setcounter{page}{451}")
        < output.index(r"\chapter{Edge Colourings}")
    )
    assert any("2 个可信印刷页码锚点" in item["reason"] for item in notes)

    # Applying the same stable template again is a no-op, so counters cannot
    # duplicate even when a caller retries import/export.
    ops, retry_notes = build_template_ops(output, template=FAITHFULBOOK)
    assert ops == []
    assert "已存在" in retry_notes[0]["reason"]


def test_faithfulbook_leaves_invalid_printed_page_markers_inert():
    source = r"""\documentclass{book}
\begin{document}
% LaTeXStruct-Printed-Page: 0
% LaTeXStruct-Printed-Page: 1000000
% LaTeXStruct-Printed-Page: 12\input{bad}
% LaTeXStruct-Printed-Page: -3
\chapter{Graphs}
Body.
\end{document}
"""
    output, notes = _apply(source)

    assert r"\setcounter{page}" not in output
    assert output.count("% LaTeXStruct-Printed-Page:") == 4
    assert any("4 个非法印刷页码 marker" in item["reason"] for item in notes)


def test_faithfulbook_mainmatter_transition_does_not_add_a_blank_page():
    from latexstruct.core.compilecheck import compile_latex

    source = r"""\documentclass{book}
\begin{document}
% Page 1
Front title page.
\clearpage
% Page 2
\chapter{Graphs}
Chapter body.
\end{document}
"""
    output, _ = _apply(source)
    assert output.count("\n\\LSFirstPageEmpty\n") == 1
    assert (
        output.index(r"\LSFirstPageEmpty")
        < output.index("Front title page.")
        < output.index(r"\clearpage")
        < output.index(r"\chapter{Graphs}")
    )
    compiled = compile_latex(output)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]
        assert compiled["pages"] == 2


def test_faithfulbook_first_page_empty_hook_does_not_strip_a_direct_first_chapter():
    direct_chapter = r"""\documentclass{book}
\begin{document}
\chapter{Graphs}
Chapter body.
\end{document}
"""
    direct_output, direct_notes = _apply(direct_chapter)

    assert "\n\\LSFirstPageEmpty\n" not in direct_output
    assert not any("empty 页式" in item["reason"] for item in direct_notes)

    frontmatter = r"""\documentclass{book}
\begin{document}
\chapter*{Preface}
Front matter text.
\chapter{Graphs}
Chapter body.
\end{document}
"""
    front_output, front_notes = _apply(frontmatter)
    assert front_output.count("\n\\LSFirstPageEmpty\n") == 1
    assert any("empty 页式" in item["reason"] for item in front_notes)


def test_faithfulbook_is_idempotent_and_rejects_non_book_classes():
    first, _ = _apply()
    ops, notes = build_template_ops(first, template=FAITHFULBOOK)
    assert ops == []
    assert "已存在" in notes[0]["reason"]
    assert uses_faithfulbook_style(first)

    beamer = "\\documentclass{beamer}\n\\begin{document}\nText\n\\end{document}\n"
    ops, notes = build_template_ops(beamer, template=FAITHFULBOOK)
    assert ops == []
    assert notes[0]["status"] == "rejected"
    assert "安全转换名单" in notes[0]["reason"]


def test_faithfulbook_asset_is_bundled_and_verified():
    data = faithfulbook_style_asset_bytes()
    assert data.startswith(FAITHFULBOOK_STYLE_MARKER.encode("utf-8"))
    assert b"\\localtableofcontents" in data
    assert b"OCR running head" in data
    # Both chapter-contents rules start without paragraph indentation; otherwise
    # the closing rule is exactly one \parindent wider than the text block.
    assert data.count(b"\\noindent\\color{LSBookRule}\\rule{\\linewidth}") == 2


def test_faithfulbook_compiles_when_xelatex_is_available():
    from latexstruct.core.compilecheck import compile_latex

    source = r"""\documentclass[11pt]{book}
\usepackage{amsmath}
\usepackage{amsthm}
\usepackage{algorithm}
\usepackage{algpseudocode}
\newtheorem{theorem}{Theorem}[chapter]
\begin{document}
\tableofcontents
\chapter{Graphs}
\section{Definitions}
\begin{theorem}Every tree is a graph.\end{theorem}
\begin{proof}Immediate.\end{proof}
\begin{algorithm}
\caption{Breadth-first search}
\begin{algorithmic}\State Visit a vertex.\end{algorithmic}
\end{algorithm}
\clearpage
% Page 2
Second source page.
\end{document}
"""
    output, _ = _apply(source)
    compiled = compile_latex(output)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]
        assert compiled["pages"] >= 2


def test_faithfulbook_explicit_theorem_notes_render_as_unparenthesized_source_numbers():
    from latexstruct.core.compilecheck import find_xelatex

    source = r"""\documentclass{book}
\begin{document}
\chapter{Flows}
Placeholder.
\end{document}
"""
    output, _ = _apply(source)
    declarations = r"""\theoremstyle{plain}
\newtheorem*{theorem}{Theorem}
\newtheorem*{proposition}{Proposition}
"""
    body = r"""\chapter{Flows}
\begin{theorem}[7.7]
\textsc{The Max--Flow Min--Cut Theorem}. In any network, the value is optimal.
\end{theorem}
\begin{proposition}[4.2]
Every nontrivial tree has at least two leaves.
\end{proposition}
\begin{theorem}
An ordinary unnumbered theorem remains ordinary.
\end{theorem}
"""
    output = output.replace(r"\begin{document}", declarations + r"\begin{document}", 1)
    output = output.replace(r"\chapter{Flows}" + "\nPlaceholder.", body, 1)

    assert r"\thmnote{ #3}" in output
    assert r"\textsc{The Max--Flow Min--Cut Theorem}" in output
    exe = find_xelatex()
    if not exe:
        return

    with tempfile.TemporaryDirectory(prefix="ls-faithfulbook-theorem-") as tmp:
        tex_path = Path(tmp) / "main.tex"
        tex_path.write_text(output, encoding="utf-8")
        proc = subprocess.run(
            [exe, "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=tmp,
            capture_output=True,
            timeout=240,
        )
        assert proc.returncode == 0, (Path(tmp) / "main.log").read_text(
            encoding="utf-8", errors="replace"
        )[-4000:]

        try:
            import fitz
        except ImportError:
            return
        with fitz.open(str(Path(tmp) / "main.pdf")) as document:
            page = document[0]
            compact = re.sub(r"\s+", " ", page.get_text()).strip()
            assert "Theorem 7.7." in compact
            assert "Proposition 4.2." in compact
            assert "Theorem (7.7)" not in compact
            assert "Proposition (4.2)" not in compact
            assert "Theorem. An ordinary" in compact

            # PDF producers may split a visually continuous heading or phrase
            # into several adjacent spans.  Locate the rendered line by its
            # concatenated text, then verify that the expected face occurs in
            # one of that line's constituent spans.
            visual_lines = [
                line.get("spans", [])
                for block in page.get_text("dict")["blocks"]
                for line in block.get("lines", [])
                if line.get("spans")
            ]

            def matching_line(pattern):
                return next(
                    spans
                    for spans in visual_lines
                    if re.search(
                        pattern,
                        re.sub(r"\s+", " ", "".join(
                            str(span.get("text", "")) for span in spans
                        )),
                        re.I,
                    )
                )

            theorem_line = matching_line(r"Theorem\s*7\.7")
            proposition_line = matching_line(r"Proposition\s*4\.2")
            proposition_body_line = matching_line(r"nontrivial\s+tree")
            caps_title_line = matching_line(r"Max.*Flow.*Min.*Cut")

            assert any("Bold" in span["font"] for span in theorem_line)
            assert any("Bold" in span["font"] for span in proposition_line)
            assert any("Italic" in span["font"] for span in proposition_body_line)
            assert any("Caps" in span["font"] for span in caps_title_line)


def main():
    import traceback

    tests = [
        (name, value)
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except Exception:
            failed += 1
            print("FAIL", name)
            traceback.print_exc()
    print(f"{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()

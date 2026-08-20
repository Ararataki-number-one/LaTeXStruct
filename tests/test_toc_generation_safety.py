# -*- coding: utf-8 -*-
"""Global-TOC generation and OCR content-preservation regressions."""

from latexstruct.core.ocrstruct import (
    build_ocr_structure_ops,
    check_ocr_structure,
    encode_ocr_metadata,
)
from latexstruct.core.patch import Decision, apply_patches, validate_ops
from latexstruct.core.template import (
    ELEGANTBOOK,
    FAITHFULBOOK,
    build_template_ops,
)


def _apply_ops(text, ops, candidate_id="test"):
    lines = text.split("\n")
    planned, rejected = validate_ops(
        lines,
        [(Decision(candidate_id=candidate_id, action="none"), ops)],
    )
    assert not rejected, rejected[0].error if rejected else ""
    out, _applied, patch_rejected = apply_patches(lines, planned)
    assert not patch_rejected
    return "\n".join(out)


def _apply_template(text, template):
    ops, notes = build_template_ops(text, template=template)
    return _apply_ops(text, ops, candidate_id=f"template-{template}"), notes


def test_elegantbook_generates_exactly_one_toc_from_numbered_article_structure():
    source = r"""\documentclass{article}
\begin{document}
Article title and abstract remain before the directory.
\section{First result}
First body.
\subsection{Details}
Details body.
\section{Second result}
Second body.
\section*{REFERENCES}
\addcontentsline{toc}{section}{REFERENCES}
References body.
\end{document}
"""
    output, notes = _apply_template(source, ELEGANTBOOK)

    assert output.count(r"\tableofcontents") == 1
    assert output.index("Article title and abstract") < output.index(r"\tableofcontents")
    assert output.index(r"\tableofcontents") < output.index(r"\chapter{First result}")
    assert (
        r"\frontmatter" + "\n" + r"\tableofcontents" + "\n"
        + r"\clearpage" + "\n" + r"\mainmatter"
    ) in output
    assert r"\chapter*{REFERENCES}" in output
    assert r"\addcontentsline{toc}{chapter}{REFERENCES}" in output
    assert r"\addcontentsline{toc}{section}{REFERENCES}" not in output
    assert any("唯一的全局目录" in item["reason"] for item in notes)

    retry, _retry_notes = _apply_template(output, ELEGANTBOOK)
    assert retry == output


def test_faithfulbook_generates_one_toc_and_is_idempotent():
    source = r"""\documentclass{book}
\begin{document}
Front title.
\chapter{First}
Body one.
\chapter{Second}
Body two.
\end{document}
"""
    output, _notes = _apply_template(source, FAITHFULBOOK)
    assert output.count(r"\tableofcontents") == 1
    assert (
        r"\tableofcontents" + "\n" + r"\clearpage" + "\n"
        + r"\LSMainMatter" + "\n" + r"\chapter{First}"
    ) in output

    retry_ops, _retry_notes = build_template_ops(output, template=FAITHFULBOOK)
    assert retry_ops == []


def test_duplicate_toc_commands_collapse_but_manual_directory_is_not_duplicated():
    duplicated = r"""\documentclass{article}
\begin{document}
\tableofcontents
\tableofcontents
\section{First}
Body.
\section{Second}
Body.
\end{document}
"""
    deduplicated, notes = _apply_template(duplicated, ELEGANTBOOK)
    assert deduplicated.count(r"\tableofcontents") == 1
    assert any("重复的全局目录" in item["reason"] for item in notes)

    manual = r"""\documentclass{article}
\begin{document}
Contents
First result \dotfill 1
Second result \dotfill 2
References \dotfill 3
\section{First result}
Body.
\section{Second result}
Body.
\end{document}
"""
    preserved, manual_notes = _apply_template(manual, ELEGANTBOOK)
    assert r"\tableofcontents" not in preserved
    assert preserved.count(r"\dotfill") == 3
    assert any("手排目录" in item["reason"] for item in manual_notes)


def test_two_row_manual_toc_blocks_auto_toc_but_contents_prose_does_not():
    manual = r"""\documentclass{article}
\begin{document}
Contents
First result \dotfill 1
Second result \dotfill 2
\section{First result}
Body.
\section{Second result}
Body.
\end{document}
"""
    preserved, manual_notes = _apply_template(manual, ELEGANTBOOK)
    assert r"\tableofcontents" not in preserved
    assert preserved.count(r"\dotfill") == 2
    assert any("手排目录" in item["reason"] for item in manual_notes)

    prose = r"""\documentclass{article}
\begin{document}
Contents
This paragraph discusses the contents of the two results without listing pages.
\section{First result}
Body.
\section{Second result}
Body.
\end{document}
"""
    generated, prose_notes = _apply_template(prose, ELEGANTBOOK)
    assert generated.count(r"\tableofcontents") == 1
    assert "This paragraph discusses the contents" in generated
    assert any("唯一的全局目录" in item["reason"] for item in prose_notes)


def test_repeated_theorem_math_tails_survive_while_true_running_heads_are_removed():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "First result", "page": 7},
            {"level": 0, "title": "Second result", "page": 8},
        ],
        "article",
        [7, 8],
        False,
    )
    tail = r"\textit{as $d \to \infty$.}"
    source = "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsmath}",
        r"\usepackage{amssymb}",
        r"\begin{document}",
        metadata,
        r"% Page 7",
        "Graph Theory",
        r"\section{First result}",
        r"\textbf{Theorem 2.3.} Statement.",
        r"\[",
        r"\alpha(G) \ge (1+o(1))n/d",
        r"\]",
        tail,
        r"\clearpage",
        r"%=== PAGE BREAK === 2",
        r"% Page 8",
        "Graph Theory",
        r"\section{Second result}",
        r"\textbf{Theorem 2.6.} Statement.",
        r"\[",
        r"\mathbb{E}|S| \ge (1+o(1))n/d",
        r"\]",
        tail,
        r"\end{document}",
    ])

    ops, notes = build_ocr_structure_ops(source)
    assert not any(op.kind == "delete_line" and op.old == tail for op in ops)
    result = _apply_ops(source, ops, candidate_id="ocr-content-safety")
    assert result.count(tail) == 2
    assert "Graph Theory" not in result
    assert sum(item.get("status") == "removed-header" for item in notes) == 2


def test_display_math_blank_lines_are_removed_without_changing_math_tokens():
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "First", "page": 1}],
        "article",
        [1],
        False,
    )
    source = "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsmath}",
        r"\usepackage{amssymb}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\section{First}",
        r"\begin{equation}",
        r"R(k) \leqslant 4^k",
        "",
        r"\tag{1}",
        r"\end{equation}",
        "",
        "Outside paragraph.",
        r"\[",
        "",
        r"x=y",
        "",
        r"\]",
        r"\end{document}",
    ])
    ops, notes = build_ocr_structure_ops(source)
    blank_deletes = [op for op in ops if op.kind == "delete_line" and op.old == ""]
    assert len(blank_deletes) == 3
    result = _apply_ops(source, ops, candidate_id="display-spacing")
    assert "R(k) \\leqslant 4^k\n\\tag{1}" in result
    assert r"\end{equation}" + "\n\nOutside paragraph." in result
    assert r"x=y" in result
    assert sum(
        item.get("status") == "normalized-display-spacing" for item in notes
    ) == 3

    retry_ops, _retry_notes = build_ocr_structure_ops(result)
    assert not any(
        op.kind == "delete_line" and op.old == "" for op in retry_ops
    )

    from latexstruct.core.compilecheck import compile_latex

    compiled = compile_latex(result)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]


def test_publication_template_gate_requires_generated_toc_from_pdf_outline():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "First", "page": 1},
            {"level": 0, "title": "Second", "page": 2},
        ],
        "article",
        [1, 2],
        False,
    )
    without_toc = "\n".join([
        r"\documentclass[lang=en,11pt]{elegantbook}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\chapter{First}",
        r"\clearpage",
        r"%=== PAGE BREAK === 2",
        r"% Page 2",
        r"\chapter{Second}",
        r"\end{document}",
    ])
    failed = check_ocr_structure(without_toc)
    assert failed["toc_expected"] is True
    assert failed["ok"] is False
    assert any(r"\tableofcontents" in issue["reason"] for issue in failed["issues"])

    with_toc = without_toc.replace(
        metadata,
        metadata + "\n" + r"\tableofcontents",
        1,
    )
    passed = check_ocr_structure(with_toc)
    assert passed["ok"] is True, passed["issues"]

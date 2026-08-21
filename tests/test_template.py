# -*- coding: utf-8 -*-
"""模板转换（elegantbook）测试。"""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.ocrstruct import encode_ocr_metadata  # noqa: E402
from latexstruct.core.patch import Decision, apply_patches, validate_ops  # noqa: E402
from latexstruct.core.template import (  # noqa: E402
    ELEGANTBOOK,
    FAITHFULBOOK,
    PRESERVE_SOURCE,
    PROFESSIONAL_HANDOUT,
    build_template_ops,
    list_template_presets,
    normalize_template_id,
    uses_elegantbook_class,
)
from latexstruct.core.verify import check_env_balance  # noqa: E402

SYNTHETIC = """\\documentclass[10pt]{article}
\\usepackage[verbose, a4paper, hmargin=2.5cm, vmargin=2.5cm]{geometry}
\\usepackage{fontspec}
\\usepackage{ctex}
\\usepackage{amsmath}
\\usepackage[most]{tcolorbox}
\\newcommand*\\circled[1]{\\tikz[baseline=(char.base)]{\\node[shape=circle,draw,inner sep=1.5pt] (char) {\\small #1};}}

\\begin{document}

\\section*{Preface}

\\begin{tcolorbox}\\relax
\\section*{前言}
\\end{tcolorbox}

Some preface text.

\\section*{Contents}

\\begin{tcolorbox}\\relax
\\section*{目录}
\\end{tcolorbox}

\\section*{Preface}

\\begin{tcolorbox}\\relax
\\section*{前言}
\\end{tcolorbox}

vii

1 Graphs 1

\\begin{tcolorbox}\\relax
1 图 1
\\end{tcolorbox}

1.1 Graphs 1

\\begin{tcolorbox}\\relax
1.1 图 1
\\end{tcolorbox}

\\section*{1 Graphs}

\\begin{tcolorbox}\\relax
\\section*{1 图}
\\end{tcolorbox}

\\section*{1.1 Graphs}

\\begin{tcolorbox}\\relax
\\section*{1.1 图}
\\end{tcolorbox}

Theorem 1.1. A statement.

Proof. First step.

Then the second step.

\\end{document}
"""


def test_build_template_ops():
    ops, notes = build_template_ops(SYNTHETIC)
    kinds = [op.kind for op in ops]
    assert "replace_line" in kinds and "delete_line" in kinds and "insert_line" in kinds
    # documentclass 替换
    dc = next(op for op in ops if "documentclass" in op.old)
    assert dc.new == "\\documentclass[lang=cn,scheme=chinese,11pt]{elegantbook}"
    # geometry/ctex/tcolorbox/\circled 删除（elegantbook 自带，避免选项冲突）
    assert any("geometry" in op.old for op in ops if op.kind == "delete_line")
    assert any("ctex" in op.old for op in ops if op.kind == "delete_line")
    assert any("tcolorbox" in op.old for op in ops if op.kind == "delete_line")
    assert any("circled" in op.old for op in ops if op.kind == "delete_line")
    # 没有 OCR 大纲证据时不得凭数字标题删除/伪造目录。
    assert not any(op.new == "\\tableofcontents" for op in ops)
    assert not any(op.kind == "delete_line" and "vii" in op.old for op in ops)
    # article 的已解析标题层级整体上移；不再用 refstepcounter 伪造章号。
    ch = [op for op in ops if "\\chapter*{1 Graphs}" == op.new]
    assert len(ch) == 1
    assert not any(op.new == "\\refstepcounter{chapter}" for op in ops)
    assert any("\\elegantnewtheorem{remark}" in op.new for op in ops)


def test_pipeline_with_elegantbook_template():
    res = run_pipeline(SYNTHETIC, mode="rule", template="elegantbook")
    assert res.ok, res.report_md
    out = res.result
    assert "\\documentclass[lang=cn,scheme=chinese,11pt]{elegantbook}" in out
    assert uses_elegantbook_class(out)
    assert "geometry" not in out.split("\\begin{document}")[0]
    assert "\\usepackage{ctex}" not in out
    assert "\\tableofcontents" not in out
    # 没有 PDF 大纲证据时旧目录逐字保留，交给审阅而不是猜测删除边界。
    assert "1 Graphs 1" in out
    assert "vii" in out
    # article 层级适配成 book 章级命令；不再额外推进章计数器。
    assert "\\chapter*{1 Graphs（1 图）}" in out
    assert "\\refstepcounter{chapter}" not in out
    assert "\\addcontentsline{toc}{chapter}{1 Graphs（1 图）}" in out
    assert "\\addcontentsline{toc}{chapter}{1.1 Graphs（1.1 图）}" in out
    # elegantbook：不补 amsthm
    assert "\\usepackage{amsthm}" not in out
    # 原书编号作为 ElegantBook 无编号色块的标题参数，只显示一套编号。
    assert "\\begin{theorem*}[1.1]" in out
    assert "Theorem 1.1. A statement." not in out
    assert not any("避免双编号" in item["reason"] for item in res.ambiguous)
    # 证明覆盖整段（Then 续段并入）
    i1 = out.index("\\begin{proof}")
    i2 = out.index("\\end{proof}")
    assert i1 < out.index("First step") < i2
    assert i1 < out.index("Then the second step") < i2
    assert res.verification["content_invariant"] is True
    assert res.verification["env_balance"]["ok"] is True


def test_template_without_contents():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "\\section*{1 Graphs}\n\nbody\n\\end{document}\n"
    )
    res = run_pipeline(text, mode="rule", template="elegantbook")
    assert res.ok, res.report_md
    out = res.result
    assert "\\tableofcontents" not in out  # 不凭数字标题臆造目录
    assert "\\chapter*{1 Graphs}" in out


def test_template_verification_covers_original_and_preserves_crlf_export():
    text = (
        "\\documentclass{article}\r\n\\begin{document}\r\n"
        "\\section*{1 Graphs}\r\n\r\nTheorem 1. X.\r\n\\end{document}\r\n"
    )
    res = run_pipeline(text, mode="rule", template="elegantbook")
    assert res.ok, res.report_md
    assert res.original.startswith("\\documentclass{article}\n")
    assert res.verification["content_invariant"] is True
    assert "\r\n" in res.export_text and "\n" not in res.export_text.replace("\r\n", "")
    assert "\\begin{theorem*}[1]" in res.result
    assert not any("避免双编号" in item["reason"] for item in res.ambiguous)


def test_template_ops_env_balance():
    ops, notes = build_template_ops(SYNTHETIC)
    from latexstruct.core.patch import Decision, apply_patches, validate_ops

    lines = SYNTHETIC.split("\n")
    ok, rejected = validate_ops(lines, [(Decision(candidate_id="tpl", action="none"), ops)])
    assert not rejected, rejected[0].error if rejected else ""
    out, _, _ = apply_patches(lines, ok)
    assert check_env_balance("\n".join(out))["ok"] is True


def test_professional_handout_is_fixed_reversible_style_layer():
    text = """\\documentclass{article}
\\usepackage{amsmath}
\\title{Ramsey Theory}
\\author{Lecture Notes}
\\begin{document}
\\maketitle
\\tableofcontents
\\section{Foundations}

Theorem. Every finite graph has a Ramsey number.

Proof. This is a test.
\\end{document}
"""
    res = run_pipeline(text, mode="rule", template=PROFESSIONAL_HANDOUT)
    assert res.ok, res.report_md
    assert "\\documentclass{article}" in res.result
    assert "% LaTeXStruct template: professional-handout begin" in res.result
    assert "\\titleformat{\\section}" in res.result
    assert "\\pagestyle{latexstructhandout}" in res.result
    assert "\\tcolorboxenvironment{#1}" in res.result
    assert "\\renewcommand{\\maketitle}" in res.result
    assert "\\tableofcontents\n\\clearpage" in res.result
    assert "\\begin{theorem}" in res.result
    assert "Every finite graph has a Ramsey number." in res.result
    assert res.verification["content_invariant"] is True
    assert "模板排版（专业讲义（旧项目））" in res.report_md


def test_professional_handout_uses_escaped_project_title_without_inventing_body():
    text = """\\documentclass{article}
\\begin{document}
Body stays byte-for-byte.
\\end{document}
"""
    res = run_pipeline(
        text,
        mode="rule",
        template=PROFESSIONAL_HANDOUT,
        template_context={
            "title": "Graphs & Proofs_100%",
            "title_policy": "project",
        },
    )
    assert res.ok, res.report_md
    assert r"Graphs \& Proofs\_100\%" in res.result
    assert "Professional Lecture Notes" in res.result
    assert "Body stays byte-for-byte." in res.result
    assert res.verification["content_invariant"] is True


def test_professional_handout_is_source_first_unless_project_title_is_explicit():
    text = """\\documentclass{article}
\\begin{document}
\\begin{center}
\\textbf{THE SOURCE TITLE}
\\end{center}
Body.
\\end{document}
"""
    ops, notes = build_template_ops(
        text,
        template=PROFESSIONAL_HANDOUT,
        context={"title": "OCR"},
    )
    inserted = "\n".join(op.new for op in ops)

    assert r"\\title{OCR}" not in inserted
    assert r"\\maketitle" not in inserted
    assert not any("OCR" in op.new for op in ops)
    assert any("source-first" in item["reason"] for item in notes)


def test_professional_handout_skips_unsupported_class_and_custom_boxes():
    beamer = "\\documentclass{beamer}\n\\begin{document}\nText\n\\end{document}\n"
    ops, notes = build_template_ops(beamer, template=PROFESSIONAL_HANDOUT)
    assert ops == []
    assert "安全名单" in notes[0]["reason"]

    custom = """\\documentclass{article}
\\usepackage{tcolorbox}
\\newtcbtheorem{theorem}{Theorem}{}{}
\\begin{document}
Text
\\end{document}
"""
    ops, _ = build_template_ops(custom, template=PROFESSIONAL_HANDOUT)
    inserted = "\n".join(op.new for op in ops)
    assert r"\LSHandoutStyleEnv{theorem}{LSBlue}" not in inserted
    assert r"\LSHandoutStyleEnv{lemma}{LSBlue}" in inserted

    ctex = "\\documentclass{ctexart}\n\\begin{document}\n正文\n\\end{document}\n"
    ops, _ = build_template_ops(
        ctex,
        template=PROFESSIONAL_HANDOUT,
        context={"title": "图论专题讲义", "title_policy": "project"},
    )
    inserted = "\n".join(op.new for op in ops)
    assert "专业讲义" in inserted
    assert r"\usepackage{titlesec}" not in inserted


def test_ocr_publication_is_source_first_and_reflows_37_page_merge_boundaries():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "1. Introduction", "page": 1},
            {"level": 0, "title": "2. Upper bounds", "page": 19},
        ],
        "article",
        range(1, 38),
        False,
    )
    lines = [
        r"\documentclass[11pt]{article}",
        r"\usepackage{amsmath}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"\begin{center}",
        r"\textbf{SOME RECENT RESULTS IN RAMSEY THEORY}",
        r"\end{center}",
        r"\begin{center}",
        r"ROBERT MORRIS",
        r"\end{center}",
        r"\section{1. Introduction}",
        "Source body page 1.",
    ]
    for page in range(2, 38):
        lines.extend([
            r"\clearpage",
            f"%=== PAGE BREAK === 第 {page} 段",
            f"% Page {page}",
        ])
        if page == 19:
            lines.append(r"\section{2. Upper bounds}")
        lines.append(f"Source body page {page}.")
    lines.extend([r"\end{document}", ""])
    source = "\n".join(lines)

    ops, notes = build_template_ops(
        source,
        template=ELEGANTBOOK,
        context={"title": "OCR"},
    )
    planned, rejected = validate_ops(
        source.split("\n"),
        [(Decision(candidate_id="template", action="none"), ops)],
    )
    assert not rejected, rejected[0].error if rejected else ""
    output_lines, _, patch_rejected = apply_patches(source.split("\n"), planned)
    assert not patch_rejected
    output = "\n".join(output_lines)

    # The visible source cover is authoritative; a project label such as
    # "OCR" cannot silently become a second title page.
    assert r"\title{OCR}" not in output
    assert r"\maketitle" not in output
    assert output.count("SOME RECENT RESULTS IN RAMSEY THEORY") == 1
    assert output.count("ROBERT MORRIS") == 1

    # All 36 merger-owned hard breaks are removed.  The sole remaining break
    # is the template-owned global-TOC/main-matter transition.
    assert source.count(r"\clearpage") == 36
    assert output.count(r"\clearpage") == 1
    assert output.count("% Page ") == 37
    assert output.count("%=== PAGE BREAK ===") == 36
    assert output.count(r"\tableofcontents") == 1
    assert any("移除 36 个" in item["reason"] for item in notes)
    assert any("source-first" in item["reason"] for item in notes)

    preserve_ops, _ = build_template_ops(
        source,
        template=ELEGANTBOOK,
        context={"title": "OCR", "pagination_policy": "preserve"},
    )
    preserve_planned, preserve_rejected = validate_ops(
        source.split("\n"),
        [(Decision(candidate_id="template", action="none"), preserve_ops)],
    )
    assert not preserve_rejected
    preserve_lines, _, preserve_patch_rejected = apply_patches(
        source.split("\n"), preserve_planned,
    )
    assert not preserve_patch_rejected
    preserve_output = "\n".join(preserve_lines)
    assert preserve_output.count(r"\clearpage") == 37

    # The same provenance rule is shared by both other publication renderers;
    # no template gets a separate, looser definition of an OCR page break.
    for related_template in (PROFESSIONAL_HANDOUT, FAITHFULBOOK):
        related_ops, _ = build_template_ops(
            source,
            template=related_template,
            context={"title": "OCR"},
        )
        deleted_boundaries = [
            op for op in related_ops
            if op.kind == "delete_line" and op.old == r"\clearpage"
        ]
        assert len(deleted_boundaries) == 36
        assert not any(op.new == r"\title{OCR}" for op in related_ops)


def test_ordinary_tex_preserves_author_page_breaks_by_default():
    source = """\\documentclass{article}
\\begin{document}
\\section{One}
Text.
\\clearpage
% Page 2
\\section{Two}
More text.
\\end{document}
"""
    ops, _ = build_template_ops(source, template=ELEGANTBOOK)

    assert not any(
        op.kind == "delete_line" and op.old == r"\clearpage"
        for op in ops
    )

    marker_only = source.replace(
        "% Page 2",
        "%=== PAGE BREAK === legacy merger evidence",
    )
    semantic_ops, _ = build_template_ops(
        marker_only,
        template=ELEGANTBOOK,
        context={"pagination_policy": "semantic"},
    )
    assert sum(
        op.kind == "delete_line" and op.old == r"\clearpage"
        for op in semantic_ops
    ) == 1


def test_elegantbook_rejects_incompatible_document_classes_fail_closed():
    for document_class in ("beamer", "letter"):
        text = (
            f"\\documentclass{{{document_class}}}\n"
            "\\begin{document}\nText\n\\end{document}\n"
        )
        ops, notes = build_template_ops(text, template=ELEGANTBOOK)

        assert ops == []
        assert notes[0]["status"] == "rejected"
        assert "安全转换名单" in notes[0]["reason"]
        result = run_pipeline(text, mode="rule", template=ELEGANTBOOK)
        assert result.ok is False
        assert result.verification["template"]["ok"] is False
        assert result.verification["safe_to_export"] is False
        assert result.result == text


def test_template_compile_uses_pre_template_source_and_requires_final_success():
    text = "\\documentclass{article}\n\\begin{document}\nText\n\\end{document}\n"
    failed = {
        "available": True,
        "ok": False,
        "pages": 0,
        "errors": ["Undefined control sequence"],
        "log": "",
    }
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        return_value=failed,
    ) as compile_latex:
        result = run_pipeline(
            text,
            mode="rule",
            template=ELEGANTBOOK,
        )

    assert compile_latex.call_count == 2
    before_call, after_call = compile_latex.call_args_list
    assert before_call.args[0] == text
    assert "\\documentclass[lang=en,11pt]{elegantbook}" in after_call.args[0]
    assert result.ok is False
    assert result.verification["compile"]["ok"] is False
    assert result.verification["safe_to_export"] is False


def test_template_registry_and_professional_idempotence():
    presets = list_template_presets()
    assert {item["id"] for item in presets} == {
        PRESERVE_SOURCE, FAITHFULBOOK, ELEGANTBOOK,
    }
    assert all(item["qa_profile"] in {"structural", "publication"} for item in presets)
    assert next(item for item in presets if item["id"] == PRESERVE_SOURCE)[
        "layout_change"
    ] is False
    faithful = next(item for item in presets if item["id"] == FAITHFULBOOK)
    assert faithful["layout_change"] is True
    assert faithful["qa_profile"] == "publication"
    assert "保证" in faithful["description"]
    assert all("bondy" not in str(item).lower() for item in presets)
    assert normalize_template_id(None) == PRESERVE_SOURCE
    assert normalize_template_id(PROFESSIONAL_HANDOUT) == PROFESSIONAL_HANDOUT
    try:
        normalize_template_id("free-form-ai-preamble")
    except ValueError as exc:
        assert "未知排版模板" in str(exc)
    else:
        raise AssertionError("未知模板必须被拒绝")

    text = "\\documentclass{article}\n\\begin{document}\nText\n\\end{document}\n"
    first = run_pipeline(text, template=PROFESSIONAL_HANDOUT)
    second = run_pipeline(first.result, template=PROFESSIONAL_HANDOUT)
    assert second.result.count("LaTeXStruct template: professional-handout begin") == 1


def test_elegantbook_preserves_real_chapter_toc_and_is_idempotent():
    text = """\\documentclass{book}
\\title{Ramsey Theory}
\\begin{document}
\\tableofcontents
\\chapter{Diagonal Ramsey Numbers}
\\section{The probabilistic method}

Theorem 2.4. A source-numbered statement.

Remark. The original numbering must not be duplicated.
\\end{document}
"""
    first = run_pipeline(text, mode="rule", template=ELEGANTBOOK)
    assert first.ok, first.report_md
    assert "\\chapter{Diagonal Ramsey Numbers}" in first.result
    assert "\\section{The probabilistic method}" in first.result
    assert "% LaTeXStruct: clean ElegantBook title page" in first.result
    assert "example-image" not in first.result
    assert "\\frontmatter\n\\tableofcontents" in first.result
    assert "\\tableofcontents\n\\clearpage" in first.result
    assert "\\clearpage\n\\mainmatter" in first.result
    assert "\\refstepcounter{chapter}" not in first.result
    assert "\\begin{theorem*}[2.4]" in first.result
    assert "\\begin{remark*}" in first.result
    assert first.result.count("LaTeXStruct template: elegantbook v4.7") == 1

    second = run_pipeline(first.result, mode="rule", template=ELEGANTBOOK)
    assert second.ok, second.report_md
    assert second.result == first.result
    assert second.result.count("\\documentclass") == 1
    assert second.result.count("\\elegantnewtheorem{remark}") == 1
    assert second.result.count("LaTeXStruct: clean ElegantBook title page") == 1


def test_elegantbook_article_hierarchy_moves_up_without_number_guessing():
    text = """\\documentclass{article}
\\begin{document}
\\section{First}
\\subsection{First detail}
\\subsubsection{Fine point}
\\end{document}
"""
    result = run_pipeline(text, template=ELEGANTBOOK)
    assert result.ok, result.report_md
    assert "\\chapter{First}" in result.result
    assert "\\section{First detail}" in result.result
    assert "\\subsection{Fine point}" in result.result
    assert "\\tableofcontents" not in result.result


def test_professional_handout_compiles_when_xelatex_is_available():
    from latexstruct.core.compilecheck import compile_latex

    text = """\\documentclass{article}
\\begin{document}
\\section{One}
Definition. A graph is a pair of sets.

Theorem. The first result holds.

Proof. Immediate.
\\end{document}
"""
    result = run_pipeline(
        text,
        template=PROFESSIONAL_HANDOUT,
        template_context={"title": "A Short Course in Graph Theory"},
    )
    compiled = compile_latex(result.result)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]


def test_professional_handout_preserves_book_chapters_and_toc_semantics():
    from latexstruct.core.compilecheck import compile_latex

    text = """\\documentclass{book}
\\title{Algebraic Graph Theory}
\\begin{document}
\\maketitle
\\tableofcontents
\\chapter{Spectra of Graphs}
\\section{Adjacency matrices}
Theorem. Every real symmetric adjacency matrix is diagonalizable.
\\end{document}
"""
    result = run_pipeline(text, template=PROFESSIONAL_HANDOUT)
    assert result.ok, result.report_md
    assert "\\documentclass{book}" in result.result
    assert "\\titleformat{\\chapter}[display]" in result.result
    assert "\\chapter{Spectra of Graphs}" in result.result
    assert "\\tableofcontents\n\\clearpage" in result.result
    assert result.verification["content_invariant"] is True
    compiled = compile_latex(result.result)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]


def main():
    import traceback

    tests = [
        (k, v)
        for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()

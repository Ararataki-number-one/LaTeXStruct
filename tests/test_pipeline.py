# -*- coding: utf-8 -*-
"""流水线端到端测试（规则模式 / 无 Key 降级）。"""

import hashlib
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.patch import Decision, PatchContext, build_ops  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import resolve_overlaps, run_pipeline  # noqa: E402
from latexstruct.core.rules import build_rule_decisions  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def test_basic_book_fast_mode():
    res = run_pipeline(read_sample("basic_book.tex"), mode="rule")
    assert res.ok, res.report_md
    out = res.result
    # 新增环境包裹
    for env in ("definition", "theorem", "remark", "proof"):
        assert f"\\begin{{{env}}}" in out, env
    # 编号提取：编号进可选参数，标题词条从前缀剥离
    assert "\\begin{theorem}[2.3.4]" in out
    assert "Theorem 2.3.4" not in out
    assert "\\begin{definition}[1.1.1]" in out
    assert "Definition 1.1.1" not in out
    # 无编号条目也剥离重复标题词条，但保留其后的正文
    assert "This is a short note" in out
    assert "Remark. This is a short note" not in out
    # proof 起始语剥离 + 整段证明覆盖（align 环境与收束句并入，后续叙述不并入）
    assert "Proof. Fix" not in out
    assert "Fix a sequence" in out
    i1 = out.index("\\begin{proof}")
    i2 = out.index("\\end{proof}")
    assert i1 < out.index("a^2 + b^2") < i2  # align 公式属于证明
    assert i1 < out.index("This completes the proof.") < i2
    assert out.index("A known result by Lemma 3.1") > i2  # 叙述段不并入
    # 双语标题合并
    assert "\\section*{1.1 The Probabilistic Method（概率方法）}" in out
    assert "\\addcontentsline{toc}{section}{1.1 The Probabilistic Method（概率方法）}" in out
    assert "\\section*{EXERCISES（练习）}" in out
    # 习题节转换（book 类无 exercise 环境 → enumerate）
    assert "\\item First problem text" in out
    assert out.count("\\begin{enumerate}") == 2
    # 范围修正：环境外正文收进 theorem
    assert "The body of Theorem 9.9 was left outside" in out
    # 导言区补充
    assert "\\usepackage{amsthm}" in out
    assert "\\newtheorem*{definition}{Definition}" in out
    # 校验
    assert res.verification["content_invariant"] is True
    assert res.verification["env_balance"]["ok"] is True
    # 汇报各节齐全
    for sec in ("新增环境包裹", "环境范围修正", "习题节转换", "双语标题合并", "导言区补充", "机器校验"):
        assert sec in res.report_md, sec


def test_compile_checks_receive_preserved_ocr_resources():
    compile_result = {
        "available": True,
        "ok": True,
        "pages": 1,
        "errors": [],
        "log": "",
    }
    extra_files = {"images/page_0001_01.png": b"actual-image-bytes"}
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        return_value=compile_result,
    ) as compile_latex:
        result = run_pipeline(
            read_sample("basic_book.tex"),
            mode="rule",
            compile_check=True,
            compile_extra_files=extra_files,
        )

    assert result.ok is True
    assert compile_latex.call_count == 2
    assert all(
        call.kwargs.get("extra_files") == extra_files
        for call in compile_latex.call_args_list
    )


def test_pipeline_separates_captured_pdf_from_json_verification():
    before = {
        "available": True,
        "ok": True,
        "pages": 1,
        "errors": [],
        "log": "before",
        "preview_status": "COMPILED",
    }
    after = {
        **before,
        "log": "after",
        "pdf_bytes": b"%PDF-captured-preview",
    }
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=[before, after],
    ) as compile_latex:
        result = run_pipeline(
            read_sample("basic_book.tex"),
            mode="rule",
            compile_check=True,
            capture_compile_artifact=True,
        )

    assert result.compiled_pdf == b"%PDF-captured-preview"
    assert result.compiled_pdf_name == "compiled.pdf"
    assert result.compiled_tex == result.result
    assert result.compiled_snapshot == result.result
    assert "pdf_bytes" not in result.verification["compile_after"]
    artifact = result.verification["preview_artifact"]
    assert artifact["sha256"] == hashlib.sha256(
        result.compiled_pdf
    ).hexdigest()
    assert artifact["filename"].startswith("LATEXSTRUCT-ARTIFACTS/compiled-")
    assert artifact["tex_lf_normalized_sha256"] == hashlib.sha256(
        result.compiled_tex.encode("utf-8")
    ).hexdigest()
    assert "include_pdf" not in compile_latex.call_args_list[0].kwargs
    assert compile_latex.call_args_list[1].kwargs["include_pdf"] is True


def test_folder_compile_cannot_overwrite_selected_candidate_with_unrelated_main_tex():
    selected_main = (
        "\\documentclass{article}\n"
        "\\begin{document}\n"
        "Selected candidate.\n"
        "\\input{chapter}\n"
        "\\end{document}\n"
    )
    selected = (
        selected_main.replace(
            "\\input{chapter}\n",
            "\\input{chapter}\n"
            "% === LATEXSTRUCT-FILE-START: chapter.tex ===\n"
            "Child body.\n"
            "% === LATEXSTRUCT-FILE-END: chapter.tex ===\n",
        )
    )
    unrelated = (
        "\\documentclass{article}\n"
        "\\begin{document}\nUNRELATED MAIN.\n\\end{document}\n"
    ).encode("utf-8")
    observed = []

    def fake_compile(text, *, extra_files=None, include_pdf=False):
        folded = {str(name).casefold() for name in (extra_files or {})}
        assert text == selected_main
        assert "book.tex" not in folded
        assert "main.tex" not in folded
        assert "main.pdf" not in folded
        observed.append((text, dict(extra_files or {})))
        result = {
            "available": True,
            "ok": True,
            "pages": 1,
            "errors": [],
            "log": "selected candidate compiled",
            "preview_status": "COMPILED",
        }
        if include_pdf:
            result["pdf_bytes"] = b"%PDF-selected-candidate"
        return result

    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=fake_compile,
    ):
        result = run_pipeline(
            selected,
            mode="rule",
            compile_check=True,
            compile_project_main_rel="book.tex",
            compile_extra_files={
                "book.tex": selected.encode("utf-8"),
                "MAIN.TEX": unrelated,
                "main.pdf": b"%PDF-stale-project-output",
                "main.log": b"stale project log",
                "main.aux": b"stale project aux",
                "figures/keep.bin": b"resource",
            },
            capture_compile_artifact=True,
        )

    assert result.ok is True
    assert result.result == selected
    assert result.compiled_tex == selected_main
    assert result.compiled_pdf == b"%PDF-selected-candidate"
    assert result.verification["preview_artifact"]["tex_sha256"] == hashlib.sha256(
        selected_main.encode("utf-8")
    ).hexdigest()
    assert len(observed) == 2
    assert all(
        files == {
            "chapter.tex": b"Child body.",
            "figures/keep.bin": b"resource",
        }
        for _text, files in observed
    )


def test_cn_fragment_fast_mode():
    source = read_sample("cn_fragment.tex")
    res = run_pipeline(source, mode="rule")
    assert res.ok is False
    assert res.verification["safe_to_export"] is False
    assert res.result == source
    # Safe transformations may be constructed in the draft, but the presence
    # of unresolved numbered remark/example candidates rolls the whole export
    # back to the source.
    planned = {ap.decision.env for ap in res.applied if ap.decision.action == "wrap"}
    # ElegantBook 内置的星号色块不会自动计数，可安全保留原书编号；没有可证明
    # 星号版本的旧 remark/example 仍宁可保留原文，不冒险产生双编号。
    for env, number in (
        ("definition", "1.1"),
        ("theorem", "2.1"),
        ("proposition", "2.2"),
        ("corollary", "2.3"),
        ("lemma", "1"),
    ):
        assert f"{env}*" in planned, (env, number)
    assert "注 3. 一个注记" in res.result
    assert "例 5. 一个例子" in res.result
    assert any("避免双编号" in item["reason"] for item in res.ambiguous)
    assert sum(ap.decision.env == "proof" for ap in res.applied) == 2
    assert res.verification["content_invariant"] is True
    assert res.verification["env_balance"]["ok"] is True


def test_cn_numbered_titles_use_generated_unnumbered_environments():
    text = read_sample("cn_fragment.tex").replace(
        "\\documentclass{elegantbook}", "\\documentclass{book}", 1,
    )
    res = run_pipeline(text, mode="rule")
    assert res.ok, res.report_md
    out = res.result
    assert "\\newtheorem*{theorem}{Theorem}" in out
    assert "\\begin{theorem}[2.1]" in out and "定理 2.1" not in out
    assert "（某某）. 结论陈述" in out
    assert "\\begin{definition}[1.1]" in out and "定义 1.1" not in out
    assert "\\begin{remark}[3]" in out and "\\begin{example}[5]" in out


def test_unnumbered_title_prefix_is_removed_but_title_only_is_preserved():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Theorem. A statement without a source number.\n\n"
        "Remark\n"
        "\\end{document}\n"
    )
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    assert "\\begin{theorem}\nA statement without a source number." in result.result
    assert "Theorem. A statement without a source number." not in result.result
    assert "\\begin{remark}\nRemark\n\\end{remark}" in result.result


def test_unnumbered_chinese_title_prefix_consumes_punctuation_safely():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "定理：结论成立。\n\n"
        "注：这是注记。\n\n"
        "例。这里是例子。\n\n"
        "定理：\n"
        "\\end{document}\n"
    )
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    assert "\\begin{theorem}\n结论成立。" in result.result
    assert "\\begin{remark}\n这是注记。" in result.result
    assert "\\begin{example}\n这里是例子。" in result.result
    assert "\n：" not in result.result and "\n。这里" not in result.result
    # 标题词条后没有正文时不剥离，避免生成空内容。
    assert "\\begin{theorem}\n定理：\n\\end{theorem}" in result.result


def test_existing_numbered_theorem_declaration_defers_explicit_source_number():
    text = (
        "\\documentclass{book}\n\\usepackage{amsthm}\n"
        "\\newtheorem{theorem}{Theorem}\n\\begin{document}\n"
        "Theorem 7. A statement with its own number.\n"
        "\\end{document}\n"
    )
    first = run_pipeline(text, mode="rule")
    assert first.ok is False
    assert first.verification["safe_to_export"] is False
    assert first.result == text
    assert not first.applied
    assert any("避免双编号" in item["reason"] for item in first.ambiguous)

    # 缓存/审阅复用也必须再次经过最终应用保护，不能绕过。
    reused = run_pipeline(
        text,
        mode="rule",
        decisions_override=first.decisions,
        ambiguous_override=[],
    )
    assert reused.ok is False
    assert reused.verification["safe_to_export"] is False
    assert reused.result == text
    assert reused.verification["decisions_reused"] is True
    assert any("避免双编号" in item["reason"] for item in reused.ambiguous)


def test_existing_starred_theorem_declaration_accepts_explicit_source_number():
    text = (
        "\\documentclass{book}\n\\usepackage{amsthm}\n"
        "\\newtheorem*{theorem}{Theorem}\n\\begin{document}\n"
        "Theorem 7. A statement with its own number.\n"
        "\\end{document}\n"
    )
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    assert "\\begin{theorem}[7]\nA statement with its own number." in result.result
    assert result.result.count("\\newtheorem*{theorem}{Theorem}") == 1


def test_crlf_export_preserved():
    text = "\\documentclass{book}\r\n\\begin{document}\r\nTheorem. X.\r\n\\end{document}\r\n"
    res = run_pipeline(text, mode="rule")
    assert res.ok
    assert "\r\n" in res.export_text
    assert res.export_text.startswith("\\documentclass{book}\r\n")


def test_ai_mode_without_key_fails_closed():
    from latexstruct.core.ai import LLMError

    try:
        run_pipeline(read_sample("basic_book.tex"), mode="ai")
    except LLMError as exc:
        assert "未使用规则模式替代" in str(exc)
    else:
        raise AssertionError("AI 模式缺少 Key 时不得静默执行规则模式")


def test_real_godsil_excerpt():
    # 真实书稿摘录回归：双语段 + \relax 翻译框 + 编号定理/引理 + Proof + 习题节
    text = read_sample("real_godsil_excerpt.tex")
    res = run_pipeline(text, mode="rule")
    assert res.ok, res.report_md
    out = res.result
    # 编号提取
    assert "\\begin{lemma}[1.7.1]" in out
    assert "Lemma 1.7.1" not in out
    assert "\\begin{theorem}[1.7.2]" in out
    assert "\\begin{proof}" in out and "Proof." not in out
    # 证明不吞入其后的叙述性重启段
    assert out.index("\\end{proof}") < out.index("There is another interesting")
    # 双语标题合并（\relax 盒）
    assert "\\section*{Exercises（练习）}" in out
    # 习题转换：仅英文条目 \item，盒内中文翻译不改写
    assert "\\item Let \\(X\\) be a graph" in out
    assert "\\item 设" not in out
    assert "1. 设 \\(X\\)" in out  # 盒内译文保留原编号
    assert res.verification["content_invariant"] is True
    assert res.verification["env_balance"]["ok"] is True


def test_known_issues_reported():
    # \left( 内嵌 matrix 是原书既有编译问题，仅报告不修改
    text = (
        "\\documentclass{book}\n\\begin{document}\n\n"
        "Theorem 1. A formula.\n\n{2}^{\\left( \\begin{matrix} n \\\\ 2 \\end{matrix}\\right) }.\n\n"
        "\\end{document}\n"
    )
    res = run_pipeline(text, mode="rule")
    assert res.ok
    ki = res.verification["known_issues"]
    assert ki and "matrix" in ki[0]["reason"]
    assert "已知问题（原书既有" in res.report_md
    # 内容未被修改
    assert "{2}^{\\left( \\begin{matrix} n \\\\ 2 \\end{matrix}\\right) }" in res.result


def test_repeated_known_issues_are_grouped_in_report():
    matrix = r"\left( \begin{matrix} n \\ 2 \end{matrix}\right)"
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        f"{matrix} + {matrix}\n{matrix}\n"
        "\\end{document}\n"
    )
    res = run_pipeline(text, mode="rule")
    assert res.ok
    assert len(res.verification["known_issues"]) == 3
    assert res.report_md.count("内嵌 matrix 环境") == 1
    assert "共 3 处，涉及 2 行" in res.report_md


def test_bracket_display_with_tag_fails_closed_without_tex_engine():
    text = r"""\documentclass{book}
\usepackage{amsmath}
\begin{document}
\[
\begin{aligned}
a &= b \\
c &= d \tag{5.4}
\end{aligned}
\tag{duplicate}
\]
\end{document}
"""
    result = run_pipeline(text, mode="rule")
    assert result.ok is False
    assert result.verification["display_tags"]["ok"] is False
    assert result.verification["display_tags"]["count"] == 2
    assert result.verification["safe_to_export"] is False
    assert result.verification["export_blocked"] is True
    assert "\\tag 不能直接用于 \\[...\\]" in result.report_md


def test_unbalanced_bracket_display_fails_closed_without_tex_engine():
    cases = (
        ("unmatched-open", "\\[x=y\n", "缺少对应 \\]"),
        ("stray-close", "x=y\\]\n", "没有对应 \\["),
        ("nested-open", "\\[x+\\[y\\]\\]\n", "尚未闭合又出现新的 \\["),
    )
    for name, body, expected_reason in cases:
        text = (
            "\\documentclass{book}\n\\begin{document}\n"
            + body
            + "\\end{document}\n"
        )
        result = run_pipeline(text, mode="rule")
        assert result.ok is False, name
        assert result.verification["display_tags"]["ok"] is False, name
        assert result.verification["safe_to_export"] is False, name
        assert result.verification["export_blocked"] is True, name
        assert expected_reason in result.report_md, name


def test_tag_in_ams_math_environments_is_not_misreported():
    text = r"""\documentclass{book}
\usepackage{amsmath}
\begin{document}
\begin{equation}a=b\tag{1}\end{equation}
\begin{align}a&=b\tag{2}\end{align}
\begin{alignat}{2}a&=b&\quad c&=d\tag{3}\end{alignat}
\begin{gather}a=b\tag{4}\end{gather}
\begin{multline}a+b+c=d\tag{5}\end{multline}
\[
x=y % \tag{ignored-comment}
\]
% \[ ignored unmatched display in a comment
\begin{verbatim}
\[ \tag{literal} \]
\end{verbatim}
\begin{minted}{tex}
\[ \tag{literal} \]
\end{minted}
\end{document}
"""
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    assert result.verification["display_tags"] == {"ok": True, "count": 0, "issues": []}
    assert result.verification["safe_to_export"] is True


def test_ocr_repaired_tagged_display_passes_static_safety_gate():
    from latexstruct.ocr import _clean_page_output

    raw = r"""\[
\begin{aligned}
a &= b \\
c &= d \tag{5.4}
\end{aligned}
\]"""
    cleaned = _clean_page_output(raw)
    assert r"\begin{equation}" in cleaned and r"\[" not in cleaned
    result = run_pipeline(
        "\\documentclass{book}\n\\usepackage{amsmath}\n\\begin{document}\n"
        + cleaned
        + "\n\\end{document}\n",
        mode="rule",
    )
    assert result.ok, result.report_md
    assert result.verification["display_tags"]["ok"] is True
    assert result.verification["safe_to_export"] is True


def test_overlapping_decisions_are_both_deferred():
    lines = ["Theorem. A.", "body", "Proof. B."]
    d1 = Decision(candidate_id="a", action="wrap", env="theorem", body_span=(1, 2))
    d2 = Decision(candidate_id="b", action="wrap", env="proof", body_span=(2, 3))
    ctx = PatchContext()
    planned = []
    for d in (d1, d2):
        ops, err = build_ops(d, lines, ctx)
        assert not err
        planned.append((d, ops))
    kept, dropped = resolve_overlaps(planned, lines)
    assert kept == []
    assert {d.candidate_id for d, _ in dropped} == {"a", "b"}


def test_scope_fixes_do_not_guess_from_adjacent_paragraphs():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "\\begin{theorem}\nTheorem A.\n\\end{theorem}\n"
        "Body belonging to A.\n\n"
        "\\begin{theorem}\nTheorem B.\n\\end{theorem}\n"
        "\\section{Next}\n\\end{document}\n"
    )
    doc = parse_latex(text)
    decisions, ambiguous = build_rule_decisions(doc, scan(doc))
    moves = [d for d in decisions if d.action == "move-boundary"]
    # An ordinary paragraph after a closed theorem may be commentary.  Its
    # adjacency alone is not enough evidence to move a structural boundary.
    assert moves == []
    assert ambiguous == []


def test_used_but_undefined_theorem_is_declared_for_wrapped_output():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Theorem 1. A new statement.\n\n"
        "\\begin{theorem}\nExisting but previously undefined.\n\\end{theorem}\n"
        "\\end{document}\n"
    )
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    assert "\\newtheorem*{theorem}{Theorem}" in result.result


def test_existing_amsthm_package_is_not_inserted_twice():
    text = (
        "\\documentclass{book}\n\\usepackage{amsthm}\n\\begin{document}\n"
        "Definition 1. A definition.\n\\end{document}\n"
    )
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    assert result.result.count("\\usepackage{amsthm}") == 1
    assert "\\newtheorem*{definition}{Definition}" in result.result


def test_real_godsil_section_1_7():
    # 真实书稿 1.7 节切片（含引理/定理/证明/图注/翻译框）规则模式回归
    text = read_sample("godsil_1_7.tex")
    res = run_pipeline(text, mode="rule")
    assert res.ok, res.report_md
    out = res.result
    assert "\\begin{lemma}[1.7.1]" in out
    assert "\\begin{theorem}[1.7.2]" in out
    assert "\\begin{proof}" in out
    assert res.verification["content_invariant"] is True
    assert res.verification["env_balance"]["ok"] is True


def test_styled_ocr_titles_cross_math_and_page_boundaries():
    text = r"""\documentclass{article}
\begin{document}
\textbf{Theorem 1.1.} \textit{There exists $\varepsilon>0$ such that}
\[
R(k) < (4-\varepsilon)^k.
\]
\textit{for every sufficiently large $k$.}

This paragraph comments on the theorem and is not part of its statement.

\textit{Proof.} Start with the recurrence.
\[
R(k)\leq 4^k.
\]

%=== PAGE BREAK === 第 2 段
% Page 2
Then improve the estimate. \hfill $\square$

After the proof, a new discussion begins.

\textbf{Question 1.2.} Is the bound sharp?
\end{document}
"""
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    output = result.result
    theorem_start = output.index(r"\begin{theorem}[1.1]")
    theorem_end = output.index(r"\end{theorem}")
    assert theorem_start < output.index(r"R(k) <") < theorem_end
    assert theorem_start < output.index("for every sufficiently") < theorem_end
    assert output.index("This paragraph comments") > theorem_end
    assert r"\textbf{Theorem 1.1.}" not in output

    proof_start = output.index(r"\begin{proof}")
    proof_end = output.index(r"\end{proof}")
    assert proof_start < output.index("Then improve the estimate") < proof_end
    assert output.index("After the proof") > proof_end
    assert r"\textit{Proof.}" not in output

    assert r"\begin{question}[1.2]" in output
    assert r"\newtheorem*{question}{Question}" in output


def test_proof_of_decimal_theorem_number_becomes_one_proof_heading():
    text = r"""\documentclass{article}
\begin{document}
\textit{Proof of the upper bound in Theorem 1.2.} Let $G$ be a graph. \hfill $\square$

Proof of Theorem 2.7 up to a constant factor. The key idea follows. \hfill $\square$
\end{document}
"""
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    output = result.result
    assert r"\begin{proof}[Proof of the upper bound in Theorem 1.2]" in output
    assert r"\begin{proof}[Proof of Theorem 2.7 up to a constant factor]" in output
    assert r"\textit{Proof of the upper bound in Theorem 1.2.}" not in output
    assert "Proof of Theorem 2.7 up to a constant factor." not in output
    assert output.count(r"\begin{proof}") == 2


def test_styled_theorem_and_proof_keep_style_without_duplicate_titles():
    text = r"""\documentclass{article}
\begin{document}
\textbf{Theorem 4.2. Every graph has a useful ordering.}

\textit{Proof. Choose a vertex of minimum degree.} \hfill $\square$
\end{document}
"""
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    output = result.result
    assert r"\begin{theorem}[4.2]" in output
    assert r"\textbf{Every graph has a useful ordering.}" in output
    assert r"\textbf{Theorem 4.2." not in output
    assert r"\begin{proof}" in output
    assert r"\textit{Choose a vertex of minimum degree.}" in output
    assert r"\textit{Proof." not in output
    assert result.verification["content_invariant"] is True
    assert result.verification["env_balance"]["ok"] is True


def test_standalone_styled_titles_are_removed_only_after_body_is_confirmed():
    text = r"""\documentclass{article}
\begin{document}
\textbf{Lemma 3.1.}

Every graph has an independent set.

\textit{Proof.}

Choose a maximal one. \hfill $\square$
\end{document}
"""
    result = run_pipeline(text, mode="rule")
    assert result.ok, result.report_md
    output = result.result
    assert r"\begin{lemma}[3.1]" in output
    assert r"\textbf{Lemma 3.1.}" not in output
    assert r"\begin{proof}" in output
    assert r"\textit{Proof.}" not in output
    assert "Every graph has an independent set." in output
    assert "Choose a maximal one." in output
    assert result.verification["content_invariant"] is True


def test_pdf_outline_rebuilds_book_chapters_and_real_toc():
    from latexstruct.ocr import merge_book

    outline = [
        {"level": 0, "title": "Introduction", "page": 2},
        {"level": 0, "title": "Contents", "page": 3},
        {"level": 0, "title": "Ramsey numbers", "page": 4},
        {"level": 1, "title": "History", "page": 4},
        {
            "level": 1,
            "title": "The off-diagonal problem and the exponent gap",
            "page": 5,
        },
    ]
    raw = merge_book(
        [
            "% Page 1\nA cover page.",
            "% Page 2\n\\section*{Introduction}\nIntroductory text.",
            (
                "% Page 3\n\\section*{Contents}\n"
                "\\textbf{1 Ramsey numbers} \\dotfill 1\n"
                "\\textbf{1.1 History} \\dotfill 1"
            ),
            (
                "% Page 4\n\\section*{Chapter 1}\n"
                "\\section*{Ramsey numbers}\n"
                "\\subsection*{1.1 History}\n"
                "\\subsection*{Off-diagonal Ramsey numbers}\nHistory text."
            ),
            (
                "% Page 5\n\\subsection*{Off-diagonal Ramsey numbers}\n"
                "\\subsection*{1.2 The off-diagonal problem and the exponent gap}\n"
                "More text."
            ),
        ],
        outline=outline,
    )
    result = run_pipeline(raw, mode="rule")
    assert result.ok, result.report_md
    output = result.result
    assert r"\documentclass[11pt]{book}" in output
    assert r"\chapter*{Introduction}" in output
    assert r"\addcontentsline{toc}{chapter}{Introduction}" in output
    assert r"\tableofcontents" in output
    assert r"\addcontentsline{toc}{chapter}{Contents}" not in output
    assert r"\tableofcontents" + "\n" + r"\clearpage" in output
    assert r"\dotfill" not in output
    assert r"\chapter{Ramsey numbers}" in output
    assert r"\section{History}" in output
    assert r"\section{The off-diagonal problem and the exponent gap}" in output
    assert "Chapter 1" not in output
    assert r"\subsection*{Off-diagonal Ramsey numbers}" not in output
    assert result.verification["ocr_structure"]["ok"] is True
    assert result.verification["content_invariant"] is True


def test_pdf_outline_recovers_inline_numbered_headings_and_allows_real_duplicates():
    from latexstruct.ocr import merge_book

    repeated = "Sampling and extracting the Ramsey bound"
    outline = [
        {"level": 0, "title": "1. First method", "page": 1},
        {"level": 1, "title": f"1.1. {repeated}", "page": 1},
        {"level": 0, "title": "2. Second method", "page": 2},
        {"level": 1, "title": f"2.1. {repeated}", "page": 2},
    ]
    raw = merge_book(
        [
            (
                "% Page 1\n\\section*{1. First method}\n"
                f"1.1. {repeated}. This sentence is body text and must be preserved."
            ),
            (
                "% Page 2\n\\section*{2. Second method}\n"
                f"\\textbf{{2.1. {repeated}.}} More body text."
            ),
        ],
        outline=outline,
    )
    result = run_pipeline(raw, mode="rule")
    assert result.ok, result.report_md
    output = result.result
    assert output.count(r"\subsection{Sampling and extracting the Ramsey bound}") == 2
    assert "This sentence is body text and must be preserved." in output
    assert "More body text." in output
    assert result.verification["ocr_structure"] == {
        "checked": True,
        "ok": True,
        "issues": [],
        "expected": 4,
        "matched": 4,
        "actual": 4,
        "toc_expected": False,
    }
    assert result.verification["content_invariant"] is True


def test_ocr_article_outline_maps_to_elegantbook_book_hierarchy():
    from latexstruct.ocr import merge_book

    raw = merge_book(
        [
            "% Page 1\n\\section*{1 Foundations}\nOpening text.",
            "% Page 2\n\\section*{2 Probabilistic method}\n\nTheorem 2.1. A result.",
        ],
        outline=[
            {"level": 0, "title": "1 Foundations", "page": 1},
            {"level": 0, "title": "2 Probabilistic method", "page": 2},
        ],
    )
    assert r"\documentclass[11pt]{article}" in raw

    result = run_pipeline(raw, mode="rule", template="elegantbook")
    assert result.ok, result.report_md
    assert r"\documentclass[lang=en,11pt]{elegantbook}" in result.result
    assert r"\chapter{Foundations}" in result.result
    assert r"\chapter{Probabilistic method}" in result.result
    assert r"\begin{theorem*}[2.1]" in result.result
    assert result.verification["ocr_structure"]["ok"] is True
    assert result.verification["safe_to_export"] is True


def test_unsafe_manual_toc_region_preserves_body_and_fails_closed():
    from latexstruct.ocr import merge_book

    raw = merge_book(
        [
            (
                "% Page 1\n\\section*{Contents}\n"
                "\\textbf{1 First result} \\dotfill 2\n\n"
                "This real paragraph shares the contents page and must not be deleted."
            ),
            "% Page 2\n\\section*{1 First result}\nActual section body.",
        ],
        outline=[
            {"level": 0, "title": "Contents", "page": 1},
            {"level": 0, "title": "1 First result", "page": 2},
        ],
    )
    result = run_pipeline(raw, mode="rule")
    assert "This real paragraph shares the contents page" in result.result
    assert r"\dotfill" in result.result
    assert r"\tableofcontents" not in result.result
    assert result.verification["ocr_structure"]["ok"] is False
    assert result.verification["safe_to_export"] is False
    assert "手抄目录区混有无法确认的正文" in result.report_md


def test_ocr_compile_gate_requires_success_when_engine_exists_but_allows_unavailable():
    from unittest.mock import patch

    text = r"""\documentclass{article}
\begin{document}
Plain OCR text.
\end{document}
"""
    unavailable = {"available": False, "ok": None, "pages": 0, "errors": [], "log": ""}
    with patch("latexstruct.core.compilecheck.compile_latex", side_effect=[unavailable, unavailable]):
        result = run_pipeline(
            text,
            mode="rule",
            compile_check=True,
            require_compile_when_available=True,
        )
    assert result.ok
    assert result.verification["compile"]["checked"] is False
    assert "本机不可用" in result.report_md

    failed = {
        "available": True,
        "ok": False,
        "pages": 0,
        "errors": ["Undefined control sequence"],
        "log": "",
    }
    with patch("latexstruct.core.compilecheck.compile_latex", side_effect=[failed, failed]):
        result = run_pipeline(
            text,
            mode="rule",
            compile_check=True,
            require_compile_when_available=True,
        )
    assert not result.ok
    assert result.verification["compile"]["checked"] is True
    assert result.verification["safe_to_export"] is False


def test_failed_before_and_after_with_patch_is_unverified_even_if_first_errors_match():
    text = (
        "\\documentclass{article}\n"
        "\\usepackage{amsthm}\n"
        "\\newtheorem{theorem}{Theorem}\n"
        "\\begin{document}\n"
        "\\undefinedA\n"
        "\\begin{tabular}{l}\n"
        "Theorem 1. A cached decision must not be trusted here. \\\\\n"
        "\\end{tabular}\n"
        "\\end{document}\n"
    )
    failed = {
        "available": True,
        "ok": False,
        "pages": 0,
        # -halt-on-error exposes only the pre-existing first error in both runs;
        # the modified run could contain a later "Not allowed in LR mode".
        "errors": ["Undefined control sequence @l.5: \\undefinedA"],
        "log": "",
    }
    cached_wrap = Decision(
        candidate_id="cached-tabular-title",
        action="wrap",
        env="theorem",
        body_span=(7, 7),
        source="ai",
    )
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=[dict(failed), dict(failed)],
    ):
        result = run_pipeline(
            text,
            mode="rule",
            compile_check=True,
            decisions_override=[cached_wrap],
        )

    assert result.applied
    assert result.ok is False
    assert result.result == text
    assert result.verification["compile"] == {
        "ok": False,
        "checked": True,
        "unverified": True,
    }
    assert result.verification["safe_to_export"] is False
    assert "首个错误相同不足以证明补丁未引入后续错误" in result.report_md


def test_failed_identical_compile_without_patch_preserves_noop_path():
    text = "\\documentclass{article}\n\\begin{document}\n\\undefinedA\n\\end{document}\n"
    failed = {
        "available": True,
        "ok": False,
        "pages": 0,
        "errors": ["Undefined control sequence @l.3: \\undefinedA"],
        "log": "",
    }
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=[dict(failed), dict(failed)],
    ):
        result = run_pipeline(text, mode="rule", compile_check=True)

    assert result.applied == []
    assert result.ok is True
    assert result.verification["compile"] == {
        "ok": True,
        "checked": True,
        "unverified": False,
    }


def test_required_ocr_image_resource_missing_blocks_export():
    text = r"""\documentclass{article}
\usepackage{graphicx}
\begin{document}
\includegraphics{images/definitely-missing-ocr-figure}
\end{document}
"""
    result = run_pipeline(
        text,
        mode="rule",
        resource_root=SAMPLES,
        require_resources=True,
    )
    assert not result.ok
    assert result.verification["resources"]["checked"] is True
    assert result.verification["resources"]["ok"] is False
    assert result.verification["resources"]["missing"] == [
        "images/definitely-missing-ocr-figure"
    ]
    assert result.verification["safe_to_export"] is False


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

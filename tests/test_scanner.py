# -*- coding: utf-8 -*-
"""规则扫描引擎测试（pytest 兼容；也可直接 python tests/test_scanner.py 运行）。"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.scanner import _declared_theorem_envs, scan  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def scan_sample(name: str):
    return scan(parse_latex(read_sample(name)))


def para_line(doc, needle: str):
    for b in doc.blocks_of_kind("para"):
        if needle in b.text:
            return b.span.start_line
    return -1


def test_theorem_like_basic_book():
    doc = parse_latex(read_sample("basic_book.tex"))
    res = scan(doc)
    tl = [c for c in res.candidates if c.kind == "theorem-like"]
    by_env = {c.env_hint: c for c in tl}
    assert set(by_env) == {"definition", "theorem", "remark"}, by_env
    assert by_env["definition"].title_text.startswith("Definition 1.1.1")
    assert by_env["theorem"].title_text.startswith("Theorem 2.3.4")
    # 引用性文字（段中 by Lemma 3.1）不得成为候选
    line = para_line(doc, "by Lemma 3.1")
    assert line > 0 and not any(c.span.start_line == line for c in tl)


def test_styled_result_and_proof_accept_bounded_tex_spacing_separators():
    text = (
        r"\textbf{Theorem 7.7}\quad \textsc{The Max-Flow Min-Cut Theorem}"
        "\n\n"
        r"\textit{In any network, a maximum equals a minimum.}"
        "\n\n"
        r"\textbf{Proof}\qquad Let $f$ be maximum. \hfill $\square$"
        "\n"
    )
    for pack in (None, "english"):
        candidates = scan(parse_latex(text), pack=pack).candidates
        theorem = next(c for c in candidates if c.kind == "theorem-like")
        proof = next(c for c in candidates if c.kind == "proof")
        assert theorem.env_hint == "theorem"
        assert theorem.payload["number"] == "7.7"
        assert theorem.payload["title_prefix"] == r"\textbf{Theorem 7.7}\quad "
        assert theorem.payload["title_remainder"] == (
            r"\textsc{The Max-Flow Min-Cut Theorem}"
        )
        assert proof.payload["strip_prefix"] == r"\textbf{Proof}\qquad "
        assert proof.payload["title_remainder"].startswith("Let $f$ be maximum")


def test_old_style_formal_and_presentation_wrapped_proof_are_semantic_candidates():
    text = (
        r"{\bfseries Conjecture 1.1 (Erdos and Sos, [15]).}"
        "\n\n"
        r"\[\lim_{m\to\infty} f(m)=\infty.\]"
        "\n\n"
        r"\textbf{Proof of \textcolor{cyan}{Theorem 2.1}.} "
        r"Consider the ordered choices. \(\blacksquare\)"
        "\n"
    )
    for pack in (None, "academic-paper"):
        candidates = scan(parse_latex(text), pack=pack).candidates
        conjecture = next(c for c in candidates if c.kind == "theorem-like")
        proof = next(c for c in candidates if c.kind == "proof")
        assert conjecture.env_hint == "conjecture"
        assert conjecture.payload["number"] == (
            r"1.1 {(Erdos and Sos, {\char91}15{\char93})}"
        )
        assert conjecture.payload["title_prefix"] == (
            r"{\bfseries Conjecture 1.1 (Erdos and Sos, [15]).}"
        )
        assert conjecture.payload["title_line_old"] == ""
        assert conjecture.payload["title_line_new"] == ""
        assert proof.payload["proof_arg"] == "Proof of Theorem 2.1"
        assert proof.payload["strip_prefix"] == (
            r"\textbf{Proof of \textcolor{cyan}{Theorem 2.1}.} "
        )
        assert proof.payload["title_remainder"].startswith("Consider the ordered choices")


def test_arbitrary_tex_command_after_result_keyword_is_not_a_separator():
    text = (
        r"\textbf{Theorem 2}\ref{old-result} shows the estimate."
        "\n\n"
        r"\textbf{Proof}\ref{old-proof} is cited here."
        "\n"
    )
    candidates = scan(parse_latex(text)).candidates
    assert not [
        candidate for candidate in candidates
        if candidate.kind in {"theorem-like", "proof"}
    ]


def test_reference_sentences_are_not_bare_structure_titles():
    text = (
        "Note that the second step is essential.\n\n"
        "Theorem 1.2 has an application to this graph.\n\n"
        "Lemma 3.4 implies the desired estimate.\n"
    )
    result = scan(parse_latex(text))
    assert [c for c in result.candidates if c.kind == "theorem-like"] == []


def test_parenthesized_or_bracketed_named_titles_are_candidates():
    text = (
        "Theorem (Pythagoras). For a right triangle, $a^2+b^2=c^2$.\n\n"
        "Lemma [Key estimate]: The norm is bounded.\n\n"
        "Definition (Linear Independence \\& Linear Dependence (I)). "
        "A family is independent when only the trivial combination vanishes.\n\n"
        "Theorem (Pythagoras) has many applications.\n"
    )
    result = scan(parse_latex(text))
    candidates = [c for c in result.candidates if c.kind == "theorem-like"]
    assert [(c.env_hint, c.span.start_line) for c in candidates] == [
        ("theorem", 1),
        ("lemma", 3),
        ("definition", 5),
    ]


def test_proof_of_cross_reference_is_precise_candidate():
    text = (
        "Proof of \\Cref{thm:main}: Apply the preceding estimate. 证毕\n\n"
        "Proof of \\Cref{thm:main} gives a useful summary.\n\n"
        "Proof of concept is discussed next.\n"
    )
    for pack in (None, "english"):
        result = scan(parse_latex(text), pack=pack)
        proofs = [candidate for candidate in result.candidates if candidate.kind == "proof"]
        assert [(candidate.span.start_line, candidate.payload["proof_arg"]) for candidate in proofs] == [
            (1, "Proof of \\Cref{thm:main}"),
        ]


def test_proof_of_custom_ref_and_named_result_titles_are_candidates():
    text = (
        "Proof of \\thmref{thm:localization}: The argument continues.\n\n"
        "Proof of Green's theorem for $U$ of type III. Apply the identity. \\qed\n\n"
        "Proof of the spectral theorem. Apply the transform.\n\n"
        "Proof of \\Cref*{thm:unlinked}. Use the direct argument.\n\n"
        "Proof of Theorem~\\ref{thm:numbered}. Use the preceding lemma.\n\n"
        "Proof of Theorem 2.7 up to a constant factor. Compare both bounds.\n\n"
        "Proof of Lemma 4. we first reduce to the finite case.\n\n"
        "Proof of Corollary 5"
    )
    for pack in (None, "english"):
        result = scan(parse_latex(text), pack=pack)
        proofs = [candidate for candidate in result.candidates if candidate.kind == "proof"]
        assert [candidate.payload["proof_arg"] for candidate in proofs] == [
            "Proof of \\thmref{thm:localization}",
            "Proof of Green's theorem for $U$ of type III",
            "Proof of the spectral theorem",
            "Proof of \\Cref*{thm:unlinked}",
            "Proof of Theorem~\\ref{thm:numbered}",
            "Proof of Theorem 2.7 up to a constant factor",
            "Proof of Lemma 4",
            "Proof of Corollary 5",
        ]


def test_proof_of_link_commands_and_narrative_phrases_are_not_candidates():
    text = (
        "Proof of \\href{https://example.test}: This is a hyperlink caption.\n\n"
        "Proof of \\hyperref{sec:intro}: This is another link command.\n\n"
        "Proof of \\myhref{target}: This alias still denotes a link.\n\n"
        "Proof of a theorem. This generic phrase is discussed next.\n\n"
        "Proof of this theorem. This generic phrase is discussed next.\n\n"
        "Proof of Theorem 1 appears in Appendix A.\n\n"
        "Proof of the upper bound is omitted from this survey.\n\n"
        "Proof of concept is discussed next.\n"
    )
    for pack in (None, "english"):
        proofs = [
            candidate for candidate in scan(parse_latex(text), pack=pack).candidates
            if candidate.kind == "proof"
        ]
        assert proofs == []


def test_multiline_parenthesized_named_title_is_detected_without_lossy_strip():
    text = (
        "  Theorem (Fubini version A%\n"
        "\\footnote{Named after the Italian mathematician\n"
        "\\href{https://example.test}{Guido Fubini}\n"
        "(1879--1943).}):\n"
        "\\label{mv:fubini} Let $R$ be a closed rectangle.\n"
        "The associated functions are integrable.\n"
    )
    candidates = [
        candidate for candidate in scan(parse_latex(text)).candidates
        if candidate.kind == "theorem-like"
    ]
    assert len(candidates) == 1
    assert candidates[0].env_hint == "theorem"
    assert candidates[0].title_text.endswith("}):")
    # Only the literal first-line keyword is safe to strip.  The parenthesis,
    # comments and all nested TeX arguments must remain byte-for-byte source.
    assert candidates[0].payload["title_prefix"] == ""
    assert candidates[0].payload["title_line_old"] == "  Theorem (Fubini version A%"
    assert candidates[0].payload["title_line_new"] == "  (Fubini version A%"
    transformed = run_pipeline(text, mode="rule")
    assert transformed.ok and len(transformed.applied) == 1
    assert "Theorem (Fubini version A" not in transformed.result
    assert "\n  (Fubini version A%" in transformed.result
    assert "\\footnote{Named after the Italian mathematician" in transformed.result
    assert "\\href{https://example.test}{Guido Fubini}" in transformed.result
    assert transformed.verification["invariants"]["ok"] is True


def test_comment_and_verbatim_not_scanned():
    res = scan_sample("basic_book.tex")
    line_comment = para_line(parse_latex(read_sample("basic_book.tex")), "Definition 9.9.9")
    assert line_comment < 0  # 注释行不成为段落
    assert not any("verbatim" in c.title_text for c in res.candidates)


def test_proof_candidate():
    res = scan_sample("basic_book.tex")
    proofs = [c for c in res.candidates if c.kind == "proof"]
    assert len(proofs) == 1
    assert proofs[0].title_text.startswith("Proof.")


def test_environment_inner_not_rescanned():
    res = scan_sample("basic_book.tex")
    tl = [c for c in res.candidates if c.kind == "theorem-like"]
    # "Theorem 9.9. A statement." 已在 theorem 环境内，不得再成为候选
    assert not any("Theorem 9.9" in c.title_text for c in tl)


def test_custom_theorem_and_math_environments_are_not_rescanned():
    text = (
        "\\documentclass{book}\n"
        "\\usepackage{amsthm}\n\\newtheorem{myresult}{Result}\n"
        "\\newtheorem*{myremark}{Remark}\n"
        "\\begin{document}\n"
        "\\begin{myresult}\nTheorem 7. This is already structured.\n\\end{myresult}\n"
        "\\begin{myremark}\nTheorem 7.5. This is also structured.\n\\end{myremark}\n"
        "\\begin{equation}\nTheorem 8. This is literal math content.\n\\end{equation}\n"
        "\\end{document}\n"
    )
    res = scan(parse_latex(text))
    assert [c for c in res.candidates if c.kind == "theorem-like"] == []


def test_declaration_option_scanning_is_bounded_and_keeps_valid_aliases():
    valid = (
        "\\declaretheorem[name={Main theorem}]{axiom}\n"
        "\\newtcbtheorem[number within=section]{boxedthm}{Boxed theorem}{}{}\n"
        "\\newmdtheoremenv[linecolor={blue}]{mdlemma}[Lemma]\n"
    )
    assert _declared_theorem_envs(valid) == {"axiom", "boxedthm", "mdlemma"}

    # The former overlapping ``[^][] | {..}`` alternatives backtracked
    # exponentially on this malformed input.  A thousand option groups should
    # now be a tiny linear scan rather than a document-level denial of service.
    malformed = "\\declaretheorem[" + "{a}" * 1000 + "!{never}"
    started = time.perf_counter()
    assert _declared_theorem_envs(malformed) == set()
    assert time.perf_counter() - started < 0.25


def test_title_word_of_another_kind_inside_structured_env_is_body_content():
    text = (
        "\\begin{proof}\nExercise.\n\\end{proof}\n\n"
        "\\begin{theorem}\nTheorem.\n\\end{theorem}\n"
    )
    scope = [
        candidate for candidate in scan(parse_latex(text)).candidates
        if candidate.kind == "scope-fix"
    ]
    assert [(candidate.rule_id, candidate.env_hint) for candidate in scope] == [
        ("env-only-title", "theorem"),
    ]


def test_env_only_title_is_fail_closed_for_aliases_proofs_and_visible_hypertargets():
    text = (
        "\\newtheorem{myresult}{Result}\n"
        "\\begin{myresult}\nTheorem.\n\\end{myresult}\n\n"
        "\\begin{proof}\nProof.\n\\end{proof}\n\n"
        "\\begin{theorem}\n"
        "\\hypertarget{thm:visible}{Visible theorem body.}\n"
        "\\end{theorem}\n\n"
        "\\begin{theorem*}\nTheorem.\n\\end{theorem*}\n\n"
        "\\begin{theorem}\n\\hypertarget{thm:empty}{}\n\\end{theorem}\n"
    )
    scope = [
        candidate for candidate in scan(parse_latex(text)).candidates
        if candidate.kind == "scope-fix"
    ]
    assert [(candidate.rule_id, candidate.env_hint) for candidate in scope] == [
        ("env-only-title", "theorem*"),
        ("env-only-title", "theorem"),
    ]


def test_titles_inside_alignment_and_lr_mode_environments_are_not_scanned():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "\\begin{tabular}{l}\nTheorem 1. A cell is not a theorem block. \\\\\n\\end{tabular}\n"
        "\\[\\begin{array}{c}\nProof. This is array cell text. \\\\\n\\end{array}\\]\n"
        "\\begin{tabularx}{\\linewidth}{X}\nLemma 2. Another cell. \\\\\n\\end{tabularx}\n"
        "\\end{document}\n"
    )
    result = scan(parse_latex(text))
    assert [
        candidate for candidate in result.candidates
        if candidate.kind in {"theorem-like", "proof"}
    ] == []


def test_exercise_sections():
    res = scan_sample("basic_book.tex")
    ex = [c for c in res.candidates if c.kind == "exercise-section"]
    assert len(ex) == 1, [c.title_text for c in ex]
    assert ex[0].title_text == "Real exercises"
    assert len(ex[0].payload["item_lines"]) == 3
    # EXERCISES 节的条目已在 enumerate 内，不得重复转换
    assert all("EXERCISES" != c.title_text for c in ex)


def test_bilingual_titles():
    res = scan_sample("basic_book.tex")
    bt = [c for c in res.candidates if c.kind == "bilingual-title"]
    pairs = {(c.payload["en_title"], c.payload["cn_title"]) for c in bt}
    assert ("1.1 The Probabilistic Method", "概率方法") in pairs
    assert ("EXERCISES", "练习") in pairs


def test_exercise_items_exclude_translation_boxes():
    # 习题条目的中文翻译框内容不得被当成题目编号（不得改写翻译文本）
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "\\section*{EXERCISES}\n\n"
        "1. Let $X$ be a graph.\n\n"
        "\\begin{tcolorbox}\\relax\n1. 设 $X$ 为图。\n\\end{tcolorbox}\n\n"
        "2. Show that $X$ is complete.\n\n"
        "\\begin{tcolorbox}\\relax\n2. 证明 $X$ 是完全图。\n\\end{tcolorbox}\n\n"
        "\\end{document}\n"
    )
    res = scan(parse_latex(text))
    ex = [c for c in res.candidates if c.kind == "exercise-section"]
    assert len(ex) == 1
    assert ex[0].payload["item_lines"] == [5, 11]  # 仅英文条目，盒内翻译不计入


def test_bilingual_box_with_relax():
    # 真实书稿常见 \begin{tcolorbox}\relax —— 盒内前导 \relax 不应阻断识别
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "\\section*{Preface}\n\n"
        "\\begin{tcolorbox}\\relax\n\\section*{前言}\n\\end{tcolorbox}\n"
        "\n正文。\n\\end{document}\n"
    )
    res = scan(parse_latex(text))
    bt = [c for c in res.candidates if c.kind == "bilingual-title"]
    assert len(bt) == 1
    assert (bt[0].payload["en_title"], bt[0].payload["cn_title"]) == ("Preface", "前言")


def test_bilingual_box_with_extra_content_not_flagged():
    # R5 硬条件：盒内除中文标题外还有任何内容 → 不得合并
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "\\section*{1.1 The Method}\n"
        "\\begin{tcolorbox}\n\\section*{方法}\n一些额外说明文字。\n\\end{tcolorbox}\n"
        "\n正文。\n\\end{document}\n"
    )
    res = scan(parse_latex(text))
    bt = [c for c in res.candidates if c.kind == "bilingual-title"]
    assert bt == []


def test_scope_fix_candidates():
    res = scan_sample("basic_book.tex")
    sf = [c for c in res.candidates if c.kind == "scope-fix"]
    rules = {c.rule_id for c in sf}
    # The explicit outside-body signal subsumes the weaker title-only signal;
    # emitting both creates duplicate candidate IDs for one environment.
    assert rules == {"env-body-outside"}
    outside = [c for c in sf if c.rule_id == "env-body-outside"]
    assert len(outside) == 1 and outside[0].env_hint == "theorem"


def test_cn_fragment():
    res = scan_sample("cn_fragment.tex")
    tl = [c for c in res.candidates if c.kind == "theorem-like"]
    envs = {c.env_hint for c in tl}
    assert envs == {"definition", "theorem", "proposition", "corollary", "lemma", "remark", "example"}, envs
    # 陷阱：例如 / 注意 / 定义域 均不得成为候选
    assert not any(c.title_text.startswith(("例如", "注意", "定义域")) for c in tl)
    proofs = [c for c in res.candidates if c.kind == "proof"]
    assert len(proofs) == 2  # 证明：略 / 证明如下：
    assert {c.title_text[:4] for c in proofs} == {"证明：略", "证明如下"}


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

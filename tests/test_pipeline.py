# -*- coding: utf-8 -*-
"""流水线端到端测试（规则模式 / 无 Key 降级）。"""

import os
import sys

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


def test_cn_fragment_fast_mode():
    res = run_pipeline(read_sample("cn_fragment.tex"), mode="rule")
    assert res.ok, res.report_md
    out = res.result
    # elegantbook 自带环境的计数语义无法证明安全；显式源编号全部保守保留。
    for env in ("definition", "theorem", "proposition", "corollary", "lemma", "remark", "example"):
        assert f"\\begin{{{env}}}" not in out, env
    assert "定理 2.1（某某）. 结论陈述" in out
    assert "定义 1.1. 设 $A$ 是集合" in out
    assert any("避免双编号" in item["reason"] for item in res.ambiguous)
    # 证明起始语剥离
    assert out.count("\\begin{proof}") == 2
    assert "证明：略" not in out and "略。" in out
    assert "证明如下" not in out and "先证存在性。" in out
    # elegantbook：不补 amsthm
    assert "\\usepackage{amsthm}" not in out
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
    assert "\\begin{theorem}\n A statement without a source number." in result.result
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
    assert first.ok, first.report_md
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
    assert reused.ok, reused.report_md
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
    assert "\\begin{theorem}[7]\n A statement with its own number." in result.result
    assert result.result.count("\\newtheorem*{theorem}{Theorem}") == 1


def test_crlf_export_preserved():
    text = "\\documentclass{book}\r\n\\begin{document}\r\nTheorem. X.\r\n\\end{document}\r\n"
    res = run_pipeline(text, mode="rule")
    assert res.ok
    assert "\r\n" in res.export_text
    assert res.export_text.startswith("\\documentclass{book}\r\n")


def test_ai_mode_without_key_degrades():
    res = run_pipeline(read_sample("basic_book.tex"), mode="ai")
    assert res.ok
    assert res.verification["ai_degraded"] is True
    assert "\\begin{theorem}" in res.result  # 规则降级仍然包裹


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


def test_scope_fixes_are_grouped_by_environment_instance():
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
    assert len(moves) == 1
    assert any("只包住标题" in item["reason"] for item in ambiguous)


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

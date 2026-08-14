# -*- coding: utf-8 -*-
"""流水线端到端测试（规则模式 / 无 Key 降级）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.pipeline import run_pipeline  # noqa: E402

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
    # 无编号条目保留标题文本
    assert "Remark. This is a short note" in out
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
    assert "\\newtheorem{definition}{Definition}" in out
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
    for env in ("definition", "theorem", "proposition", "corollary", "lemma", "remark", "example"):
        assert f"\\begin{{{env}}}" in out, env
    # 中文编号提取
    assert "\\begin{theorem}[2.1]" in out and "定理 2.1" not in out
    assert "（某某）. 结论陈述" in out
    assert "\\begin{definition}[1.1]" in out and "定义 1.1" not in out
    assert "\\begin{remark}[3]" in out and "\\begin{example}[5]" in out
    # 证明起始语剥离
    assert out.count("\\begin{proof}") == 2
    assert "证明：略" not in out and "略。" in out
    assert "证明如下" not in out and "先证存在性。" in out
    # elegantbook：不补 amsthm
    assert "\\usepackage{amsthm}" not in out
    assert res.verification["content_invariant"] is True
    assert res.verification["env_balance"]["ok"] is True


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

# -*- coding: utf-8 -*-
"""规则扫描引擎测试（pytest 兼容；也可直接 python tests/test_scanner.py 运行）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

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
    assert "env-only-title" in rules
    assert "env-body-outside" in rules
    outside = [c for c in sf if c.rule_id == "env-body-outside"]
    assert outside and outside[0].env_hint == "theorem"


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

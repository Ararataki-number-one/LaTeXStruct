# -*- coding: utf-8 -*-
"""解析器测试（pytest 兼容；也可直接 python tests/test_parser.py 运行）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.parser import detect_newline, parse_latex  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def load_basic() :
    return parse_latex(read_sample("basic_book.tex"))


def test_newline_detection():
    assert detect_newline("a\r\nb") == "\r\n"
    assert detect_newline("a\nb") == "\n"
    doc = parse_latex("\\documentclass{book}\r\n\\begin{document}\r\nTheorem.\r\n\\end{document}\r\n")
    assert doc.newline == "\r\n"
    # 规范化文本不含 \r
    assert "\r" not in doc.text


def test_env_ranges_and_balance():
    doc = load_basic()
    names = [r[0] for r in doc.env_ranges]
    for expected in ("document", "tcolorbox", "theorem", "align", "verbatim", "enumerate"):
        assert expected in names, f"missing env: {expected}"
    assert names.count("tcolorbox") == 2
    assert doc.unbalanced_begins == []
    assert doc.unbalanced_ends == []


def test_preamble_span():
    doc = load_basic()
    assert doc.preamble_span is not None
    assert doc.preamble_span.start_line == 1
    assert doc.preamble_span.end_line == 3
    kinds = [b.kind for b in doc.blocks]
    assert "preamble" in kinds


def test_sections():
    doc = load_basic()
    titles = [(s.cmd, s.title, s.starred) for s in doc.sections]
    assert ("chapter", "Probability", False) in titles
    assert ("section", "1.1 The Probabilistic Method", True) in titles
    assert ("section", "概率方法", True) in titles
    assert ("section", "EXERCISES", True) in titles
    assert ("section", "练习", True) in titles
    assert ("section", "Real exercises", True) in titles


def test_comment_masked():
    doc = load_basic()
    assert "Definition 9.9.9" not in doc.masked
    assert "Definition 9.9.9" in doc.text  # 原文保留
    paras = doc.blocks_of_kind("para")
    assert not any(b.text.startswith("%") for b in paras)


def test_verbatim_masked_and_blocked():
    doc = load_basic()
    assert "Theorem 0.0 inside verbatim" not in doc.masked
    assert "Theorem 0.0 inside verbatim" in doc.text
    vb = [b for b in doc.blocks if b.kind == "verbatim"]
    assert len(vb) == 1 and vb[0].name == "verbatim"
    assert "Theorem 0.0" in vb[0].text
    # verbatim 内部不得被切成段落
    paras = doc.blocks_of_kind("para")
    assert not any("inside verbatim" in b.text for b in paras)


def test_paragraphs():
    doc = load_basic()
    paras = doc.blocks_of_kind("para")
    all_text = "\n".join(b.text for b in paras)
    for needle in (
        "Definition 1.1.1",
        "Here is the body of the definition",
        "Theorem 2.3.4 (Erd",
        "by Lemma 3.1",
        "The body of Theorem 9.9 was left outside",
        "1. First problem text",
    ):
        assert needle in all_text, f"missing para text: {needle}"


def test_in_env_annotations():
    doc = load_basic()
    paras = doc.blocks_of_kind("para")
    # tcolorbox 内的中文节标题行应标注祖先环境
    box_paras = [b for b in paras if "tcolorbox" in b.in_env]
    assert box_paras, "tcolorbox 内的段落应有 in_env 标注"
    # theorem 环境内的正文
    inner = [b for b in paras if "theorem" in b.in_env]
    assert inner and "A statement" in inner[0].text
    # 环境外的正文不应带 theorem 祖先
    outside = [b for b in paras if "was left outside" in b.text]
    assert outside and "theorem" not in outside[0].in_env


def test_display_math_block():
    doc = load_basic()
    disp = doc.blocks_of_kind("displaymath")
    assert disp and "int_0^1" in disp[0].text
    # 显示公式内部不得拆段
    paras = doc.blocks_of_kind("para")
    assert not any("int_0^1" in b.text for b in paras)


def test_section_path_assignment():
    doc = load_basic()
    paras = doc.blocks_of_kind("para")
    ex = [b for b in paras if "First problem text" in b.text]
    assert ex and ex[0].section_path == ("Probability", "Real exercises")


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

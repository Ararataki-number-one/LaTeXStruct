# -*- coding: utf-8 -*-
"""平衡括号解析测试（texparse）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402
from latexstruct.core.texparse import find_commands, interior_section_command, parse_command_args  # noqa: E402


def test_nested_braces_section_title():
    text = r"\section{A \textit{very important} theorem}"
    cmds = find_commands(text, ("section",))
    assert len(cmds) == 1
    assert cmds[0].required[0] == r"A \textit{very important} theorem"
    assert cmds[0].star is False and cmds[0].optional is None


def test_math_braces_in_title():
    text = r"\section{The case $K_{r,s}$ and \{x\}}"
    cmds = find_commands(text, ("section",))
    assert len(cmds) == 1
    assert cmds[0].required[0] == r"The case $K_{r,s}$ and \{x\}"


def test_star_and_optional_arg():
    text = r"\section*[Short \emph{toc}]{Long \textbf{title}}"
    cmds = find_commands(text, ("section",))
    assert len(cmds) == 1
    assert cmds[0].star is True
    assert cmds[0].optional == r"[Short \emph{toc}]"
    assert cmds[0].required[0] == r"Long \textbf{title}"


def test_unbalanced_returns_none():
    assert parse_command_args(r"\section{A {broken", 8, "section") is None
    assert find_commands(r"\section{A {broken}", ("section",)) == []


def test_parser_integration_nested_title():
    doc = parse_latex(
        "\\documentclass{book}\n\\begin{document}\n"
        "\\section*{1.1 The \\textit{Probabilistic} Method for $K_{r,s}$}\n\n"
        "body\n\\end{document}\n"
    )
    titles = [s.title for s in doc.sections]
    assert titles == ["1.1 The \\textit{Probabilistic} Method for $K_{r,s}$"]


def test_bilingual_box_nested_cn_title():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "\\section*{1.1 The Method}\n"
        "\\begin{tcolorbox}\\relax\n\\section*{1.1 方法\\textbf{（图）}}\n\\end{tcolorbox}\n"
        "\n正文。\n\\end{document}\n"
    )
    res = scan(parse_latex(text))
    bt = [c for c in res.candidates if c.kind == "bilingual-title"]
    assert len(bt) == 1
    assert bt[0].payload["cn_title"] == "1.1 方法\\textbf{（图）}"


def test_interior_section_command_rejects_extra_content():
    assert interior_section_command(r"\relax\section*{前言}") == ("前言", True, None)
    assert interior_section_command(r"\section*{前言} 额外说明") is None
    assert interior_section_command("plain text") is None


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

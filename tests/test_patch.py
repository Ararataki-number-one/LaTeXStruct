# -*- coding: utf-8 -*-
"""补丁引擎单元测试（pytest 兼容；也可直接 python tests/test_patch.py 运行）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.patch import (  # noqa: E402
    AppliedPatch,
    Decision,
    Edit,
    PatchContext,
    apply_patches,
    build_ops,
    content_invariant,
)


def run(lines, d, ctx=None):
    ops, err = build_ops(d, lines, ctx or PatchContext())
    assert not err, err
    return apply_patches(lines, [(d, ops)])


def test_wrap_basic():
    lines = ["Theorem 1. A statement.", "", "Proof. By induction."]
    d = Decision(candidate_id="c1", action="wrap", env="theorem", body_span=(1, 1), source="rule")
    out, applied, rejected = run(lines, d)
    assert rejected == []
    assert out == ["\\begin{theorem}", "Theorem 1. A statement.", "\\end{theorem}", "", "Proof. By induction."]
    assert content_invariant(lines, out, applied)


def test_wrap_optional_arg():
    lines = ["Theorem 2.3.4. Result."]
    d = Decision(candidate_id="c1", action="wrap", env="theorem", body_span=(1, 1), optional_arg="2.3.4")
    out, applied, _ = run(lines, d)
    assert out[0] == "\\begin{theorem}[2.3.4]"
    assert content_invariant(lines, out, applied)


def test_wrap_multi_line_body():
    lines = ["Theorem. First line.", "Second line of the statement."]
    d = Decision(candidate_id="c1", action="wrap", env="theorem", body_span=(1, 2))
    out, applied, _ = run(lines, d)
    assert out == ["\\begin{theorem}", "Theorem. First line.", "Second line of the statement.", "\\end{theorem}"]
    assert content_invariant(lines, out, applied)


def test_move_boundary():
    lines = ["\\begin{theorem}", "Theorem 9.9. A statement.", "\\end{theorem}", "The body was left outside."]
    d = Decision(candidate_id="c2", action="move-boundary", env="theorem",
                 payload={"old_end_line": 3, "new_end_line": 4})
    out, applied, rejected = run(lines, d)
    assert rejected == []
    assert out == ["\\begin{theorem}", "Theorem 9.9. A statement.", "The body was left outside.", "\\end{theorem}"]
    assert content_invariant(lines, out, applied)


def test_move_boundary_bad_anchor_rejected():
    lines = ["\\begin{theorem}", "Theorem 9.9. A statement.", "\\end{theorem}", "The body."]
    d = Decision(candidate_id="c2", action="move-boundary", env="theorem",
                 payload={"old_end_line": 2, "new_end_line": 4})
    ops, err = build_ops(d, lines, PatchContext())
    assert err and ops == []  # 行 2 不是 \end{theorem}，保守放弃


def test_exercise_conversion():
    lines = ["1. First problem.", "2. Second problem."]
    d = Decision(candidate_id="c3", action="convert-to-exercise-env", env="enumerate",
                 payload={"item_lines": [1, 2]})
    out, applied, rejected = run(lines, d)
    assert rejected == []
    assert out == ["\\begin{enumerate}", "\\item First problem.", "\\item Second problem.", "\\end{enumerate}"]
    assert content_invariant(lines, out, applied)


def test_exercise_item_prefix_mismatch_rejected():
    lines = ["1. First problem.", "Second problem without number."]
    d = Decision(candidate_id="c3", action="convert-to-exercise-env", env="enumerate",
                 payload={"item_lines": [1, 2]})
    ops, err = build_ops(d, lines, PatchContext())
    assert err and ops == []  # 行 2 缺编号前缀，保守放弃


def test_merge_bilingual_title():
    lines = [
        "\\section*{1.1 The Method}",
        "\\begin{tcolorbox}",
        "\\section*{方法}",
        "\\end{tcolorbox}",
        "",
        "Some text.",
    ]
    d = Decision(candidate_id="c4", action="merge-bilingual-title",
                 payload={"section_line": 1, "section_cmd": "section",
                          "en_title": "1.1 The Method", "cn_title": "方法", "box_lines": (2, 4)})
    out, applied, rejected = run(lines, d)
    assert rejected == []
    assert out[0] == "\\section*{1.1 The Method（方法）}"
    assert out[1] == "\\addcontentsline{toc}{section}{1.1 The Method（方法）}"
    assert "tcolorbox" not in out and "方法" in out[0]
    assert content_invariant(lines, out, applied)


def test_merge_bilingual_delete_ops_cover_whole_box():
    # 补丁层按扫描器给出的 box_lines 删除整盒；盒内含多余内容时是否合并由扫描器把关
    lines = [
        "\\section*{1.1 The Method}",
        "\\begin{tcolorbox}",
        "\\section*{方法}",
        "\\end{tcolorbox}",
        "",
        "Some text.",
    ]
    d = Decision(candidate_id="c4", action="merge-bilingual-title",
                 payload={"section_line": 1, "section_cmd": "section",
                          "en_title": "1.1 The Method", "cn_title": "方法", "box_lines": (2, 4)})
    ops, err = build_ops(d, lines, PatchContext())
    assert not err
    delete_lines = sorted(op.line for op in ops if op.kind == "delete_line")
    assert delete_lines == [2, 3, 4]  # 整盒删除，内容不变校验由 revert 兜底


def test_preamble_add():
    lines = ["\\documentclass{book}", "", "\\begin{document}", "text", "\\end{document}"]
    ctx = PatchContext(preamble_anchor=3)
    d = Decision(candidate_id="pre", action="preamble-add", source="rule")
    ops, err = build_ops(d, lines, ctx)
    assert not err and len(ops) == 10
    out, applied, rejected = run(lines, d, ctx)
    assert rejected == []
    assert "\\usepackage{amsthm}" in out and "\\newtheorem*{theorem}{Theorem}" in out
    assert out[-1] == "\\end{document}"
    assert content_invariant(lines, out, applied)


def test_preamble_add_does_not_redeclare_existing_customization():
    lines = ["\\documentclass{book}", "\\newtheorem{definition}{定义}",
             "\\begin{document}", "x", "\\end{document}"]
    ctx = PatchContext(preamble_anchor=3, existing_envs={"definition"})
    d = Decision(candidate_id="pre", action="preamble-add")
    ops, err = build_ops(d, lines, ctx)
    assert not err
    assert not any(op.new.startswith("\\newtheorem*{definition}") for op in ops)


def test_wrap_with_title_strip():
    # 编号进可选参数 + 标题词条剥离（可逆）
    lines = ["Theorem 2.3.4 Result statement."]
    d = Decision(candidate_id="c1", action="wrap", env="theorem", body_span=(1, 1),
                 optional_arg="2.3.4", keep_title_text=False,
                 payload={"title_prefix": "Theorem 2.3.4 "})
    out, applied, rejected = run(lines, d)
    assert rejected == []
    assert out == ["\\begin{theorem}[2.3.4]", "Result statement.", "\\end{theorem}"]
    assert content_invariant(lines, out, applied)


def test_wrap_title_strip_skipped_when_empty_remainder():
    # 标题独占一行时不得剥离（剩余为空 → 保守保留）
    lines = ["Theorem 2.3.4"]
    d = Decision(candidate_id="c1", action="wrap", env="theorem", body_span=(1, 1),
                 optional_arg="2.3.4", keep_title_text=True)
    ops, err = build_ops(d, lines, PatchContext())
    assert not err
    out, applied, _ = apply_patches(lines, [(d, ops)])
    assert out == ["\\begin{theorem}[2.3.4]", "Theorem 2.3.4", "\\end{theorem}"]
    assert content_invariant(lines, out, applied)


def test_unrecorded_change_detected():
    # 任何未被编辑日志记录的改动都必须导致内容不变校验失败
    original = ["a", "b"]
    out = ["A", "b"]
    assert not content_invariant(original, out, [])
    # 编辑日志损坏（替换文本与记录不符）也应失败
    bad = [AppliedPatch(decision=Decision(candidate_id="x", action="none"),
                        edits=[Edit("replace_line", 1, old="WRONG", new="A")])]
    assert not content_invariant(original, out, bad)


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

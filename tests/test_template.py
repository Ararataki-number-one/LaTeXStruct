# -*- coding: utf-8 -*-
"""模板转换（elegantbook）测试。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.template import build_template_ops  # noqa: E402
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
    assert dc.new == "\\documentclass{elegantbook}"
    # geometry/ctex/tcolorbox/\circled 删除（elegantbook 自带，避免选项冲突）
    assert any("geometry" in op.old for op in ops if op.kind == "delete_line")
    assert any("ctex" in op.old for op in ops if op.kind == "delete_line")
    assert any("tcolorbox" in op.old for op in ops if op.kind == "delete_line")
    assert any("circled" in op.old for op in ops if op.kind == "delete_line")
    # 目录替换
    toc = next(op for op in ops if op.new == "\\tableofcontents")
    assert "Contents" in toc.old
    # 章标题转换 + 计数器
    ch = [op for op in ops if "\\chapter*{1 Graphs}" == op.new]
    assert len(ch) == 1
    assert any(op.new == "\\refstepcounter{chapter}" for op in ops)
    # 目录区内条目不得转章（"1 Graphs 1" 以页号结尾）
    assert not any("\\chapter*{1 Graphs 1}" in op.new for op in ops)


def test_pipeline_with_elegantbook_template():
    res = run_pipeline(SYNTHETIC, mode="rule", template="elegantbook")
    assert res.ok, res.report_md
    out = res.result
    assert "\\documentclass{elegantbook}" in out
    assert "geometry" not in out.split("\\begin{document}")[0]
    assert "\\usepackage{ctex}" not in out
    assert "\\tableofcontents" in out
    # 旧目录区（含页号条目）已删除
    assert "1 Graphs 1" not in out
    assert "vii" not in out
    # 章转换 + 章计数器 + 章级目录条目
    assert "\\chapter*{1 Graphs（1 图）}" in out
    assert "\\refstepcounter{chapter}" in out
    assert "\\addcontentsline{toc}{chapter}{1 Graphs（1 图）}" in out
    # 节级目录条目
    assert "\\addcontentsline{toc}{section}{1.1 Graphs（1.1 图）}" in out
    # elegantbook：不补 amsthm
    assert "\\usepackage{amsthm}" not in out
    # 模板自带 theorem 的计数语义不由本工具控制；显式源编号不得自动包裹成双编号。
    assert "\\begin{theorem}" not in out
    assert "Theorem 1.1. A statement." in out
    assert any("避免双编号" in item["reason"] for item in res.ambiguous)
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
    assert "\\tableofcontents" in out  # 无旧目录时在第一章前插入
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
    assert "\\begin{theorem}" not in res.result
    assert any("避免双编号" in item["reason"] for item in res.ambiguous)


def test_template_ops_env_balance():
    ops, notes = build_template_ops(SYNTHETIC)
    from latexstruct.core.patch import Decision, apply_patches, validate_ops

    lines = SYNTHETIC.split("\n")
    ok, rejected = validate_ops(lines, [(Decision(candidate_id="tpl", action="none"), ops)])
    assert not rejected, rejected[0].error if rejected else ""
    out, _, _ = apply_patches(lines, ok)
    assert check_env_balance("\n".join(out))["ok"] is True


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

# -*- coding: utf-8 -*-
"""从真实书稿切出回归摘录 + 重新落盘两本书结果/汇报。

摘录规则：保留原书导言区（到 \\begin{document} 为止）+
指定正文行区间 + \\end{document}，内容逐字来自原书，仅作回归测试。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.pipeline import run_pipeline  # noqa: E402

GODSIL = r"C:\Users\ZQY\Desktop\deepseek\corpus\godsil\Algebraic-Graph-Theory-by-Chris-Godsil.tex"
EXTREMAL = r"C:\Users\ZQY\Desktop\deepseek\corpus\extremal\Extremal_Combinatorics_With_Applications_in_Computer_Science_Texts_in_Theoretical_Computer_Sci.tex"
EXCERPT_OUT = Path(__file__).resolve().parents[1] / "tests" / "samples" / "real_godsil_excerpt.tex"


def make_excerpt(path: str, body_ranges) -> str:
    lines = open(path, encoding="utf-8").read().split("\n")
    begin = next(i for i, l in enumerate(lines) if l.startswith("\\begin{document}"))
    parts = lines[: begin + 1]
    for a, b in body_ranges:
        parts.extend(lines[a - 1 : b])
    parts.append("\\end{document}")
    parts.append("")
    return "\n".join(parts)


def main():
    # 1) 摘录：引理/定理/证明区 + 习题节（含中文翻译框）
    excerpt = make_excerpt(GODSIL, [(2987, 3045), (3258, 3305)])
    EXCERPT_OUT.write_text(excerpt, encoding="utf-8")
    print(f"excerpt -> {EXCERPT_OUT} ({len(excerpt.splitlines())} 行)")

    # 2) 两本书结果/汇报落盘
    for path, tag in ((GODSIL, "godsil"), (EXTREMAL, "extremal")):
        pr = run_pipeline(open(path, encoding="utf-8").read(), mode="rule")
        outdir = Path(path).parent
        (outdir / f"result-{tag}.tex").write_text(pr.export_text, encoding="utf-8")
        (outdir / f"report-{tag}.md").write_text(pr.report_md, encoding="utf-8")
        print(f"{tag}: applied={len(pr.applied)} rejected={len(pr.rejected)} "
              f"ambiguous={len(pr.ambiguous)} -> {outdir}")


if __name__ == "__main__":
    main()

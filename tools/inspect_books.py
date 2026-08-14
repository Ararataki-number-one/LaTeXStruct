# -*- coding: utf-8 -*-
"""真实书稿检查与结果落盘：节标题/习题节/定理区样例 + 输出 result.tex 与 report.md。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402

BOOKS = [
    (r"C:\Users\ZQY\Desktop\deepseek\corpus\godsil\Algebraic-Graph-Theory-by-Chris-Godsil.tex", "godsil"),
    (r"C:\Users\ZQY\Desktop\deepseek\corpus\extremal\Extremal_Combinatorics_With_Applications_in_Computer_Science_Texts_in_Theoretical_Computer_Sci.tex", "extremal"),
]


def main():
    for path, tag in BOOKS:
        text = open(path, encoding="utf-8").read()
        doc = parse_latex(text)
        lines = doc.text.split("\n")
        print(f"\n########## {tag} ##########")

        # 1) 节标题样例 + 紧随其后的盒子
        print("\n--- 节标题样例（前 10 个带编号节 + 下一行）---")
        n = 0
        for s in doc.sections:
            if s.cmd == "section":
                L = s.span.start_line
                print(f"[{L}] {lines[L-1].strip()[:70]}")
                if L < len(lines):
                    print(f"     下一行: {lines[L].strip()[:70]}")
                n += 1
                if n >= 10:
                    break

        # 2) EXERCISES 节
        print("\n--- EXERCISES 相关节 ---")
        ex = [s for s in doc.sections if s.cmd == "section" and "xercis" in s.title]
        for s in ex[:4]:
            print(f"[{s.span.start_line}] {s.title[:60]}")
            for j in range(s.span.start_line + 1, min(s.span.start_line + 8, len(lines) + 1)):
                print(f"      {lines[j-1].strip()[:70]}")

        # 3) 流水线 + 落盘
        pr = run_pipeline(text, mode="rule")
        outdir = Path(path).parent
        (outdir / f"result-{tag}.tex").write_text(pr.export_text, encoding="utf-8")
        (outdir / f"report-{tag}.md").write_text(pr.report_md, encoding="utf-8")
        print(f"\n--- 落盘: {outdir}/result-{tag}.tex, report-{tag}.md ---")
        print(f"applied={len(pr.applied)} rejected={len(pr.rejected)} ambiguous={len(pr.ambiguous)}")

        # 4) 首个 theorem 包装附近的 diff 样例
        res = pr.result.split("\n")
        print("\n--- 首个 theorem 包装区域（整理后）---")
        hit = None
        for i, ln in enumerate(res):
            if ln.startswith("\\begin{theorem}"):
                hit = i
                break
        if hit is not None:
            for j in range(max(0, hit - 2), min(len(res), hit + 6)):
                print(f"[{j + 1}] {res[j][:80]}")


if __name__ == "__main__":
    main()

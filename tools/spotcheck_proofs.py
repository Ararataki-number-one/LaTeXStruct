# -*- coding: utf-8 -*-
"""抽查：最长的 proof 环境、叙述重启边界、目录/章区形态。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.pipeline import run_pipeline  # noqa: E402

path = r"C:\Users\ZQY\Desktop\deepseek\corpus\godsil\Algebraic-Graph-Theory-by-Chris-Godsil.tex"
pr = run_pipeline(open(path, encoding="utf-8").read(), mode="rule", template="elegantbook")
res = pr.result.split("\n")

# 1) 最长 proof
proofs = []
cur = None
for i, l in enumerate(res):
    if l.startswith("\\begin{proof}"):
        cur = i
    elif l.startswith("\\end{proof}") and cur is not None:
        proofs.append((cur, i))
        cur = None
longest = max(proofs, key=lambda p: p[1] - p[0])
print(f"最长 proof: 行 {longest[0] + 1}–{longest[1] + 1}（{longest[1] - longest[0] + 1} 行）")
print("首 6 行与末 6 行:")
for j in list(range(longest[0], longest[0] + 6)) + list(range(longest[1] - 5, longest[1] + 1)):
    print(f"[{j + 1}] {res[j][:75]}")
print()

# 2) 叙述重启边界（"There is another interesting"）
for i, l in enumerate(res):
    if "There is another interesting" in l:
        print(f"叙述重启 @ 行 {i + 1}，其前 3 行:")
        for j in range(i - 3, i):
            print(f"[{j + 1}] {res[j][:75]}")
        break
print()

# 3) 目录与章区
for i, l in enumerate(res):
    if l.startswith("\\tableofcontents") or l.startswith("\\chapter") or l.startswith("\\refstep"):
        print(f"[{i + 1}] {l[:75]}")
        if l.startswith("\\chapter"):
            for j in range(i + 1, min(i + 3, len(res))):
                print(f"[{j + 1}] {res[j][:75]}")
            break

# 落盘
outdir = Path(path).parent
(outdir / "result-godsil-elegantbook.tex").write_text(pr.export_text, encoding="utf-8")
(outdir / "report-godsil-elegantbook.md").write_text(pr.report_md, encoding="utf-8")
print("\n已落盘 result-godsil-elegantbook.tex / report-godsil-elegantbook.md")

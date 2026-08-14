# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_template import SYNTHETIC  # noqa: E402

from latexstruct.core.pipeline import run_pipeline  # noqa: E402

res = run_pipeline(SYNTHETIC, mode="rule", template="elegantbook")
print("ok:", res.ok)
out = res.result.split("\n")
for i, l in enumerate(out):
    if "chapter" in l or "tableofcontents" in l or "refstep" in l or "1 Graph" in l or "1 图" in l:
        print(f"[{i + 1}] {l[:80]!r}")
print("--- 汇报 ---")
print(res.report_md)

# -*- coding: utf-8 -*-
"""Benchmark CLI：跑全部金标集并输出报告。

用法：python tools/benchmark.py [--compile] [--json]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.benchmark import BENCHMARK_DIR, render_markdown, run_all  # noqa: E402


def main():
    args = sys.argv[1:]
    compile_check = "--compile" in args
    reports = run_all(compile_check=compile_check)
    md = render_markdown(reports)
    (BENCHMARK_DIR / "report.md").write_text(md, encoding="utf-8")
    print(md)
    if "--json" in args:
        print(json.dumps(reports, ensure_ascii=False, indent=1))
    failed = [r["name"] for r in reports if not r["ok"]]
    if failed:
        print(f"\n未通过: {failed}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

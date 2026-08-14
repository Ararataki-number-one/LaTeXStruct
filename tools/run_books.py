# -*- coding: utf-8 -*-
"""对给定 .tex 文件运行解析/扫描/流水线并打印统计（真实书稿摸底工具）。

用法：python tools/run_books.py <file1.tex> [file2.tex ...]
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402


def report(path: str, template: str = None):
    t = open(path, encoding="utf-8").read()
    t0 = time.time()
    doc = parse_latex(t)
    t1 = time.time()
    res = scan(doc)
    t2 = time.time()
    total = doc.text.count("\n") + 1
    print(f"=== {Path(path).name}" + (f" [template={template}]" if template else "") + " ===")
    print(f"  行数 {total} · 解析 {t1 - t0:.2f}s · 扫描 {t2 - t1:.2f}s")
    print(
        "  blocks:",
        {k: len(doc.blocks_of_kind(k)) for k in ("para", "env", "displaymath", "verbatim", "preamble")},
    )
    print(
        f"  env_ranges {len(doc.env_ranges)} · sections {len(doc.sections)} · "
        f"unbalanced begin {doc.unbalanced_begins[:5]} / end {doc.unbalanced_ends[:5]}"
    )
    print(f"  candidates: {res.stats} · skipped: {len(res.skipped)}")
    t3 = time.time()
    pr = run_pipeline(t, mode="rule", template=template)
    t4 = time.time()
    v = pr.verification
    print(
        f"  流水线(rule{'+tpl' if template else ''}): {t4 - t3:.2f}s · ok={pr.ok} · applied={len(pr.applied)} · "
        f"rejected={len(pr.rejected)} · ambiguous={len(pr.ambiguous)}"
    )
    print(
        f"  校验: content_invariant={v.get('content_invariant')} · "
        f"env_balance={v.get('env_balance', {}).get('ok')} · braces={v.get('braces', {}).get('ok')}"
    )
    # 证明扩展统计
    proofs = [ap for ap in pr.applied if ap.decision.action == "wrap" and ap.decision.env == "proof"]
    if proofs:
        spans = [d.body_span[1] - d.body_span[0] + 1 for d in (ap.decision for ap in proofs)]
        multi = sum(1 for s in spans if s > 1)
        print(f"  proof 环境: {len(proofs)} 个，其中跨多行（覆盖续段/公式/译文框）{multi} 个，最长 {max(spans)} 行")
    if pr.rejected:
        print("  rejected 样例:")
        for r in pr.rejected[:3]:
            print(f"    - {r.decision.candidate_id}: {r.error}")
    return pr


if __name__ == "__main__":
    args = sys.argv[1:]
    template = None
    if "--template" in args:
        i = args.index("--template")
        template = args[i + 1]
        args = args[:i] + args[i + 2 :]
    for p in args:
        report(p, template=template)
        print()

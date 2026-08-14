# -*- coding: utf-8 -*-
"""整本书 AI 模式实测：真实 Key 跑完整流水线（决策 + 复查分块 + span 合法化）。

用法：python tools/e2e_book.py <book.tex> [review_model] [--template elegantbook]
默认复查模型 deepseek-chat（控成本）；--reasoner 可切 deepseek-reasoner（切片已验证）。
输出：<book>-ai-result.tex、<book>-ai-report.md 与统计。
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.config import load_config  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402


def main():
    args = sys.argv[1:]
    template = None
    if "--template" in args:
        i = args.index("--template")
        template = args[i + 1]
        args = args[:i] + args[i + 2 :]
    if not args:
        print("用法: python tools/e2e_book.py <book.tex> [review_model] [--template elegantbook]")
        return 1
    path = args[0]
    review_model = args[1] if len(args) > 1 else "deepseek-chat"

    cfg = load_config()
    ai = cfg.to_ai_config()
    if not ai.decide.api_key:
        print("未配置 API Key")
        return 1
    ai.review.model = review_model
    ai.review_batch = 25
    print(f"决策: {ai.decide.model} · 复查: {ai.review.model} · template: {template or '无'}", flush=True)

    text = open(path, encoding="utf-8").read()
    print(f"行数: {text.count(chr(10)) + 1}，开始处理……", flush=True)
    t0 = time.time()
    pr = run_pipeline(text, mode="ai", ai_config=ai, template=template)
    dt = time.time() - t0
    v = pr.verification
    print(f"耗时: {dt / 60:.1f} 分钟", flush=True)
    print(f"ok={pr.ok} applied={len(pr.applied)} rejected={len(pr.rejected)} "
          f"ambiguous={len(pr.ambiguous)} degraded={v.get('ai_degraded')}", flush=True)
    print(f"校验: invariant={v.get('content_invariant')} balance={v.get('env_balance', {}).get('ok')}", flush=True)
    print(f"AI 用量: {v.get('ai_usage', {})}", flush=True)
    if pr.review.get("findings"):
        fixes = [f for f in pr.review["findings"] if f["verdict"] != "ok"]
        print(f"复查: {len(pr.review['findings'])} 项，修正 {len(fixes)} 项", flush=True)

    outdir = Path(path).parent
    (outdir / f"{Path(path).stem}-ai-result.tex").write_text(pr.export_text, encoding="utf-8")
    (outdir / f"{Path(path).stem}-ai-report.md").write_text(pr.report_md, encoding="utf-8")
    print(f"已输出: {outdir / (Path(path).stem + '-ai-result.tex')}", flush=True)
    return 0 if pr.ok else 1


if __name__ == "__main__":
    sys.exit(main())

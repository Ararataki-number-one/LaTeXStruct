# -*- coding: utf-8 -*-
"""真实 AI Key 端到端验证：读取本机 %APPDATA%/LaTeXStruct/config.json 的 Key，
对合成样例与真实书稿摘录跑 AI 模式（真实 DeepSeek 决策 + deepseek-reasoner 复查）。

用法：python tools/e2e_ai.py [样例文件...]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.config import load_config  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402

TESTS = Path(__file__).resolve().parents[1] / "tests"


def main():
    cfg = load_config()
    ai_cfg = cfg.to_ai_config()  # Key 缺失时互相回退
    if not ai_cfg.decide.api_key:
        print("未配置任何 API Key：请在客户端 AI 设置页填入 Key，或设环境变量 LATEXSTRUCT_DECIDE_KEY")
        return 1
    print(f"决策模型: {ai_cfg.decide.model} · 复查模型: {ai_cfg.review.model} · 复查开关: {ai_cfg.review_enabled}")

    samples = sys.argv[1:] or [
        str(TESTS / "samples" / "basic_book.tex"),
        str(TESTS / "samples" / "real_godsil_excerpt.tex"),
    ]
    failed = 0
    for path in samples:
        text = open(path, encoding="utf-8").read()
        print(f"\n=== {Path(path).name}（{text.count(chr(10)) + 1} 行，AI 模式）===", flush=True)
        res = run_pipeline(text, mode="ai", ai_config=ai_cfg)
        v = res.verification
        print(f"ok={res.ok} applied={len(res.applied)} rejected={len(res.rejected)} "
              f"ambiguous={len(res.ambiguous)} degraded={v.get('ai_degraded')}")
        print(f"校验: invariant={v.get('content_invariant')} balance={v.get('env_balance', {}).get('ok')}")
        print(f"AI 用量: {v.get('ai_usage', {})}")
        if res.review.get("findings"):
            fixes = [f for f in res.review["findings"] if f["verdict"] != "ok"]
            print(f"复查: {len(res.review['findings'])} 项，修正 {len(fixes)} 项：")
            for f in fixes[:5]:
                print(f"  - {f['candidate_id']}: {f['verdict']}（{f.get('reason', '')[:60]}）")
        elif res.review.get("error"):
            print(f"复查失败: {res.review['error']}")
        if not res.ok:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

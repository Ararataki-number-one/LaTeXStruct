# -*- coding: utf-8 -*-
"""span 合法化测试（实测驱动：AI 多包图注/叙述段/译文框时的确定性收缩）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.legalize import legalize_decisions, legalize_wrap  # noqa: E402
from latexstruct.core.patch import Decision  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def test_theorem_span_clamped_to_title_para():
    # 真实切片：AI 若把图注/翻译框/叙述段包进定理，应收缩到标题段
    doc = parse_latex(read_sample("godsil_1_7.tex"))
    res = scan(doc)
    cands = [c for c in res.candidates if c.kind == "theorem-like"]
    assert cands
    c = cands[0]
    # 伪造 AI 过度扩张的 span（覆盖到标题段之后 40 行）
    d = Decision(candidate_id=c.id, action="wrap", env=c.env_hint, source="ai",
                 body_span=(c.span.start_line, c.span.end_line + 40))
    legalize_wrap(doc, d, c)
    assert d.body_span == (c.span.start_line, c.span.end_line)
    assert d.body_span[1] - d.body_span[0] + 1 <= 3  # 标题段只有 1-3 行


def test_proof_span_stops_before_next_title():
    # proof 的 span 不得越过下一定理类标题
    text = (
        "\\documentclass{book}\n\\begin{document}\n\n"
        "Theorem 1. A.\n\n"
        "Proof. Fix it.\n\n"
        "More argument.\n\n"
        "Theorem 2. B.\n\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    res = scan(doc)
    proof = [c for c in res.candidates if c.kind == "proof"][0]
    d = Decision(candidate_id=proof.id, action="wrap", env="proof", source="ai",
                 body_span=(proof.span.start_line, 11))  # 越过 Theorem 2（第 10 行）
    legalize_wrap(doc, d, proof)
    # 终点必须落在下一停点（Theorem 2）之前，且吸附到"More argument."段尾
    assert d.body_span == (proof.span.start_line, 9)


def test_proof_span_snapped_to_block_end():
    # 终点落在段中间 → 吸附到段尾
    text = (
        "\\documentclass{book}\n\\begin{document}\n\n"
        "Theorem 1. A.\n\n"
        "Proof. First line.\n"
        "Second line of argument.\n\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    res = scan(doc)
    proof = [c for c in res.candidates if c.kind == "proof"][0]
    d = Decision(candidate_id=proof.id, action="wrap", env="proof", source="ai",
                 body_span=(proof.span.start_line, proof.span.start_line + 1))
    legalize_wrap(doc, d, proof)
    blk = next(b for b in doc.blocks if b.kind == "para" and "Second line" in b.text)
    assert d.body_span[1] == blk.span.end_line


def test_rule_and_review_sources_untouched():
    doc = parse_latex(read_sample("godsil_1_7.tex"))
    res = scan(doc)
    c = [c for c in res.candidates if c.kind == "theorem-like"][0]
    span = (1, 5)
    d_rule = Decision(candidate_id=c.id, action="wrap", env="theorem", source="rule", body_span=span)
    d_review = Decision(candidate_id=c.id, action="wrap", env="theorem", source="review", body_span=span)
    legalize_decisions(doc, [d_rule, d_review], {c.id: c})
    assert d_rule.body_span == span and d_review.body_span == span


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

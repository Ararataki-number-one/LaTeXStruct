# -*- coding: utf-8 -*-
"""Benchmark 金标评测测试。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.benchmark import GOLDEN_DIR, evaluate_golden, render_markdown  # noqa: E402


def test_basic_book_golden_perfect():
    r = evaluate_golden(GOLDEN_DIR / "basic_book.json")
    assert r["ok"] is True, r
    assert r["macro"]["f1"] == 1.0
    for m in r["by_kind"].values():
        assert m["f1"] == 1.0 and m["fp"] == 0 and m["fn"] == 0


def test_cn_fragment_golden_perfect():
    r = evaluate_golden(GOLDEN_DIR / "cn_fragment.json")
    assert r["ok"] is True, r
    assert r["macro"]["f1"] == 1.0


def test_godsil_1_7_golden_perfect():
    r = evaluate_golden(GOLDEN_DIR / "godsil_1_7.json")
    assert r["ok"] is True, r
    assert r["labels_total"] == 7
    assert r["macro"]["tp"] == 7


def test_negatives_no_false_positives():
    r = evaluate_golden(GOLDEN_DIR / "negatives.json")
    assert r["ok"] is True, r
    # 无标签、无候选 → 无误报
    assert r["macro"]["fp"] == 0 and r["macro"]["fn"] == 0


def test_report_markdown():
    md = render_markdown([evaluate_golden(GOLDEN_DIR / "basic_book.json")])
    assert "Precision" in md and "basic-book" in md and "内容不变" in md


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

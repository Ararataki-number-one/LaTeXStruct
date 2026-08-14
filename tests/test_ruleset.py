# -*- coding: utf-8 -*-
"""Rule Pack 配置化测试。"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.ruleset import list_builtin_packs, load_pack  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def test_builtin_packs_listed():
    names = list_builtin_packs()
    for expected in ("bilingual", "english", "chinese", "academic-paper"):
        assert expected in names


def test_default_pack_preserves_behavior():
    # default 包（含 None）与原有行为一致
    doc = parse_latex(read_sample("basic_book.tex"))
    r_default = scan(doc, pack=None)
    r_explicit = scan(doc, pack="bilingual")
    assert r_default.stats == r_explicit.stats
    assert {c.env_hint for c in r_default.candidates if c.kind == "theorem-like"} == {
        "definition", "theorem", "remark"}


def test_english_pack_ignores_chinese():
    doc = parse_latex(read_sample("cn_fragment.tex"))
    res = scan(doc, pack="english")
    tl = [c for c in res.candidates if c.kind == "theorem-like"]
    assert tl == []  # 中文标题不识别
    assert [c for c in res.candidates if c.kind == "proof"] == []


def test_chinese_pack_ignores_english():
    doc = parse_latex(read_sample("basic_book.tex"))
    res = scan(doc, pack="chinese")
    tl = [c for c in res.candidates if c.kind == "theorem-like"]
    assert tl == []  # 英文标题不识别


def test_academic_paper_extensions():
    text = (
        "\\documentclass{article}\n\\begin{document}\n\n"
        "Conjecture 1. A bold guess.\n\n"
        "Fact 2. A known fact.\n\n"
        "Observation. Something noticed.\n\n"
        "Claim. We assert this.\n\n"
        "\\end{document}\n"
    )
    res = scan(parse_latex(text), pack="academic-paper")
    envs = {c.env_hint for c in res.candidates if c.kind == "theorem-like"}
    assert {"conjecture", "proposition", "remark", "claim"} <= envs


def test_academic_paper_disables_bilingual():
    doc = parse_latex(read_sample("basic_book.tex"))
    res = scan(doc, pack="academic-paper")
    assert [c for c in res.candidates if c.kind == "bilingual-title"] == []


def test_custom_json_pack():
    tmp = tempfile.mkdtemp(prefix="ls-pack-", dir=os.path.dirname(os.path.abspath(__file__)))
    try:
        pack_path = os.path.join(tmp, "custom.json")
        with open(pack_path, "w", encoding="utf-8") as f:
            json.dump(
                {"name": "custom", "title_patterns": {"remark": ["Observation", "注"], "theorem": ["Theorem"]}},
                f,
            )
        rp = load_pack(pack_path)
        assert rp.name == "custom"
        text = (
            "\\documentclass{book}\n\\begin{document}\n\n"
            "Observation. A custom remark.\n\n"
            "Theorem 3. A theorem.\n\n"
            "\\end{document}\n"
        )
        res = scan(parse_latex(text), pack=pack_path)
        envs = {c.env_hint for c in res.candidates if c.kind == "theorem-like"}
        assert envs == {"remark", "theorem"}
        # 未提供的字段回退默认（证明续段词等）
        assert rp.continue_re is not None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_pipeline_with_custom_pack():
    tmp = tempfile.mkdtemp(prefix="ls-pack2-", dir=os.path.dirname(os.path.abspath(__file__)))
    try:
        pack_path = os.path.join(tmp, "custom.json")
        with open(pack_path, "w", encoding="utf-8") as f:
            json.dump({"name": "custom", "title_patterns": {"remark": ["Observation"]}}, f)
        text = (
            "\\documentclass{book}\n\\begin{document}\n\n"
            "Observation. A custom remark.\n\n"
            "\\end{document}\n"
        )
        res = run_pipeline(text, mode="rule", pack=pack_path)
        assert res.ok
        assert "\\begin{remark}" in res.result
        assert res.verification["invariants"]["ok"] is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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

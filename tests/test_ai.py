# -*- coding: utf-8 -*-
"""AI 决策/复查引擎测试（Fake 客户端，不依赖网络与 API Key）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.ai import AIConfig, RoleConfig, parse_decisions  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.prompts import build_decide_user, build_review_user  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


class FakeClient:
    def __init__(self, responses, model="fake-model"):
        self.responses = responses if isinstance(responses, list) else [responses]
        self.model = model
        self.calls = []
        self.idx = 0

    @property
    def cfg(self):
        class _Cfg:
            model = self.model
        return _Cfg()

    def chat_json(self, system, user):
        self.calls.append((system, user))
        r = self.responses[min(self.idx, len(self.responses) - 1)]
        self.idx += 1
        return r, {"total_tokens": 100}


def build_fake_decide_response(doc, res):
    decisions = []
    for c in res.candidates:
        if c.kind not in ("theorem-like", "proof", "scope-fix"):
            continue
        if c.kind == "theorem-like":
            decisions.append({
                "candidate_id": c.id, "action": "wrap", "env": c.env_hint,
                "body_span": {"start_line": c.span.start_line, "end_line": c.span.end_line},
                "optional_arg": "", "keep_title_text": True, "reason": "包裹",
                "confidence": 0.9,
            })
        elif c.kind == "proof":
            decisions.append({
                "candidate_id": c.id, "action": "wrap", "env": "proof",
                "body_span": {"start_line": c.span.start_line, "end_line": c.span.end_line},
                "optional_arg": "", "keep_title_text": True, "reason": "包裹",
                "confidence": 0.9,
            })
        elif c.rule_id == "env-body-outside":
            decisions.append({
                "candidate_id": c.id, "action": "move-boundary", "env": c.env_hint,
                "reason": "扩展边界", "confidence": 0.8,
                "move_payload": {"old_end_line": c.span.end_line,
                                 "new_end_line": c.payload["next_end_line"]},
            })
        else:
            decisions.append({"candidate_id": c.id, "action": "none", "reason": "无需处理"})
    return {"decisions": decisions}


def test_parse_decisions_validation():
    text = "\\documentclass{book}\n\\begin{document}\n\nTheorem 1. A statement.\n\n\\end{document}\n"
    doc = parse_latex(text)
    res = scan(doc)
    cands = [c for c in res.candidates if c.kind == "theorem-like"]
    c = cands[0]
    total = doc.text.count("\n") + 1
    windows = {c.id: (1, total)}
    ok = {"decisions": [{
        "candidate_id": c.id, "action": "wrap", "env": "theorem",
        "body_span": {"start_line": c.span.start_line, "end_line": c.span.end_line},
        "optional_arg": "1", "reason": "ok", "confidence": 0.9,
    }]}
    ds, amb, notes = parse_decisions(ok, cands, windows, doc)
    assert len(ds) == 1 and ds[0].env == "theorem" and ds[0].optional_arg == "1"
    assert amb == [] and notes == []
    # 越界 span → 歧义
    bad = {"decisions": [{
        "candidate_id": c.id, "action": "wrap", "env": "theorem",
        "body_span": {"start_line": 999, "end_line": 1000}, "reason": "",
    }]}
    ds2, amb2, _ = parse_decisions(bad, cands, windows, doc)
    assert ds2 == [] and amb2
    # 非法环境 → 歧义
    bad_env = {"decisions": [{
        "candidate_id": c.id, "action": "wrap", "env": "banana",
        "body_span": {"start_line": c.span.start_line, "end_line": c.span.end_line}, "reason": "",
    }]}
    ds3, amb3, _ = parse_decisions(bad_env, cands, windows, doc)
    assert ds3 == [] and amb3
    # none → 说明项
    none = {"decisions": [{"candidate_id": c.id, "action": "none", "reason": "引用性文字"}]}
    ds4, amb4, notes4 = parse_decisions(none, cands, windows, doc)
    assert ds4 == [] and amb4 == [] and notes4


def test_ai_mode_pipeline_with_fake_decide():
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    fake = FakeClient(build_fake_decide_response(doc, res))
    cfg = AIConfig(decide=RoleConfig(api_key="test"), review_enabled=False)
    out = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=fake)
    assert out.ok, out.report_md
    assert "\\begin{theorem}" in out.result
    assert "\\begin{proof}" in out.result
    assert "\\begin{definition}" in out.result
    # 规则部分照常生效
    assert "（概率方法）" in out.result and "\\item First problem text" in out.result
    assert out.verification["content_invariant"] is True
    assert out.verification["env_balance"]["ok"] is True
    assert out.verification["ai_degraded"] is False
    assert out.verification["ai_usage"]["decide"]["model"] == "fake-model"
    # 伪决策全部被采用
    assert len(fake.calls) == 1


def test_ai_mode_without_key_degrades_to_rules():
    res = run_pipeline(read_sample("basic_book.tex"), mode="ai",
                       ai_config=AIConfig(decide=RoleConfig(api_key=""), review_enabled=False))
    assert res.ok
    assert res.verification["ai_degraded"] is True
    assert "\\begin{theorem}" in res.result  # 规则降级仍然包裹
    assert "AI 不可用" in res.report_md


def test_review_wrong_env_auto_fix():
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    target = [c for c in res.candidates if c.kind == "theorem-like" and c.env_hint == "theorem"][0]
    fake_decide = FakeClient(build_fake_decide_response(doc, res))
    fake_review = FakeClient({"findings": [
        {"candidate_id": target.id, "verdict": "wrong-env", "fix": {"env": "lemma"}, "reason": "应为引理"},
    ]})
    cfg = AIConfig(decide=RoleConfig(api_key="t"), review=RoleConfig(api_key="t"), review_enabled=True)
    out = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=fake_decide, review_client=fake_review)
    assert out.ok, out.report_md
    assert "\\begin{lemma}" in out.result
    assert out.verification["content_invariant"] is True
    assert any(f["verdict"] == "wrong-env" for f in out.review["findings"])


def test_review_should_remove():
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    target = [c for c in res.candidates if c.kind == "theorem-like" and c.env_hint == "theorem"][0]
    fake_decide = FakeClient(build_fake_decide_response(doc, res))
    fake_review = FakeClient({"findings": [
        {"candidate_id": target.id, "verdict": "should-remove", "fix": {}, "reason": "引用性文字，误包"},
    ]})
    cfg = AIConfig(decide=RoleConfig(api_key="t"), review=RoleConfig(api_key="t"), review_enabled=True)
    out = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=fake_decide, review_client=fake_review)
    assert out.ok, out.report_md
    # 样例中唯一的定理环境（范围修正后的那个）+ 被移除的包裹 → 仅剩 1 个 \begin{theorem}
    assert out.result.count("\\begin{theorem}") == 1
    assert out.verification["content_invariant"] is True


def test_review_missed_extra_adds_wrap():
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    body_para = [b for b in doc.blocks_of_kind("para") if "Here is the body" in b.text][0]
    fake_decide = FakeClient(build_fake_decide_response(doc, res))
    fake_review = FakeClient({"findings": [
        {"candidate_id": "c-x", "verdict": "missed-extra",
         "fix": {"action": "wrap", "env": "definition",
                 "body_span": {"start_line": body_para.span.start_line,
                               "end_line": body_para.span.end_line}},
         "reason": "漏包正文"},
    ]})
    cfg = AIConfig(decide=RoleConfig(api_key="t"), review=RoleConfig(api_key="t"), review_enabled=True)
    out = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=fake_decide, review_client=fake_review)
    assert out.ok, out.report_md
    assert out.result.count("\\begin{definition}") == 2
    assert out.verification["content_invariant"] is True


def test_review_missed_extra_from_ai_none():
    # 决策判 none 的候选进入复查清单，复查可 missed-extra 反悔补包
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    # 让决策对所有 theorem-like 判 none，仅保留规则部分
    decide_resp = {"decisions": [
        {"candidate_id": c.id, "action": "none", "reason": "暂不确定"}
        for c in res.candidates if c.kind in ("theorem-like", "proof", "scope-fix")
    ]}
    target = [c for c in res.candidates if c.kind == "theorem-like"][0]
    fake_decide = FakeClient(decide_resp)
    fake_review = FakeClient({"findings": [
        {"candidate_id": target.id, "verdict": "missed-extra",
         "fix": {"action": "wrap", "env": target.env_hint,
                 "body_span": {"start_line": target.span.start_line,
                               "end_line": target.span.end_line}},
         "reason": "漏包"},
    ]})
    cfg = AIConfig(decide=RoleConfig(api_key="t"), review=RoleConfig(api_key="t"), review_enabled=True)
    out = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=fake_decide, review_client=fake_review)
    assert out.ok, out.report_md
    assert f"\\begin{{{target.env_hint}}}" in out.result
    assert out.verification["content_invariant"] is True


def test_prompt_builders():
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    cands = [c for c in res.candidates if c.kind == "theorem-like"]
    user = build_decide_user(doc, cands, context_lines=4)
    assert "候选" in user and cands[0].id in user
    assert f"[{cands[0].span.start_line:4d}]" in user
    ruser = build_review_user(doc.text.split("\n"),
                              [{"candidate_id": "c-1", "action": "wrap", "env": "theorem",
                                "reason": "包裹", "body_span": (20, 21)}],
                              [], context_lines=4)
    assert "修改 1" in ruser and "body_span=20..21" in ruser


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

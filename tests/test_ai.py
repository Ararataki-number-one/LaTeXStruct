# -*- coding: utf-8 -*-
"""AI 决策/复查引擎测试（Fake 客户端，不依赖网络与 API Key）。"""

import json
import os
import sys
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.ai import (  # noqa: E402
    AIConfig,
    LLMClient,
    LLMError,
    RoleConfig,
    _NoRedirectHandler,
    parse_decisions,
)
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

    # 模型生成的 LaTeX 可选参数不得进入补丁；仅使用原文提取出的编号。
    injected = {"decisions": [{
        "candidate_id": c.id, "action": "wrap", "env": "theorem",
        "body_span": {"start_line": c.span.start_line, "end_line": c.span.end_line},
        "optional_arg": r"1]\\input{outside}", "reason": "ok", "confidence": 0.9,
    }]}
    ds5, amb5, _ = parse_decisions(injected, cands, windows, doc)
    assert amb5 == [] and ds5[0].optional_arg == "1"
    assert ds5[0].keep_title_text is False
    assert ds5[0].payload["title_prefix"] == "Theorem 1."

    # 只有 body_span 真从候选标题行开始时才剥离前缀，避免改到前一段正文。
    earlier = {"decisions": [{
        "candidate_id": c.id, "action": "wrap", "env": "theorem",
        "body_span": {"start_line": c.span.start_line - 1, "end_line": c.span.end_line},
        "reason": "ok", "confidence": 0.9,
    }]}
    ds_earlier, amb_earlier, _ = parse_decisions(earlier, cands, windows, doc)
    assert amb_earlier == [] and ds_earlier[0].keep_title_text is True
    assert ds_earlier[0].payload["title_prefix"] == ""

    low = {"decisions": [{
        "candidate_id": c.id, "action": "wrap", "env": "theorem",
        "body_span": {"start_line": c.span.start_line, "end_line": c.span.end_line},
        "reason": "uncertain", "confidence": 0.4,
    }]}
    ds6, amb6, _ = parse_decisions(low, cands, windows, doc)
    assert ds6 == [] and "人工确认" in amb6[0]["reason"]


def test_ai_decision_strips_unnumbered_title_prefix_with_body():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Theorem. A statement without a source number.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    candidate = next(c for c in scan(doc).candidates if c.kind == "theorem-like")
    response = {"decisions": [{
        "candidate_id": candidate.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": candidate.span.start_line,
            "end_line": candidate.span.end_line,
        },
        "confidence": 0.9,
        "reason": "wrap",
    }]}
    decisions, ambiguous, _ = parse_decisions(
        response,
        [candidate],
        {candidate.id: (1, doc.text.count("\n") + 1)},
        doc,
    )
    assert ambiguous == []
    assert decisions[0].optional_arg == ""
    assert decisions[0].keep_title_text is False
    assert decisions[0].payload["title_prefix"].startswith("Theorem")


def test_llm_response_errors_are_actionable():
    try:
        LLMClient._parse_json("```json\n{broken}\n```")
    except LLMError as exc:
        assert "JSON 无法解析" in str(exc)
    else:
        raise AssertionError("畸形 JSON 应转换为 LLMError")

    try:
        LLMClient(RoleConfig(base_url="not-a-url", api_key="fake"))._endpoint_url()
    except LLMError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("无效 Base URL 应被拒绝")


def test_llm_endpoint_requires_https_except_exact_loopback():
    for unsafe in (
        "http://api.deepseek.com/v1",
        "http://192.168.1.2:8000/v1",
        "https://user:pass@api.deepseek.com/v1",
        "https://api.deepseek.com/v1?target=evil",
        "https://api.deepseek.com/v1#fragment",
        "https://api.deepseek.com:not-a-port/v1",
    ):
        try:
            LLMClient(RoleConfig(base_url=unsafe, api_key="fake"))._endpoint_url()
        except LLMError:
            pass
        else:
            raise AssertionError(f"不安全或畸形 Base URL 必须被拒绝: {unsafe}")

    assert LLMClient(RoleConfig(base_url="http://localhost:8000/v1"))._endpoint_url() == (
        "http://localhost:8000/v1/chat/completions"
    )
    assert LLMClient(RoleConfig(base_url="http://127.0.0.1:8000/v1"))._endpoint_url() == (
        "http://127.0.0.1:8000/v1/chat/completions"
    )
    assert LLMClient(RoleConfig(base_url="http://[::1]:8000/v1"))._endpoint_url() == (
        "http://[::1]:8000/v1/chat/completions"
    )


def test_llm_requests_have_finite_configurable_token_limit():
    captured = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "choices": [{"message": {"content": '{"ok": true}'}}],
                "usage": {"total_tokens": 3},
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured.append((json.loads(request.data.decode("utf-8")), timeout))
        return FakeResponse()

    assert isinstance(RoleConfig().max_tokens, int) and RoleConfig().max_tokens > 0
    cfg = RoleConfig(api_key="not-a-real-key", timeout=7, max_tokens=321, max_retries=0)
    with patch("latexstruct.core.ai._open_no_redirect", fake_urlopen):
        client = LLMClient(cfg)
        obj, usage = client.chat_json("system", "user")
        assert obj == {"ok": True}
        assert usage == {"total_tokens": 3}
        assert client.chat_vision("system", "user", "data:image/png;base64,AA==")
    assert [payload["max_tokens"] for payload, _ in captured] == [321, 321]
    assert [timeout for _, timeout in captured] == [7, 7]
    assert all(payload["thinking"] == {"type": "disabled"} for payload, _ in captured)
    assert all("enable_thinking" not in payload for payload, _ in captured)

    try:
        LLMClient(RoleConfig(api_key="fake", max_tokens=0)).chat_json("system", "user")
    except LLMError as exc:
        assert "max_tokens" in str(exc)
    else:
        raise AssertionError("非正 max_tokens 必须在发送请求前被拒绝")


def test_provider_options_require_strict_official_authority():
    captured = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "choices": [{"message": {"content": '{"ok": true}'}}],
                "usage": {},
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    spoofed = (
        RoleConfig(
            base_url="https://custom.invalid/v1", model="deepseek-v4-flash",
            api_key="not-a-real-key", max_retries=0,
        ),
        RoleConfig(
            base_url="https://api.deepseek.com.evil.invalid/v1", model="deepseek-v4-flash",
            api_key="not-a-real-key", max_retries=0,
        ),
        RoleConfig(
            base_url="https://custom.invalid/v1", model="qwen3.7-flash",
            api_key="not-a-real-key", max_retries=0,
        ),
        RoleConfig(
            base_url="https://dashscope.aliyuncs.com.evil.invalid/v1", model="qwen3.7-flash",
            api_key="not-a-real-key", max_retries=0,
        ),
    )
    with patch("latexstruct.core.ai._open_no_redirect", fake_urlopen):
        for cfg in spoofed:
            assert LLMClient(cfg).chat_json("system", "user")[0] == {"ok": True}
    assert all("thinking" not in payload for payload in captured)
    assert all("enable_thinking" not in payload for payload in captured)

    captured.clear()
    official = RoleConfig(
        base_url="https://api.deepseek.com:443/v1", model="qwen-spoofed-name",
        api_key="not-a-real-key", max_retries=0,
    )
    with patch("latexstruct.core.ai._open_no_redirect", fake_urlopen):
        LLMClient(official).chat_json("system", "user")
    assert captured[0]["thinking"] == {"type": "disabled"}
    assert "enable_thinking" not in captured[0]


def test_role_config_repr_redacts_api_key():
    secret = "synthetic-role-secret"
    assert secret not in repr(RoleConfig(api_key=secret))


def test_llm_retry_count_is_configurable():
    attempts = 0

    def temporary_failure(_request, timeout):
        nonlocal attempts
        attempts += 1
        raise urllib.error.URLError("temporary")

    cfg = RoleConfig(
        api_key="not-a-real-key", max_tokens=10, max_retries=2, retry_delay=0,
    )
    try:
        with patch("latexstruct.core.ai._open_no_redirect", temporary_failure):
            LLMClient(cfg).chat_json("system", "user")
    except LLMError as exc:
        assert "网络错误" in str(exc)
    else:
        raise AssertionError("连续网络错误必须抛出 LLMError")
    assert attempts == 3


def test_llm_redirects_are_rejected_without_retry():
    handler = _NoRedirectHandler()
    request = urllib.request.Request("https://api.deepseek.com/chat/completions")
    assert handler.redirect_request(
        request, None, 302, "Found", {}, "https://attacker.invalid/collect",
    ) is None

    attempts = 0

    def redirect(_request, timeout):
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError(
            "https://api.deepseek.com/chat/completions", 302, "Found", {}, None,
        )

    try:
        with patch("latexstruct.core.ai._open_no_redirect", redirect):
            LLMClient(RoleConfig(api_key="not-a-real-key", retry_delay=0)).chat_json(
                "system", "user",
            )
    except LLMError as exc:
        assert "HTTP 302" in str(exc)
    else:
        raise AssertionError("Chat API 重定向必须被拒绝")
    assert attempts == 1


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
    assert "\\begin{definition}[1.1.1]\n A graph" in out.result
    assert "\\begin{theorem}[2.3.4]\n(Erd" in out.result
    assert "Theorem 2.3.4 (Erd" not in out.result
    assert "\\begin{proof}\nFix a sequence" in out.result
    assert "Proof. Fix a sequence" not in out.result
    # 规则部分照常生效
    assert "（概率方法）" in out.result and "\\item First problem text" in out.result
    assert out.verification["content_invariant"] is True
    assert out.verification["env_balance"]["ok"] is True
    assert out.verification["ai_degraded"] is False
    assert out.verification["ai_usage"]["decide"]["model"] == "fake-model"
    # 伪决策全部被采用
    assert len(fake.calls) == 1


def test_ai_batches_emit_progressive_tex_previews():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Theorem 1. First statement.\n\n"
        "Theorem 2. Second statement.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    scanned = scan(doc)
    fake = FakeClient(build_fake_decide_response(doc, scanned))
    cfg = AIConfig(
        decide=RoleConfig(api_key="test"),
        review_enabled=False,
        batch_size=1,
    )
    events = []

    result = run_pipeline(
        text,
        mode="ai",
        ai_config=cfg,
        ai_client=fake,
        progress_callback=lambda phase, progress, message, data: events.append(
            (phase, progress, message, data)
        ),
    )

    assert result.ok, result.report_md
    batch_events = [event for event in events if event[0] == "decide" and "preview" in event[3]]
    assert len(batch_events) == 2
    assert [event[3]["processed_candidates"] for event in batch_events] == [1, 2]
    assert batch_events[0][3]["preview"].count("\\begin{theorem}") == 1
    assert batch_events[1][3]["preview"].count("\\begin{theorem}") == 2
    assert batch_events[0][3]["preview"] != batch_events[1][3]["preview"]


def test_ai_cannot_wrap_explicit_number_in_existing_numbered_environment():
    text = (
        "\\documentclass{book}\n\\usepackage{amsthm}\n"
        "\\newtheorem{theorem}{Theorem}\n\\begin{document}\n"
        "Theorem 7. A statement with its own number.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    scanned = scan(doc)
    target = next(c for c in scanned.candidates if c.kind == "theorem-like")
    response = {"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": target.span.end_line,
        },
        "confidence": 0.99,
        "reason": "wrap",
    }]}
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=AIConfig(decide=RoleConfig(api_key="test"), review_enabled=False),
        ai_client=FakeClient(response),
    )
    assert result.ok, result.report_md
    assert result.result == text
    assert any("避免双编号" in item["reason"] for item in result.ambiguous)


def test_cached_review_decisions_do_not_call_ai_again():
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    scanned = scan(doc)
    first_client = FakeClient(build_fake_decide_response(doc, scanned))
    cfg = AIConfig(decide=RoleConfig(api_key="test"), review_enabled=False)
    first = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=first_client)
    assert first.ok

    class ExplodingClient:
        def chat_json(self, *_args, **_kwargs):
            raise AssertionError("复用审阅决策时不应再次调用 AI")

    second = run_pipeline(
        text,
        mode="ai",
        ai_config=cfg,
        ai_client=ExplodingClient(),
        decisions_override=first.decisions,
        ambiguous_override=first.ambiguous,
        ai_notes_override=first.ai_notes,
        exclude={first.decisions[0].candidate_id},
    )
    assert second.ok
    assert second.verification["decisions_reused"] is True


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


def test_review_wrong_range_cannot_expand_before_numbered_theorem_title():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Intro paragraph.\n\n"
        "Theorem 7. A numbered statement.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    target = next(c for c in scan(doc).candidates if c.kind == "theorem-like")
    fake_decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": target.span.end_line,
        },
        "confidence": 0.99,
        "reason": "wrap",
    }]})
    fake_review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "wrong-range",
        "fix": {
            "body_span": {
                "start_line": target.span.start_line - 2,
                "end_line": target.span.end_line,
            },
        },
        "reason": "unsafe expansion",
    }]})
    cfg = AIConfig(
        decide=RoleConfig(api_key="test"),
        review=RoleConfig(api_key="test"),
        review_enabled=True,
        review_max_rounds=1,
    )
    result = run_pipeline(
        text, mode="ai", ai_config=cfg,
        ai_client=fake_decide, review_client=fake_review,
    )
    assert result.ok, result.report_md
    assert "Intro paragraph.\n\n\\begin{theorem}[7]" in result.result
    assert "Theorem 7. A numbered statement." not in result.result
    assert result.result.count("\\begin{theorem}[7]") == 1


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


def test_review_missed_extra_cannot_bypass_numbered_environment_guard():
    text = (
        "\\documentclass{book}\n\\usepackage{amsthm}\n"
        "\\newtheorem{theorem}{Theorem}\n\\begin{document}\n"
        "Theorem 7. A statement with its own number.\n\n"
        "Proof. A separate proof paragraph.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    scanned = scan(doc)
    target = next(c for c in scanned.candidates if c.kind == "theorem-like")
    proof = next(c for c in scanned.candidates if c.kind == "proof")
    decide = FakeClient({"decisions": [
        {"candidate_id": target.id, "action": "none", "reason": "uncertain"},
        {
            "candidate_id": proof.id,
            "action": "wrap",
            "env": "proof",
            "body_span": {
                "start_line": proof.span.start_line,
                "end_line": proof.span.end_line,
            },
            "confidence": 0.9,
            "reason": "wrap proof",
        },
    ]})
    review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "missed-extra",
        "fix": {
            "action": "wrap",
            "env": "theorem",
            "body_span": {
                "start_line": target.span.start_line,
                "end_line": target.span.end_line,
            },
        },
        "reason": "try to add theorem",
    }]})
    cfg = AIConfig(
        decide=RoleConfig(api_key="test"),
        review=RoleConfig(api_key="test"),
        review_enabled=True,
        review_max_rounds=1,
    )
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=cfg,
        ai_client=decide,
        review_client=review,
    )
    assert result.ok, result.report_md
    assert "\\begin{theorem}" not in result.result
    assert "Theorem 7. A statement with its own number." in result.result
    assert "\\begin{proof}\nA separate proof paragraph." in result.result
    assert any("避免双编号" in item["reason"] for item in result.ambiguous)


def test_review_batching():
    # review_batch=2 时，5 个 AI 补丁（4 wrap + 1 move-boundary）应分 3 次复查调用
    text = read_sample("basic_book.tex")
    doc = parse_latex(text)
    res = scan(doc)
    fake_decide = FakeClient(build_fake_decide_response(doc, res))
    fake_review = FakeClient([{"findings": []}, {"findings": []}, {"findings": []}])
    cfg = AIConfig(decide=RoleConfig(api_key="t"), review=RoleConfig(api_key="t"),
                   review_enabled=True, review_batch=2)
    out = run_pipeline(text, mode="ai", ai_config=cfg, ai_client=fake_decide, review_client=fake_review)
    assert out.ok, out.report_md
    # decide 1 次 + review 分块 3 次
    assert fake_decide.calls and len(fake_review.calls) == 3


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

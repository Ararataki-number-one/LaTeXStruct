# -*- coding: utf-8 -*-
"""Token 统计与人民币费用估算测试。"""

from latexstruct.pricing import add_usage, estimate_call_cost, summarize_ai_usage, usage_tokens


def test_usage_tokens_supports_openai_and_compatible_fields():
    assert usage_tokens({
        "prompt_tokens": 120,
        "completion_tokens": 30,
        "total_tokens": 150,
        "prompt_tokens_details": {"cached_tokens": 20},
    }) == {"input_tokens": 120, "output_tokens": 30, "cached_tokens": 20, "total_tokens": 150}
    assert usage_tokens({"input_tokens": 12, "output_tokens": 3})["total_tokens"] == 15


def test_qwen_tiered_cost_and_unknown_model():
    low = estimate_call_cost("qwen3.7-flash", {"prompt_tokens": 10_000, "completion_tokens": 1_000})
    assert low["cny"] == 0.0028
    high = estimate_call_cost("qwen3.7-flash", {"prompt_tokens": 40_000, "completion_tokens": 1_000})
    assert high["cny"] == 0.0264
    assert estimate_call_cost("my-private-model", {"prompt_tokens": 10}) is None


def test_usage_accumulates_per_call_before_summarizing():
    role = {}
    add_usage(role, {"prompt_tokens": 1000, "completion_tokens": 100}, "qwen3.7-flash")
    add_usage(role, {"prompt_tokens": 2000, "completion_tokens": 200}, "qwen3.7-flash")
    summary = summarize_ai_usage({"decide": role})
    assert role["calls"] == 2
    assert summary["total_tokens"] == 3300
    assert summary["estimated_cost_cny"] == role["estimated_cost_cny"]
    compatible = {}
    add_usage(compatible, {"input_tokens": 12, "output_tokens": 3}, "qwen3.7-flash")
    assert summarize_ai_usage({"decide": compatible})["total_tokens"] == 15


def test_unknown_model_keeps_tokens_but_not_fake_price():
    summary = summarize_ai_usage({
        "decide": {"model": "private-model", "prompt_tokens": 123, "completion_tokens": 4,
                   "total_tokens": 127}
    })
    assert summary["total_tokens"] == 127
    assert summary["estimated_cost_cny"] is None


def test_codex_usage_is_labelled_as_subscription_not_api_price():
    role = {}
    add_usage(role, {
        "input_tokens": 120,
        "cached_tokens": 20,
        "output_tokens": 8,
        "backend": "codex_cli",
        "billing_mode": "chatgpt_subscription",
    }, "codex-cli-default")

    summary = summarize_ai_usage({"decide": role})

    assert summary["backend"] == "codex_cli"
    assert summary["billing_mode"] == "chatgpt_subscription"
    assert summary["estimated_cost_cny"] is None
    assert summary["estimated"] is False
    assert "订阅额度" in summary["note"]
    assert summary["roles"]["decide"]["backend"] == "codex_cli"


def test_provider_strings_cannot_spoof_codex_billing_metadata():
    role = {}
    add_usage(role, {
        "prompt_tokens": 3,
        "backend": "codex_cli-but-not-really",
        "billing_mode": "free",
        "untrusted_note": "free forever",
    }, "private-model")
    assert "backend" not in role
    assert "billing_mode" not in role
    assert "untrusted_note" not in role

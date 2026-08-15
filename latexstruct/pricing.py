# -*- coding: utf-8 -*-
"""离线 Token 费用估算。

价格只用于界面提示，不参与计费。模型供应商仍以自己的账单为准；优惠、免费额度、
上下文缓存和汇率变化都可能让最终费用与这里不同。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


USD_TO_CNY_REFERENCE = 7.2
PRICING_CHECKED_AT = "2026-08-15"


@dataclass(frozen=True)
class PriceBand:
    max_input_tokens: Optional[int]
    input_cny_per_million: float
    output_cny_per_million: float
    cached_input_cny_per_million: Optional[float] = None


@dataclass(frozen=True)
class ModelPrice:
    bands: tuple[PriceBand, ...]
    source: str
    note: str = ""


DEEPSEEK_PRICING_URL = "https://api-docs.deepseek.com/quick_start/pricing"
QWEN_PRICING_URL = "https://help.aliyun.com/en/model-studio/model-pricing"


MODEL_PRICES: Dict[str, ModelPrice] = {
    # DeepSeek 官方当前以美元列价；这里按固定参考汇率换算成人民币，只显示约数。
    "deepseek-v4-flash": ModelPrice(
        bands=(PriceBand(None, 0.14 * USD_TO_CNY_REFERENCE, 0.28 * USD_TO_CNY_REFERENCE,
                         0.0028 * USD_TO_CNY_REFERENCE),),
        source=DEEPSEEK_PRICING_URL,
        note=f"美元官方价按参考汇率 1 USD≈{USD_TO_CNY_REFERENCE:g} CNY 换算",
    ),
    "deepseek-v4-pro": ModelPrice(
        bands=(PriceBand(None, 0.435 * USD_TO_CNY_REFERENCE, 0.87 * USD_TO_CNY_REFERENCE,
                         0.003625 * USD_TO_CNY_REFERENCE),),
        source=DEEPSEEK_PRICING_URL,
        note=f"美元官方价按参考汇率 1 USD≈{USD_TO_CNY_REFERENCE:g} CNY 换算",
    ),
    # 兼容旧项目的历史模型名；官方已退役，配置加载时会迁移到 V4。
    "deepseek-chat": ModelPrice(
        bands=(PriceBand(None, 0.14 * USD_TO_CNY_REFERENCE, 0.28 * USD_TO_CNY_REFERENCE,
                         0.0028 * USD_TO_CNY_REFERENCE),),
        source=DEEPSEEK_PRICING_URL,
        note="旧模型名按 DeepSeek V4 Flash 估算",
    ),
    "deepseek-reasoner": ModelPrice(
        bands=(PriceBand(None, 0.435 * USD_TO_CNY_REFERENCE, 0.87 * USD_TO_CNY_REFERENCE,
                         0.003625 * USD_TO_CNY_REFERENCE),),
        source=DEEPSEEK_PRICING_URL,
        note="旧模型名按 DeepSeek V4 Pro 估算",
    ),
    "qwen3.7-flash": ModelPrice(
        bands=(
            PriceBand(32_000, 0.2, 0.8),
            PriceBand(256_000, 0.6, 2.4),
            PriceBand(None, 1.2, 4.8),
        ),
        source=QWEN_PRICING_URL,
        note="中国内地实时调用公开价，不计免费额度、批量优惠和缓存优惠",
    ),
    "qwen3.7-plus": ModelPrice(
        bands=(PriceBand(256_000, 2.0, 8.0), PriceBand(None, 6.0, 24.0)),
        source=QWEN_PRICING_URL,
        note="中国内地公开原价，不计限时折扣、免费额度和缓存优惠",
    ),
    "qwen3.6-flash": ModelPrice(
        bands=(PriceBand(256_000, 1.2, 7.2), PriceBand(None, 4.8, 28.8)),
        source=QWEN_PRICING_URL,
        note="中国内地公开价，不计免费额度、批量优惠和缓存优惠",
    ),
}


def _number(value) -> float:
    return float(value) if isinstance(value, (int, float)) and value >= 0 else 0.0


def usage_tokens(usage: Dict) -> Dict[str, int]:
    """兼容 OpenAI/DashScope 常见 usage 字段。"""
    usage = usage if isinstance(usage, dict) else {}
    input_tokens = _number(usage.get("prompt_tokens", usage.get("input_tokens", 0)))
    output_tokens = _number(usage.get("completion_tokens", usage.get("output_tokens", 0)))
    details = usage.get("prompt_tokens_details")
    cached_tokens = _number(details.get("cached_tokens", 0)) if isinstance(details, dict) else 0
    cached_tokens = _number(usage.get("cached_tokens", cached_tokens))
    cached_tokens = min(cached_tokens, input_tokens)
    total = _number(usage.get("total_tokens", input_tokens + output_tokens))
    return {
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "cached_tokens": int(cached_tokens),
        "total_tokens": int(total),
    }


def estimate_call_cost(model: str, usage: Dict) -> Optional[Dict]:
    """估算单次调用费用；未知模型返回 ``None``，避免虚假精确。"""
    price = MODEL_PRICES.get((model or "").strip().lower())
    if price is None:
        return None
    tokens = usage_tokens(usage)
    band = next(
        (item for item in price.bands
         if item.max_input_tokens is None or tokens["input_tokens"] <= item.max_input_tokens),
        price.bands[-1],
    )
    cached = tokens["cached_tokens"]
    regular = max(0, tokens["input_tokens"] - cached)
    cached_rate = (
        band.cached_input_cny_per_million
        if band.cached_input_cny_per_million is not None
        else band.input_cny_per_million
    )
    input_cny = (regular * band.input_cny_per_million + cached * cached_rate) / 1_000_000
    output_cny = tokens["output_tokens"] * band.output_cny_per_million / 1_000_000
    return {
        **tokens,
        "cny": round(input_cny + output_cny, 6),
        "input_cny": round(input_cny, 6),
        "output_cny": round(output_cny, 6),
        "estimated": True,
        "source": price.source,
        "note": price.note,
        "checked_at": PRICING_CHECKED_AT,
    }


def add_usage(total: Dict, usage: Dict, model: str) -> Dict:
    """把一次模型调用的 usage 与费用累加到角色统计中。"""
    total["model"] = model or total.get("model", "")
    for key, value in (usage or {}).items():
        if isinstance(value, (int, float)):
            total[key] = total.get(key, 0) + value
    tokens = usage_tokens(usage)
    # 嵌套的缓存命中字段不会被上面的顶层数值循环处理，单独汇总。
    if "cached_tokens" not in usage and tokens["cached_tokens"]:
        total["cached_tokens"] = total.get("cached_tokens", 0) + tokens["cached_tokens"]
    estimate = estimate_call_cost(model, usage)
    if estimate:
        total["estimated_cost_cny"] = round(
            total.get("estimated_cost_cny", 0.0) + estimate["cny"], 6
        )
        total["pricing_source"] = estimate["source"]
        total["pricing_note"] = estimate["note"]
        total["pricing_checked_at"] = estimate["checked_at"]
    total["calls"] = int(total.get("calls", 0)) + 1
    return total


def summarize_ai_usage(ai_usage: Dict) -> Dict:
    """生成前端可直接展示的跨角色汇总。"""
    roles = {}
    input_total = output_total = token_total = 0
    cost_total = 0.0
    all_priced = True
    for role, raw in (ai_usage or {}).items():
        if not isinstance(raw, dict):
            continue
        tokens = usage_tokens(raw)
        model = str(raw.get("model", ""))
        estimated_cost = raw.get("estimated_cost_cny")
        if not isinstance(estimated_cost, (int, float)):
            estimate = estimate_call_cost(model, raw)
            estimated_cost = estimate["cny"] if estimate else None
        if estimated_cost is None:
            all_priced = False
        else:
            cost_total += float(estimated_cost)
        input_total += tokens["input_tokens"]
        output_total += tokens["output_tokens"]
        token_total += tokens["total_tokens"]
        roles[role] = {
            "model": model,
            **tokens,
            "estimated_cost_cny": (
                round(float(estimated_cost), 6) if estimated_cost is not None else None
            ),
        }
    return {
        "input_tokens": input_total,
        "output_tokens": output_total,
        "total_tokens": token_total,
        "estimated_cost_cny": round(cost_total, 6) if roles and all_priced else None,
        "priced_roles": sum(v["estimated_cost_cny"] is not None for v in roles.values()),
        "roles": roles,
        "estimated": True,
        "note": "费用为公开单价估算，不含优惠、免费额度与供应商最终结算差异",
    }

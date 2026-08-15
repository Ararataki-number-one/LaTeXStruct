# -*- coding: utf-8 -*-
"""已验证的模型供应商预设。

预设只保存公开的端点与模型标识；API Key 始终来自环境变量或本机凭据。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ProviderPreset:
    id: str
    label: str
    base_url: str
    model: str
    api_key_env: str
    provider: str = "custom"
    provider_label: str = "自定义"
    roles: tuple[str, ...] = ("decide", "review")
    vision: bool = False
    recommended: bool = False
    note: str = ""

    def public_dict(self) -> Dict:
        return asdict(self)


# 中国内地旧兼容域名仍受官方支持，且无需用户先查 Workspace ID。若控制台提供了
# workspace 专属 API Host，用户可在设置页或 LATEXSTRUCT_OCR_BASE_URL 中覆盖。
QWEN_CN_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# 自动凭据（例如 DASHSCOPE_API_KEY）只允许发送到这些已知供应商域名。
# workspace 专属地址形如 <WorkspaceId>.<region>.maas.aliyuncs.com，因此使用
# 带点边界的官方后缀；绝不能使用简单 substring 匹配。
DEEPSEEK_API_HOSTS = frozenset({"api.deepseek.com"})
QWEN_API_HOSTS = frozenset({"dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com"})
QWEN_API_HOST_SUFFIXES = (".maas.aliyuncs.com",)

PROVIDER_PRESETS = (
    ProviderPreset(
        id="deepseek-v4-flash",
        label="DeepSeek V4 Flash（省钱快速）",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
        api_key_env="LATEXSTRUCT_DECIDE_KEY",
        provider="deepseek",
        provider_label="DeepSeek",
        roles=("decide", "review"),
        recommended=True,
        note="适合日常结构判断；速度快、成本低，不支持图片 OCR。",
    ),
    ProviderPreset(
        id="deepseek-v4-pro",
        label="DeepSeek V4 Pro（更强复查）",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
        api_key_env="LATEXSTRUCT_REVIEW_KEY",
        provider="deepseek",
        provider_label="DeepSeek",
        roles=("decide", "review"),
        note="适合复杂文档复查；速度和成本高于 Flash，不支持图片 OCR。",
    ),
    ProviderPreset(
        id="qwen3.7-flash-cn",
        label="Qwen3.7-Flash（中国内地，推荐）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3.7-flash",
        api_key_env="DASHSCOPE_API_KEY",
        provider="qwen-cn",
        provider_label="阿里云百炼（中国内地）",
        roles=("decide", "review", "ocr"),
        vision=True,
        recommended=True,
        note="Qwen3.7 原生视觉 Flash；支持图片、文本和视频输入。",
    ),
    ProviderPreset(
        id="qwen3-vl-flash-cn",
        label="Qwen3-VL-Flash（中国内地）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3-vl-flash",
        api_key_env="DASHSCOPE_API_KEY",
        provider="qwen-cn",
        provider_label="阿里云百炼（中国内地）",
        roles=("decide", "review", "ocr"),
        vision=True,
        note="成熟的 Qwen3-VL 视觉 Flash 兼容选项。",
    ),
    ProviderPreset(
        id="qwen3.6-flash-cn",
        label="Qwen3.6-Flash（视觉）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3.6-flash",
        api_key_env="DASHSCOPE_API_KEY",
        provider="qwen-cn",
        provider_label="阿里云百炼（中国内地）",
        roles=("decide", "review", "ocr"),
        vision=True,
        note="上一代低延迟视觉模型。",
    ),
    ProviderPreset(
        id="qwen3.7-plus-cn",
        label="Qwen3.7-Plus（视觉推理）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3.7-plus",
        api_key_env="DASHSCOPE_API_KEY",
        provider="qwen-cn",
        provider_label="阿里云百炼（中国内地）",
        roles=("decide", "review", "ocr"),
        vision=True,
        note="适合比 Flash 更重的视觉推理任务。",
    ),
)

_BY_ID = {preset.id: preset for preset in PROVIDER_PRESETS}


def get_provider_preset(preset_id: str) -> Optional[ProviderPreset]:
    return _BY_ID.get((preset_id or "").strip())


def list_provider_presets() -> List[Dict]:
    return [preset.public_dict() for preset in PROVIDER_PRESETS]


def api_hostname(base_url: str) -> Optional[str]:
    """返回规范化的 HTTPS hostname；畸形/含凭据/非 HTTPS 地址返回 None。"""
    try:
        parsed = urlsplit((base_url or "").strip())
        # 访问 port 会触发对非法端口的校验（例如 :not-a-port）。
        port = parsed.port
        hostname = parsed.hostname
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
    ):
        return None
    return hostname.rstrip(".").lower()


def api_provider(base_url: str) -> Optional[str]:
    """仅按严格 HTTPS hostname 识别可自动携带凭据的内置供应商。"""
    hostname = api_hostname(base_url)
    if hostname in DEEPSEEK_API_HOSTS:
        return "deepseek"
    if hostname in QWEN_API_HOSTS or any(
        hostname and hostname.endswith(suffix) for suffix in QWEN_API_HOST_SUFFIXES
    ):
        return "qwen"
    return None


def is_qwen_config(base_url: str, model: str) -> bool:
    # model 名可由用户任意指定，不能作为注入 DASHSCOPE_API_KEY 的信任依据。
    _ = model
    return api_provider(base_url) == "qwen"

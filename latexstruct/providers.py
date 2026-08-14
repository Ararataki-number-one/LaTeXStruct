# -*- coding: utf-8 -*-
"""已验证的模型供应商预设。

预设只保存公开的端点与模型标识；API Key 始终来自环境变量或本机凭据。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ProviderPreset:
    id: str
    label: str
    base_url: str
    model: str
    api_key_env: str
    vision: bool = False
    note: str = ""

    def public_dict(self) -> Dict:
        return asdict(self)


# 中国内地旧兼容域名仍受官方支持，且无需用户先查 Workspace ID。若控制台提供了
# workspace 专属 API Host，用户可在设置页或 LATEXSTRUCT_OCR_BASE_URL 中覆盖。
QWEN_CN_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

PROVIDER_PRESETS = (
    ProviderPreset(
        id="qwen3.7-flash-cn",
        label="Qwen3.7-Flash（中国内地，推荐）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3.7-flash",
        api_key_env="DASHSCOPE_API_KEY",
        vision=True,
        note="Qwen3.7 原生视觉 Flash；支持图片、文本和视频输入。",
    ),
    ProviderPreset(
        id="qwen3-vl-flash-cn",
        label="Qwen3-VL-Flash（中国内地）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3-vl-flash",
        api_key_env="DASHSCOPE_API_KEY",
        vision=True,
        note="成熟的 Qwen3-VL 视觉 Flash 兼容选项。",
    ),
    ProviderPreset(
        id="qwen3.6-flash-cn",
        label="Qwen3.6-Flash（视觉）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3.6-flash",
        api_key_env="DASHSCOPE_API_KEY",
        vision=True,
        note="上一代低延迟视觉模型。",
    ),
    ProviderPreset(
        id="qwen3.7-plus-cn",
        label="Qwen3.7-Plus（视觉推理）",
        base_url=QWEN_CN_BASE_URL,
        model="qwen3.7-plus",
        api_key_env="DASHSCOPE_API_KEY",
        vision=True,
        note="适合比 Flash 更重的视觉推理任务。",
    ),
)

_BY_ID = {preset.id: preset for preset in PROVIDER_PRESETS}


def get_provider_preset(preset_id: str) -> Optional[ProviderPreset]:
    return _BY_ID.get((preset_id or "").strip())


def list_provider_presets() -> List[Dict]:
    return [preset.public_dict() for preset in PROVIDER_PRESETS]


def is_qwen_config(base_url: str, model: str) -> bool:
    return "aliyuncs.com" in (base_url or "").lower() or (model or "").lower().startswith("qwen")

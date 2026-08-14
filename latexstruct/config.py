# -*- coding: utf-8 -*-
"""应用配置（三角色模型配置 + 复查开关）。Key 存本机配置文件/环境变量，不上传。"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Dict

from .core.ai import AIConfig, RoleConfig
from .ocr import OcrConfig
from .store import default_data_dir

CONFIG_PATH = os.path.join(default_data_dir(), "config.json")


@dataclass
class AppConfig:
    decide_base_url: str = "https://api.deepseek.com"
    decide_model: str = "deepseek-chat"
    decide_api_key: str = ""
    review_base_url: str = "https://api.deepseek.com"
    review_model: str = "deepseek-reasoner"
    review_api_key: str = ""
    review_enabled: bool = True
    ocr_base_url: str = "https://api.deepseek.com"
    ocr_model: str = ""
    ocr_api_key: str = ""

    def to_ai_config(self) -> AIConfig:
        # 同供应商场景下 Key 互相回退（多数用户只配一把 DeepSeek Key）
        decide_key = self.decide_api_key or self.review_api_key
        review_key = self.review_api_key or self.decide_api_key
        decide = RoleConfig(self.decide_base_url, self.decide_model, decide_key)
        review = RoleConfig(self.review_base_url, self.review_model, review_key)
        return AIConfig(decide=decide, review=review, review_enabled=self.review_enabled)

    def to_ocr_config(self) -> OcrConfig:
        # Key 回退链：OCR → 决策 → 复查（同一供应商一把 Key 的场景）
        key = self.ocr_api_key or self.decide_api_key or self.review_api_key
        model = self.ocr_model or "deepseek-chat"
        return OcrConfig(role=RoleConfig(self.ocr_base_url or self.decide_base_url, model, key))

    def masked(self) -> Dict:
        d = asdict(self)
        for k in list(d):
            if "key" in k:
                d[k] = "已配置" if d[k] else ""
        return d


def _env_or(key: str, default: str) -> str:
    return os.environ.get(key) or default


def load_config() -> AppConfig:
    cfg = AppConfig()
    if os.path.exists(CONFIG_PATH):
        try:
            data = json.loads(open(CONFIG_PATH, encoding="utf-8").read())
            for k in asdict(cfg):
                if k in data:
                    setattr(cfg, k, data[k])
        except Exception:  # noqa: BLE001
            pass
    cfg.decide_api_key = _env_or("LATEXSTRUCT_DECIDE_KEY", cfg.decide_api_key)
    cfg.review_api_key = _env_or("LATEXSTRUCT_REVIEW_KEY", cfg.review_api_key)
    cfg.ocr_api_key = _env_or("LATEXSTRUCT_OCR_KEY", cfg.ocr_api_key)
    if os.environ.get("LATEXSTRUCT_DECIDE_MODEL"):
        cfg.decide_model = os.environ["LATEXSTRUCT_DECIDE_MODEL"]
    if os.environ.get("LATEXSTRUCT_REVIEW_MODEL"):
        cfg.review_model = os.environ["LATEXSTRUCT_REVIEW_MODEL"]
    if os.environ.get("LATEXSTRUCT_OCR_MODEL"):
        cfg.ocr_model = os.environ["LATEXSTRUCT_OCR_MODEL"]
    return cfg


def save_config(cfg: AppConfig):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, ensure_ascii=False, indent=1)

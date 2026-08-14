# -*- coding: utf-8 -*-
"""应用配置（三角色模型配置 + 复查开关）。Key 存本机配置文件/环境变量，不上传。"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, Optional

from .core.ai import AIConfig, RoleConfig
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

    def to_ai_config(self) -> AIConfig:
        decide = RoleConfig(self.decide_base_url, self.decide_model, self.decide_api_key)
        review = RoleConfig(self.review_base_url, self.review_model, self.review_api_key)
        return AIConfig(decide=decide, review=review, review_enabled=self.review_enabled)

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
    if os.environ.get("LATEXSTRUCT_DECIDE_MODEL"):
        cfg.decide_model = os.environ["LATEXSTRUCT_DECIDE_MODEL"]
    if os.environ.get("LATEXSTRUCT_REVIEW_MODEL"):
        cfg.review_model = os.environ["LATEXSTRUCT_REVIEW_MODEL"]
    return cfg


def save_config(cfg: AppConfig):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, ensure_ascii=False, indent=1)

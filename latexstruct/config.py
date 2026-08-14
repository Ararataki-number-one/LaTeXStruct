# -*- coding: utf-8 -*-
"""应用配置（三角色模型配置 + 复查开关）。Key 存本机配置文件/环境变量，不上传。

开启 keyring 后密钥改存 Windows 凭据管理器（见 keystore.py），config.json 仅存
占位符 ``__keyring__``；不可用平台自动回退明文配置文件（原有行为）。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict

from .core.ai import AIConfig, RoleConfig
from .keystore import KEY_FIELDS, PLACEHOLDER, KeystoreBackend, default_backend
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
    keyring: bool = False
    # 非持久化：标记各 Key 是否来自系统凭据管理器（masked 展示用）
    _keyring_resolved: Dict[str, bool] = field(default_factory=dict, repr=False)

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
            if "key" in k and k in KEY_FIELDS:
                if d[k]:
                    d[k] = "已配置(系统凭据)" if self._keyring_resolved.get(k) else "已配置"
                else:
                    d[k] = ""
        d.pop("_keyring_resolved", None)
        return d


def load_config(backend: KeystoreBackend | None = None) -> AppConfig:
    backend = backend if backend is not None else default_backend()
    cfg = AppConfig()
    if os.path.exists(CONFIG_PATH):
        try:
            data = json.loads(open(CONFIG_PATH, encoding="utf-8").read())
            for k in asdict(cfg):
                if k in data and k != "_keyring_resolved":
                    setattr(cfg, k, data[k])
        except Exception:  # noqa: BLE001
            pass
    # keyring 占位符解析回真实密钥（不可用时留空，不崩溃）
    for k in KEY_FIELDS:
        if getattr(cfg, k) == PLACEHOLDER:
            secret = backend.get(k)
            setattr(cfg, k, secret)
            cfg._keyring_resolved[k] = bool(secret)
    for k, envk in (("decide_api_key", "LATEXSTRUCT_DECIDE_KEY"),
                    ("review_api_key", "LATEXSTRUCT_REVIEW_KEY"),
                    ("ocr_api_key", "LATEXSTRUCT_OCR_KEY")):
        if os.environ.get(envk):
            setattr(cfg, k, os.environ[envk])
            cfg._keyring_resolved[k] = False
    if os.environ.get("LATEXSTRUCT_DECIDE_MODEL"):
        cfg.decide_model = os.environ["LATEXSTRUCT_DECIDE_MODEL"]
    if os.environ.get("LATEXSTRUCT_REVIEW_MODEL"):
        cfg.review_model = os.environ["LATEXSTRUCT_REVIEW_MODEL"]
    if os.environ.get("LATEXSTRUCT_OCR_MODEL"):
        cfg.ocr_model = os.environ["LATEXSTRUCT_OCR_MODEL"]
    return cfg


def save_config(cfg: AppConfig, backend: KeystoreBackend | None = None):
    backend = backend if backend is not None else default_backend()
    data = {k: v for k, v in asdict(cfg).items() if k != "_keyring_resolved"}
    use_ring = cfg.keyring and backend.available()
    for k in KEY_FIELDS:
        secret = data.get(k) or ""
        if use_ring:
            if secret:
                backend.set(k, secret)
            else:
                backend.delete(k)
            data[k] = PLACEHOLDER
        else:
            backend.delete(k)  # 关闭 keyring 时清理系统凭据，避免残留旧密钥
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

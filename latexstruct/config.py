# -*- coding: utf-8 -*-
"""应用配置（三角色模型配置 + 复查开关）。Key 存本机配置文件/环境变量，不上传。

开启 keyring 后密钥改存 Windows 凭据管理器（见 keystore.py），config.json 仅存
占位符 ``__keyring__``；若凭据管理器不可用或写入失败，保存会明确失败，不会静默
降级为明文。
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, Optional
from urllib.parse import urlsplit

from .core.ai import AIConfig, RoleConfig
from .keystore import KEY_FIELDS, PLACEHOLDER, KeystoreBackend, default_backend
from .ocr import OcrConfig
from .providers import get_provider_preset, is_qwen_config
from .store import default_data_dir

CONFIG_PATH = os.path.join(default_data_dir(), "config.json")


@dataclass
class AppConfig:
    decide_base_url: str = "https://api.deepseek.com"
    decide_model: str = "deepseek-v4-flash"
    decide_api_key: str = ""
    review_base_url: str = "https://api.deepseek.com"
    review_model: str = "deepseek-v4-pro"
    review_api_key: str = ""
    review_enabled: bool = True
    ocr_base_url: str = "https://api.deepseek.com"
    ocr_model: str = ""
    ocr_api_key: str = ""
    keyring: bool = False
    # 非持久化：标记各 Key 是否来自系统凭据管理器（masked 展示用）
    _keyring_resolved: Dict[str, bool] = field(default_factory=dict, repr=False)
    # 非持久化：防止环境变量注入的 Key 在保存设置时被回写到 config.json/keyring。
    _env_resolved: Dict[str, bool] = field(default_factory=dict, repr=False)

    def to_ai_config(self) -> AIConfig:
        # 同供应商场景下 Key 互相回退；不同 API Host 之间绝不复用 Key。
        decide_key = self.decide_api_key
        review_key = self.review_api_key
        if not decide_key and _same_api_host(self.decide_base_url, self.review_base_url):
            decide_key = self.review_api_key
        if not review_key and _same_api_host(self.review_base_url, self.decide_base_url):
            review_key = self.decide_api_key
        decide = RoleConfig(self.decide_base_url, self.decide_model, decide_key)
        review = RoleConfig(self.review_base_url, self.review_model, review_key)
        return AIConfig(decide=decide, review=review, review_enabled=self.review_enabled)

    def to_ocr_config(self) -> OcrConfig:
        base_url = self.ocr_base_url or self.decide_base_url
        model = self.ocr_model or self.decide_model or "deepseek-v4-flash"
        key = self.ocr_api_key
        if not key and _same_api_host(base_url, self.decide_base_url):
            key = self.decide_api_key
        if not key and _same_api_host(base_url, self.review_base_url):
            key = self.review_api_key
        return OcrConfig(role=RoleConfig(base_url, model, key))

    def masked(self) -> Dict:
        d = asdict(self)
        for k in list(d):
            if "key" in k and k in KEY_FIELDS:
                if d[k]:
                    d[k] = "已配置(系统凭据)" if self._keyring_resolved.get(k) else "已配置"
                else:
                    d[k] = ""
        d.pop("_keyring_resolved", None)
        d.pop("_env_resolved", None)
        return d


def _read_config_data() -> Dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _same_api_host(left: str, right: str) -> bool:
    try:
        return bool(left and right and urlsplit(left).netloc.lower() == urlsplit(right).netloc.lower())
    except ValueError:
        return False


def load_config(backend: KeystoreBackend | None = None) -> AppConfig:
    backend = backend if backend is not None else default_backend()
    cfg = AppConfig()
    data = _read_config_data()
    for k in asdict(cfg):
        if k in data and k not in ("_keyring_resolved", "_env_resolved"):
            setattr(cfg, k, data[k])
    # DeepSeek 于 2026-07-24 退役旧别名。无感迁移，避免用户 Key 正确却收到模型不存在。
    legacy_models = {
        "deepseek-chat": "deepseek-v4-flash",
        "deepseek-reasoner": "deepseek-v4-pro",
    }
    cfg.decide_model = legacy_models.get(cfg.decide_model, cfg.decide_model)
    cfg.review_model = legacy_models.get(cfg.review_model, cfg.review_model)
    # keyring 占位符解析回真实密钥（不可用时留空，不崩溃）
    for k in KEY_FIELDS:
        if getattr(cfg, k) == PLACEHOLDER:
            secret = backend.get(k)
            setattr(cfg, k, secret)
            cfg._keyring_resolved[k] = bool(secret)

    preset = get_provider_preset(os.environ.get("LATEXSTRUCT_OCR_PROVIDER", ""))
    if preset:
        cfg.ocr_base_url = preset.base_url
        cfg.ocr_model = preset.model

    for field_name, env_name in (
        ("decide_base_url", "LATEXSTRUCT_DECIDE_BASE_URL"),
        ("review_base_url", "LATEXSTRUCT_REVIEW_BASE_URL"),
        ("ocr_base_url", "LATEXSTRUCT_OCR_BASE_URL"),
        ("decide_model", "LATEXSTRUCT_DECIDE_MODEL"),
        ("review_model", "LATEXSTRUCT_REVIEW_MODEL"),
        ("ocr_model", "LATEXSTRUCT_OCR_MODEL"),
    ):
        if os.environ.get(env_name):
            setattr(cfg, field_name, os.environ[env_name])

    for k, envk in (("decide_api_key", "LATEXSTRUCT_DECIDE_KEY"),
                    ("review_api_key", "LATEXSTRUCT_REVIEW_KEY"),
                    ("ocr_api_key", "LATEXSTRUCT_OCR_KEY")):
        if os.environ.get(envk):
            setattr(cfg, k, os.environ[envk])
            cfg._keyring_resolved[k] = False
            cfg._env_resolved[k] = True
    if not cfg._env_resolved.get("ocr_api_key") and is_qwen_config(
        cfg.ocr_base_url, cfg.ocr_model
    ) and os.environ.get("DASHSCOPE_API_KEY"):
        cfg.ocr_api_key = os.environ["DASHSCOPE_API_KEY"]
        cfg._keyring_resolved["ocr_api_key"] = False
        cfg._env_resolved["ocr_api_key"] = True
    return cfg


def save_config(
    cfg: AppConfig,
    backend: KeystoreBackend | None = None,
    secret_updates: Optional[Dict[str, str]] = None,
):
    backend = backend if backend is not None else default_backend()
    data = {
        k: v for k, v in asdict(cfg).items()
        if k not in ("_keyring_resolved", "_env_resolved")
    }
    stored = _read_config_data()
    # 服务端传入 secret_updates：只持久化本次明确提交的 Key。若运行时 Key 来自
    # 环境变量，则恢复保存前的磁盘/keyring 值，避免一次普通设置保存造成 secret 落盘。
    if secret_updates is not None:
        for k in KEY_FIELDS:
            if k in secret_updates:
                data[k] = secret_updates[k]
            elif cfg._env_resolved.get(k):
                old = stored.get(k, "")
                data[k] = backend.get(k) if old == PLACEHOLDER else old
    use_ring = cfg.keyring and backend.available()
    if cfg.keyring and not use_ring:
        raise OSError("系统凭据管理器不可用；为避免密钥明文落盘，本次设置未保存")
    old_credentials = {k: backend.get(k) for k in KEY_FIELDS} if use_ring else {}

    def restore_credentials():
        for field_name, old_secret in old_credentials.items():
            if old_secret:
                backend.set(field_name, old_secret)
            else:
                backend.delete(field_name)

    if use_ring:
        try:
            for k in KEY_FIELDS:
                secret = data.get(k) or ""
                if secret:
                    if not backend.set(k, secret):
                        raise OSError("API Key 写入系统凭据管理器失败；配置文件未保存")
                else:
                    backend.delete(k)
                data[k] = PLACEHOLDER
        except Exception:
            restore_credentials()
            raise
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = f"{CONFIG_PATH}.{uuid.uuid4().hex}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CONFIG_PATH)
    except Exception:
        if use_ring:
            restore_credentials()
        raise
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if not use_ring:
        for k in KEY_FIELDS:
            backend.delete(k)  # 配置落盘成功后再清理旧凭据，避免写盘失败造成密钥丢失

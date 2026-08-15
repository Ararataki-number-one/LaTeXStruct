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
    decide_api_key: str = field(default="", repr=False)
    review_base_url: str = "https://api.deepseek.com"
    review_model: str = "deepseek-v4-pro"
    review_api_key: str = field(default="", repr=False)
    review_enabled: bool = True
    ocr_base_url: str = "https://api.deepseek.com"
    ocr_model: str = ""
    ocr_api_key: str = field(default="", repr=False)
    keyring: bool = False
    # 非持久化：标记各 Key 是否来自系统凭据管理器（masked 展示用）
    _keyring_resolved: Dict[str, bool] = field(default_factory=dict, repr=False)
    # 非持久化：标记环境变量影响的字段，防止运行时覆盖被保存回 config.json/keyring。
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


def _api_authority(value: str, allow_loopback_http: bool = False):
    try:
        parsed = urlsplit((value or "").strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    scheme = parsed.scheme.lower()
    normalized_host = hostname.rstrip(".").lower()
    if scheme == "https":
        return scheme, normalized_host, port or 443
    if scheme == "http" and allow_loopback_http and normalized_host in {
        "localhost", "127.0.0.1", "::1",
    }:
        return scheme, normalized_host, port or 80
    return None


def _same_api_host(left: str, right: str) -> bool:
    """自动 Key 回退只允许在相同的合法 HTTPS authority 内。"""
    left_authority = _api_authority(left)
    right_authority = _api_authority(right)
    return bool(left_authority and left_authority == right_authority)


def _validated_env_base_url(value: str, env_name: str) -> str:
    """环境覆盖必须是无内嵌凭据的 HTTPS Base URL。"""
    candidate = (value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError:
        parsed = None
    if (
        parsed is None
        or _api_authority(candidate) is None
    ):
        raise ValueError(f"{env_name} 必须是有效的 HTTPS API Base URL（不得包含凭据、查询或片段）")
    return candidate


def _credential_may_follow_base_override(source: str, target: str) -> bool:
    """磁盘/keyring 凭据仅允许跟随到相同的 HTTPS host + 有效端口。"""
    source_authority = _api_authority(source)
    target_authority = _api_authority(target)
    return bool(source_authority and source_authority == target_authority)


def _set_env_role_base(cfg: AppConfig, role: str, target: str, env_name: str) -> None:
    """应用 Base URL 环境覆盖；跨信任域时丢弃磁盘/keyring 中的旧凭据。"""
    base_field = f"{role}_base_url"
    key_field = f"{role}_api_key"
    source = getattr(cfg, base_field)
    validated = _validated_env_base_url(target, env_name)
    setattr(cfg, base_field, validated)
    cfg._env_resolved[base_field] = True
    if getattr(cfg, key_field) and not _credential_may_follow_base_override(source, validated):
        setattr(cfg, key_field, "")
        cfg._keyring_resolved[key_field] = False
        # save_config 会恢复磁盘/keyring 中的原值，避免普通设置保存把环境覆盖持久化，
        # 进而在下次（无环境保护）启动时把旧凭据发送到新 host。
        cfg._env_resolved[key_field] = True


def _new_config_uses_keyring() -> bool:
    return os.name == "nt"


def load_config(backend: KeystoreBackend | None = None) -> AppConfig:
    backend = backend if backend is not None else default_backend()
    config_exists = os.path.exists(CONFIG_PATH)
    cfg = AppConfig()
    if _new_config_uses_keyring() and not config_exists:
        # Windows 新安装默认使用系统凭据管理器；已有配置（含显式 false）不强制迁移。
        cfg.keyring = True
    data = _read_config_data()
    for k in asdict(cfg):
        if k in data and k not in ("_keyring_resolved", "_env_resolved"):
            setattr(cfg, k, data[k])
    # 旧版允许空 OCR Base URL 动态回退 decide；立即固化到迁移当时的地址，
    # 避免之后仅覆盖 decide host 时把既有 OCR Key 隐式带到新 host。
    if not (cfg.ocr_base_url or "").strip():
        cfg.ocr_base_url = cfg.decide_base_url
    # keyring 占位符解析回真实密钥（不可用时留空，不崩溃）
    for k in KEY_FIELDS:
        if getattr(cfg, k) == PLACEHOLDER:
            secret = backend.get(k)
            setattr(cfg, k, secret)
            cfg._keyring_resolved[k] = bool(secret)

    preset = get_provider_preset(os.environ.get("LATEXSTRUCT_OCR_PROVIDER", ""))
    if preset and preset.vision and "ocr" in preset.roles:
        _set_env_role_base(cfg, "ocr", preset.base_url, "LATEXSTRUCT_OCR_PROVIDER")
        cfg.ocr_model = preset.model
        cfg._env_resolved["ocr_model"] = True

    for role, env_name in (
        ("decide", "LATEXSTRUCT_DECIDE_BASE_URL"),
        ("review", "LATEXSTRUCT_REVIEW_BASE_URL"),
        ("ocr", "LATEXSTRUCT_OCR_BASE_URL"),
    ):
        if os.environ.get(env_name):
            _set_env_role_base(cfg, role, os.environ[env_name], env_name)

    for field_name, env_name in (
        ("decide_model", "LATEXSTRUCT_DECIDE_MODEL"),
        ("review_model", "LATEXSTRUCT_REVIEW_MODEL"),
        ("ocr_model", "LATEXSTRUCT_OCR_MODEL"),
    ):
        if os.environ.get(env_name):
            setattr(cfg, field_name, os.environ[env_name])
            cfg._env_resolved[field_name] = True

    for k, envk in (("decide_api_key", "LATEXSTRUCT_DECIDE_KEY"),
                    ("review_api_key", "LATEXSTRUCT_REVIEW_KEY"),
                    ("ocr_api_key", "LATEXSTRUCT_OCR_KEY")):
        if os.environ.get(envk):
            setattr(cfg, k, os.environ[envk])
            cfg._keyring_resolved[k] = False
            cfg._env_resolved[k] = True
    dashscope_key = os.environ.get("DASHSCOPE_API_KEY")
    if dashscope_key:
        for role in ("decide", "review", "ocr"):
            key_field = f"{role}_api_key"
            role_key_env = f"LATEXSTRUCT_{role.upper()}_KEY"
            if (
                not os.environ.get(role_key_env)
                and is_qwen_config(
                    getattr(cfg, f"{role}_base_url"), getattr(cfg, f"{role}_model")
                )
            ):
                setattr(cfg, key_field, dashscope_key)
                cfg._keyring_resolved[key_field] = False
                cfg._env_resolved[key_field] = True
    # DeepSeek 于 2026-07-24 退役旧别名。磁盘值和三个角色的环境覆盖均需迁移。
    legacy_models = {
        "deepseek-chat": "deepseek-v4-flash",
        "deepseek-reasoner": "deepseek-v4-pro",
    }
    for field_name in ("decide_model", "review_model", "ocr_model"):
        model = getattr(cfg, field_name)
        setattr(cfg, field_name, legacy_models.get(model, model))
    return cfg


def save_config(
    cfg: AppConfig,
    backend: KeystoreBackend | None = None,
    secret_updates: Optional[Dict[str, str]] = None,
):
    backend = backend if backend is not None else default_backend()
    if not (cfg.ocr_base_url or "").strip():
        cfg.ocr_base_url = cfg.decide_base_url
    data = {
        k: v for k, v in asdict(cfg).items()
        if k not in ("_keyring_resolved", "_env_resolved")
    }
    stored = _read_config_data()
    defaults = AppConfig()
    for role in ("decide", "review", "ocr"):
        base_field = f"{role}_base_url"
        key_field = f"{role}_api_key"
        if _api_authority(getattr(cfg, base_field), allow_loopback_http=True) is None:
            raise ValueError(
                f"{base_field} 必须是有效的 HTTPS API Base URL（仅本机 loopback 允许 HTTP）"
            )
        if (
            secret_updates is not None
            and key_field in secret_updates
            and (
                cfg._env_resolved.get(base_field)
                or cfg._env_resolved.get(f"{role}_model")
                or cfg._env_resolved.get(key_field)
            )
        ):
            raise ValueError(
                f"{role} 的配置正由环境变量覆盖；请先移除环境覆盖再保存 API Key"
            )

        stored_base = stored.get(base_field, getattr(defaults, base_field))
        if role == "ocr" and not (stored_base or "").strip():
            stored_base = stored.get("decide_base_url", defaults.decide_base_url)
        authority_changed = (
            _api_authority(stored_base, allow_loopback_http=True)
            != _api_authority(getattr(cfg, base_field), allow_loopback_http=True)
        )
        if (
            secret_updates is not None
            and not cfg._env_resolved.get(base_field)
            and authority_changed
            and getattr(cfg, key_field)
            and key_field not in secret_updates
        ):
            raise ValueError(f"更换 {role} API Host 时必须在同一请求中提交对应的新 API Key")

    for field_name in (
        "decide_base_url", "review_base_url", "ocr_base_url",
        "decide_model", "review_model", "ocr_model",
    ):
        if cfg._env_resolved.get(field_name):
            data[field_name] = stored.get(field_name, getattr(defaults, field_name))
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
                    deleted = backend.delete(k)
                    if old_credentials.get(k) and not deleted:
                        raise OSError("API Key 从系统凭据管理器删除失败；配置文件未保存")
                data[k] = PLACEHOLDER
        except Exception:
            restore_credentials()
            raise
    tmp = f"{CONFIG_PATH}.{uuid.uuid4().hex}.tmp"
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
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

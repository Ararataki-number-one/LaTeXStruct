# -*- coding: utf-8 -*-
"""keystore/config 密钥存储测试（FakeBackend 注入，不触碰真实凭据管理器）。"""

import json
import os
import shutil
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct import config
from latexstruct.keystore import PLACEHOLDER, FakeBackend, WindowsCredBackend
from latexstruct.providers import QWEN_CN_BASE_URL, is_qwen_config

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_orig_path = config.CONFIG_PATH
_CONFIG_ENV_NAMES = (
    "LATEXSTRUCT_OCR_PROVIDER", "DASHSCOPE_API_KEY",
    "LATEXSTRUCT_DECIDE_BASE_URL", "LATEXSTRUCT_REVIEW_BASE_URL",
    "LATEXSTRUCT_OCR_BASE_URL", "LATEXSTRUCT_DECIDE_MODEL",
    "LATEXSTRUCT_REVIEW_MODEL", "LATEXSTRUCT_OCR_MODEL",
    "LATEXSTRUCT_DECIDE_KEY", "LATEXSTRUCT_REVIEW_KEY", "LATEXSTRUCT_OCR_KEY",
)


def _isolated_env(**updates):
    values = {name: "" for name in _CONFIG_ENV_NAMES}
    values.update(updates)
    return patch.dict(os.environ, values, clear=False)


def _tmp():
    p = tempfile.mkdtemp(prefix="ls-ks-", dir=_TESTS_DIR)
    config.CONFIG_PATH = os.path.join(p, "config.json")
    return p


def _restore(tmp):
    config.CONFIG_PATH = _orig_path
    shutil.rmtree(tmp, ignore_errors=True)


def test_fake_backend_roundtrip():
    b = FakeBackend()
    assert b.set("decide_api_key", "sk-1") is True
    assert b.get("decide_api_key") == "sk-1"
    assert b.get("nope") == ""
    b.delete("decide_api_key")
    assert b.get("decide_api_key") == ""


def test_app_config_repr_redacts_all_api_keys():
    secrets = ("synthetic-decide", "synthetic-review", "synthetic-ocr")
    rendered = repr(config.AppConfig(
        decide_api_key=secrets[0], review_api_key=secrets[1], ocr_api_key=secrets[2],
    ))
    assert all(secret not in rendered for secret in secrets)


def test_windows_backend_availability():
    wb = WindowsCredBackend()
    assert wb.available() in (True, False)  # 平台相关，仅要求不抛异常
    if not wb.available():
        assert wb.get("x") == "" and wb.set("x", "y") is False


def test_save_load_with_keyring_on():
    tmp = _tmp()
    try:
        b = FakeBackend()
        cfg = config.AppConfig(decide_api_key="sk-abc", review_api_key="sk-xyz", keyring=True)
        config.save_config(cfg, backend=b)
        on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
        assert on_disk["decide_api_key"] == PLACEHOLDER
        assert on_disk["review_api_key"] == PLACEHOLDER
        assert "sk-abc" not in json.dumps(on_disk)  # 明文绝不落盘
        cfg2 = config.load_config(backend=b)
        assert cfg2.decide_api_key == "sk-abc"
        assert cfg2.review_api_key == "sk-xyz"
        assert cfg2.keyring is True
        assert cfg2._keyring_resolved["decide_api_key"] is True
        assert cfg2.masked()["decide_api_key"] == "已配置(系统凭据)"
    finally:
        _restore(tmp)


def test_save_load_with_keyring_off():
    tmp = _tmp()
    try:
        b = FakeBackend()
        cfg = config.AppConfig(decide_api_key="sk-plain", keyring=False)
        config.save_config(cfg, backend=b)
        on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
        assert on_disk["decide_api_key"] == "sk-plain"  # 回退行为与旧版一致
        cfg2 = config.load_config(backend=b)
        assert cfg2.decide_api_key == "sk-plain"
        assert cfg2.masked()["decide_api_key"] == "已配置"
        assert cfg2._keyring_resolved.get("decide_api_key") is not True
    finally:
        _restore(tmp)


def test_keyring_off_cleans_system_cred():
    tmp = _tmp()
    try:
        b = FakeBackend()
        b.set("decide_api_key", "sk-old")
        cfg = config.AppConfig(decide_api_key="", keyring=False)
        config.save_config(cfg, backend=b)
        assert b.get("decide_api_key") == ""  # 关闭后清理系统凭据
        assert "LaTeXStruct/decide_api_key" in b.deleted
    finally:
        _restore(tmp)


def test_cleared_key_placeholder_resolves_empty():
    tmp = _tmp()
    try:
        b = FakeBackend()
        cfg = config.AppConfig(decide_api_key="", keyring=True)
        config.save_config(cfg, backend=b)
        cfg2 = config.load_config(backend=b)
        assert cfg2.decide_api_key == ""
        assert cfg2._keyring_resolved.get("decide_api_key") is not True
        assert cfg2.masked()["decide_api_key"] == ""
    finally:
        _restore(tmp)


def test_qwen_environment_key_is_runtime_only():
    tmp = _tmp()
    try:
        with _isolated_env(
            LATEXSTRUCT_OCR_PROVIDER="qwen3-vl-flash-cn",
            DASHSCOPE_API_KEY="runtime-only-value",
        ):
            b = FakeBackend()
            cfg = config.load_config(backend=b)
            role = cfg.to_ocr_config().role
            assert role.base_url == QWEN_CN_BASE_URL
            assert role.model == "qwen3-vl-flash"
            assert role.api_key == "runtime-only-value"
            cfg.keyring = False  # 本测试只验证环境变量不落盘；默认值另有独立测试。
            config.save_config(cfg, backend=b, secret_updates={})
            on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
            assert on_disk["ocr_api_key"] == ""
            assert "runtime-only-value" not in json.dumps(on_disk)
    finally:
        _restore(tmp)


def test_qwen_auto_key_requires_strict_official_https_host():
    assert is_qwen_config(QWEN_CN_BASE_URL, "custom-model") is True
    assert is_qwen_config(
        "https://workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", "qwen3-vl-flash",
    ) is True
    assert is_qwen_config("https://aliyuncs.com.evil.invalid/v1", "qwen3-vl-flash") is False
    assert is_qwen_config("https://evil.invalid/aliyuncs.com/v1", "qwen3-vl-flash") is False
    assert is_qwen_config("https://evil.invalid/v1", "qwen3-vl-flash") is False
    assert is_qwen_config("http://dashscope.aliyuncs.com/v1", "qwen3-vl-flash") is False
    assert is_qwen_config("https://dashscope.aliyuncs.com:444/v1", "qwen3-vl-flash") is False
    assert is_qwen_config("https://dashscope.aliyuncs.com/v1?redirect=evil", "qwen3-vl-flash") is False


def test_environment_base_override_cannot_retarget_disk_secret():
    tmp = _tmp()
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "decide_base_url": "https://api.deepseek.com",
                "decide_api_key": "stored-disk-value",
                "keyring": False,
            }, f)
        with _isolated_env(LATEXSTRUCT_DECIDE_BASE_URL="https://attacker.invalid/v1"):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.decide_base_url == "https://attacker.invalid/v1"
            assert cfg.decide_api_key == ""
            # 普通设置保存必须恢复环境覆盖前的 host/key，不能留下延迟泄漏。
            config.save_config(cfg, backend=FakeBackend(), secret_updates={})
        on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
        assert on_disk["decide_base_url"] == "https://api.deepseek.com"
        assert on_disk["decide_api_key"] == "stored-disk-value"
    finally:
        _restore(tmp)


def test_environment_base_override_cannot_retarget_keyring_secret():
    tmp = _tmp()
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "review_base_url": "https://api.deepseek.com",
                "review_api_key": PLACEHOLDER,
                "keyring": True,
            }, f)
        backend = FakeBackend()
        backend.set("review_api_key", "stored-keyring-value")
        with _isolated_env(LATEXSTRUCT_REVIEW_BASE_URL="https://attacker.invalid/v1"):
            cfg = config.load_config(backend=backend)
            assert cfg.review_api_key == ""
            config.save_config(cfg, backend=backend, secret_updates={})
        on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
        assert on_disk["review_base_url"] == "https://api.deepseek.com"
        assert on_disk["review_api_key"] == PLACEHOLDER
        assert backend.get("review_api_key") == "stored-keyring-value"
    finally:
        _restore(tmp)


def test_persisted_qwen_key_does_not_follow_to_another_official_hostname():
    tmp = _tmp()
    workspace_url = "https://workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "ocr_base_url": QWEN_CN_BASE_URL,
                "ocr_model": "qwen3-vl-flash",
                "ocr_api_key": "stored-qwen-value",
                "keyring": False,
            }, f)
        with _isolated_env(LATEXSTRUCT_OCR_BASE_URL=workspace_url):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.ocr_api_key == ""
        # 显式 DASHSCOPE 环境 Key 可在严格 Qwen allowlist host 上使用。
        with _isolated_env(
            LATEXSTRUCT_OCR_BASE_URL=workspace_url,
            DASHSCOPE_API_KEY="runtime-qwen-value",
        ):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.ocr_api_key == "runtime-qwen-value"
            assert cfg._env_resolved["ocr_api_key"] is True
    finally:
        _restore(tmp)


def test_environment_base_override_requires_https():
    tmp = _tmp()
    try:
        with _isolated_env(LATEXSTRUCT_DECIDE_BASE_URL="http://api.deepseek.com/v1"):
            try:
                config.load_config(backend=FakeBackend())
            except ValueError as exc:
                assert "HTTPS" in str(exc)
            else:
                raise AssertionError("环境 Base URL 的 HTTP 覆盖必须被拒绝")
    finally:
        _restore(tmp)


def test_qwen_key_is_not_injected_into_custom_host_or_invalid_ocr_provider():
    tmp = _tmp()
    try:
        with _isolated_env(
            LATEXSTRUCT_OCR_BASE_URL="https://dashscope.aliyuncs.com.evil.invalid/v1",
            LATEXSTRUCT_OCR_MODEL="qwen3-vl-flash",
            DASHSCOPE_API_KEY="runtime-only-value",
        ):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.ocr_api_key == ""
        with _isolated_env(
            LATEXSTRUCT_OCR_PROVIDER="deepseek-v4-flash",
            DASHSCOPE_API_KEY="runtime-only-value",
        ):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.ocr_model == ""
            assert cfg.ocr_base_url == "https://api.deepseek.com"
            assert cfg.ocr_api_key == ""
    finally:
        _restore(tmp)


def test_dashscope_key_supports_all_strict_qwen_roles_with_role_key_priority():
    tmp = _tmp()
    try:
        with _isolated_env(
            LATEXSTRUCT_DECIDE_BASE_URL=QWEN_CN_BASE_URL,
            LATEXSTRUCT_REVIEW_BASE_URL=QWEN_CN_BASE_URL,
            LATEXSTRUCT_OCR_BASE_URL=QWEN_CN_BASE_URL,
            LATEXSTRUCT_DECIDE_MODEL="qwen3.7-flash",
            LATEXSTRUCT_REVIEW_MODEL="qwen3.7-plus",
            LATEXSTRUCT_OCR_MODEL="qwen3-vl-flash",
            LATEXSTRUCT_REVIEW_KEY="role-specific-review",
            DASHSCOPE_API_KEY="shared-runtime-value",
        ):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.decide_api_key == "shared-runtime-value"
            assert cfg.review_api_key == "role-specific-review"
            assert cfg.ocr_api_key == "shared-runtime-value"
            assert all(cfg._env_resolved.get(k) for k in (
                "decide_api_key", "review_api_key", "ocr_api_key",
            ))
    finally:
        _restore(tmp)


def test_env_resolved_role_rejects_explicit_secret_save_atomically():
    tmp = _tmp()
    try:
        original = {
            "ocr_base_url": "https://api.deepseek.com",
            "ocr_model": "deepseek-v4-flash",
            "ocr_api_key": "stored-ocr-value",
            "keyring": False,
        }
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(original, f)
        with _isolated_env(
            LATEXSTRUCT_OCR_BASE_URL=QWEN_CN_BASE_URL,
            LATEXSTRUCT_OCR_MODEL="qwen3-vl-flash",
            DASHSCOPE_API_KEY="runtime-qwen-value",
        ):
            cfg = config.load_config(backend=FakeBackend())
            cfg.ocr_api_key = "new-explicit-value"
            try:
                config.save_config(
                    cfg, backend=FakeBackend(),
                    secret_updates={"ocr_api_key": "new-explicit-value"},
                )
            except ValueError as exc:
                assert "环境变量" in str(exc)
            else:
                raise AssertionError("环境覆盖生效时不得持久化该角色的新 Key")
        assert json.loads(open(config.CONFIG_PATH, encoding="utf-8").read()) == original
    finally:
        _restore(tmp)


def test_empty_legacy_ocr_base_is_frozen_before_decide_env_override():
    tmp = _tmp()
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "decide_base_url": "https://api.deepseek.com",
                "ocr_base_url": "",
                "ocr_api_key": "stored-ocr-value",
                "keyring": False,
            }, f)
        with _isolated_env(LATEXSTRUCT_DECIDE_BASE_URL="https://custom.invalid/v1"):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.decide_base_url == "https://custom.invalid/v1"
            assert cfg.ocr_base_url == "https://api.deepseek.com"
            assert cfg.ocr_api_key == "stored-ocr-value"
            assert cfg.to_ocr_config().role.base_url == "https://api.deepseek.com"
        with _isolated_env():
            cfg = config.load_config(backend=FakeBackend())
            config.save_config(cfg, backend=FakeBackend(), secret_updates={})
        stored = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
        assert stored["ocr_base_url"] == "https://api.deepseek.com"
        assert stored["ocr_api_key"] == "stored-ocr-value"
    finally:
        _restore(tmp)


def test_environment_port_change_does_not_retarget_persisted_key():
    tmp = _tmp()
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "decide_base_url": "https://api.deepseek.com",
                "decide_api_key": "stored-decide-value",
                "keyring": False,
            }, f)
        with _isolated_env(
            LATEXSTRUCT_DECIDE_BASE_URL="https://api.deepseek.com:444/v1",
        ):
            cfg = config.load_config(backend=FakeBackend())
            assert cfg.decide_api_key == ""
    finally:
        _restore(tmp)


def test_legacy_model_migration_covers_disk_and_all_environment_roles():
    tmp = _tmp()
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "decide_model": "deepseek-chat",
                "review_model": "deepseek-reasoner",
                "ocr_model": "deepseek-chat",
            }, f)
        with _isolated_env():
            cfg = config.load_config(backend=FakeBackend())
        assert cfg.decide_model == "deepseek-v4-flash"
        assert cfg.review_model == "deepseek-v4-pro"
        assert cfg.ocr_model == "deepseek-v4-flash"
        with _isolated_env(
            LATEXSTRUCT_DECIDE_MODEL="deepseek-reasoner",
            LATEXSTRUCT_REVIEW_MODEL="deepseek-chat",
            LATEXSTRUCT_OCR_MODEL="deepseek-reasoner",
        ):
            cfg = config.load_config(backend=FakeBackend())
        assert cfg.decide_model == "deepseek-v4-pro"
        assert cfg.review_model == "deepseek-v4-flash"
        assert cfg.ocr_model == "deepseek-v4-pro"
    finally:
        _restore(tmp)


def test_windows_new_config_defaults_to_keyring_without_migrating_existing_false():
    tmp = _tmp()
    try:
        with _isolated_env(), patch.object(config, "_new_config_uses_keyring", return_value=True):
            assert config.load_config(backend=FakeBackend()).keyring is True
            with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"keyring": False}, f)
            assert config.load_config(backend=FakeBackend()).keyring is False
    finally:
        _restore(tmp)


def test_cross_provider_keys_are_not_reused():
    cfg = config.AppConfig(
        decide_base_url="https://api.deepseek.com",
        decide_api_key="deepseek-only-value",
        review_base_url=QWEN_CN_BASE_URL,
        review_api_key="qwen-only-value",
        ocr_base_url=QWEN_CN_BASE_URL,
        ocr_model="qwen3-vl-flash",
    )
    ai = cfg.to_ai_config()
    assert ai.decide.api_key == "deepseek-only-value"
    assert ai.review.api_key == "qwen-only-value"
    assert cfg.to_ocr_config().role.api_key == "qwen-only-value"
    cfg2 = config.AppConfig(
        decide_api_key="deepseek-only-value",
        review_api_key="deepseek-review-only-value",
        ocr_base_url=QWEN_CN_BASE_URL,
        ocr_model="qwen3-vl-flash",
    )
    assert cfg2.to_ocr_config().role.api_key == ""
    cfg3 = config.AppConfig(
        decide_base_url="https://api.deepseek.com",
        decide_api_key="https-only-value",
        review_base_url="http://api.deepseek.com",
        ocr_base_url="http://api.deepseek.com",
    )
    assert cfg3.to_ai_config().review.api_key == ""
    assert cfg3.to_ocr_config().role.api_key == ""


def test_keyring_unavailable_never_falls_back_to_plaintext():
    tmp = _tmp()
    try:
        cfg = config.AppConfig(decide_api_key="must-not-hit-disk", keyring=True)
        try:
            config.save_config(cfg, backend=FakeBackend(ok=False))
        except OSError as exc:
            assert "明文" in str(exc)
        else:
            raise AssertionError("凭据管理器不可用时必须拒绝明文回退")
        assert not os.path.exists(config.CONFIG_PATH)
    finally:
        _restore(tmp)


def test_keyring_rolls_back_if_config_directory_creation_fails():
    tmp = _tmp()
    try:
        backend = FakeBackend()
        backend.set("decide_api_key", "old-keyring-value")
        cfg = config.AppConfig(decide_api_key="new-keyring-value", keyring=True)
        with patch.object(config.os, "makedirs", side_effect=OSError("synthetic failure")):
            try:
                config.save_config(cfg, backend=backend)
            except OSError:
                pass
            else:
                raise AssertionError("目录创建失败必须中止保存")
        assert backend.get("decide_api_key") == "old-keyring-value"
        assert not os.path.exists(config.CONFIG_PATH)
    finally:
        _restore(tmp)


def test_keyring_delete_failure_aborts_and_keeps_old_secret():
    class DeleteFailBackend(FakeBackend):
        def delete(self, name: str) -> bool:
            if name == "decide_api_key":
                return False
            return super().delete(name)

    tmp = _tmp()
    try:
        backend = DeleteFailBackend()
        backend.set("decide_api_key", "old-keyring-value")
        cfg = config.AppConfig(decide_api_key="", keyring=True)
        try:
            config.save_config(cfg, backend=backend)
        except OSError as exc:
            assert "删除失败" in str(exc)
        else:
            raise AssertionError("凭据删除失败必须中止保存")
        assert backend.get("decide_api_key") == "old-keyring-value"
        assert not os.path.exists(config.CONFIG_PATH)
    finally:
        _restore(tmp)


def test_codex_analysis_settings_roundtrip_into_ai_config():
    tmp = _tmp()
    try:
        with _isolated_env():
            cfg = config.AppConfig(
                analysis_backend="codex_cli",
                codex_model="openai/gpt-5.4",
                codex_reasoning_effort="xhigh",
                keyring=False,
            )
            config.save_config(cfg, backend=FakeBackend())
            on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
            assert on_disk["analysis_backend"] == "codex_cli"
            assert on_disk["codex_model"] == "openai/gpt-5.4"
            assert on_disk["codex_reasoning_effort"] == "xhigh"

            loaded = config.load_config(backend=FakeBackend())
            ai_cfg = loaded.to_ai_config()
            assert loaded.masked()["analysis_backend"] == "codex_cli"
            assert ai_cfg.analysis_backend == "codex_cli"
            assert ai_cfg.codex_model == "openai/gpt-5.4"
            assert ai_cfg.codex_reasoning_effort == "xhigh"
    finally:
        _restore(tmp)


def test_invalid_persisted_codex_settings_fall_back_safely():
    tmp = _tmp()
    try:
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "analysis_backend": "automatic-api-fallback",
                "codex_model": 'gpt-5\" --yolo',
                "codex_reasoning_effort": "maximum",
            }, f)
        with _isolated_env():
            loaded = config.load_config(backend=FakeBackend())
        assert loaded.analysis_backend == "api"
        assert loaded.codex_model == ""
        assert loaded.codex_reasoning_effort == "medium"
    finally:
        _restore(tmp)


def test_invalid_codex_settings_are_rejected_before_config_is_replaced():
    tmp = _tmp()
    try:
        original = {
            "analysis_backend": "api",
            "codex_model": "",
            "codex_reasoning_effort": "medium",
        }
        with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(original, f)
        cfg = config.AppConfig(
            analysis_backend="codex_cli",
            codex_model='gpt-5\" --config forced_login_method="apikey"',
            codex_reasoning_effort="high",
            keyring=False,
        )

        try:
            config.save_config(cfg, backend=FakeBackend())
        except ValueError as exc:
            assert "模型 ID" in str(exc)
        else:
            raise AssertionError("非法 Codex 模型不得保存")

        assert json.loads(open(config.CONFIG_PATH, encoding="utf-8").read()) == original
    finally:
        _restore(tmp)


def main():
    import traceback

    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
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
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

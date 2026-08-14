# -*- coding: utf-8 -*-
"""keystore/config 密钥存储测试（FakeBackend 注入，不触碰真实凭据管理器）。"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct import config
from latexstruct.keystore import PLACEHOLDER, FakeBackend, WindowsCredBackend
from latexstruct.providers import QWEN_CN_BASE_URL

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_orig_path = config.CONFIG_PATH


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
    env_names = ("LATEXSTRUCT_OCR_PROVIDER", "DASHSCOPE_API_KEY", "LATEXSTRUCT_OCR_KEY")
    old_env = {name: os.environ.get(name) for name in env_names}
    try:
        os.environ.pop("LATEXSTRUCT_OCR_KEY", None)
        os.environ["LATEXSTRUCT_OCR_PROVIDER"] = "qwen3-vl-flash-cn"
        os.environ["DASHSCOPE_API_KEY"] = "runtime-only-value"
        b = FakeBackend()
        cfg = config.load_config(backend=b)
        role = cfg.to_ocr_config().role
        assert role.base_url == QWEN_CN_BASE_URL
        assert role.model == "qwen3-vl-flash"
        assert role.api_key == "runtime-only-value"
        config.save_config(cfg, backend=b, secret_updates={})
        on_disk = json.loads(open(config.CONFIG_PATH, encoding="utf-8").read())
        assert on_disk["ocr_api_key"] == ""
        assert "runtime-only-value" not in json.dumps(on_disk)
    finally:
        for name, value in old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
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

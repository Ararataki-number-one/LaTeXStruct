# -*- coding: utf-8 -*-
"""系统凭据管理器密钥存储（Windows Credential Manager + 可注入后端）。

设计原则：密钥不落 config.json 明文。开启 keyring 后，save_config 把各 API Key
写入系统凭据管理器（目标名 ``LaTeXStruct/<字段>``），配置文件只存占位符
``__keyring__``；load_config 再解析回内存。凭据操作集中在 CredReadW/CredWriteW/
CredDeleteW（advapi32，无第三方依赖），全部经 backend 抽象注入，测试可用
FakeBackend 无污染验证，真实写操作默认不进测试。
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

SERVICE = "LaTeXStruct"
PLACEHOLDER = "__keyring__"
KEY_FIELDS = ("decide_api_key", "review_api_key", "ocr_api_key")


class KeystoreBackend:
    """凭据存储后端接口。可用性取决于平台与权限。"""

    def available(self) -> bool:
        return False

    def get(self, name: str) -> str:
        return ""

    def set(self, name: str, secret: str) -> bool:
        return False

    def delete(self, name: str) -> bool:
        return False


def _target(name: str) -> str:
    return f"{SERVICE}/{name}"


class WindowsCredBackend(KeystoreBackend):
    """Windows 凭据管理器（Generic 类型凭据）。仅 Windows 可用。"""

    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", wintypes.LPBYTE),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    def available(self) -> bool:
        return sys.platform == "win32" and hasattr(ctypes, "windll")

    def _advapi32(self):
        return ctypes.windll.advapi32

    def get(self, name: str) -> str:
        if not self.available():
            return ""
        adv = self._advapi32()
        target = _target(name)
        pcred = ctypes.c_void_p()
        if not adv.CredReadW(target, self.CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
            return ""
        try:
            cred = ctypes.cast(pcred, ctypes.POINTER(self._CREDENTIAL)).contents
            size = cred.CredentialBlobSize
            if not size:
                return ""
            raw = ctypes.string_at(cred.CredentialBlob, size)
            return raw.decode("utf-16-le", errors="ignore")
        finally:
            adv.CredFree(pcred)

    def set(self, name: str, secret: str) -> bool:
        if not self.available():
            return False
        adv = self._advapi32()
        target = _target(name)
        blob = secret.encode("utf-16-le")
        buf = ctypes.create_string_buffer(blob, len(blob))
        cred = self._CREDENTIAL()
        cred.Type = self.CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ctypes.cast(buf, wintypes.LPBYTE)
        cred.Persist = self.CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = ctypes.cast(ctypes.create_unicode_buffer("latexstruct"), wintypes.LPWSTR)
        return bool(adv.CredWriteW(ctypes.byref(cred), 0))

    def delete(self, name: str) -> bool:
        if not self.available():
            return False
        adv = self._advapi32()
        return bool(adv.CredDeleteW(_target(name), self.CRED_TYPE_GENERIC, 0))


class FakeBackend(KeystoreBackend):
    """内存后端：测试与降级环境使用。"""

    def __init__(self, data: dict | None = None, ok: bool = True):
        self.data = dict(data or {})
        self.ok = ok
        self.deleted = []

    def available(self) -> bool:
        return self.ok

    def get(self, name: str) -> str:
        return self.data.get(_target(name), "")

    def set(self, name: str, secret: str) -> bool:
        self.data[_target(name)] = secret
        return True

    def delete(self, name: str) -> bool:
        self.deleted.append(_target(name))
        self.data.pop(_target(name), None)
        return True


def default_backend() -> KeystoreBackend:
    """默认后端：Windows 上走 Credential Manager，否则不可用（回退 config.json）。"""
    wb = WindowsCredBackend()
    return wb if wb.available() else KeystoreBackend()

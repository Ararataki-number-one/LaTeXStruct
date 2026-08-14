# -*- coding: utf-8 -*-
"""项目存储（本地磁盘，单用户，无数据库依赖）。"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Dict, List, Optional

SAFE_NAME_RE = re.compile(r"[^0-9a-zA-Z\u4e00-\u9fff _\-]+")
PID_RE = re.compile(r"^[0-9a-f]{12}$")


def default_data_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "LaTeXStruct")


class ProjectStore:
    def __init__(self, root: Optional[str] = None):
        self.root = root or os.path.join(default_data_dir(), "projects")
        os.makedirs(self.root, exist_ok=True)

    # ---- 基础 CRUD ----

    def create(self, text: str, name: str = "", mode: str = "rule", template: str = "",
               pack: str = "") -> str:
        pid = uuid.uuid4().hex[:12]
        d = self._dir(pid)
        os.makedirs(d, exist_ok=True)
        name = SAFE_NAME_RE.sub("_", name).strip() or "未命名项目"
        meta = {"id": pid, "name": name, "mode": mode, "template": template, "pack": pack,
                "created": time.strftime("%Y-%m-%d %H:%M:%S")}
        self._write_json(d, "meta.json", meta)
        self._write_text(d, "source.tex", text)
        return pid

    def delete(self, pid: str):
        import shutil

        d = self._dir(pid)
        if os.path.isdir(d):
            shutil.rmtree(d)

    def get(self, pid: str) -> Optional[Dict]:
        d = self._dir(pid)
        meta_path = os.path.join(d, "meta.json")
        if not os.path.exists(meta_path):
            return None
        meta = json.loads(self._read(meta_path))
        meta["has_result"] = os.path.exists(os.path.join(d, "result.tex"))
        meta["source_size"] = os.path.getsize(os.path.join(d, "source.tex")) if os.path.exists(
            os.path.join(d, "source.tex")
        ) else 0
        return meta

    def list(self) -> List[Dict]:
        out = []
        for name in sorted(os.listdir(self.root)):
            if not PID_RE.fullmatch(name):
                continue
            p = os.path.join(self.root, name)
            if os.path.isdir(p) and os.path.exists(os.path.join(p, "meta.json")):
                out.append(self.get(name))
        return out

    # ---- 内容读写 ----

    def read_source(self, pid: str) -> str:
        return self._read(os.path.join(self._dir(pid), "source.tex"))

    def read_result(self, pid: str) -> Optional[str]:
        return self._read_optional(os.path.join(self._dir(pid), "result.tex"))

    def read_report(self, pid: str) -> Optional[str]:
        return self._read_optional(os.path.join(self._dir(pid), "report.md"))

    def set_mode(self, pid: str, mode: str):
        meta = json.loads(self._read(os.path.join(self._dir(pid), "meta.json")))
        meta["mode"] = mode
        self._write_json(self._dir(pid), "meta.json", meta)

    def set_result(
        self,
        pid: str,
        result_text: str,
        report_md: str,
        decisions: List[Dict],
        verification: Dict,
    ):
        d = self._dir(pid)
        self._write_text(d, "result.tex", result_text)
        self._write_text(d, "report.md", report_md)
        self._write_json(d, "decisions.json", decisions)
        self._write_json(d, "verification.json", verification)

    def read_decisions(self, pid: str) -> List[Dict]:
        return json.loads(self._read_optional(os.path.join(self._dir(pid), "decisions.json")) or "[]")

    # ---- 内部 ----

    def _dir(self, pid: str) -> str:
        if not PID_RE.fullmatch(str(pid or "")):
            raise ValueError("项目 ID 格式无效")
        return os.path.join(self.root, pid)

    def _read(self, path: str) -> str:
        with open(path, encoding="utf-8") as f:
            return f.read()

    def _read_optional(self, path: str) -> Optional[str]:
        return self._read(path) if os.path.exists(path) else None

    def _write_text(self, d: str, name: str, text: str):
        self._atomic_write(d, name, text, newline="")

    def _write_json(self, d: str, name: str, obj):
        self._atomic_write(d, name, json.dumps(obj, ensure_ascii=False, indent=1))

    def _atomic_write(self, d: str, name: str, text: str, newline=None):
        """同目录临时文件 + os.replace，避免崩溃留下半个 JSON/TeX 文件。"""
        os.makedirs(d, exist_ok=True)
        target = os.path.join(d, name)
        tmp = os.path.join(d, f".{name}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8", newline=newline) as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

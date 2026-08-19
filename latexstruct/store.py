# -*- coding: utf-8 -*-
"""项目存储（本地磁盘，单用户，无数据库依赖）。"""

from __future__ import annotations

import hashlib
import hmac
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

    def create(
        self,
        text: str,
        name: str = "",
        mode: str = "rule",
        template: str = "",
        pack: str = "",
        kind: str = "",
        template_title: str = "",
        original_source: bytes = None,
        source_format: Dict = None,
    ) -> str:
        pid = uuid.uuid4().hex[:12]
        d = self._dir(pid)
        os.makedirs(d, exist_ok=True)
        name = SAFE_NAME_RE.sub("_", name).strip() or "未命名项目"
        meta = {
            "id": pid,
            "name": name,
            "mode": mode,
            "template": template,
            "pack": pack,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if kind:
            meta["kind"] = kind
        if template_title:
            meta["template_title"] = str(template_title).strip()[:160]
        if original_source is not None:
            meta["has_original_source"] = True
            if source_format:
                meta["source_format"] = dict(source_format)
        self._write_json(d, "meta.json", meta)
        self._write_text(d, "source.tex", text)
        if original_source is not None:
            self._atomic_write_bytes(d, "original-source.tex", bytes(original_source))
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

    def record_failed_attempt(
        self,
        pid: str,
        draft_text: str,
        report_md: str,
        details: Dict,
    ):
        """保存仅供诊断的失败草稿，绝不移动或覆盖正式提交标记。"""
        record = {
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "draft_sha256": hashlib.sha256(draft_text.encode("utf-8")).hexdigest(),
            "report_sha256": hashlib.sha256(report_md.encode("utf-8")).hexdigest(),
            "details": dict(details),
        }
        # 先验证 JSON；运行时对象泄漏时不触碰任何现有文件。
        json.dumps(record, ensure_ascii=False, indent=1)
        directory = self._dir(pid)
        self._write_text(directory, "last-failed-draft.tex", draft_text)
        self._write_text(directory, "last-failure-report.md", report_md)
        # 最后写 marker。中途崩溃时旧 marker 的哈希会不匹配，读取端 fail-closed。
        self._write_json(directory, "last-failure.json", record)

    def read_failed_attempt(self, pid: str) -> Optional[Dict]:
        directory = self._dir(pid)
        marker_path = os.path.join(directory, "last-failure.json")
        draft_path = os.path.join(directory, "last-failed-draft.tex")
        report_path = os.path.join(directory, "last-failure-report.md")
        if not all(os.path.exists(path) for path in (marker_path, draft_path, report_path)):
            return None
        try:
            record = json.loads(self._read(marker_path))
            draft = self._read(draft_path)
            report = self._read(report_path)
        except (OSError, ValueError, TypeError):
            return None
        draft_hash = record.get("draft_sha256")
        if not isinstance(draft_hash, str) or not hmac.compare_digest(
            draft_hash,
            hashlib.sha256(draft.encode("utf-8")).hexdigest(),
        ):
            return None
        report_hash = record.get("report_sha256")
        if not isinstance(report_hash, str) or not hmac.compare_digest(
            report_hash,
            hashlib.sha256(report.encode("utf-8")).hexdigest(),
        ):
            return None
        return {**record, "draft": draft, "report": report}

    def set_mode(self, pid: str, mode: str):
        meta = json.loads(self._read(os.path.join(self._dir(pid), "meta.json")))
        meta["mode"] = mode
        self._write_json(self._dir(pid), "meta.json", meta)

    def set_template(self, pid: str, template: str):
        meta = json.loads(self._read(os.path.join(self._dir(pid), "meta.json")))
        meta["template"] = str(template or "")
        self._write_json(self._dir(pid), "meta.json", meta)

    def set_result(
        self,
        pid: str,
        result_text: str,
        report_md: str,
        decisions: List[Dict],
        verification: Dict,
    ):
        committed = dict(verification)
        committed["result_sha256"] = hashlib.sha256(
            result_text.encode("utf-8")
        ).hexdigest()
        committed["report_sha256"] = hashlib.sha256(
            report_md.encode("utf-8")
        ).hexdigest()
        # Validate both JSON documents before moving the previous commit marker
        # or writing any new result files.  A leaked runtime object must leave the
        # entire prior commit byte-for-byte untouched.
        json.dumps(decisions, ensure_ascii=False, indent=1)
        json.dumps(committed, ensure_ascii=False, indent=1)

        d = self._dir(pid)
        marker = os.path.join(d, "verification.json")
        old_marker = os.path.join(d, f".verification.json.{uuid.uuid4().hex}.previous")
        commit_names = ("result.tex", "report.md", "decisions.json", "verification.json")
        # 跨文件没有单个 os.replace 可用。写入前保存上一安全提交的原始 bytes；
        # 任一后续写入失败时恢复 result/report/decisions，最后再恢复 marker。
        # 这样不只是 fail-closed，上一次已验证成果也能 byte-for-byte 继续导出。
        previous = {}
        for name in commit_names:
            path = os.path.join(d, name)
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    previous[name] = handle.read()
        had_marker = os.path.exists(marker)
        if had_marker:
            # verification.json 是整组结果的提交标记。先原子移走旧标记，保证后续任一
            # 文件写入失败时，导出端不会用旧验证结果放行新 result.tex。
            os.replace(marker, old_marker)
        try:
            self._write_text(d, "result.tex", result_text)
            self._write_text(d, "report.md", report_md)
            self._write_json(d, "decisions.json", decisions)
            # 必须最后写：只有该原子 replace 成功，整组结果才可导出。
            self._write_json(d, "verification.json", committed)
        except Exception:
            restored = True
            # marker 必须最后恢复；恢复过程中任何读取者都会 fail-closed。
            if os.path.exists(marker):
                try:
                    os.remove(marker)
                except OSError:
                    restored = False
            for name in commit_names[:-1]:
                path = os.path.join(d, name)
                try:
                    if name in previous:
                        self._atomic_write_bytes(d, name, previous[name])
                    elif os.path.exists(path):
                        os.remove(path)
                except OSError:
                    restored = False
            if restored and had_marker:
                try:
                    if os.path.exists(old_marker):
                        os.replace(old_marker, marker)
                    else:
                        self._atomic_write_bytes(d, "verification.json", previous["verification.json"])
                except OSError:
                    restored = False
            if not restored and os.path.exists(marker):
                try:
                    os.remove(marker)
                except OSError:
                    pass
            if restored and os.path.exists(old_marker):
                try:
                    os.remove(old_marker)
                except OSError:
                    pass
            raise
        else:
            if os.path.exists(old_marker):
                try:
                    os.remove(old_marker)
                except OSError:
                    pass
            for name in (
                "last-failed-draft.tex",
                "last-failure-report.md",
                "last-failure.json",
            ):
                path = os.path.join(d, name)
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        # 正式安全提交已经完成；陈旧诊断记录即使清理失败也绝不参与导出。
                        pass

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

    def _atomic_write_bytes(self, d: str, name: str, data: bytes):
        """原样恢复上一提交；不经过文本解码，保持换行与字节完全一致。"""
        os.makedirs(d, exist_ok=True)
        target = os.path.join(d, name)
        tmp = os.path.join(d, f".{name}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

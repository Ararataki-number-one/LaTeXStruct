# -*- coding: utf-8 -*-
"""通过本机 LaTeXStruct 服务可靠地运行整本书 OCR + AI 分析。

这个工具只编排现有 HTTP API，不包含模型实现，也不会回退到按量计费 API。
它会先确认 Codex 是 ChatGPT 登录态，再把 OCR、分析和审阅统一设为
``codex_cli`` + medium。运行状态和阶段性草稿会原子写入输出目录，进程被
中断后可用 ``resume`` 继续；Ctrl+C 会尽力在当前页面/分析批次边界安全暂停。

示例（先在另一终端运行 ``python -m latexstruct --server``）：

    python tools/run_local_book.py run book.pdf --start-page 3 --end-page 473 --dpi 220
    python tools/run_local_book.py pause output/book-runs/book/run-state.json
    python tools/run_local_book.py resume output/book-runs/book/run-state.json

本文件只依赖 Python 标准库，便于在开发环境和已安装客户端旁直接运行。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


SCHEMA_VERSION = 1
OCR_TERMINAL = {"done", "partial", "error"}
OCR_ACTIVE = {"starting", "running", "pausing", "paused"}
PROCESS_TERMINAL = {"done", "blocked", "error", "cancelled"}
PROCESS_ACTIVE = {"running", "pausing", "paused", "cancelling", "committing"}
SOURCE_ONLY_REPORT = "本次分析尚未产生可校验的结构化草稿"
DEFAULT_ARTIFACT_TIMEOUT = 15 * 60.0
ATOMIC_REPLACE_RETRY_DELAYS = (0.025, 0.05, 0.1, 0.2, 0.4, 0.8, 1.0)


class RunnerError(RuntimeError):
    """可安全展示并持久化的编排错误。"""


class ApiError(RunnerError):
    def __init__(self, status: int, message: str, path: str = ""):
        super().__init__(message)
        self.status = int(status)
        self.path = path


@dataclass(frozen=True)
class ApiResponse:
    body: bytes
    headers: Mapping[str, str]
    status: int = 200

    def json(self) -> dict:
        try:
            value = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError("本机 LaTeXStruct 返回了无法解析的 JSON") from exc
        if not isinstance(value, dict):
            raise RunnerError("本机 LaTeXStruct 返回的 JSON 不是对象")
        return value


def _safe_detail(raw: bytes, fallback: str) -> str:
    try:
        value = json.loads(raw.decode("utf-8", errors="replace"))
        if isinstance(value, dict):
            detail = value.get("detail") or value.get("message")
            if detail:
                return str(detail)[:1000]
    except (TypeError, ValueError):
        pass
    text = raw.decode("utf-8", errors="replace").strip()
    return (text or fallback)[:1000]


class LocalApi:
    """极小的 loopback-only HTTP 客户端，避免给工具增加 requests 依赖。"""

    def __init__(
        self,
        base_url: str,
        timeout: float = 60.0,
        artifact_timeout: float = DEFAULT_ARTIFACT_TIMEOUT,
    ):
        parsed = urlsplit(str(base_url or "").strip())
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RunnerError("--base-url 必须是本机 http://127.0.0.1/localhost 地址")
        self.base_url = str(base_url).rstrip("/")
        self.timeout = max(1.0, float(timeout))
        self.artifact_timeout = max(self.timeout, float(artifact_timeout))

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Optional[dict[str, str]] = None,
        query: Optional[dict[str, Any]] = None,
        retryable: bool = False,
        timeout: Optional[float] = None,
    ) -> ApiResponse:
        if query:
            encoded = urlencode({k: v for k, v in query.items() if v is not None})
            path = f"{path}{'&' if '?' in path else '?'}{encoded}"
        url = f"{self.base_url}{path}"
        attempts = 3 if retryable else 1
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            request = Request(url, data=body, headers=headers or {}, method=method.upper())
            try:
                with urlopen(request, timeout=timeout or self.timeout) as response:
                    return ApiResponse(
                        response.read(),
                        {str(k).lower(): str(v) for k, v in response.headers.items()},
                        int(response.status),
                    )
            except HTTPError as exc:
                raw = exc.read()
                message = _safe_detail(raw, f"HTTP {exc.code}")
                if retryable and exc.code >= 500 and attempt < attempts:
                    last_error = exc
                    time.sleep(min(2.0, 0.4 * attempt))
                    continue
                raise ApiError(exc.code, message, path) from None
            except (URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if retryable and attempt < attempts:
                    time.sleep(min(2.0, 0.4 * attempt))
                    continue
                raise RunnerError(f"无法连接本机 LaTeXStruct：{exc}") from exc
        raise RunnerError(f"本机 LaTeXStruct 请求失败：{last_error}")

    def json(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[dict[str, Any]] = None,
        form: Optional[dict[str, Any]] = None,
        query: Optional[dict[str, Any]] = None,
        retryable: bool = False,
        long_running: bool = False,
    ) -> dict:
        body = None
        headers: dict[str, str] = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urlencode({k: v for k, v in form.items() if v is not None}).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self._request(
            method,
            path,
            body=body,
            headers=headers,
            query=query,
            retryable=retryable,
            timeout=self.artifact_timeout if long_running else None,
        ).json()

    def upload(self, path: str, file_path: Path, field: str = "file") -> dict:
        boundary = f"----LaTeXStruct-{uuid.uuid4().hex}"
        filename = file_path.name.replace('"', "")
        prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            "Content-Type: application/pdf\r\n\r\n"
        ).encode("utf-8")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        body = prefix + file_path.read_bytes() + suffix
        response = self._request(
            "POST",
            path,
            body=body,
            headers={
                "Accept": "application/json",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            # inspect 不触发模型；响应丢失时重传只会留下一个 24h 后清理的 ready job。
            retryable=True,
        )
        return response.json()

    def download(self, path: str, *, long_running: bool = False) -> ApiResponse:
        # OCR 裁图、ZIP 和整项目导出可能数分钟没有响应字节。它们失败后重放会
        # 让服务端从头重复 CPU/内存密集工作，因此长工件由显式 resume 再尝试。
        return self._request(
            "GET",
            path,
            retryable=not long_running,
            timeout=self.artifact_timeout if long_running else None,
        )


def _utc_stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_entry_signature(path: Path) -> tuple[int, int, int, int, int] | None:
    """Return enough metadata to notice a different destination directory entry."""

    try:
        stat = path.lstat()
    except FileNotFoundError:
        return None
    return (stat.st_mode, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    expected_destination = _path_entry_signature(path)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(len(ATOMIC_REPLACE_RETRY_DELAYS) + 1):
            if _path_entry_signature(path) != expected_destination:
                raise RunnerError(
                    f"原子写入等待期间目标文件已被其他进程改动，已拒绝覆盖：{path}"
                )
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt >= len(ATOMIC_REPLACE_RETRY_DELAYS):
                    raise
                time.sleep(ATOMIC_REPLACE_RETRY_DELAYS[attempt])
    finally:
        if temporary.exists():
            temporary.unlink()


class StateStore:
    """原子状态/工件保存；每个网络阶段后都可独立恢复或诊断。"""

    def __init__(self, state_path: Path):
        self.path = state_path.resolve()
        self.output_dir = self.path.parent
        self.state: dict[str, Any] = {}

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError(f"无法读取续跑状态文件：{self.path}") from exc
        if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
            raise RunnerError("续跑状态文件版本不受支持")
        self.state = value
        return value

    def initialize(self, source: Path, options: dict[str, Any], base_url: str) -> dict[str, Any]:
        source = source.resolve(strict=True)
        self.state = {
            "schema_version": SCHEMA_VERSION,
            "run_id": uuid.uuid4().hex,
            "created_at": _utc_stamp(),
            "updated_at": _utc_stamp(),
            "phase": "created",
            "active_stage": "",
            "base_url": base_url,
            "source": {
                "path": str(source),
                "name": source.name,
                "bytes": source.stat().st_size,
                "sha256": _sha256_path(source),
            },
            "options": options,
            "ocr": {"retry_rounds": 0},
            "analysis": {},
            "artifacts": {},
            "diagnostics": [],
        }
        self.note("created", "已创建可恢复运行状态")
        return self.state

    def save(self) -> None:
        self.state["updated_at"] = _utc_stamp()
        payload = json.dumps(self.state, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        _atomic_write(self.path, payload)

    def note(self, kind: str, message: str, **data: Any) -> None:
        events = self.state.setdefault("diagnostics", [])
        event: dict[str, Any] = {"at": _utc_stamp(), "kind": kind, "message": message[:1000]}
        if data:
            event["data"] = data
        events.append(event)
        del events[:-200]
        self.save()

    def phase(self, phase: str, active_stage: Optional[str] = None) -> None:
        self.state["phase"] = phase
        if active_stage is not None:
            self.state["active_stage"] = active_stage
        self.save()

    def artifact(self, name: str, data: bytes) -> Path:
        if Path(name).name != name:
            raise RunnerError("工件名称无效")
        path = self.output_dir / name
        _atomic_write(path, data)
        self.state.setdefault("artifacts", {})[name] = {
            "path": str(path.resolve()),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "updated_at": _utc_stamp(),
        }
        self.save()
        return path


class BookRunner:
    def __init__(
        self,
        api: Any,
        store: StateStore,
        *,
        poll_seconds: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.api = api
        self.store = store
        self.poll_seconds = max(0.05, float(poll_seconds))
        self.sleep = sleep

    @property
    def state(self) -> dict[str, Any]:
        return self.store.state

    def _configure_codex(self) -> None:
        self.store.phase("codex_preflight")
        status = self.api.json("GET", "/api/codex/status", retryable=True)
        self.state["codex_status"] = status
        self.store.save()
        if status.get("ready") is not True:
            action = str(status.get("action") or "请先用 ChatGPT 登录 Codex CLI")
            raise RunnerError(f"Codex 尚未就绪：{status.get('message', '状态未知')}；{action}")
        options = self.state["options"]
        payload = {
            "analysis_backend": "codex_cli",
            "codex_reasoning_effort": options.get("reasoning_effort", "medium"),
            "codex_model": options.get("codex_model", ""),
        }
        config = self.api.json("PUT", "/api/config", payload=payload, retryable=True)
        if config.get("analysis_backend") != "codex_cli":
            raise RunnerError("LaTeXStruct 未接受 codex_cli 后端设置")
        if config.get("codex_reasoning_effort") != payload["codex_reasoning_effort"]:
            raise RunnerError("LaTeXStruct 未接受指定的 Codex 推理强度")
        self.state["applied_config"] = {
            "analysis_backend": "codex_cli",
            "codex_model": config.get("codex_model", ""),
            "codex_reasoning_effort": config.get("codex_reasoning_effort"),
        }
        self.store.note("codex_ready", "Codex ChatGPT 登录态与统一后端设置已确认")

    def _source_path(self) -> Path:
        path = Path(str(self.state.get("source", {}).get("path") or ""))
        if not path.is_file():
            raise RunnerError(f"原 PDF 不存在，无法重新上传：{path}")
        expected = str(self.state["source"].get("sha256") or "")
        actual = _sha256_path(path)
        if not expected or actual != expected:
            raise RunnerError("原 PDF 自上次运行后已改变；为避免页码错位，拒绝续跑")
        return path

    def _start_ocr(self) -> None:
        source = self._source_path()
        self.store.phase("ocr_uploading", "ocr")
        inspected = self.api.upload("/api/ocr/inspect", source)
        jid = str(inspected.get("id") or "")
        if not jid:
            raise RunnerError("OCR inspect 未返回任务编号")
        self.state["ocr"].update({
            "job_id": jid,
            "inspection": inspected,
            "retry_rounds": 0,
        })
        self.store.note("ocr_inspected", "PDF 已上传并读取页数", job_id=jid)
        options = self.state["options"]
        started = self.api.json(
            "POST",
            f"/api/ocr/jobs/{jid}/start",
            form={
                "start_page": options.get("start_page"),
                "end_page": options.get("end_page"),
                "dpi": options.get("dpi", 220),
                # 整书编排器以出版审校为目标：在付费调用前冻结严格页级门
                # 和成品模板，避免 GUI/全局设置在长任务中途改变结果语义。
                "quality_profile": "publication",
                "output_template": "faithfulbook",
                # Codex 模式冻结全局配置，不传任何 API Key/付费端点。
                "base_url": "",
                "model": "",
                "api_key": "",
            },
            retryable=True,
        )
        self.state["ocr"]["start_response"] = started
        self.store.phase("ocr_running", "ocr")

    def _snapshot_ocr_preview(self, status: dict[str, Any]) -> None:
        revision = int(status.get("raw_revision") or 0)
        if revision <= int(self.state["ocr"].get("saved_preview_revision") or 0):
            return
        jid = self.state["ocr"]["job_id"]
        response = self.api.download(f"/api/ocr/jobs/{jid}/preview")
        self.store.artifact("ocr-preview.tex", response.body)
        self.state["ocr"]["saved_preview_revision"] = revision
        self.store.save()

    def _wait_ocr(self, auto_resume: bool) -> dict[str, Any]:
        jid = str(self.state["ocr"].get("job_id") or "")
        if not jid:
            raise RunnerError("续跑状态中缺少 OCR 任务编号")
        retries = int(self.state["options"].get("ocr_retries", 2))
        previous_marker: tuple[Any, ...] | None = None
        while True:
            status = self.api.json("GET", f"/api/ocr/jobs/{jid}", retryable=True)
            self.state["ocr"]["last_status"] = status
            self.store.save()
            self._snapshot_ocr_preview(status)
            marker = (
                status.get("status"), status.get("done"), status.get("total"),
                status.get("page"), status.get("phase"), status.get("state_revision"),
            )
            if marker != previous_marker:
                self.store.note(
                    "ocr_status",
                    str(status.get("phase") or status.get("status") or "OCR 状态更新"),
                    status=status.get("status"),
                    done=status.get("done"),
                    total=status.get("total"),
                    page=status.get("page"),
                )
                previous_marker = marker
            current = str(status.get("status") or "")
            if current in {"paused", "pausing"}:
                if auto_resume:
                    self.api.json("POST", f"/api/ocr/jobs/{jid}/resume", retryable=True)
                    auto_resume = False
                    self.store.note("ocr_resumed", "已继续安全暂停的 OCR 任务")
                else:
                    self.store.phase("paused", "ocr")
                    raise RunnerError("OCR 已安全暂停；使用 resume 子命令继续")
            elif current == "done":
                self.store.phase("ocr_done", "")
                return status
            elif current in {"partial", "error"}:
                rounds = int(self.state["ocr"].get("retry_rounds") or 0)
                failed = list(status.get("errors") or [])
                if failed and rounds < retries:
                    self.state["ocr"]["retry_rounds"] = rounds + 1
                    self.store.note(
                        "ocr_retry",
                        f"开始第 {rounds + 1}/{retries} 轮失败页批量重试",
                        failed_pages=[item.get("page") for item in failed if isinstance(item, dict)],
                    )
                    self.api.json(
                        # 批量重试会消费模型额度；响应丢失时由下一轮 GET 判断，
                        # 不能像 start/import 那样盲目重放 POST。
                        "POST", f"/api/ocr/jobs/{jid}/retry-failed"
                    )
                    self.sleep(self.poll_seconds)
                    continue
                self._save_ocr_artifacts(allow_partial=True)
                raise RunnerError(
                    f"OCR 仍有 {len(failed)} 个失败页面；已保存部分工程与诊断，未进入分析"
                )
            elif current not in OCR_ACTIVE:
                raise RunnerError(f"未知 OCR 状态：{current or '空'}")
            self.sleep(self.poll_seconds)

    def _save_ocr_artifacts(self, allow_partial: bool = False) -> None:
        jid = str(self.state["ocr"].get("job_id") or "")
        if not jid:
            return
        errors: list[str] = []
        for endpoint, name, long_running in (
            (f"/api/ocr/jobs/{jid}/result", "ocr-result.tex", False),
            (f"/api/ocr/jobs/{jid}/package", "ocr-project.zip", True),
        ):
            try:
                response = self.api.download(endpoint, long_running=long_running)
                self.store.artifact(name, response.body)
                if name == "ocr-project.zip":
                    self._record_ocr_resource_diagnostics(response.body)
            except ApiError as exc:
                errors.append(f"{name}: HTTP {exc.status} {exc}")
            except RunnerError as exc:
                errors.append(f"{name}: {exc}")
        try:
            saved = self.api.json(
                "POST",
                f"/api/ocr/jobs/{jid}/save",
                long_running=True,
            )
            self.state["ocr"]["app_saved"] = saved
            self.store.save()
        except RunnerError as exc:
            # 工作区内的 OCR ZIP 已是完整留档；客户端“下载”目录副本失败不应丢失成果。
            errors.append(f"客户端下载副本: {exc}")
        if errors:
            self.store.note("ocr_save_warning", "；".join(errors))
            if not allow_partial and "ocr-project.zip" not in self.state.get("artifacts", {}):
                raise RunnerError("OCR 工程包未能保存")
        else:
            self.store.note("ocr_saved", "OCR TEX、图片工程包与客户端副本均已保存")

    def _record_ocr_resource_diagnostics(self, package: bytes) -> None:
        """Best-effort read of the bounded manifest; never replaces server validation."""
        try:
            with zipfile.ZipFile(io.BytesIO(package)) as archive:
                manifest = json.loads(archive.read("OCR-MANIFEST.json").decode("utf-8"))
            resources = manifest.get("resources") or {}
            total = int(resources.get("total_bytes") or 0)
            unresolved = [str(item) for item in (resources.get("unresolved") or [])]
            assets = len(resources.get("assets") or [])
            self.state["ocr"]["resource_summary"] = {
                "assets": assets,
                "bytes": total,
                "unresolved": len(unresolved),
            }
            self.store.save()
            if unresolved:
                self.store.note(
                    "ocr_resource_blocked",
                    f"OCR 工程仍有 {len(unresolved)} 个未解析图片；分析导入将保持关闭",
                    examples=unresolved[:10],
                )
            elif total >= 90 * 1024 * 1024:
                self.store.note(
                    "ocr_resource_near_limit",
                    f"OCR 图片资源已达 {total / (1024 * 1024):.1f} MB，接近 100 MB 上限",
                    assets=assets,
                )
            else:
                self.store.note(
                    "ocr_resources_verified",
                    f"OCR 工程清单包含 {assets} 个图片资源，共 {total / (1024 * 1024):.1f} MB",
                )
        except (KeyError, OSError, UnicodeDecodeError, ValueError, zipfile.BadZipFile):
            # 兼容旧服务/测试桩；导入端仍会执行强制资源完整性门。
            self.store.note("ocr_resource_manifest_unavailable", "OCR ZIP 未提供可读资源清单")

    def _import_project(self) -> None:
        jid = str(self.state["ocr"].get("job_id") or "")
        options = self.state["options"]
        source_name = Path(self.state["source"]["name"]).stem
        imported = self.api.json(
            "POST",
            f"/api/ocr/jobs/{jid}/import",
            query={
                "name": options.get("name") or f"{source_name}-AI排版",
                "mode": "ai",
                "template": "faithfulbook",
                "title": options.get("title") or source_name,
            },
            # 导入会同步裁切全部图片；超时后的 POST 结果具有歧义，留给 resume
            # 通过服务端 revision 幂等键恢复，不能在同一请求中盲目重放。
            long_running=True,
        )
        pid = str(imported.get("id") or "")
        if not pid:
            raise RunnerError("OCR 导入未返回项目编号")
        self.state["project_id"] = pid
        self.state["analysis"]["import_response"] = imported
        self.store.note(
            "analysis_imported",
            "OCR 工程已带裁切图片导入 AI + faithfulbook",
            project_id=pid,
        )
        self.store.phase("analysis_running", "analysis")

    def _snapshot_analysis_preview(self, status: dict[str, Any]) -> None:
        revision = int(status.get("preview_revision") or 0)
        if revision <= int(self.state["analysis"].get("saved_preview_revision") or 0):
            return
        pid = self.state["project_id"]
        response = self.api.download(f"/api/projects/{pid}/process/preview")
        self.store.artifact("analysis-preview.tex", response.body)
        self.state["analysis"]["saved_preview_revision"] = revision
        self.store.save()

    def _recover_or_restart_idle_analysis(self) -> Optional[dict[str, Any]]:
        """服务重启会丢失内存任务；优先识别已落盘结果，避免重复模型费用。"""
        pid = self.state["project_id"]
        try:
            report = self.api.download(f"/api/projects/{pid}/export-current-report")
            text = report.body.decode("utf-8", errors="replace")
            verified = report.headers.get("x-latexstruct-verified", "").lower() == "true"
            if verified or SOURCE_ONLY_REPORT not in text:
                self.store.note(
                    "analysis_recovered",
                    "服务内存任务已消失，但发现已落盘的分析结果，将直接导出",
                    verified=verified,
                )
                return {"status": "done" if verified else "blocked", "recovered": True}
        except RunnerError as exc:
            self.store.note("analysis_recovery_probe", f"未发现可恢复分析结果：{exc}")
        # 只有确认没有已落盘草稿、必须重新消费模型额度时才重新探测登录并
        # 冻结配置。这样进程若恰好在提交后、导出前中断，即使随后离线也仍
        # 能先把已经完成的成果取回。
        self._configure_codex()
        started = self.api.json(
            "POST", f"/api/projects/{pid}/process/start", retryable=True
        )
        self.state["analysis"]["restart_response"] = started
        self.store.note("analysis_restarted", "服务重启后重新启动尚未落盘的分析任务")
        self.store.phase("analysis_running", "analysis")
        return None

    def _wait_analysis(self, auto_resume: bool) -> dict[str, Any]:
        pid = str(self.state.get("project_id") or "")
        if not pid:
            raise RunnerError("续跑状态中缺少分析项目编号")
        previous_marker: tuple[Any, ...] | None = None
        while True:
            status = self.api.json(
                "GET", f"/api/projects/{pid}/process/status", retryable=True
            )
            self.state["analysis"]["last_status"] = status
            self.store.save()
            self._snapshot_analysis_preview(status)
            marker = (
                status.get("status"), status.get("phase"), status.get("progress"),
                status.get("preview_revision"), status.get("message"),
            )
            if marker != previous_marker:
                self.store.note(
                    "analysis_status",
                    str(status.get("message") or status.get("phase_label") or "分析状态更新"),
                    status=status.get("status"),
                    phase=status.get("phase"),
                    progress=status.get("progress"),
                )
                previous_marker = marker
            current = str(status.get("status") or "")
            if current == "idle":
                recovered = self._recover_or_restart_idle_analysis()
                if recovered is not None:
                    status = recovered
                    current = str(recovered["status"])
                else:
                    self.sleep(self.poll_seconds)
                    continue
            if current in {"paused", "pausing"}:
                if auto_resume:
                    self.api.json(
                        "POST", f"/api/projects/{pid}/process/resume", retryable=True
                    )
                    auto_resume = False
                    self.store.note("analysis_resumed", "已继续安全暂停的分析任务")
                else:
                    self.store.phase("paused", "analysis")
                    raise RunnerError("分析已安全暂停；使用 resume 子命令继续")
            elif current in PROCESS_TERMINAL:
                self.state["analysis"]["terminal_status"] = status
                self.store.phase("analysis_terminal", "")
                return status
            elif current not in PROCESS_ACTIVE:
                raise RunnerError(f"未知分析状态：{current or '空'}")
            self.sleep(self.poll_seconds)

    def _export_current(self) -> bool:
        pid = str(self.state.get("project_id") or "")
        required_errors: list[str] = []
        verified_values: list[bool] = []
        exports = (
            (f"/api/projects/{pid}/export-current-package", "current-project.zip", True),
            (f"/api/projects/{pid}/export-current-report", "analysis-report.md", True),
            (f"/api/projects/{pid}/export-current", "current.tex", False),
        )
        for endpoint, name, required in exports:
            try:
                response = self.api.download(endpoint, long_running=name.endswith(".zip"))
                self.store.artifact(name, response.body)
                header = response.headers.get("x-latexstruct-verified", "").lower()
                if header in {"true", "false"}:
                    verified_values.append(header == "true")
            except RunnerError as exc:
                self.store.note("export_error", f"{name} 导出失败：{exc}")
                if required:
                    required_errors.append(f"{name}: {exc}")
        if required_errors:
            raise RunnerError("当前包/报告没有全部导出：" + "；".join(required_errors))
        verified = bool(verified_values) and all(verified_values)
        self.state["verified"] = verified
        self.store.note(
            "exports_saved",
            "已导出当前工程包、报告和 TEX" + ("（验证通过）" if verified else "（未验证标记）"),
        )
        return verified

    def execute(self, *, auto_resume: bool = False) -> dict[str, Any]:
        """运行或续跑；即使分析 blocked/error，也会先导出 current 包和报告。"""
        if self.state.get("phase") == "complete":
            return self.state
        if not self.state.get("project_id"):
            self._configure_codex()
            jid = str(self.state.get("ocr", {}).get("job_id") or "")
            if jid:
                try:
                    current = self.api.json("GET", f"/api/ocr/jobs/{jid}", retryable=True)
                    self.state["ocr"]["last_status"] = current
                    self.store.save()
                except ApiError as exc:
                    if exc.status != 404:
                        raise
                    self.store.note(
                        "ocr_job_lost",
                        "服务重启后 OCR 内存任务已不存在；显式续跑将从原 PDF 重新开始",
                    )
                    self.state["ocr"] = {"retry_rounds": 0}
                    jid = ""
            if not jid:
                self._start_ocr()
            status = str(self.state["ocr"].get("last_status", {}).get("status") or "")
            if status != "done" or "ocr-project.zip" not in self.state.get("artifacts", {}):
                self._wait_ocr(auto_resume=auto_resume)
                self._save_ocr_artifacts()
            self._import_project()
        self.store.phase("analysis_running", "analysis")
        terminal = self.state.get("analysis", {}).get("terminal_status")
        if not isinstance(terminal, dict) or terminal.get("status") not in PROCESS_TERMINAL:
            terminal = self._wait_analysis(auto_resume=auto_resume)
        verified = self._export_current()
        terminal_status = str(terminal.get("status") or "")
        outcome = "verified" if verified else "unverified"
        self.state["outcome"] = outcome
        self.state["process_status"] = terminal_status
        self.store.phase("complete", "")
        self.store.note(
            "complete",
            f"端到端运行完成：analysis={terminal_status or 'unknown'}, export={outcome}",
        )
        return self.state

    def pause_active(self, timeout: float = 60.0) -> dict[str, Any]:
        stage = str(self.state.get("active_stage") or "")
        if stage == "ocr":
            jid = str(self.state.get("ocr", {}).get("job_id") or "")
            if not jid:
                raise RunnerError("状态文件中没有活动 OCR 任务")
            path = f"/api/ocr/jobs/{jid}"
            pause_path = f"{path}/pause"
        elif stage == "analysis":
            pid = str(self.state.get("project_id") or "")
            if not pid:
                raise RunnerError("状态文件中没有活动分析项目")
            path = f"/api/projects/{pid}/process/status"
            pause_path = f"/api/projects/{pid}/process/pause"
        else:
            self.store.note("pause_noop", "当前没有可暂停的 OCR/分析任务")
            return self.state
        status = self.api.json("GET", path, retryable=True)
        current = str(status.get("status") or "")
        terminal = OCR_TERMINAL if stage == "ocr" else PROCESS_TERMINAL | {"idle"}
        if current in terminal:
            self.store.note("pause_noop", f"{stage} 已是终态 {current}")
            return self.state
        self.api.json("POST", pause_path, retryable=True)
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            status = self.api.json("GET", path, retryable=True)
            current = str(status.get("status") or "")
            if current == "paused" or current in terminal:
                break
            self.sleep(min(self.poll_seconds, 1.0))
        self.state.setdefault(stage, {})["last_status"] = status
        if current == "paused":
            self.store.phase("paused", stage)
            self.store.note("paused", f"{stage} 已在安全边界暂停")
        else:
            self.store.note("pause_timeout", f"等待 {stage} 安全暂停超时", status=current)
        return self.state

    def refresh_status(self) -> dict[str, Any]:
        stage = str(self.state.get("active_stage") or "")
        if stage == "ocr" and self.state.get("ocr", {}).get("job_id"):
            jid = self.state["ocr"]["job_id"]
            status = self.api.json("GET", f"/api/ocr/jobs/{jid}", retryable=True)
            self.state["ocr"]["last_status"] = status
        elif self.state.get("project_id"):
            pid = self.state["project_id"]
            status = self.api.json(
                "GET", f"/api/projects/{pid}/process/status", retryable=True
            )
            self.state["analysis"]["last_status"] = status
        else:
            status = {"status": "not_started"}
        self.store.save()
        return status


def _slug(value: str) -> str:
    clean = re.sub(r"[^0-9A-Za-z._-]+", "-", value).strip("-.")
    return clean[:80] or "book"


def _default_state(pdf: Path) -> Path:
    return Path.cwd() / "output" / "book-runs" / _slug(pdf.stem) / "run-state.json"


def _add_connection_args(parser: argparse.ArgumentParser, stored_default: bool = False) -> None:
    parser.add_argument(
        "--base-url",
        default=None if stored_default else os.environ.get("LATEXSTRUCT_URL", "http://127.0.0.1:8080"),
        help="本机 LaTeXStruct 服务地址",
    )
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="轮询间隔（秒）")
    parser.add_argument("--http-timeout", type=float, default=60.0, help="单次 HTTP 超时（秒）")
    parser.add_argument(
        "--artifact-timeout",
        type=float,
        default=DEFAULT_ARTIFACT_TIMEOUT,
        help="同步裁图/ZIP/整项目导出的单次超时（秒，默认 900）",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="创建并运行新的 OCR + AI 书籍任务")
    run.add_argument("pdf", type=Path)
    run.add_argument("--start-page", type=int, default=1)
    run.add_argument("--end-page", type=int)
    run.add_argument("--dpi", type=int, default=220, help="出版审校渲染 DPI（200-300）")
    run.add_argument("--ocr-retries", type=int, default=2)
    run.add_argument("--reasoning-effort", choices=("low", "medium"), default="medium")
    run.add_argument("--codex-model", default="", help="留空使用 Codex 默认模型")
    run.add_argument("--name", default="")
    run.add_argument("--title", default="")
    run.add_argument("--state", type=Path, help="状态文件（默认在 output/book-runs 下）")
    _add_connection_args(run)

    for command, help_text in (
        ("resume", "从原子状态文件继续任务"),
        ("pause", "请求活动任务在安全边界暂停"),
        ("status", "刷新并显示任务状态"),
    ):
        child = sub.add_parser(command, help=help_text)
        child.add_argument("state", type=Path)
        _add_connection_args(child, stored_default=True)
    return parser


def _open_existing(args: argparse.Namespace) -> tuple[StateStore, LocalApi, BookRunner]:
    store = StateStore(args.state)
    state = store.load()
    base_url = args.base_url or str(state.get("base_url") or "http://127.0.0.1:8080")
    if args.base_url and args.base_url != state.get("base_url"):
        state["base_url"] = args.base_url
        store.note("base_url_changed", "续跑时更新了本机服务地址", base_url=args.base_url)
    api = LocalApi(
        base_url,
        timeout=args.http_timeout,
        artifact_timeout=args.artifact_timeout,
    )
    runner = BookRunner(api, store, poll_seconds=args.poll_seconds)
    return store, api, runner


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            pdf = args.pdf.resolve(strict=True)
            if pdf.suffix.lower() != ".pdf":
                raise RunnerError("run 当前只接受 PDF")
            if not 200 <= args.dpi <= 300:
                raise RunnerError("整书出版审校的 DPI 必须在 200-300 之间")
            if args.start_page < 1 or (args.end_page is not None and args.end_page < args.start_page):
                raise RunnerError("页码范围无效")
            state_path = (args.state or _default_state(pdf)).resolve()
            store = StateStore(state_path)
            if store.exists():
                raise RunnerError(f"状态文件已存在；请使用 resume：{state_path}")
            options = {
                "start_page": args.start_page,
                "end_page": args.end_page,
                "dpi": args.dpi,
                "ocr_retries": max(0, args.ocr_retries),
                "reasoning_effort": args.reasoning_effort,
                "codex_model": args.codex_model.strip(),
                "name": args.name.strip(),
                "title": args.title.strip(),
            }
            store.initialize(pdf, options, args.base_url)
            runner = BookRunner(
                LocalApi(
                    args.base_url,
                    timeout=args.http_timeout,
                    artifact_timeout=args.artifact_timeout,
                ),
                store,
                poll_seconds=args.poll_seconds,
            )
            auto_resume = False
        else:
            store, _api, runner = _open_existing(args)
            if args.command == "pause":
                result = runner.pause_active()
                print(json.dumps({
                    "phase": result.get("phase"),
                    "state": str(store.path),
                }, ensure_ascii=False, indent=2))
                return 0
            if args.command == "status":
                print(json.dumps(runner.refresh_status(), ensure_ascii=False, indent=2))
                return 0
            auto_resume = True
        try:
            result = runner.execute(auto_resume=auto_resume)
        except KeyboardInterrupt:
            print("\n收到中断，正在请求安全暂停……", file=sys.stderr, flush=True)
            try:
                runner.pause_active()
            except RunnerError as pause_exc:
                store.note("interrupt_pause_error", str(pause_exc))
            print(f"状态已保存在：{store.path}", file=sys.stderr)
            return 130
        print(json.dumps({
            "outcome": result.get("outcome"),
            "process_status": result.get("process_status"),
            "verified": result.get("verified"),
            "state": str(store.path),
            "output_dir": str(store.output_dir),
        }, ensure_ascii=False, indent=2))
        return 0 if result.get("verified") else 2
    except (RunnerError, OSError) as exc:
        store_obj = locals().get("store")
        if isinstance(store_obj, StateStore) and store_obj.state:
            if store_obj.state.get("phase") != "paused":
                store_obj.state["failed_phase"] = store_obj.state.get("phase")
                store_obj.state["phase"] = "failed"
            store_obj.state["last_error"] = str(exc)
            store_obj.note("error", str(exc))
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# -*- coding: utf-8 -*-
"""FastAPI 本地服务（127.0.0.1）。"""

from __future__ import annotations

import difflib
import base64
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import AppConfig, load_config, save_config
from ..core.pipeline import run_pipeline
from ..providers import list_provider_presets
from ..store import ProjectStore

STATIC_DIR = Path(__file__).parent / "static"

_store: Optional[ProjectStore] = None
_config: Optional[AppConfig] = None
_ocr_jobs: Dict[str, dict] = {}

MAX_FOLDER_FILES = 1000
MAX_FOLDER_FILE_BYTES = 25 * 1024 * 1024
MAX_FOLDER_TOTAL_BYTES = 100 * 1024 * 1024
MAX_OCR_UPLOAD_BYTES = 100 * 1024 * 1024
OCR_JOB_TTL_SECONDS = 24 * 60 * 60


def _decode_folder_files(raw_files: dict) -> Dict[str, bytes]:
    """校验浏览器文件夹载荷，兼容旧版纯文本值与新版 Base64 二进制值。"""
    from ..core.project import safe_project_relpath

    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("未收到项目文件")
    if len(raw_files) > MAX_FOLDER_FILES:
        raise ValueError(f"项目文件过多（最多 {MAX_FOLDER_FILES} 个）")
    out: Dict[str, bytes] = {}
    total = 0
    for raw_rel, value in raw_files.items():
        rel = safe_project_relpath(raw_rel)
        if rel in out:
            raise ValueError(f"项目中存在重复路径：{rel}")
        if isinstance(value, str):
            data = value.encode("utf-8")
        elif isinstance(value, dict) and value.get("encoding") == "base64":
            encoded = value.get("data")
            if not isinstance(encoded, str):
                raise ValueError(f"文件内容格式无效：{rel}")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError):
                raise ValueError(f"文件 Base64 内容损坏：{rel}") from None
        else:
            raise ValueError(f"文件内容格式不受支持：{rel}")
        if len(data) > MAX_FOLDER_FILE_BYTES:
            raise ValueError(f"单个文件过大（上限 25 MB）：{rel}")
        total += len(data)
        if total > MAX_FOLDER_TOTAL_BYTES:
            raise ValueError("项目总大小超过 100 MB，请精简后重试")
        out[rel] = data
    return out


def _cleanup_ocr_jobs(now: float = None):
    """清理已结束且超过 24 小时的 OCR 临时页；运行中的任务绝不触碰。"""
    now = now or time.time()
    for jid, job in list(_ocr_jobs.items()):
        if job.get("status") == "running" or now - job.get("created", now) < OCR_JOB_TTL_SECONDS:
            continue
        tmpdir = job.get("dir")
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        _ocr_jobs.pop(jid, None)


def _decision_dict(decision) -> dict:
    return {
        "candidate_id": decision.candidate_id,
        "action": decision.action,
        "env": decision.env,
        "title_span": list(decision.title_span) if decision.title_span else None,
        "body_span": list(decision.body_span) if decision.body_span else None,
        "optional_arg": decision.optional_arg,
        "keep_title_text": decision.keep_title_text,
        "source": decision.source,
        "reason": decision.reason,
        "confidence": decision.confidence,
        "payload": decision.payload,
    }


def _decision_from_dict(data: dict):
    from ..core.patch import Decision

    return Decision(
        candidate_id=str(data.get("candidate_id", "")),
        action=str(data.get("action", "none")),
        env=str(data.get("env", "")),
        title_span=tuple(data["title_span"]) if data.get("title_span") else None,
        body_span=tuple(data["body_span"]) if data.get("body_span") else None,
        optional_arg=str(data.get("optional_arg", "")),
        keep_title_text=bool(data.get("keep_title_text", True)),
        source=str(data.get("source", "rule")),
        reason=str(data.get("reason", "")),
        confidence=float(data.get("confidence", 0.0)),
        payload=dict(data.get("payload") or {}),
    )


def get_store() -> ProjectStore:
    global _store
    if _store is None:
        _store = ProjectStore()
    return _store


def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config


class CreateRequest(BaseModel):
    text: str = ""
    name: str = ""
    mode: str = "rule"
    template: str = ""
    pack: str = ""


class FolderRequest(BaseModel):
    files: dict  # {相对路径: 内容}
    name: str = ""
    mode: str = "rule"
    template: str = ""
    pack: str = ""


class BatchRejectRequest(BaseModel):
    cids: list = Field(default_factory=list)


class ConfigRequest(BaseModel):
    decide_base_url: Optional[str] = None
    decide_model: Optional[str] = None
    decide_api_key: Optional[str] = None
    review_base_url: Optional[str] = None
    review_model: Optional[str] = None
    review_api_key: Optional[str] = None
    review_enabled: Optional[bool] = None
    ocr_base_url: Optional[str] = None
    ocr_model: Optional[str] = None
    ocr_api_key: Optional[str] = None
    keyring: Optional[bool] = None


def create_app() -> FastAPI:
    app = FastAPI(title="LaTeXStruct", docs_url="/api/docs")

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, exc: ValueError):
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc) or "输入内容无效", "action": "请检查输入后重试"},
        )

    @app.exception_handler(OSError)
    async def os_error(_request: Request, _exc: OSError):
        return JSONResponse(
            status_code=500,
            content={
                "detail": "无法读写本地文件；原文件未被覆盖",
                "action": "请检查磁盘空间、文件权限或是否被其他程序占用后重试",
            },
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_request: Request, _exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "detail": "操作未完成，已保留原始内容",
                "action": "请重试；若仍失败，请在汇报中查看安全检查并报告问题",
            },
        )

    @app.get("/api/health")
    def health():
        from .. import __version__

        return {"ok": True, "version": __version__}

    @app.get("/api/rulesets")
    def rulesets():
        from ..core.ruleset import list_builtin_packs

        return {"packs": list_builtin_packs(), "default": "bilingual"}

    @app.get("/api/providers")
    def providers():
        """只返回公开预设；此接口永远不包含 API Key。"""
        return {"providers": list_provider_presets()}

    @app.get("/api/update/check")
    def update_check():
        from .. import UPDATE_REPO, __version__
        from ..updater import check_for_updates

        info = check_for_updates(UPDATE_REPO, __version__)
        return {
            "current": __version__,
            "available": info.available,
            "latest": info.latest,
            "url": info.url,
            "notes": info.notes,
            "size": info.size,
            "error": info.error,
        }

    @app.post("/api/update/install")
    def update_install():
        from .. import UPDATE_REPO, __version__
        from ..updater import check_for_updates, download_and_install

        info = check_for_updates(UPDATE_REPO, __version__)
        if not info.available or not info.url:
            return {"ok": False, "error": info.error or "无可用更新"}
        dest = download_and_install(info)
        return {"ok": True, "installer": dest, "note": "安装器已启动，安装完成后应用将自动重启"}

    @app.get("/api/projects")
    def list_projects():
        return get_store().list()

    @app.post("/api/projects")
    def create_project(req: CreateRequest):
        if not req.text.strip():
            raise HTTPException(400, "内容为空")
        pid = get_store().create(req.text, req.name, req.mode, req.template, req.pack)
        return {"id": pid}

    @app.post("/api/projects/folder")
    def import_folder(req: FolderRequest):
        """文件夹导入：写入临时目录 → 多文件项目处理 → 返回项目与依赖图。"""
        from ..core.project import discover_main, process_project

        files = _decode_folder_files(req.files)
        tmpdir = tempfile.mkdtemp(prefix="ls-folder-")
        pid = None
        try:
            for rel, content in files.items():
                p = Path(tmpdir) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)
            main_rel = discover_main(Path(tmpdir))
            if main_rel is None:
                raise ValueError("文件夹中未找到 .tex 主文件")
            cfg = get_config()
            mode = req.mode or "rule"
            res = process_project(Path(tmpdir), mode=mode, template=req.template or None,
                                  ai_config=cfg.to_ai_config() if mode == "ai" else None,
                                  pack=req.pack or None)
            pr = res.pipeline
            # 项目源 = 展开文本（供 diff/决策审阅），原始文件另存本地 zip，导出时
            # 覆盖改动过的 .tex；图片/bib/sty 等二进制资源保持逐字节不变。
            pid = get_store().create(
                res.flattened, req.name, mode, req.template or "", req.pack or ""
            )
            project_dir = Path(get_store()._dir(pid))
            meta = json.loads((project_dir / "meta.json").read_text(encoding="utf-8"))
            meta["kind"] = "folder"
            meta["original_file_count"] = len(files)
            meta["graph"] = {
                "main_rel": res.graph.main_rel,
                "files": res.graph.files,
                "missing": res.graph.missing,
                "cycles": res.graph.cycles,
            }
            get_store()._write_json(str(project_dir), "meta.json", meta)
            import zipfile

            with zipfile.ZipFile(project_dir / "original-files.zip", "w", zipfile.ZIP_DEFLATED) as zf:
                for rel, content in files.items():
                    zf.writestr(rel, content)
            decisions = [_decision_dict(d) for d in pr.decisions]
            get_store().set_result(
                pid, pr.export_text, pr.report_md, decisions, {
                    "verification": pr.verification,
                    "ambiguous": pr.ambiguous,
                    "applied": [],
                    "rejected": [],
                    "ai_notes": pr.ai_notes,
                    "review": {k: v for k, v in pr.review.items() if k != "decisions"},
                    "items": pr.decision_items,
                    "per_file": res.per_file,
                    "decision_cache": decisions,
                }
            )
            return {"id": pid, "graph": meta["graph"],
                    "ok": pr.ok, "applied": len(pr.applied), "ambiguous": len(pr.ambiguous)}
        except Exception:
            if pid is not None:
                get_store().delete(pid)
            raise
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @app.get("/api/projects/{pid}/graph")
    def project_graph(pid: str):
        _ensure(pid)
        meta = json.loads((Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8"))
        return {"kind": meta.get("kind", "single"), "graph": meta.get("graph")}

    @app.get("/api/projects/{pid}/export-folder")
    def export_folder(pid: str):
        from ..core.project import safe_project_relpath

        _ensure(pid)
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if not info_path.exists():
            raise HTTPException(404, "尚未处理")
        info = json.loads(info_path.read_text(encoding="utf-8"))
        verification = info.get("verification", {})
        if verification.get("safe_to_export") is False:
            raise HTTPException(
                409, "安全检查未通过，已阻止导出。请先修复缺失/循环引用或查看汇报。"
            )
        per_file = info.get("per_file")
        if not per_file:
            raise HTTPException(400, "该项目不是文件夹导入")
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            meta = json.loads((Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8"))
            main_rel = safe_project_relpath(meta["graph"]["main_rel"])
            processed = {main_rel} | {
                safe_project_relpath(rel) for rel in per_file if rel
            }
            written = set()
            original_zip = Path(get_store()._dir(pid)) / "original-files.zip"
            if original_zip.exists():
                with zipfile.ZipFile(original_zip, "r") as source_zip:
                    for member in source_zip.infolist():
                        rel = safe_project_relpath(member.filename)
                        if member.is_dir() or rel in processed:
                            continue
                        zf.writestr(rel, source_zip.read(member))
                        written.add(rel)
            zf.writestr(main_rel, per_file.get("", ""))
            written.add(main_rel)
            for rel, content in per_file.items():
                if rel:
                    rel = safe_project_relpath(rel)
                    zf.writestr(rel, content)
                    written.add(rel)
            expected = meta.get("original_file_count")
            if expected is not None and len(written) != expected:
                raise HTTPException(
                    409,
                    f"文件数量安全检查未通过（原始 {expected}，导出 {len(written)}），已阻止导出。",
                )
            zf.writestr("LATEXSTRUCT-REPORT.md", get_store().read_report(pid) or "")
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{pid}-structured.zip"'},
        )

    @app.post("/api/projects/upload")
    async def upload_project(file: bytes = None, name: str = "", mode: str = "rule"):
        # 简化 multipart：由前端读文件后走 /api/projects
        raise HTTPException(400, "请使用 /api/projects 提交文本")

    @app.get("/api/projects/{pid}")
    def get_project(pid: str):
        p = get_store().get(pid)
        if p is None:
            raise HTTPException(404, "项目不存在")
        return p

    @app.delete("/api/projects/{pid}")
    def delete_project(pid: str):
        get_store().delete(pid)
        return {"ok": True}

    @app.get("/api/projects/{pid}/source")
    def source(pid: str):
        _ensure(pid)
        return PlainTextResponse(get_store().read_source(pid))

    @app.get("/api/projects/{pid}/result")
    def result(pid: str):
        _ensure(pid)
        r = get_store().read_result(pid)
        if r is None:
            raise HTTPException(404, "尚未处理")
        return PlainTextResponse(r)

    @app.get("/api/projects/{pid}/report")
    def report(pid: str):
        _ensure(pid)
        r = get_store().read_report(pid)
        if r is None:
            raise HTTPException(404, "尚未处理")
        return PlainTextResponse(r, media_type="text/markdown")

    @app.get("/api/projects/{pid}/export")
    def export(pid: str):
        _ensure(pid)
        d = Path(get_store()._dir(pid))
        target = d / "result.tex"
        if not target.exists():
            raise HTTPException(404, "尚未处理")
        info_path = d / "verification.json"
        if info_path.exists():
            info = json.loads(info_path.read_text(encoding="utf-8"))
            if info.get("verification", {}).get("safe_to_export") is False:
                raise HTTPException(
                    409, "安全检查未通过，结果已回退到原文并禁止导出；请查看汇报。"
                )
        return FileResponse(target, filename=f"{pid}-structured.tex",
                            media_type="application/x-tex")

    def _run_project(pid: str, exclude: set, reuse_decisions: bool = False):
        p = get_store().get(pid)
        text = get_store().read_source(pid)
        cfg = get_config()
        mode = p["mode"]
        template = (p.get("template") or "") or None
        pack = (p.get("pack") or "") or None
        prior = {}
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if reuse_decisions and info_path.exists():
            prior = json.loads(info_path.read_text(encoding="utf-8"))
        cached = prior.get("decision_cache") if reuse_decisions else None
        overrides = [_decision_from_dict(item) for item in cached] if cached else None
        res = run_pipeline(
            text, mode=mode, ai_config=cfg.to_ai_config() if mode == "ai" else None,
            template=template, pack=pack, exclude=exclude or None,
            decisions_override=overrides,
            ambiguous_override=prior.get("ambiguous") if overrides else None,
            ai_notes_override=prior.get("ai_notes") if overrides else None,
        )
        extra_verification = {}
        if p.get("kind") == "folder":
            from ..core.project import split_project

            graph = p.get("graph") or {}
            try:
                per_file = split_project(res.result)
                split_error = ""
            except ValueError as exc:
                per_file = {}
                split_error = str(exc)
            expected = {"", *(graph.get("files") or [])}
            project_ok = bool(
                not split_error
                and set(per_file) == expected
                and not graph.get("missing")
                and not graph.get("cycles")
            )
            project_check = {
                "ok": project_ok,
                "before_file_count": len(expected),
                "after_file_count": len(per_file),
                "file_set_equal": set(per_file) == expected,
                "missing_includes": graph.get("missing") or [],
                "cycles": graph.get("cycles") or [],
                "error": split_error,
            }
            res.verification["project"] = project_check
            res.verification.setdefault("checks", []).append(
                {"id": "project", "label": "项目文件与依赖完整", "ok": project_ok}
            )
            res.verification["safe_to_export"] = bool(
                res.verification.get("safe_to_export") and project_ok
            )
            res.verification["export_blocked"] = not res.verification["safe_to_export"]
            res.ok = bool(res.ok and project_ok)
            extra_verification["per_file"] = per_file
            if not project_ok:
                res.report_md += (
                    "\n\n## 项目安全检查\n\n"
                    "- ❌ 依赖图或文件集合不完整，已阻止导出。\n"
                    f"- 文件数量：{len(expected)} → {len(per_file)}\n"
                )
        decisions = [_decision_dict(d) for d in res.decisions]
        decision_cache = cached or decisions
        applied = [
            {
                "candidate_id": ap.decision.candidate_id,
                "action": ap.decision.action,
                "env": ap.decision.env,
                "reason": ap.decision.reason,
                "edits": [{"kind": e.kind, "line": e.line, "old": e.old, "new": e.new} for e in ap.edits],
            }
            for ap in res.applied
        ]
        get_store().set_result(
            pid, res.export_text, res.report_md, decisions, {
                "verification": res.verification,
                "ambiguous": res.ambiguous,
                "applied": applied,
                "rejected": [{"candidate_id": ap.decision.candidate_id, "error": ap.error} for ap in res.rejected],
                "ai_notes": res.ai_notes,
                "review": {k: v for k, v in res.review.items() if k != "decisions"},
                "items": res.decision_items,
                "decision_cache": decision_cache,
                **extra_verification,
            }
        )
        return {
            "ok": res.ok,
            "applied": len(res.applied),
            "rejected": len(res.rejected),
            "ambiguous": len(res.ambiguous),
            "degraded": res.verification.get("ai_degraded", False),
        }

    @app.post("/api/projects/{pid}/process")
    def process(pid: str):
        _ensure(pid)
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        return _run_project(pid, set(meta.get("excludes", [])))

    @app.get("/api/projects/{pid}/decisions")
    def decisions(pid: str):
        _ensure(pid)
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if not info_path.exists():
            return {"items": [], "excludes": get_store().get(pid).get("excludes", []),
                    "verification": None}
        info = json.loads(info_path.read_text(encoding="utf-8"))
        return {"items": info.get("items", []),
                "excludes": get_store().get(pid).get("excludes", []),
                "verification": info.get("verification")}

    @app.post("/api/projects/{pid}/decisions/{cid}/reject")
    def reject_decision(pid: str, cid: str):
        _ensure(pid)
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        excludes = set(meta.get("excludes", []))
        excludes.add(cid)
        meta["excludes"] = sorted(excludes)
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/{cid}/unreject")
    def unreject_decision(pid: str, cid: str):
        """撤销对某一项的拒绝：从排除清单移除并重跑（审阅台 Ctrl+Z 的后端）。"""
        _ensure(pid)
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        excludes = set(meta.get("excludes", []))
        excludes.discard(cid)
        meta["excludes"] = sorted(excludes)
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/reject-batch")
    def reject_batch(pid: str, req: BatchRejectRequest):
        """批量拒绝（Accept-All-Similar 的逆操作：拒绝同类其余修改）。"""
        _ensure(pid)
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        excludes = set(meta.get("excludes", [])) | set(req.cids)
        meta["excludes"] = sorted(excludes)
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, excludes, reuse_decisions=True)

    @app.post("/api/projects/{pid}/decisions/reset")
    def reset_decisions(pid: str):
        """撤销全部拒绝：清空 excludes 并重跑。"""
        _ensure(pid)
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        meta["excludes"] = []
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, set(), reuse_decisions=True)

    @app.get("/api/projects/{pid}/diff")
    def diff(pid: str):
        _ensure(pid)
        old = get_store().read_source(pid).replace("\r\n", "\n").replace("\r", "\n").split("\n")
        new_text = get_store().read_result(pid)
        if new_text is None:
            raise HTTPException(404, "尚未处理")
        new = new_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        compact = len(old) + len(new) > 20_000
        sm = difflib.SequenceMatcher(a=old, b=new, autojunk=compact)
        rows = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                if compact and i2 - i1 > 6:
                    offsets = [0, 1, 2, i2 - i1 - 3, i2 - i1 - 2, i2 - i1 - 1]
                else:
                    offsets = range(i2 - i1)
                for k in offsets:
                    rows.append({"type": "same", "old": i1 + k + 1, "new": j1 + k + 1,
                                 "text": old[i1 + k]})
            elif tag == "replace":
                for k in range(i2 - i1):
                    rows.append({"type": "del", "old": i1 + k + 1, "new": None,
                                 "text": old[i1 + k]})
                for k in range(j2 - j1):
                    rows.append({"type": "ins", "old": None, "new": j1 + k + 1,
                                 "text": new[j1 + k]})
            elif tag == "delete":
                for k in range(i2 - i1):
                    rows.append({"type": "del", "old": i1 + k + 1, "new": None,
                                 "text": old[i1 + k]})
            elif tag == "insert":
                for k in range(j2 - j1):
                    rows.append({"type": "ins", "old": None, "new": j1 + k + 1,
                                 "text": new[j1 + k]})
        info = json.loads(
            (Path(get_store()._dir(pid)) / "verification.json").read_text(encoding="utf-8")
        )
        return {"rows": rows, "compact": compact, "applied": info.get("applied", []),
                "ambiguous": info.get("ambiguous", []),
                "verification": info.get("verification", {})}

    @app.get("/api/config")
    def get_cfg():
        return get_config().masked()

    @app.put("/api/config")
    def put_cfg(req: ConfigRequest):
        global _config
        cfg = get_config()
        updates = req.model_dump()
        secret_updates = {
            k: v for k, v in updates.items() if k.endswith("_api_key") and v is not None
        }
        for k, v in updates.items():
            if v is not None:
                setattr(cfg, k, v)
        save_config(cfg, secret_updates=secret_updates)
        _config = load_config()  # 重新解析（keyring 占位符 → 真实密钥 + 来源标记）
        return _config.masked()

    # ---- OCR ----

    @app.post("/api/ocr/jobs")
    async def ocr_start(
        file: UploadFile = File(...),
        pages: str = Form(""),
        dpi: int = Form(150),
        base_url: str = Form(""),
        model: str = Form(""),
        api_key: str = Form(""),
    ):
        _cleanup_ocr_jobs()
        suffix = Path(file.filename or "scan.pdf").suffix.lower()
        if suffix not in (".pdf", ".png", ".jpg", ".jpeg"):
            raise HTTPException(400, "仅支持 PDF/PNG/JPG")
        if not 72 <= dpi <= 300:
            raise HTTPException(400, "DPI 必须在 72-300 之间")
        if len(pages) > 200 or len(model) > 160 or len(base_url) > 500:
            raise HTTPException(400, "页码、模型或 Base URL 输入过长")
        upload = await file.read(MAX_OCR_UPLOAD_BYTES + 1)
        if not upload:
            raise HTTPException(400, "上传文件为空")
        if len(upload) > MAX_OCR_UPLOAD_BYTES:
            raise HTTPException(413, "OCR 文件超过 100 MB，请拆分后重试")
        if suffix == ".pdf" and not upload.startswith(b"%PDF-"):
            raise HTTPException(400, "文件扩展名是 PDF，但内容不是有效 PDF")
        if suffix != ".pdf":
            from ..core.ai import LLMError
            from ..ocr import image_mime_type

            try:
                image_mime_type(upload)
            except LLMError as exc:
                raise HTTPException(400, str(exc)) from None
        tmpdir = tempfile.mkdtemp(prefix="ls-ocr-")
        target = os.path.join(tmpdir, f"scan{suffix}")
        with open(target, "wb") as f:
            f.write(upload)
        jid = uuid.uuid4().hex[:10]
        job = {"id": jid, "status": "running", "progress": 0.0, "total": 0, "done": 0,
               "page": 0, "phase": "准备页面", "raw_tex": "", "raw_ready": False,
               "error": "", "usage": {}, "created": time.time(), "pages": {},
               "dir": tmpdir, "errors": []}
        _ocr_jobs[jid] = job

        def _transcribe_one(job, client, page_no: int, png_path: str, max_attempts: int = 2):
            """转写单页并更新 job.pages；暂时性失败自动再试一次。"""
            from ..ocr import transcribe_page

            page = job["pages"].setdefault(
                page_no, {"status": "running", "tex": "", "error": "", "png": png_path,
                          "low_conf": False, "attempts": 0}
            )
            page["status"] = "running"
            page["error"] = ""
            with open(png_path, "rb") as image_file:
                png = image_file.read()
            for attempt in range(1, max_attempts + 1):
                page["attempts"] = page.get("attempts", 0) + 1
                try:
                    tex = transcribe_page(client, png, page_no)
                    page["tex"] = tex
                    page["status"] = "done"
                    page["error"] = ""
                    page["low_conf"] = (
                        "[?]" in tex or "% unsure" in tex or len(tex.strip()) < 40
                    )
                    return True
                except Exception as e:  # noqa: BLE001
                    message = str(e)
                    page["error"] = message
                    # 认证/权限/模型配置错误不会靠重复请求恢复，立即停下。
                    if any(token in message.lower() for token in (
                        "未配置 api key", "http 401", "http 403", "http 400", "http 404",
                    )):
                        break
                    if attempt >= max_attempts:
                        break
            page["status"] = "error"
            page["low_conf"] = True
            return False

        def _merge_job(job):
            from ..ocr import merge_book

            chunks = []
            job["errors"] = []
            for n in sorted(job["pages"]):
                p = job["pages"][n]
                if p["status"] == "done":
                    chunks.append(p["tex"])
                else:
                    job["errors"].append({"page": n, "reason": p["error"] or p["status"]})
            job["raw_tex"] = merge_book(chunks)
            job["raw_ready"] = bool(chunks)
            job["status"] = "done" if not job["errors"] else "partial"
            job["phase"] = "原始 OCR 已就绪" if not job["errors"] else "部分页面失败，等待重试"
            job["progress"] = 1.0

        job["_transcribe_one"] = _transcribe_one
        job["_merge_job"] = _merge_job

        def worker():
            from ..core.ai import LLMClient, RoleConfig
            from ..ocr import iter_pdf_pages, parse_page_range

            cfg = get_config()
            configured_role = cfg.to_ocr_config().role
            selected_base_url = base_url or configured_role.base_url
            selected_model = model or configured_role.model
            selected_key = api_key
            if not selected_key and selected_base_url.rstrip("/") == configured_role.base_url.rstrip("/"):
                selected_key = configured_role.api_key
            role = RoleConfig(
                selected_base_url,
                selected_model,
                selected_key,
            )
            client = LLMClient(role)
            job["client"] = client
            try:
                if suffix == ".pdf":
                    from ..ocr import _pdf_page_count

                    total = _pdf_page_count(target)
                    page_nos = parse_page_range(pages, total)
                    rendered = iter_pdf_pages(target, page_nos, dpi)
                else:
                    page_nos = [1]
                    with open(target, "rb") as image_file:
                        rendered = [(1, image_file.read())]
                job["total"] = len(page_nos)
                job["phase"] = "逐页渲染与忠实转写"
                for i, (page_no, png) in enumerate(rendered):
                    png_path = os.path.join(tmpdir, f"page-{page_no}.img")
                    with open(png_path, "wb") as f:
                        f.write(png)
                    job["pages"].setdefault(
                        page_no, {"status": "pending", "tex": "", "error": "", "png": png_path,
                                  "low_conf": False, "attempts": 0}
                    )
                    job["page"] = page_no
                    job["progress"] = round(i / max(1, len(page_nos)), 3)
                    _transcribe_one(job, client, page_no, png_path)
                    job["done"] = i + 1
                    job["progress"] = round((i + 1) / max(1, len(page_nos)), 3)
                    for k, v in (client.last_usage or {}).items():
                        if isinstance(v, (int, float)):
                            job["usage"][k] = job["usage"].get(k, 0) + v
                _merge_job(job)
            except Exception as e:  # noqa: BLE001
                job["status"] = "error"
                job["phase"] = "准备或渲染失败"
                message = str(e)
                if "No module named 'fitz'" in message:
                    message = "缺少 PDF 渲染组件 PyMuPDF，请重新安装完整版本后重试"
                job["error"] = message

        threading.Thread(target=worker, daemon=True).start()
        return {"id": jid}

    @app.get("/api/ocr/jobs/{jid}")
    def ocr_status(jid: str):
        job = _ocr_jobs.get(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        pages_summary = {
            str(n): {"status": p["status"], "low_conf": p["low_conf"],
                     "error": p["error"][:120], "attempts": p.get("attempts", 0)}
            for n, p in job.get("pages", {}).items()
        }
        return {k: v for k, v in job.items() if k not in (
            "raw_tex", "pages", "client", "dir", "_transcribe_one", "_merge_job"
        )} | {
            "pages": pages_summary
        }

    @app.get("/api/ocr/jobs/{jid}/pages/{n}")
    def ocr_page_png(jid: str, n: int):
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not page or not os.path.exists(page.get("png", "")):
            raise HTTPException(404, "页面不存在")
        from ..ocr import image_mime_type

        media_type = image_mime_type(Path(page["png"]).read_bytes())
        return FileResponse(page["png"], media_type=media_type)

    @app.get("/api/ocr/jobs/{jid}/pages/{n}/tex")
    def ocr_page_tex(jid: str, n: int):
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not page:
            raise HTTPException(404, "页面不存在")
        return PlainTextResponse(page.get("tex", ""))

    @app.post("/api/ocr/jobs/{jid}/pages/{n}/retry")
    def ocr_page_retry(jid: str, n: int):
        """单页重试：重新转写该页并重合并。"""
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not job or not page:
            raise HTTPException(404, "页面不存在")
        client = job.get("client")
        if client is None:
            raise HTTPException(400, "任务尚未初始化")
        job["status"] = "running"
        job["phase"] = f"重试第 {n} 页"
        ok = job["_transcribe_one"](job, client, n, page["png"])
        for k, v in (client.last_usage or {}).items():
            if isinstance(v, (int, float)):
                job["usage"][k] = job["usage"].get(k, 0) + v
        job["_merge_job"](job)
        return {"ok": ok, "page": n, "status": job["status"]}

    @app.get("/api/ocr/jobs/{jid}/result")
    def ocr_result(jid: str):
        job = _ocr_jobs.get(jid)
        if job is None or job.get("status") not in ("done", "partial"):
            raise HTTPException(404, "原始 OCR 尚未生成")
        return PlainTextResponse(
            job["raw_tex"],
            headers={"X-LaTeXStruct-OCR-Complete": "true" if job["status"] == "done" else "false"},
        )

    @app.post("/api/ocr/jobs/{jid}/import")
    def ocr_import(jid: str, name: str = "OCR 转写项目"):
        job = _ocr_jobs.get(jid)
        if job is None or job.get("status") != "done" or not job.get("raw_ready"):
            raise HTTPException(409, "仍有失败页面；请逐页重试成功后再进入结构化审阅")
        # 原始 OCR 永远作为 source.tex 保存；结构化结果单独写 result.tex，二者不混写。
        pid = get_store().create(job["raw_tex"], name, "rule", "")
        processed = _run_project(pid, set())
        return {"id": pid, "processed": processed}

    react_dir = STATIC_DIR.parent / "static-react"
    if react_dir.exists():
        app.mount("/", StaticFiles(directory=str(react_dir), html=True), name="react")
    else:
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def _ensure(pid: str):
    if get_store().get(pid) is None:
        raise HTTPException(404, "项目不存在")

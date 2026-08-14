# -*- coding: utf-8 -*-
"""FastAPI 本地服务（127.0.0.1）。"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import AppConfig, load_config, save_config
from ..core.pipeline import run_pipeline
from ..store import ProjectStore

STATIC_DIR = Path(__file__).parent / "static"

_store: Optional[ProjectStore] = None
_config: Optional[AppConfig] = None


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


class ConfigRequest(BaseModel):
    decide_base_url: Optional[str] = None
    decide_model: Optional[str] = None
    decide_api_key: Optional[str] = None
    review_base_url: Optional[str] = None
    review_model: Optional[str] = None
    review_api_key: Optional[str] = None
    review_enabled: Optional[bool] = None


def create_app() -> FastAPI:
    app = FastAPI(title="LaTeXStruct", docs_url="/api/docs")

    @app.get("/api/health")
    def health():
        from .. import __version__

        return {"ok": True, "version": __version__}

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
        pid = get_store().create(req.text, req.name, req.mode, req.template)
        return {"id": pid}

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
        return FileResponse(target, filename=f"{pid}-structured.tex",
                            media_type="application/x-tex")

    @app.post("/api/projects/{pid}/process")
    def process(pid: str):
        _ensure(pid)
        p = get_store().get(pid)
        text = get_store().read_source(pid)
        cfg = get_config()
        mode = p["mode"]
        template = (p.get("template") or "") or None
        res = run_pipeline(text, mode=mode, ai_config=cfg.to_ai_config() if mode == "ai" else None,
                           template=template)
        decisions = [
            {
                "candidate_id": d.candidate_id,
                "action": d.action,
                "env": d.env,
                "body_span": list(d.body_span) if d.body_span else None,
                "optional_arg": d.optional_arg,
                "reason": d.reason,
                "confidence": d.confidence,
                "source": d.source,
            }
            for d in res.decisions
        ]
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
            }
        )
        return {
            "ok": res.ok,
            "applied": len(res.applied),
            "rejected": len(res.rejected),
            "ambiguous": len(res.ambiguous),
            "degraded": res.verification.get("ai_degraded", False),
        }

    @app.get("/api/projects/{pid}/diff")
    def diff(pid: str):
        _ensure(pid)
        old = get_store().read_source(pid).replace("\r\n", "\n").replace("\r", "\n").split("\n")
        new_text = get_store().read_result(pid)
        if new_text is None:
            raise HTTPException(404, "尚未处理")
        new = new_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
        rows = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
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
        return {"rows": rows, "applied": info.get("applied", []),
                "ambiguous": info.get("ambiguous", []),
                "verification": info.get("verification", {})}

    @app.get("/api/config")
    def get_cfg():
        return get_config().masked()

    @app.put("/api/config")
    def put_cfg(req: ConfigRequest):
        global _config
        cfg = get_config()
        for k, v in req.model_dump().items():
            if v is not None:
                setattr(cfg, k, v)
        save_config(cfg)
        _config = cfg
        return cfg.masked()

    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def _ensure(pid: str):
    if get_store().get(pid) is None:
        raise HTTPException(404, "项目不存在")

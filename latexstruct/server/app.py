# -*- coding: utf-8 -*-
"""FastAPI 本地服务（127.0.0.1）。"""

from __future__ import annotations

import difflib
import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import AppConfig, load_config, save_config
from ..core.pipeline import run_pipeline
from ..store import ProjectStore

STATIC_DIR = Path(__file__).parent / "static"

_store: Optional[ProjectStore] = None
_config: Optional[AppConfig] = None
_ocr_jobs: Dict[str, dict] = {}


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
    cids: list = []


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


def create_app() -> FastAPI:
    app = FastAPI(title="LaTeXStruct", docs_url="/api/docs")

    @app.get("/api/health")
    def health():
        from .. import __version__

        return {"ok": True, "version": __version__}

    @app.get("/api/rulesets")
    def rulesets():
        from ..core.ruleset import list_builtin_packs

        return {"packs": list_builtin_packs(), "default": "bilingual"}

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

        if not req.files:
            raise HTTPException(400, "未收到文件")
        tmpdir = tempfile.mkdtemp(prefix="ls-folder-")
        for rel, content in req.files.items():
            p = Path(tmpdir) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8", newline="")
        main_rel = discover_main(Path(tmpdir))
        if main_rel is None:
            raise HTTPException(400, "文件夹中未找到 .tex 主文件")
        cfg = get_config()
        mode = req.mode or "rule"
        res = process_project(Path(tmpdir), mode=mode, template=req.template or None,
                              ai_config=cfg.to_ai_config() if mode == "ai" else None,
                              pack=req.pack or None)
        pr = res.pipeline
        # 项目源 = 展开文本（供 diff/决策审阅），元数据保留图与逐文件结果
        pid = get_store().create(res.flattened, req.name, mode, req.template or "", req.pack or "")
        meta = json.loads((Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8"))
        meta["kind"] = "folder"
        meta["graph"] = {
            "main_rel": res.graph.main_rel,
            "files": res.graph.files,
            "missing": res.graph.missing,
            "cycles": res.graph.cycles,
        }
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        decisions = [{
            "candidate_id": d.candidate_id, "action": d.action, "env": d.env,
            "body_span": list(d.body_span) if d.body_span else None,
            "optional_arg": d.optional_arg, "reason": d.reason,
            "confidence": d.confidence, "source": d.source,
        } for d in pr.decisions]
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
            }
        )
        return {"id": pid, "graph": meta["graph"],
                "ok": pr.ok, "applied": len(pr.applied), "ambiguous": len(pr.ambiguous)}

    @app.get("/api/projects/{pid}/graph")
    def project_graph(pid: str):
        _ensure(pid)
        meta = json.loads((Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8"))
        return {"kind": meta.get("kind", "single"), "graph": meta.get("graph")}

    @app.get("/api/projects/{pid}/export-folder")
    def export_folder(pid: str):
        _ensure(pid)
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if not info_path.exists():
            raise HTTPException(404, "尚未处理")
        info = json.loads(info_path.read_text(encoding="utf-8"))
        per_file = info.get("per_file")
        if not per_file:
            raise HTTPException(400, "该项目不是文件夹导入")
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            meta = json.loads((Path(get_store()._dir(pid)) / "meta.json").read_text(encoding="utf-8"))
            main_rel = meta["graph"]["main_rel"]
            zf.writestr(main_rel, per_file.get("", ""))
            for rel, content in per_file.items():
                if rel:
                    zf.writestr(rel, content)
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
        return FileResponse(target, filename=f"{pid}-structured.tex",
                            media_type="application/x-tex")

    def _run_project(pid: str, exclude: set):
        p = get_store().get(pid)
        text = get_store().read_source(pid)
        cfg = get_config()
        mode = p["mode"]
        template = (p.get("template") or "") or None
        pack = (p.get("pack") or "") or None
        res = run_pipeline(text, mode=mode, ai_config=cfg.to_ai_config() if mode == "ai" else None,
                           template=template, pack=pack, exclude=exclude or None)
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
                "items": res.decision_items,
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
        return _run_project(pid, set())

    @app.get("/api/projects/{pid}/decisions")
    def decisions(pid: str):
        _ensure(pid)
        info_path = Path(get_store()._dir(pid)) / "verification.json"
        if not info_path.exists():
            return {"items": [], "excludes": get_store().get(pid).get("excludes", [])}
        info = json.loads(info_path.read_text(encoding="utf-8"))
        return {"items": info.get("items", []), "excludes": get_store().get(pid).get("excludes", [])}

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
        return _run_project(pid, excludes)

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
        return _run_project(pid, excludes)

    @app.post("/api/projects/{pid}/decisions/reset")
    def reset_decisions(pid: str):
        """撤销全部拒绝：清空 excludes 并重跑。"""
        _ensure(pid)
        meta = json.loads(Path(get_store()._dir(pid), "meta.json").read_text(encoding="utf-8"))
        meta["excludes"] = []
        Path(get_store()._dir(pid), "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        return _run_project(pid, set())

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

    # ---- OCR ----

    @app.post("/api/ocr/jobs")
    async def ocr_start(
        file: UploadFile,
        pages: str = "",
        dpi: int = 150,
        base_url: str = "",
        model: str = "",
        api_key: str = "",
    ):
        suffix = Path(file.filename or "scan.pdf").suffix.lower()
        if suffix not in (".pdf", ".png", ".jpg", ".jpeg"):
            raise HTTPException(400, "仅支持 PDF/PNG/JPG")
        tmpdir = tempfile.mkdtemp(prefix="ls-ocr-")
        target = os.path.join(tmpdir, f"scan{suffix}")
        with open(target, "wb") as f:
            f.write(await file.read())
        jid = uuid.uuid4().hex[:10]
        job = {"id": jid, "status": "running", "progress": 0.0, "total": 0, "done": 0,
               "page": 0, "tex": "", "error": "", "usage": {}, "created": time.time(),
               "pages": {}, "dir": tmpdir, "errors": []}
        _ocr_jobs[jid] = job

        def _transcribe_one(job, client, page_no: int, png_path: str):
            """转写单页并更新 job.pages；返回是否成功。"""
            from ..ocr import transcribe_page

            page = job["pages"].setdefault(
                page_no, {"status": "running", "tex": "", "error": "", "png": png_path, "low_conf": False}
            )
            try:
                png = open(png_path, "rb").read()
                tex = transcribe_page(client, png, page_no)
                page["tex"] = tex
                page["status"] = "done"
                page["error"] = ""
                page["low_conf"] = ("[?]" in tex) or ("% unsure" in tex) or (len(tex.strip()) < 40)
                return True
            except Exception as e:  # noqa: BLE001
                page["status"] = "error"
                page["error"] = str(e)
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
            job["tex"] = merge_book(chunks)
            job["status"] = "done"
            job["progress"] = 1.0

        job["_transcribe_one"] = _transcribe_one
        job["_merge_job"] = _merge_job

        def worker():
            from ..core.ai import LLMClient, RoleConfig
            from ..ocr import parse_page_range, render_pdf_pages

            cfg = get_config()
            role = RoleConfig(
                base_url or cfg.ocr_base_url or cfg.decide_base_url,
                model or cfg.ocr_model or "deepseek-chat",
                api_key or cfg.ocr_api_key or cfg.decide_api_key,
            )
            client = LLMClient(role)
            job["client"] = client
            try:
                if suffix == ".pdf":
                    from ..ocr import _pdf_page_count

                    total = _pdf_page_count(target)
                    page_nos = parse_page_range(pages, total)
                    rendered = render_pdf_pages(target, page_nos, dpi)
                else:
                    page_nos = [1]
                    rendered = [(1, open(target, "rb").read())]
                job["total"] = len(page_nos)
                for i, (page_no, png) in enumerate(rendered):
                    png_path = os.path.join(tmpdir, f"page-{page_no}.png")
                    with open(png_path, "wb") as f:
                        f.write(png)
                    job["pages"].setdefault(
                        page_no, {"status": "pending", "tex": "", "error": "", "png": png_path, "low_conf": False}
                    )
                    job["done"] = i
                    job["page"] = page_no
                    job["progress"] = round(i / max(1, len(page_nos)), 3)
                    _transcribe_one(job, client, page_no, png_path)
                    for k, v in (client.last_usage or {}).items():
                        if isinstance(v, (int, float)):
                            job["usage"][k] = job["usage"].get(k, 0) + v
                _merge_job(job)
            except Exception as e:  # noqa: BLE001
                job["status"] = "error"
                job["error"] = str(e)

        threading.Thread(target=worker, daemon=True).start()
        return {"id": jid}

    @app.get("/api/ocr/jobs/{jid}")
    def ocr_status(jid: str):
        job = _ocr_jobs.get(jid)
        if job is None:
            raise HTTPException(404, "任务不存在")
        pages_summary = {
            str(n): {"status": p["status"], "low_conf": p["low_conf"], "error": p["error"][:120]}
            for n, p in job.get("pages", {}).items()
        }
        return {k: v for k, v in job.items() if k not in ("tex", "pages", "client", "dir", "_transcribe_one", "_merge_job")} | {
            "pages": pages_summary
        }

    @app.get("/api/ocr/jobs/{jid}/pages/{n}")
    def ocr_page_png(jid: str, n: int):
        job = _ocr_jobs.get(jid)
        page = (job or {}).get("pages", {}).get(n)
        if not page or not os.path.exists(page.get("png", "")):
            raise HTTPException(404, "页面不存在")
        return FileResponse(page["png"], media_type="image/png")

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
        ok = job["_transcribe_one"](job, client, n, page["png"])
        job["_merge_job"](job)
        return {"ok": ok, "page": n}

    @app.get("/api/ocr/jobs/{jid}/result")
    def ocr_result(jid: str):
        job = _ocr_jobs.get(jid)
        if job is None or job.get("status") != "done":
            raise HTTPException(404, "任务未完成")
        return PlainTextResponse(job["tex"])

    @app.post("/api/ocr/jobs/{jid}/import")
    def ocr_import(jid: str, name: str = "OCR 转写项目"):
        job = _ocr_jobs.get(jid)
        if job is None or job.get("status") != "done":
            raise HTTPException(400, "任务未完成")
        pid = get_store().create(job["tex"], name, "rule", "elegantbook")
        return {"id": pid}

    react_dir = STATIC_DIR.parent / "static-react"
    if react_dir.exists():
        from fastapi.responses import RedirectResponse

        @app.get("/legacy", include_in_schema=False)
        def _legacy_root():
            return RedirectResponse("/legacy/")

        app.mount("/legacy", StaticFiles(directory=str(STATIC_DIR), html=True), name="legacy")
        app.mount("/", StaticFiles(directory=str(react_dir), html=True), name="react")
    else:
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def _ensure(pid: str):
    if get_store().get(pid) is None:
        raise HTTPException(404, "项目不存在")

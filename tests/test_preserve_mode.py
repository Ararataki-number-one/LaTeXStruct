# -*- coding: utf-8 -*-
"""Regression coverage for the source-preserving TeX workflow.

Ordinary TeX projects default to preserving their document class and layout.
ElegantBook remains an explicit template choice; OCR defaults to faithfulbook.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SERVER_AVAILABLE = False
try:
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        from starlette.testclient import TestClient

    import latexstruct.server.app as srv
    SERVER_AVAILABLE = True
except ImportError:  # pragma: no cover - server extras are optional
    TestClient = None
    srv = None

from latexstruct.core.pipeline import run_pipeline
from latexstruct.core.template import ELEGANTBOOK, FAITHFULBOOK, PRESERVE_SOURCE


TESTS_DIR = Path(__file__).resolve().parent
ARTICLE = (
    "\\documentclass[11pt]{article}\n"
    "\\usepackage{amsmath,amssymb}\n"
    "\\begin{document}\n"
    "\\section{Introduction}\n"
    "This is already structured body text.\n"
    "\\end{document}\n"
)
BEAMER = (
    "\\documentclass{beamer}\n"
    "\\usepackage{amsmath}\n"
    "\\begin{document}\n"
    "\\begin{frame}{Introduction}\n"
    "This frame is already structured.\n"
    "\\end{frame}\n"
    "\\end{document}\n"
)
ELEGANT_ASSETS = {
    "elegantbook.cls",
    "ELEGANTBOOK-LICENSE.txt",
    "ELEGANTBOOK-BUNDLE-README.md",
}


def _compile_unavailable(*_args, **_kwargs):
    return {
        "available": False,
        "ok": None,
        "pages": 0,
        "errors": [],
        "log": "",
    }


def _require_server():
    if SERVER_AVAILABLE:
        return
    try:
        import pytest
    except ImportError as exc:  # pragma: no cover - supports direct local invocation
        raise RuntimeError("FastAPI server dependencies are not installed") from exc
    pytest.skip("FastAPI server dependencies are not installed")


@contextmanager
def _workspace_client():
    """Give each API test an isolated store/config and clean global job state."""
    _require_server()
    root = tempfile.mkdtemp(prefix="ls-preserve-", dir=TESTS_DIR)
    import latexstruct.config as configmod

    old_config_path = configmod.CONFIG_PATH
    old_store = srv._store
    old_config = srv._config
    configmod.CONFIG_PATH = os.path.join(root, "config.json")
    srv._process_jobs.clear()
    with srv._ocr_jobs_lock:
        srv._ocr_jobs.clear()
    srv._active_pipeline_runs = 0
    srv._store = srv.ProjectStore(root=os.path.join(root, "projects"))
    srv._config = None
    client = TestClient(srv.create_app())
    try:
        yield client, Path(root)
    finally:
        client.close()
        srv._process_jobs.clear()
        with srv._ocr_jobs_lock:
            srv._ocr_jobs.clear()
        srv._store = old_store
        srv._config = old_config
        configmod.CONFIG_PATH = old_config_path
        shutil.rmtree(root, ignore_errors=True)


def _create_and_process(client, text: str, *, template: str = PRESERVE_SOURCE) -> str:
    created = client.post(
        "/api/projects",
        json={"text": text, "name": "preserve-test", "mode": "rule", "template": template},
    )
    assert created.status_code == 200, created.text
    pid = created.json()["id"]
    processed = client.post(f"/api/projects/{pid}/process")
    assert processed.status_code == 200, processed.text
    assert processed.json()["ok"] is True, processed.json()
    return pid


def test_templates_api_defaults_to_preserve_while_ocr_uses_faithfulbook():
    with _workspace_client() as (client, _root):
        response = client.get("/api/templates")
        assert response.status_code == 200
        payload = response.json()
        assert payload["default"] == PRESERVE_SOURCE == ""
        assert payload["export_default"] == PRESERVE_SOURCE
        assert payload["ocr_default"] == FAITHFULBOOK
        assert payload["fixed"] is False
        assert {item["id"] for item in payload["templates"]} == {
            PRESERVE_SOURCE,
            ELEGANTBOOK,
            FAITHFULBOOK,
        }
        faithful = next(
            item for item in payload["templates"] if item["id"] == FAITHFULBOOK
        )
        assert faithful["layout_change"] is True
        assert faithful["qa_profile"] == "publication"
        assert "不代表逐页复刻" in faithful["description"]


def test_preserve_pipeline_leaves_standard_article_and_beamer_byte_for_byte():
    for source in (ARTICLE, BEAMER):
        result = run_pipeline(source, mode="rule", template=PRESERVE_SOURCE)
        assert result.ok, result.report_md
        assert result.result == source
        assert result.export_text == source
        assert "% LaTeXStruct template:" not in result.result
        assert result.applied == []


def test_explicit_elegantbook_still_converts_class_packages_and_heading_level():
    result = run_pipeline(
        ARTICLE,
        mode="rule",
        template=ELEGANTBOOK,
        template_context={"title": "Explicit conversion"},
    )
    assert result.ok, result.report_md
    assert "% LaTeXStruct template: elegantbook v4.7" in result.result
    assert "\\documentclass[lang=en,11pt]{elegantbook}" in result.result
    assert "\\usepackage{amsmath,amssymb}" in result.result
    assert "\\chapter{Introduction}" in result.result
    assert "\\documentclass[11pt]{article}" not in result.result
    assert "\\section{Introduction}" not in result.result


def test_single_file_api_honors_preserve_and_explicit_elegantbook():
    with _workspace_client() as (client, _root), patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compile_unavailable,
    ):
        preserved_pid = _create_and_process(client, ARTICLE)
        preserved_meta = client.get(f"/api/projects/{preserved_pid}").json()
        preserved_result = client.get(f"/api/projects/{preserved_pid}/result").text
        assert preserved_meta["template"] == PRESERVE_SOURCE
        assert preserved_result == ARTICLE

        elegant_pid = _create_and_process(client, ARTICLE, template=ELEGANTBOOK)
        elegant_meta = client.get(f"/api/projects/{elegant_pid}").json()
        elegant_result = client.get(f"/api/projects/{elegant_pid}/result").text
        assert elegant_meta["template"] == ELEGANTBOOK
        assert "\\documentclass[lang=en,11pt]{elegantbook}" in elegant_result
        assert "\\chapter{Introduction}" in elegant_result


def test_folder_api_honors_template_and_compares_compilation_on_initial_import():
    payload = {"files": {"main.tex": ARTICLE}, "name": "folder", "mode": "rule"}
    with _workspace_client() as (client, _root), patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compile_unavailable,
    ) as compile_latex:
        preserved = client.post(
            "/api/projects/folder",
            json={**payload, "template": PRESERVE_SOURCE},
        )
        assert preserved.status_code == 200, preserved.text
        preserved_pid = preserved.json()["id"]
        assert client.get(f"/api/projects/{preserved_pid}").json()["template"] == PRESERVE_SOURCE
        assert client.get(f"/api/projects/{preserved_pid}/result").text == ARTICLE
        assert compile_latex.call_count == 2
        assert compile_latex.call_args_list[0].args[0] == ARTICLE
        assert compile_latex.call_args_list[1].args[0] == ARTICLE

        compile_latex.reset_mock()
        elegant = client.post(
            "/api/projects/folder",
            json={**payload, "template": ELEGANTBOOK},
        )
        assert elegant.status_code == 200, elegant.text
        elegant_pid = elegant.json()["id"]
        assert client.get(f"/api/projects/{elegant_pid}").json()["template"] == ELEGANTBOOK
        elegant_result = client.get(f"/api/projects/{elegant_pid}/result").text
        assert "\\documentclass[lang=en,11pt]{elegantbook}" in elegant_result
        assert "\\chapter{Introduction}" in elegant_result
        assert compile_latex.call_count == 2


def test_preserved_verified_result_exports_without_elegantbook_bundle_assets():
    with _workspace_client() as (client, _root), patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compile_unavailable,
    ):
        pid = _create_and_process(client, ARTICLE)
        exported = client.get(f"/api/projects/{pid}/export")
        assert exported.status_code == 200, exported.text
        from latexstruct.core.provenance import strip_tex_provenance

        assert strip_tex_provenance(exported.content) == ARTICLE.encode("utf-8")

        package = client.get(f"/api/projects/{pid}/export-package")
        assert package.status_code == 200, package.text
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            names = set(archive.namelist())
            assert strip_tex_provenance(archive.read("main.tex")) == ARTICLE.encode(
                "utf-8"
            )
            assert "LATEXSTRUCT-REPORT.md" in names
            assert "LATEXSTRUCT-PROVENANCE.json" in names
            assert names.isdisjoint(ELEGANT_ASSETS)


def test_ordinary_single_file_processing_compares_compile_before_and_after():
    with _workspace_client() as (client, _root), patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compile_unavailable,
    ) as compile_latex:
        pid = _create_and_process(client, ARTICLE)
        assert compile_latex.call_count == 2
        before, after = compile_latex.call_args_list
        assert before.args[0] == ARTICLE
        assert after.args[0] == ARTICLE
        verification = client.get(f"/api/projects/{pid}/decisions").json()["verification"]
        assert verification["compile_required"] is False
        assert verification["compile_before"]["available"] is False
        assert verification["compile_after"]["available"] is False


def test_ocr_import_uses_faithfulbook_when_template_is_omitted():
    with _workspace_client() as (client, root), patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compile_unavailable,
    ):
        jid = "ocr-default-template"
        job_dir = root / "ocr-job"
        job_dir.mkdir()
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "dir": str(job_dir),
                "status": "done",
                "raw_ready": True,
                "raw_tex": ARTICLE,
                "raw_revision": 1,
                "usage_revision": 1,
                "page_revision": 1,
                "pages": {},
                "selected_pages": [],
                "importing": False,
                "saving": False,
            }

        imported = client.post(f"/api/ocr/jobs/{jid}/import?mode=rule")
        assert imported.status_code == 200, imported.text
        pid = imported.json()["id"]
        project = client.get(f"/api/projects/{pid}").json()
        assert project["kind"] == "ocr"
        assert project["template"] == FAITHFULBOOK

        deadline = time.time() + 5
        status = {}
        while time.time() < deadline:
            status = client.get(f"/api/projects/{pid}/process/status").json()
            if status.get("status") not in {
                "running",
                "pausing",
                "paused",
                "committing",
            }:
                break
            time.sleep(0.02)
        assert status.get("status") == "done", status
        result = client.get(f"/api/projects/{pid}/result").text
        assert "\\documentclass[10pt,twoside,openany]{book}" in result
        assert "% LaTeXStruct template: faithfulbook v1" in result


def test_ocr_import_honors_template_frozen_when_job_started():
    with _workspace_client() as (client, root), patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compile_unavailable,
    ):
        jid = "ocr-explicit-template"
        job_dir = root / "ocr-explicit-job"
        job_dir.mkdir()
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "dir": str(job_dir),
                "status": "done",
                "raw_ready": True,
                "raw_tex": ARTICLE,
                "raw_revision": 1,
                "usage_revision": 1,
                "page_revision": 1,
                "pages": {},
                "selected_pages": [],
                "output_template": ELEGANTBOOK,
                "importing": False,
                "saving": False,
            }

        imported = client.post(
            f"/api/ocr/jobs/{jid}/import?mode=rule&template=faithfulbook"
        )
        assert imported.status_code == 200, imported.text
        project = client.get(f"/api/projects/{imported.json()['id']}").json()
        assert project["template"] == ELEGANTBOOK

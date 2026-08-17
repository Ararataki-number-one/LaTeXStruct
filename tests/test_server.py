# -*- coding: utf-8 -*-
"""FastAPI 服务接口测试（需要 fastapi + httpx；未安装时自动跳过）。"""

import io
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLE = (
    "\\documentclass{book}\n\\begin{document}\n\n"
    "\\section*{1.1 The Method}\n\\begin{tcolorbox}\n\\section*{方法}\n\\end{tcolorbox}\n\n"
    "Theorem 1. A statement.\n\n\\end{document}\n"
)
COMMITTED_ELEGANT = (
    "\\documentclass[lang=en,11pt]{elegantbook}\n"
    "\\begin{document}\nVerified.\n\\end{document}\n"
)

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


class WorkspaceTmp:
    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="ls-test-", dir=_TESTS_DIR)
        import latexstruct.config as configmod

        self.old_config_path = configmod.CONFIG_PATH
        configmod.CONFIG_PATH = os.path.join(self.path, "config.json")
        return self.path

    def __exit__(self, *exc):
        import latexstruct.config as configmod

        configmod.CONFIG_PATH = self.old_config_path
        shutil.rmtree(self.path, ignore_errors=True)


try:
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        from starlette.testclient import TestClient

    import latexstruct.server.app as srv
except ImportError:  # 依赖未安装 → 跳过
    sys.exit(0)


def _client(tmp):
    srv._process_jobs.clear()
    srv._cancel_update_preparation()
    with srv._update_jobs_lock:
        srv._update_jobs.clear()
    srv._active_pipeline_runs = 0
    srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
    srv._config = None
    return TestClient(srv.create_app())


def _inspect_and_start_image(c, filename, image, media_type, data=None):
    inspected = c.post(
        "/api/ocr/inspect",
        files={"file": (filename, image, media_type)},
    )
    assert inspected.status_code == 200, inspected.text
    info = inspected.json()
    assert info["source_type"] == "image"
    assert re.fullmatch(r"[0-9a-f]{32}", info["id"])
    started = c.post(f"/api/ocr/jobs/{info['id']}/start", data=data or {})
    assert started.status_code == 200, started.text
    assert started.json()["id"] == info["id"]
    return started


def test_health_and_project_flow():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        assert c.get("/api/health").json()["ok"] is True
        r = c.post("/api/projects", json={"text": SAMPLE, "name": "demo", "mode": "rule"})
        assert r.status_code == 200
        pid = r.json()["id"]
        assert c.get(f"/api/projects/{pid}").json()["name"] == "demo"
        # 处理
        r = c.post(f"/api/projects/{pid}/process")
        assert r.status_code == 200
        s = r.json()
        assert s["ok"] is True and s["applied"] >= 1
        # 结果与汇报
        result = c.get(f"/api/projects/{pid}/result").text
        assert "\\begin{theorem*}[1]" in result and "（方法）" in result
        report = c.get(f"/api/projects/{pid}/report").text
        assert "机器校验" in report and "内容不变校验：通过" in report
        # diff
        d = c.get(f"/api/projects/{pid}/diff").json()
        assert any(row["type"] == "ins" for row in d["rows"])
        assert d["verification"]["content_invariant"] is True
        # 导出
        e = c.get(f"/api/projects/{pid}/export")
        assert e.status_code == 200
        package = c.get(f"/api/projects/{pid}/export-package")
        assert package.status_code == 200 and "zip" in package.headers["content-type"]
        with zipfile.ZipFile(io.BytesIO(package.content)) as zf:
            assert zf.read("main.tex") == e.content
            assert b"v4.7 ElegantBook document class" in zf.read("elegantbook.cls")
            assert "ELEGANTBOOK-LICENSE.txt" in zf.namelist()
            assert "ELEGANTBOOK-BUNDLE-README.md" in zf.namelist()
            assert zf.read("LATEXSTRUCT-REPORT.md") == c.get(f"/api/projects/{pid}/report").content
        # 删除
        c.delete(f"/api/projects/{pid}")
        assert c.get(f"/api/projects/{pid}").status_code == 404


def test_frozen_release_refuses_to_serve_incompatible_legacy_frontend():
    with WorkspaceTmp() as tmp:
        fake_static = Path(tmp) / "package" / "static"
        fake_static.mkdir(parents=True)
        with patch.object(srv, "STATIC_DIR", fake_static), patch.object(
            sys, "frozen", True, create=True
        ):
            try:
                srv.create_app()
            except RuntimeError as exc:
                assert "发布包缺少 React 前端资源" in str(exc)
            else:
                raise AssertionError("frozen release must not fall back to the legacy frontend")


def test_illegal_bracket_display_tag_blocks_server_export():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        text = (
            "\\documentclass{book}\n\\usepackage{amsmath}\n\\begin{document}\n"
            "\\[x=y\\tag{1}\\tag{2}\\]\n\\end{document}\n"
        )
        pid = c.post(
            "/api/projects", json={"text": text, "name": "unsafe-tag", "mode": "rule"}
        ).json()["id"]
        processed = c.post(f"/api/projects/{pid}/process")
        assert processed.status_code == 200 and processed.json()["ok"] is False
        verification = c.get(f"/api/projects/{pid}/decisions").json()["verification"]
        assert verification["display_tags"]["ok"] is False
        assert verification["safe_to_export"] is False
        blocked = c.get(f"/api/projects/{pid}/export")
        assert blocked.status_code == 409 and "安全检查" in blocked.json()["detail"]


def test_unclosed_bracket_display_blocks_server_export():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        text = (
            "\\documentclass{book}\n\\begin{document}\n"
            "\\[x=y\n\\end{document}\n"
        )
        pid = c.post(
            "/api/projects", json={"text": text, "name": "unclosed-display", "mode": "rule"}
        ).json()["id"]
        processed = c.post(f"/api/projects/{pid}/process")
        assert processed.status_code == 200 and processed.json()["ok"] is False
        verification = c.get(f"/api/projects/{pid}/decisions").json()["verification"]
        assert verification["display_tags"]["ok"] is False
        assert verification["safe_to_export"] is False
        blocked = c.get(f"/api/projects/{pid}/export")
        assert blocked.status_code == 409 and "安全检查" in blocked.json()["detail"]


def test_export_requires_current_committed_verification_hash():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "commit-guard", "mode": "rule"}
        ).json()["id"]
        store = srv.get_store()
        project_dir = Path(store._dir(pid))

        # 仅有 result.tex 但没有最后提交的 verification marker 时必须 fail-closed。
        store._write_text(str(project_dir), "result.tex", "UNVERIFIED")
        missing = c.get(f"/api/projects/{pid}/export")
        assert missing.status_code == 409

        # 安全 marker 不能把旧版非 ElegantBook 结果伪装成当前正式成品。
        legacy_text = "\\documentclass{book}\n\\begin{document}\nOld\n\\end{document}\n"
        store.set_result(
            pid, legacy_text, "# report", [],
            {"verification": {"safe_to_export": True}},
        )
        legacy = c.get(f"/api/projects/{pid}/export")
        assert legacy.status_code == 409 and "ElegantBook" in legacy.json()["detail"]

        committed_text = COMMITTED_ELEGANT.replace("\n", "\r\n")
        store.set_result(
            pid,
            committed_text,
            "# report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        info = json.loads((project_dir / "verification.json").read_text(encoding="utf-8"))
        assert info["result_sha256"] == hashlib.sha256(
            committed_text.encode("utf-8")
        ).hexdigest()
        assert c.get(f"/api/projects/{pid}/export").status_code == 200

        # marker 仍是旧结果的 hash 时，即使标记写着安全通过也不能放行新内容。
        store._write_text(str(project_dir), "result.tex", "TAMPERED")
        stale = c.get(f"/api/projects/{pid}/export")
        assert stale.status_code == 409 and "不一致" in stale.json()["detail"]


def test_partial_result_write_restores_previous_complete_commit():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "partial-write", "mode": "rule"}
        ).json()["id"]
        store = srv.get_store()
        store.set_result(
            pid,
            COMMITTED_ELEGANT,
            "# old report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        assert c.get(f"/api/projects/{pid}/export").status_code == 200
        original_write_text = store._write_text

        def fail_after_result(directory, name, text):
            if name == "report.md":
                raise OSError("synthetic report write failure")
            return original_write_text(directory, name, text)

        with patch.object(store, "_write_text", side_effect=fail_after_result):
            try:
                store.set_result(
                    pid,
                    "NEW",
                    "# new report",
                    [],
                    {"verification": {"safe_to_export": True}},
                )
            except OSError:
                pass
            else:
                raise AssertionError("部分写入必须向调用方报告失败")

        assert store.read_result(pid) == COMMITTED_ELEGANT
        assert store.read_report(pid) == "# old report"
        restored = c.get(f"/api/projects/{pid}/export")
        assert restored.status_code == 200
        assert restored.text == COMMITTED_ELEGANT


def test_config_masked():
    with WorkspaceTmp() as tmp:
        srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
        srv._config = None
        # hermetic：配置读写注入 FakeBackend + 临时 config.json，绝不触碰真实用户配置/凭据
        import latexstruct.config as configmod
        from latexstruct.keystore import FakeBackend

        fake = FakeBackend()
        old_path, old_save, old_load = configmod.CONFIG_PATH, srv.save_config, srv.load_config
        configmod.CONFIG_PATH = os.path.join(tmp, "config.json")
        srv.save_config = lambda cfg, secret_updates=None: configmod.save_config(
            cfg, backend=fake, secret_updates=secret_updates
        )
        srv.load_config = lambda: configmod.load_config(backend=fake)
        try:
            c = TestClient(srv.create_app())
            r = c.put(
                "/api/config",
                json={"decide_api_key": "sk-test", "review_enabled": False, "keyring": False},
            )
            assert r.status_code == 200
            masked = c.get("/api/config").json()
            assert masked["decide_api_key"] == "已配置"
            assert masked["review_enabled"] is False
            # keyring 开启：密钥进凭据后端、配置文件只存占位符、展示带来源标记
            r = c.put("/api/config", json={"keyring": True, "review_api_key": "sk-rev"})
            assert r.status_code == 200
            masked = c.get("/api/config").json()
            assert masked["keyring"] is True
            assert masked["review_api_key"] == "已配置(系统凭据)"
            on_disk = json.loads(open(configmod.CONFIG_PATH, encoding="utf-8").read())
            assert on_disk["review_api_key"] == "__keyring__"
            assert fake.get("review_api_key") == "sk-rev"
            r = c.put("/api/config", json={"decide_api_key": "", "review_enabled": True, "keyring": False})
            assert r.status_code == 200
            assert fake.get("decide_api_key") == ""
            # 环境变量只在运行时生效；普通设置保存不会把它写入 config.json/keyring。
            old_provider = os.environ.get("LATEXSTRUCT_OCR_PROVIDER")
            old_key = os.environ.get("DASHSCOPE_API_KEY")
            os.environ["LATEXSTRUCT_OCR_PROVIDER"] = "qwen3-vl-flash-cn"
            os.environ["DASHSCOPE_API_KEY"] = "runtime-only-value"
            try:
                srv._config = None
                assert c.get("/api/config").json()["ocr_api_key"] == "已配置"
                r = c.put("/api/config", json={"ocr_model": "qwen3-vl-flash"})
                assert r.status_code == 200
                on_disk = json.loads(open(configmod.CONFIG_PATH, encoding="utf-8").read())
                assert "runtime-only-value" not in json.dumps(on_disk)
            finally:
                if old_provider is None:
                    os.environ.pop("LATEXSTRUCT_OCR_PROVIDER", None)
                else:
                    os.environ["LATEXSTRUCT_OCR_PROVIDER"] = old_provider
                if old_key is None:
                    os.environ.pop("DASHSCOPE_API_KEY", None)
                else:
                    os.environ["DASHSCOPE_API_KEY"] = old_key
        finally:
            configmod.CONFIG_PATH, srv.save_config, srv.load_config = old_path, old_save, old_load


def test_config_host_change_and_save_failures_are_atomic():
    with WorkspaceTmp() as tmp:
        srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
        srv._config = None
        import latexstruct.config as configmod
        from latexstruct.keystore import FakeBackend

        backend = FakeBackend()
        old_path, old_save, old_load = configmod.CONFIG_PATH, srv.save_config, srv.load_config
        configmod.CONFIG_PATH = os.path.join(tmp, "config.json")
        srv.save_config = lambda cfg, secret_updates=None: configmod.save_config(
            cfg, backend=backend, secret_updates=secret_updates,
        )
        srv.load_config = lambda: configmod.load_config(backend=backend)
        try:
            c = TestClient(srv.create_app())
            first = c.put("/api/config", json={
                "decide_api_key": "initial-value", "keyring": False,
            })
            assert first.status_code == 200
            before = c.get("/api/config").json()
            on_disk_before = json.loads(open(configmod.CONFIG_PATH, encoding="utf-8").read())

            # 只换 host 不换 Key：后端拒绝，内存缓存和磁盘均保持原状。
            changed_host = c.put("/api/config", json={
                "decide_base_url": "https://custom.invalid/v1",
            })
            assert changed_host.status_code == 400
            assert "新 API Key" in changed_host.json()["detail"]
            assert c.get("/api/config").json() == before
            assert json.loads(open(configmod.CONFIG_PATH, encoding="utf-8").read()) == on_disk_before

            # 即使同时给 Key，远端 HTTP 也必须由后端安全门拒绝且保持原子。
            insecure = c.put("/api/config", json={
                "decide_base_url": "http://custom.invalid/v1",
                "decide_api_key": "replacement-value",
            })
            assert insecure.status_code == 400
            assert c.get("/api/config").json() == before
            assert json.loads(open(configmod.CONFIG_PATH, encoding="utf-8").read()) == on_disk_before

            # 模拟 keyring 后端失败；deepcopy 候选确保失败更新不会污染运行时缓存。
            backend.ok = False
            failed_keyring = c.put("/api/config", json={
                "keyring": True, "review_api_key": "replacement-review-value",
            })
            assert failed_keyring.status_code == 500
            assert failed_keyring.json()["detail"].startswith("系统凭据管理器不可用")
            assert "Windows Credential Manager" in failed_keyring.json()["action"]
            assert c.get("/api/config").json() == before
            assert json.loads(open(configmod.CONFIG_PATH, encoding="utf-8").read()) == on_disk_before
            backend.ok = True

            # host 与新 Key 同请求原子提交时允许安全 HTTPS 自定义端点。
            changed_with_key = c.put("/api/config", json={
                "decide_base_url": "https://custom.invalid/v1",
                "decide_api_key": "replacement-value",
            })
            assert changed_with_key.status_code == 200
            assert c.get("/api/config").json()["decide_base_url"] == "https://custom.invalid/v1"
        finally:
            configmod.CONFIG_PATH, srv.save_config, srv.load_config = old_path, old_save, old_load


def test_os_error_messages_whitelist_credential_store_failures_only():
    known = (
        "系统凭据管理器不可用；为避免密钥明文落盘，本次设置未保存",
        "API Key 写入系统凭据管理器失败；配置文件未保存",
        "API Key 从系统凭据管理器删除失败；配置文件未保存",
    )
    for message in known:
        content = srv._os_error_content(OSError(message + r" C:\private\must-not-leak"))
        assert content["detail"] == message
        assert "Windows Credential Manager" in content["action"]
        assert "不会降级为明文" in content["action"]
        assert "private" not in json.dumps(content)

    generic = srv._os_error_content(OSError(r"C:\private\config.json permission denied"))
    assert generic["detail"] == "无法读写本地文件；原文件未被覆盖"
    assert "private" not in json.dumps(generic)


def test_qwen_provider_presets_are_public_and_valid():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        response = c.get("/api/providers")
        assert response.status_code == 200
        providers = response.json()["providers"]
        qwen37 = next(p for p in providers if p["id"] == "qwen3.7-flash-cn")
        assert qwen37["model"] == "qwen3.7-flash"
        assert qwen37["vision"] is True
        qwen = next(p for p in providers if p["id"] == "qwen3-vl-flash-cn")
        assert qwen["model"] == "qwen3-vl-flash"
        assert qwen["base_url"].endswith("/compatible-mode/v1")
        assert qwen["api_key_env"] == "DASHSCOPE_API_KEY"
        assert all("api_key" not in p for p in providers)


def test_ocr_multipart_and_jpeg_preview():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        response = _inspect_and_start_image(
            c,
            "page.jpg",
            b"\xff\xd8\xff\xe0" + b"0" * 16,
            "image/jpeg",
            data={"dpi": "200"},
        )
        assert response.status_code == 200
        job_id = response.json()["id"]
        try:
            for _ in range(100):
                state = c.get(f"/api/ocr/jobs/{job_id}").json()
                if state.get("pages", {}).get("1", {}).get("status") != "pending":
                    break
                time.sleep(0.01)
            preview = c.get(f"/api/ocr/jobs/{job_id}/pages/1")
            assert preview.status_code == 200
            assert preview.headers["content-type"].startswith("image/jpeg")
        finally:
            job = srv._ocr_jobs.pop(job_id, {})
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_image_ocr_uses_inspected_job_id_and_replayed_start_is_idempotent():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        png = b"\x89PNG\r\n\x1a\n" + b"0" * 24
        entered = threading.Event()
        release = threading.Event()
        calls = {"count": 0}
        jid = ""

        def slow_vision(client, _system, _user, _image):
            calls["count"] += 1
            client.last_usage = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
            entered.set()
            assert release.wait(timeout=3)
            return "```latex\nA sufficiently long idempotent image OCR result for testing.\n```"

        try:
            inspected = c.post(
                "/api/ocr/inspect",
                files={"file": ("page.png", png, "image/png")},
            )
            assert inspected.status_code == 200
            info = inspected.json()
            jid = info["id"]
            assert info["source_type"] == "image"
            assert re.fullmatch(r"[0-9a-f]{32}", jid)

            with patch("latexstruct.core.ai.LLMClient.chat_vision", slow_vision):
                first = c.post(f"/api/ocr/jobs/{jid}/start")
                assert first.status_code == 200 and first.json()["reused"] is False
                assert entered.wait(timeout=2)
                replay = c.post(f"/api/ocr/jobs/{jid}/start")
                assert replay.status_code == 200
                assert replay.json()["id"] == jid
                assert replay.json()["reused"] is True
                assert replay.json()["status"] == "running"
                assert calls["count"] == 1
                release.set()
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)
            assert state["status"] == "done"
            assert state["usage"]["calls"] == 1
        finally:
            release.set()
            job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_inspects_once_then_processes_only_selected_original_pages():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        fake_pdf = b"%PDF-1.7\nnot-rendered-in-test"
        inspected = ""
        calls = []

        def fake_render(_path, pages, _dpi):
            assert pages == [88, 89, 90]
            for page_no in pages:
                yield page_no, b"\x89PNG\r\n\x1a\n" + bytes([page_no]) * 32

        def fake_vision(client, _system, user, _image):
            match = re.search(r"第\s*(\d+)\s*页", user)
            calls.append(int(match.group(1)))
            client.last_usage = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
            return "```latex\nThis is a sufficiently long faithful transcription for the selected page.\n```"

        try:
            source_outline = [
                {"level": 0, "title": "Introduction", "page": 1},
                {"level": 1, "title": "Selected method", "page": 88},
            ]
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 396, "outline": source_outline},
            ):
                response = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", fake_pdf, "application/pdf")},
                )
            assert response.status_code == 200, response.text
            info = response.json()
            inspected = info["id"]
            assert info["total_pages"] == 396
            assert info["max_pages_per_job"] == srv.MAX_OCR_PAGES_PER_JOB
            assert srv._ocr_jobs[inspected]["status"] == "ready"
            assert srv._ocr_jobs[inspected]["source_outline"] == source_outline

            invalid = c.post(
                f"/api/ocr/jobs/{inspected}/start",
                data={"start_page": "90", "end_page": "88"},
            )
            assert invalid.status_code == 400
            assert srv._ocr_jobs[inspected]["status"] == "ready"

            with (
                patch("latexstruct.ocr.iter_pdf_pages", fake_render),
                patch("latexstruct.core.ai.LLMClient.chat_vision", fake_vision),
            ):
                started = c.post(
                    f"/api/ocr/jobs/{inspected}/start",
                    data={"start_page": "88", "end_page": "90", "dpi": "150"},
                )
                assert started.status_code == 200, started.text
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{inspected}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)

            assert state["status"] == "done", state
            assert state["source_total"] == 396
            assert state["total"] == 3
            assert state["selected_start"] == 88 and state["selected_end"] == 90
            assert state["page"] == 90 and state["current_index"] == 3
            assert list(state["pages"]) == ["88", "89", "90"]
            assert [state["pages"][str(n)]["task_index"] for n in (88, 89, 90)] == [1, 2, 3]
            assert calls == [88, 89, 90]
            assert state["usage"]["calls"] == 3
            assert state["usage"]["total_tokens"] == 360
            assert "target" not in state and "dir" not in state
            assert c.get(f"/api/ocr/jobs/{inspected}/pages/88").status_code == 200
            replay = c.post(f"/api/ocr/jobs/{inspected}/start")
            assert replay.status_code == 200
            assert replay.json()["id"] == inspected
            assert replay.json()["reused"] is True
            assert replay.json()["status"] == "done"
            assert calls == [88, 89, 90]
        finally:
            job = srv._ocr_jobs.pop(inspected, {}) if inspected else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_keeps_completed_pages_when_later_rendering_fails():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        inspected = ""

        def interrupted_render(_path, pages, _dpi):
            assert pages == [1, 2]
            yield 1, b"\x89PNG\r\n\x1a\n" + b"1" * 32
            raise RuntimeError("renderer stopped after first page")

        def fake_vision(client, _system, _user, _image):
            client.last_usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            return "```latex\nA sufficiently long faithful transcription from the completed first page.\n```"

        try:
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 2, "outline": []},
            ):
                inspected = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                ).json()["id"]
            with (
                patch("latexstruct.ocr.iter_pdf_pages", interrupted_render),
                patch("latexstruct.core.ai.LLMClient.chat_vision", fake_vision),
            ):
                started = c.post(
                    f"/api/ocr/jobs/{inspected}/start",
                    data={"start_page": "1", "end_page": "2"},
                )
                assert started.status_code == 200
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{inspected}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)

            assert state["status"] == "partial", state
            assert state["raw_ready"] is True
            assert state["raw_revision"] == 1
            assert state["raw_chars"] > 0
            assert state["progress"] == 0.5
            assert state["pages"]["1"]["status"] == "done"
            assert state["pages"]["2"]["status"] == "pending"
            assert state["error"]
            preview = c.get(f"/api/ocr/jobs/{inspected}/preview")
            assert preview.status_code == 200
            assert preview.headers["x-latexstruct-ocr-revision"] == "1"
            assert int(preview.headers["x-latexstruct-ocr-chars"]) == len(preview.text)
            result = c.get(f"/api/ocr/jobs/{inspected}/result")
            assert result.status_code == 200
            raw = result.text
            assert raw == preview.text
            assert "completed first page" in raw
        finally:
            job = srv._ocr_jobs.pop(inspected, {}) if inspected else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_preview_revision_grows_after_each_page_without_finishing_early():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        inspected = ""
        second_started = threading.Event()
        third_started = threading.Event()
        allow_second = threading.Event()
        allow_third = threading.Event()

        def controlled_render(_path, pages, _dpi):
            assert pages == [2, 3, 4]
            for page_no in pages:
                yield page_no, b"\x89PNG\r\n\x1a\n" + bytes([page_no]) * 32

        def controlled_vision(client, _system, user, _image):
            page_no = int(re.search(r"第\s*(\d+)\s*页", user).group(1))
            client.last_usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            if page_no == 3:
                second_started.set()
                assert allow_second.wait(timeout=3)
            if page_no == 4:
                third_started.set()
                assert allow_third.wait(timeout=3)
            return f"```latex\nA sufficiently long transcription uniquely from original page {page_no}.\n```"

        try:
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 5, "outline": []},
            ):
                inspected = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                ).json()["id"]
            with (
                patch("latexstruct.ocr.iter_pdf_pages", controlled_render),
                patch("latexstruct.core.ai.LLMClient.chat_vision", controlled_vision),
            ):
                started = c.post(
                    f"/api/ocr/jobs/{inspected}/start",
                    data={"start_page": "2", "end_page": "4"},
                )
                assert started.status_code == 200
                assert second_started.wait(timeout=2)

                first = c.get(f"/api/ocr/jobs/{inspected}").json()
                assert first["status"] == "running"
                assert first["raw_revision"] == 1
                assert first["progress"] < 1
                first_preview = c.get(f"/api/ocr/jobs/{inspected}/preview")
                assert first_preview.headers["x-latexstruct-ocr-revision"] == "1"
                assert first["raw_chars"] == len(first_preview.text)
                assert "original page 2" in first_preview.text
                assert "original page 3" not in first_preview.text

                allow_second.set()
                assert third_started.wait(timeout=2)
                second = c.get(f"/api/ocr/jobs/{inspected}").json()
                assert second["status"] == "running"
                assert second["raw_revision"] == 2
                second_preview = c.get(f"/api/ocr/jobs/{inspected}/preview")
                assert second_preview.headers["x-latexstruct-ocr-revision"] == "2"
                assert second["raw_chars"] == len(second_preview.text)
                assert "original page 2" in second_preview.text
                assert "original page 3" in second_preview.text
                assert "original page 4" not in second_preview.text

                allow_third.set()
                for _ in range(100):
                    final = c.get(f"/api/ocr/jobs/{inspected}").json()
                    if final["status"] != "running":
                        break
                    time.sleep(0.02)

            assert final["status"] == "done"
            assert final["raw_revision"] == 3
            assert final["raw_chars"] > second["raw_chars"] > first["raw_chars"]
            final_preview = c.get(f"/api/ocr/jobs/{inspected}/preview")
            assert final_preview.headers["x-latexstruct-ocr-revision"] == "3"
            assert int(final_preview.headers["x-latexstruct-ocr-chars"]) == len(final_preview.text)
            assert "original page 4" in final_preview.text
            assert final["usage"]["calls"] == 3
        finally:
            allow_second.set()
            allow_third.set()
            job = srv._ocr_jobs.pop(inspected, {}) if inspected else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_rejects_malicious_or_excessive_ranges_before_starting_worker():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        before = set(srv._ocr_jobs)
        with patch(
            "latexstruct.ocr.pdf_document_info_bytes",
            return_value={"pages": 600, "outline": []},
        ):
            inspected = c.post(
                "/api/ocr/inspect",
                files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
            )
            assert inspected.status_code == 200
            jid = inspected.json()["id"]
            huge = c.post(
                f"/api/ocr/jobs/{jid}/start",
                data={"start_page": "1", "end_page": "999999999999999999999"},
            )
            excessive = c.post(
                f"/api/ocr/jobs/{jid}/start",
                data={"start_page": "1", "end_page": str(srv.MAX_OCR_PAGES_PER_JOB + 1)},
            )
        assert huge.status_code == 400
        assert excessive.status_code == 400
        assert srv._ocr_jobs[jid]["status"] == "ready"
        # 旧的一次上传直启入口必须 fail-closed，避免跨站表单直接产生模型费用。
        legacy = c.post(
            "/api/ocr/jobs",
            files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
        )
        assert legacy.status_code == 409
        assert set(srv._ocr_jobs) == before | {jid}
        job = srv._ocr_jobs.pop(jid)
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_decisions_and_reject():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.post("/api/projects", json={"text": SAMPLE, "name": "demo2", "mode": "rule"})
        pid = r.json()["id"]
        c.post(f"/api/projects/{pid}/process")
        d = c.get(f"/api/projects/{pid}/decisions").json()
        items = d["items"]
        assert items, "决策清单为空"
        theorem = next(i for i in items if i["env"] == "theorem*" and i["status"] == "applied")
        assert "line" in theorem and "section" in theorem
        # 拒绝定理包裹 → 重新整理后该环境消失、内容不变校验仍通过
        r = c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/reject")
        assert r.status_code == 200
        rejected_items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        assert next(i for i in rejected_items if i["candidate_id"] == theorem["candidate_id"])["status"] == "rejected"
        result = c.get(f"/api/projects/{pid}/result").text
        assert "\\begin{theorem*}" not in result
        info = json.loads(Path(tmp, "projects", pid, "verification.json").read_text(encoding="utf-8"))
        assert info["verification"]["content_invariant"] is True
        # 双语合并等其他修改保留
        assert "（方法）" in result
        # 撤销拒绝（unreject）：该定理包裹恢复，内容不变校验仍通过
        r = c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/unreject")
        assert r.status_code == 200
        result2 = c.get(f"/api/projects/{pid}/result").text
        assert "\\begin{theorem*}" in result2
        info2 = json.loads(Path(tmp, "projects", pid, "verification.json").read_text(encoding="utf-8"))
        assert info2["verification"]["content_invariant"] is True
        assert info2["verification"]["decisions_reused"] is True


def test_rulesets_and_folder_import():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.get("/api/rulesets").json()
        assert "bilingual" in r["packs"] and "academic-paper" in r["packs"]
        templates = c.get("/api/templates").json()
        assert templates["ocr_default"] == "elegantbook"
        assert templates["default"] == "elegantbook"
        assert templates["export_default"] == "elegantbook"
        assert templates["fixed"] is True
        assert {item["id"] for item in templates["templates"]} == {"elegantbook"}
        invalid = c.post("/api/projects", json={
            "text": "\\documentclass{article}\n\\begin{document}\nX\n\\end{document}\n",
            "template": "model-generated-preamble",
        })
        assert invalid.status_code == 400
        # 文件夹导入：main + chapters 两文件
        files = {
            "main.tex": "\\documentclass{book}\n\\begin{document}\n\\input{chapters/ch01}\n\\end{document}\n",
            "chapters/ch01.tex": "\\section{One}\n\nTheorem 1. A statement.\n\nProof. By definition.\n",
            "images/pixel.bin": {"encoding": "base64", "data": "AAEC/w=="},
        }
        r = c.post("/api/projects/folder", json={"files": files, "name": "book", "mode": "rule"})
        assert r.status_code == 200
        d = r.json()
        assert d["graph"]["main_rel"] == "main.tex"
        assert "chapters/ch01.tex" in d["graph"]["files"]
        pid = d["id"]
        # 依赖图端点
        g = c.get(f"/api/projects/{pid}/graph").json()
        assert g["kind"] == "folder" and g["graph"]["main_rel"] == "main.tex"
        # zip 导出
        z = c.get(f"/api/projects/{pid}/export-folder")
        assert z.status_code == 200 and "zip" in z.headers["content-type"]
        with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
            assert zf.read("images/pixel.bin") == b"\x00\x01\x02\xff"
            assert "\\begin{theorem*}[1]" in zf.read("chapters/ch01.tex").decode("utf-8")
            assert b"v4.7 ElegantBook document class" in zf.read("elegantbook.cls")
            assert "ELEGANTBOOK-LICENSE.txt" in zf.namelist()
            assert "ELEGANTBOOK-BUNDLE-README.md" in zf.namelist()
            assert zf.read("LATEXSTRUCT-REPORT.md") == c.get(f"/api/projects/{pid}/report").content
        # v1.1.2 的旧 marker 尚无 report_sha256；读取旧项目时继续兼容。
        store = srv.get_store()
        project_dir = Path(store._dir(pid))
        marker_path = project_dir / "verification.json"
        legacy_marker = json.loads(marker_path.read_text(encoding="utf-8"))
        legacy_marker.pop("report_sha256")
        marker_path.write_text(json.dumps(legacy_marker, ensure_ascii=False), encoding="utf-8")
        assert c.get(f"/api/projects/{pid}/export-folder").status_code == 200
        # 审阅拒绝会重跑，但逐文件结果和原始二进制资源仍可安全导出。
        items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        theorem = next(i for i in items if i["kind"] == "theorem-like")
        assert c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/reject").status_code == 200
        assert c.get(f"/api/projects/{pid}/export-folder").status_code == 200
        # 文件夹导出同样必须核对 result.tex 与最终 verification marker。
        report_text = store.read_report(pid)
        store._write_text(str(project_dir), "report.md", report_text + "\n篡改")
        stale_report = c.get(f"/api/projects/{pid}/export-folder")
        assert stale_report.status_code == 409 and "汇报" in stale_report.json()["detail"]
        store._write_text(str(project_dir), "report.md", report_text)
        store._write_text(
            str(project_dir), "result.tex", store.read_result(pid) + "% stale hash\n"
        )
        stale = c.get(f"/api/projects/{pid}/export-folder")
        assert stale.status_code == 409 and "不一致" in stale.json()["detail"]


def test_folder_import_rejects_unsafe_paths_and_incomplete_graphs():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        bad = c.post("/api/projects/folder", json={"files": {"../outside.tex": "x"}})
        assert bad.status_code == 400
        assert "不安全" in bad.json()["detail"]

        files = {
            "main.tex": "\\documentclass{book}\n\\begin{document}\n\\input{missing}\n\\end{document}\n",
        }
        created = c.post("/api/projects/folder", json={"files": files, "mode": "rule"})
        assert created.status_code == 200 and created.json()["ok"] is False
        pid = created.json()["id"]
        blocked = c.get(f"/api/projects/{pid}/export-folder")
        assert blocked.status_code == 409 and "安全检查" in blocked.json()["detail"]


def test_zip_import_strips_wrapper_and_defers_processing():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "my-book/main.tex",
                "\\documentclass{book}\n\\begin{document}\n"
                "\\input{chapters/one}\n\\end{document}\n",
            )
            zf.writestr(
                "my-book/chapters/one.tex",
                "Theorem 1. A statement.\n\nProof. Clear.\n",
            )
            zf.writestr("my-book/images/pixel.bin", b"\x00\x01\xff")
        created = c.post(
            "/api/projects/archive",
            files={"file": ("my-book.zip", buf.getvalue(), "application/zip")},
            data={"mode": "rule", "defer_process": "true"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["processed"] is False
        assert body["graph"]["main_rel"] == "main.tex"
        pid = body["id"]
        assert c.get(f"/api/projects/{pid}/result").status_code == 404

        started = c.post(f"/api/projects/{pid}/process/start")
        assert started.status_code == 200
        for _ in range(200):
            state = c.get(f"/api/projects/{pid}/process/status").json()
            if state["status"] in {"done", "error", "cancelled"}:
                break
            time.sleep(0.01)
        assert state["status"] == "done", state
        assert state["result"]["ok"] is True
        exported = c.get(f"/api/projects/{pid}/export-folder")
        assert exported.status_code == 200
        with zipfile.ZipFile(io.BytesIO(exported.content)) as zf:
            assert "main.tex" in zf.namelist()
            assert "my-book/main.tex" not in zf.namelist()
            assert zf.read("images/pixel.bin") == b"\x00\x01\xff"


def test_zip_import_rejects_traversal_and_extreme_compression():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        bad_path = io.BytesIO()
        with zipfile.ZipFile(bad_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../outside.tex", "unsafe")
        response = c.post(
            "/api/projects/archive",
            files={"file": ("bad.zip", bad_path.getvalue(), "application/zip")},
        )
        assert response.status_code == 400
        assert "不安全" in response.json()["detail"]

        bomb = io.BytesIO()
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("main.tex", "A" * 1_100_000)
        response = c.post(
            "/api/projects/archive",
            files={"file": ("bomb.zip", bomb.getvalue(), "application/zip")},
        )
        assert response.status_code == 400
        assert "压缩比异常" in response.json()["detail"]


def test_background_process_can_pause_preview_resume_and_finish():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "pause-demo", "mode": "rule"}
        ).json()["id"]
        entered = threading.Event()
        original_pipeline = srv.run_pipeline

        def slow_pipeline(*args, **kwargs):
            callback = kwargs.get("progress_callback")
            control = kwargs.get("control_callback")
            if callback:
                callback("test-wait", 0.12, "正在测试安全暂停点", {
                    "preview": args[0], "preview_label": "测试草稿"
                })
            entered.set()
            for _ in range(100):
                time.sleep(0.005)
                if control:
                    control()
            return original_pipeline(*args, **kwargs)

        with patch.object(srv, "run_pipeline", slow_pipeline):
            assert c.post(f"/api/projects/{pid}/process/start").status_code == 200
            assert entered.wait(1)
            assert c.post(f"/api/projects/{pid}/process/pause").status_code == 200
            for _ in range(100):
                state = c.get(f"/api/projects/{pid}/process/status").json()
                if state["status"] == "paused":
                    break
                time.sleep(0.01)
            assert state["status"] == "paused", state
            preview = c.get(f"/api/projects/{pid}/process/preview")
            assert preview.status_code == 200 and "documentclass" in preview.text
            assert state["preview_chars"] == len(preview.text)
            assert preview.headers["X-LaTeXStruct-Preview-Revision"] == str(state["preview_revision"])
            assert preview.headers["Cache-Control"] == "no-store"
            assert c.post(f"/api/projects/{pid}/process/resume").status_code == 200
            for _ in range(300):
                state = c.get(f"/api/projects/{pid}/process/status").json()
                if state["status"] in {"done", "error", "cancelled"}:
                    break
                time.sleep(0.01)
        assert state["status"] == "done", state
        assert c.get(f"/api/projects/{pid}/result").status_code == 200


def test_background_process_commits_ai_review_without_runtime_patch_objects():
    """A completed multi-batch review must not fail at the final JSON commit."""
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "review-commit", "mode": "rule"},
        ).json()["id"]
        original_pipeline = srv.run_pipeline

        def pipeline_with_full_runtime_review(*args, **kwargs):
            result = original_pipeline(*args, **kwargs)
            assert result.applied
            runtime_patch = result.applied[0]
            result.review = {
                "findings": [{
                    "candidate_id": runtime_patch.decision.candidate_id,
                    "verdict": "ok",
                    "reason": "复查通过",
                }],
                "invalid": [],
                "usage": {"input_tokens": 1234, "output_tokens": 56},
                "decisions": result.decisions,
                "out": result.result.splitlines(),
                # Match the reported 48-candidate job and retain the exact
                # non-JSON AppliedPatch type that caused the v1.1.6 failure.
                "applied": [runtime_patch] * 48,
                "rejected": result.rejected,
            }
            return result

        with patch.object(srv, "run_pipeline", pipeline_with_full_runtime_review):
            assert c.post(f"/api/projects/{pid}/process/start").status_code == 200
            for _ in range(300):
                state = c.get(f"/api/projects/{pid}/process/status").json()
                if state["status"] in {"done", "error", "cancelled"}:
                    break
                time.sleep(0.01)

        assert state["status"] == "done", state
        assert state["progress"] == 1.0
        assert c.get(f"/api/projects/{pid}/result").status_code == 200
        record = json.loads(
            (Path(srv.get_store()._dir(pid)) / "verification.json").read_text(
                encoding="utf-8"
            )
        )
        review = record["review"]
        assert set(review) == {"findings", "invalid", "usage"}
        assert len(review["findings"]) == 1
        assert review["findings"][0]["candidate_id"]
        assert review["findings"][0]["verdict"] == "ok"
        assert review["findings"][0]["reason"] == "复查通过"
        assert review["invalid"] == []
        assert review["usage"] == {"input_tokens": 1234, "output_tokens": 56}
        assert not ({"decisions", "out", "applied", "rejected"} & review.keys())
        assert "AppliedPatch" not in json.dumps(record, ensure_ascii=False)


def test_task_error_hides_internal_json_runtime_type():
    message = srv._safe_task_error(
        TypeError("Object of type AppliedPatch is not JSON serializable")
    )
    assert "AppliedPatch" not in message
    assert "原项目和上一份已验证结果保持不变" in message
    assert "更新到最新版本" in message


def test_background_commit_failure_never_reports_one_hundred_percent():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "commit-failure", "mode": "rule"},
        ).json()["id"]
        store = srv.get_store()
        with patch.object(store, "set_result", side_effect=OSError("simulated disk failure")):
            assert c.post(f"/api/projects/{pid}/process/start").status_code == 200
            for _ in range(300):
                state = c.get(f"/api/projects/{pid}/process/status").json()
                if state["status"] in {"done", "error", "cancelled"}:
                    break
                time.sleep(0.01)

        assert state["status"] == "error", state
        assert state["phase"] == "error"
        assert state["progress"] == 0.99
        assert c.get(f"/api/projects/{pid}/result").status_code == 404


def test_project_list_keeps_latest_terminal_process_status_and_message():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        project_ids = {
            status: c.post(
                "/api/projects",
                json={"text": SAMPLE, "name": status, "mode": "rule"},
            ).json()["id"]
            for status in ("done", "error", "cancelled")
        }

        done = srv._process_jobs.create(project_ids["done"], SAMPLE)
        srv._process_jobs.complete(done["id"], {"ok": True})
        failed = srv._process_jobs.create(project_ids["error"], SAMPLE)
        srv._process_jobs.fail(failed["id"], "未配置 API Key")
        cancelled = srv._process_jobs.create(project_ids["cancelled"], SAMPLE)
        srv._process_jobs.cancelled(cancelled["id"])

        listed = {item["id"]: item for item in c.get("/api/projects").json()}
        assert listed[project_ids["done"]]["processing"] == {
            "status": "done",
            "progress": 1.0,
            "message": "安全检查通过",
            "error": "",
        }
        assert listed[project_ids["error"]]["processing"] == {
            "status": "error",
            "progress": 0.0,
            "message": "处理未完成，原项目保持不变",
            "error": "未配置 API Key",
        }
        assert listed[project_ids["cancelled"]]["processing"] == {
            "status": "cancelled",
            "progress": 0.0,
            "message": "未保存未验证草稿，原项目保持不变",
            "error": "",
        }


def test_batch_reject_and_reset():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.post("/api/projects", json={"text": SAMPLE, "name": "demo3", "mode": "rule"})
        pid = r.json()["id"]
        c.post(f"/api/projects/{pid}/process")
        items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        applied = [i for i in items if i["status"] == "applied"]
        assert len(applied) >= 2
        # 批量拒绝前两个
        cids = [i["candidate_id"] for i in applied[:2]]
        c.post(f"/api/projects/{pid}/decisions/reject-batch", json={"cids": cids})
        d = c.get(f"/api/projects/{pid}/decisions").json()
        assert d["excludes"] == sorted(cids)
        # 重置 → 全部恢复
        c.post(f"/api/projects/{pid}/decisions/reset")
        d2 = c.get(f"/api/projects/{pid}/decisions").json()
        assert d2["excludes"] == []
        assert len([i for i in d2["items"] if i["status"] == "applied"]) >= 2


def test_ocr_job_error_path_without_key():
    with WorkspaceTmp() as tmp:
        srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
        srv._config = None
        c = TestClient(srv.create_app())
        png = b"\x89PNG\r\n\x1a\n" + b"0" * 16
        r = _inspect_and_start_image(c, "a.png", png, "image/png")
        assert r.status_code == 200
        jid = r.json()["id"]
        # 无 Key：任务进入 partial，禁止混入结构化流程，但允许逐页恢复。
        for _ in range(50):
            j = c.get(f"/api/ocr/jobs/{jid}").json()
            if j["status"] != "running":
                break
            import time as _t

            _t.sleep(0.2)
        assert j["status"] == "partial"
        assert j["errors"], j
        assert j["pages"] and list(j["pages"].values())[0]["status"] == "error"
        assert c.post(f"/api/ocr/jobs/{jid}/import").status_code == 409


def test_ocr_per_page_endpoints():
    with WorkspaceTmp() as tmp:
        srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
        srv._config = None
        c = TestClient(srv.create_app())
        png = b"\x89PNG\r\n\x1a\n" + b"0" * 16
        r = _inspect_and_start_image(c, "a.png", png, "image/png")
        jid = r.json()["id"]
        for _ in range(50):
            j = c.get(f"/api/ocr/jobs/{jid}").json()
            if j["status"] != "running":
                break
            import time as _t

            _t.sleep(0.2)
        # 页面 PNG / tex 端点
        r = c.get(f"/api/ocr/jobs/{jid}/pages/1")
        assert r.status_code == 200 and r.headers["content-type"].startswith("image/png")
        r = c.get(f"/api/ocr/jobs/{jid}/pages/1/tex")
        assert r.status_code == 200
        r = c.get(f"/api/ocr/jobs/{jid}/pages/999/tex")
        assert r.status_code == 404
        # 单页重试：无 Key 时仍优雅失败（ok=False、200 返回）
        r = c.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False and body["page"] == 1 and body["status"] == "partial"


def test_ocr_retry_rejects_same_page_double_click_without_double_counting_usage():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        png = b"\x89PNG\r\n\x1a\n" + b"0" * 24
        retry_started = threading.Event()
        allow_retry = threading.Event()
        calls = {"count": 0}
        first_response = {}
        jid = ""

        def controlled_vision(client, _system, _user, _image):
            calls["count"] += 1
            client.last_usage = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
            if calls["count"] > 1:
                retry_started.set()
                assert allow_retry.wait(timeout=3)
            return (
                "```latex\nA sufficiently long OCR transcription for retry concurrency "
                f"testing, revision {calls['count']}.\n```"
            )

        try:
            with patch("latexstruct.core.ai.LLMClient.chat_vision", controlled_vision):
                created = _inspect_and_start_image(c, "a.png", png, "image/png")
                assert created.status_code == 200
                jid = created.json()["id"]
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)
                assert state["status"] == "done"
                with patch(
                    "latexstruct.server.downloads.download_root",
                    return_value=Path(tmp) / "ocr-downloads",
                ):
                    assert c.post(f"/api/ocr/jobs/{jid}/save").status_code == 200
                with srv._ocr_jobs_lock:
                    first_revision = srv._ocr_jobs[jid]["raw_revision"]
                    assert srv._ocr_jobs[jid]["downloaded_revision"] == first_revision

                def run_first_retry():
                    first_response["value"] = c.post(f"/api/ocr/jobs/{jid}/pages/1/retry")

                thread = threading.Thread(target=run_first_retry)
                thread.start()
                assert retry_started.wait(timeout=2)
                duplicate = c.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
                assert duplicate.status_code == 409
                allow_retry.set()
                thread.join(timeout=3)

            assert first_response["value"].status_code == 200
            final = c.get(f"/api/ocr/jobs/{jid}").json()
            assert final["status"] == "done"
            assert final["pages"]["1"]["attempts"] == 2
            assert final["pages"]["1"]["retrying"] is False
            assert final["usage"]["calls"] == 2
            assert final["usage"]["total_tokens"] == 20
            assert final["raw_revision"] == first_revision + 1
            assert final["downloaded_revision"] == first_revision
            with patch("latexstruct.updater.check_for_updates") as check:
                blocked = c.post("/api/update/install")
            assert blocked.status_code == 409
            assert "尚未保存的 OCR 结果" in blocked.json()["detail"]
            check.assert_not_called()
        finally:
            allow_retry.set()
            job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_failed_paid_retry_invalidates_saved_usage_and_page_snapshot():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        png = b"\x89PNG\r\n\x1a\n" + b"0" * 24
        jid = ""

        def initial_success(client, _system, _user, _image):
            client.last_usage = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
            return "```latex\nA sufficiently long OCR result saved before a paid retry failure.\n```"

        def paid_failure(client, _system, _user, _image):
            from latexstruct.core.ai import LLMError

            client.last_usage = {"prompt_tokens": 6, "completion_tokens": 1, "total_tokens": 7}
            raise LLMError("temporary paid retry failure")

        try:
            with patch("latexstruct.core.ai.LLMClient.chat_vision", initial_success):
                created = _inspect_and_start_image(c, "a.png", png, "image/png")
                jid = created.json()["id"]
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)
            assert state["status"] == "done"
            with patch(
                "latexstruct.server.downloads.download_root",
                return_value=Path(tmp) / "ocr-downloads",
            ):
                saved = c.post(f"/api/ocr/jobs/{jid}/save")
            assert saved.status_code == 200
            saved_snapshot = saved.json()

            with patch("latexstruct.core.ai.LLMClient.chat_vision", paid_failure):
                retried = c.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
            assert retried.status_code == 200 and retried.json()["ok"] is False
            final = c.get(f"/api/ocr/jobs/{jid}").json()
            assert final["status"] == "partial"
            assert final["raw_revision"] == saved_snapshot["revision"]
            assert final["usage_revision"] > saved_snapshot["usage_revision"]
            assert final["page_revision"] > saved_snapshot["page_revision"]
            assert final["downloaded_usage_revision"] == saved_snapshot["usage_revision"]
            assert final["downloaded_page_revision"] == saved_snapshot["page_revision"]

            with patch("latexstruct.updater.check_for_updates") as check:
                blocked = c.post("/api/update/install")
            assert blocked.status_code == 409
            assert "尚未保存的 OCR 结果" in blocked.json()["detail"]
            check.assert_not_called()

            with srv._ocr_jobs_lock:
                srv._ocr_jobs[jid]["created"] = time.time() - srv.OCR_JOB_TTL_SECONDS - 60
            srv._cleanup_ocr_jobs()
            assert jid in srv._ocr_jobs
        finally:
            job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_ocr_import_blocks_duplicate_import_and_retry_until_snapshot_is_saved():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        import_started = threading.Event()
        allow_import = threading.Event()
        response = {}
        jid = "importing-ocr"
        job_dir = tempfile.mkdtemp(prefix="ocr-import-", dir=tmp)
        page_path = os.path.join(job_dir, "page-1.png")
        Path(page_path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 24)
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "status": "done",
                "raw_ready": True,
                "raw_tex": "A paid OCR snapshot that must be imported exactly once.",
                "raw_revision": 1,
                "downloaded_revision": 0,
                "imported_revision": 0,
                "importing": False,
                "usage": {"calls": 1, "total_tokens": 10},
                "pages": {1: {"png": page_path, "status": "done"}},
                "dir": job_dir,
            }

        store = srv.get_store()
        original_create = store.create

        def slow_create(*args, **kwargs):
            import_started.set()
            assert allow_import.wait(timeout=3)
            return original_create(*args, **kwargs)

        def run_import():
            response["value"] = c.post(f"/api/ocr/jobs/{jid}/import")

        try:
            with patch.object(store, "create", slow_create):
                thread = threading.Thread(target=run_import)
                thread.start()
                assert import_started.wait(timeout=2)
                duplicate = c.post(f"/api/ocr/jobs/{jid}/import")
                retry = c.post(f"/api/ocr/jobs/{jid}/pages/1/retry")
                assert duplicate.status_code == 409
                assert retry.status_code == 409
                allow_import.set()
                thread.join(timeout=3)

            assert response["value"].status_code == 200
            first_body = response["value"].json()
            repeated = c.post(f"/api/ocr/jobs/{jid}/import")
            assert repeated.status_code == 200
            assert repeated.json()["id"] == first_body["id"]
            assert repeated.json()["reused"] is True
            with srv._ocr_jobs_lock:
                saved = srv._ocr_jobs[jid]
                assert saved["importing"] is False
                assert saved["imported_revision"] == saved["raw_revision"] == 1
                assert saved["imported_usage_revision"] == saved.get("usage_revision", 0)
                assert saved["imported_page_revision"] == saved.get("page_revision", 0)
        finally:
            allow_import.set()
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)
            shutil.rmtree(job_dir, ignore_errors=True)


def test_ocr_transient_page_failure_retries_then_imports_raw_and_structured_separately():
    with WorkspaceTmp() as tmp:
        srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
        srv._config = None
        c = TestClient(srv.create_app())
        calls = {"count": 0}

        def flaky_vision(_self, _system, _user, _image):
            calls["count"] += 1
            if calls["count"] == 1:
                from latexstruct.core.ai import LLMError

                raise LLMError("暂时性网络错误")
            return "```latex\nTheorem 1. A recovered statement.\n\nProof. Recovered proof text.\n```"

        png = b"\x89PNG\r\n\x1a\n" + b"0" * 16
        with patch("latexstruct.core.ai.LLMClient.chat_vision", flaky_vision):
            created = _inspect_and_start_image(c, "a.png", png, "image/png")
            jid = created.json()["id"]
            for _ in range(100):
                state = c.get(f"/api/ocr/jobs/{jid}").json()
                if state["status"] != "running":
                    break
                time.sleep(0.02)
        assert state["status"] == "done"
        assert state["pages"]["1"]["attempts"] == 2
        assert c.get(f"/api/ocr/jobs/{jid}/result").headers["x-latexstruct-ocr-complete"] == "true"

        def fake_structure_ai(_self, system, user):
            if '"findings"' in system:
                return {"findings": []}, {"total_tokens": 4}
            decisions = []
            for block in re.split(r"(?=### 候选 c-\d+)", user):
                header = re.search(r"### 候选 (c-\d+).*?kind: ([^ |]+).*?建议环境: ([^ |]+)", block, re.S)
                if header is None:
                    continue
                candidate_id, kind, env = header.groups()
                marked = [int(value) for value in re.findall(r">>>\[\s*(\d+)\]", block)]
                if kind not in {"theorem-like", "proof"} or not marked:
                    decisions.append({
                        "candidate_id": candidate_id,
                        "action": "none",
                        "reason": "离线测试无需处理",
                    })
                    continue
                decisions.append({
                    "candidate_id": candidate_id,
                    "action": "wrap",
                    "env": "proof" if kind == "proof" else env,
                    "body_span": {
                        "start_line": min(marked),
                        "end_line": max(marked),
                    },
                    "confidence": 0.99,
                    "reason": "离线假模型确认结构",
                })
            return {"decisions": decisions}, {"total_tokens": 8}

        # AI 模式现在 fail-closed，此离线端到端测试必须显式提供
        # 决策/复查假模型，不再依赖旧版“无 Key 静默降级规则”行为。
        with patch("latexstruct.core.ai.LLMClient.chat_json", fake_structure_ai):
            imported = c.post(f"/api/ocr/jobs/{jid}/import?mode=ai")
            assert imported.status_code == 200
            pid = imported.json()["id"]
            assert imported.json()["process"]["status"] in {"running", "committing", "done"}
            for _ in range(600):
                process = c.get(f"/api/projects/{pid}/process/status").json()
                if process["status"] not in {"running", "pausing", "paused", "committing"}:
                    break
                time.sleep(0.02)
        assert process["status"] == "done", process
        raw = c.get(f"/api/projects/{pid}/source").text
        structured = c.get(f"/api/projects/{pid}/result").text
        assert "Theorem 1." in raw and "\\begin{theorem}" not in raw
        assert "% LaTeXStruct template: elegantbook v4.7" in structured
        assert "\\documentclass[lang=en,11pt]{elegantbook}" in structured
        assert "\\begin{theorem*}[1]" in structured
        assert "Theorem 1. A recovered statement." not in structured
        assert "\\begin{proof}" in structured
        project = srv.get_store().get(pid)
        assert project["kind"] == "ocr"
        assert project["mode"] == "ai"
        assert project["template"] == "elegantbook"
        job = srv._ocr_jobs.pop(jid, {})
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_ocr_import_rejects_unknown_structure_mode():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        response = c.post("/api/ocr/jobs/missing/import?mode=freeform-agent")
        assert response.status_code == 400
        assert "AI 或规则" in response.json()["detail"]


def test_ocr_page_with_broken_display_is_done_but_marked_low_confidence():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)

        def broken_display(_self, _system, _user, _image):
            return r"""```latex
\[
\begin{aligned}
a &= b + c \tag{5.4}
\end{aligned}
This paragraph is long enough not to trigger the short-page heuristic.
\[
d &= e
\]
```"""

        png = b"\x89PNG\r\n\x1a\n" + b"0" * 16
        jid = ""
        try:
            with patch("latexstruct.core.ai.LLMClient.chat_vision", broken_display):
                created = _inspect_and_start_image(c, "a.png", png, "image/png")
                assert created.status_code == 200, created.text
                jid = created.json()["id"]
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)

            assert state["status"] == "done"
            assert state["pages"]["1"]["status"] == "done"
            assert state["pages"]["1"]["low_conf"] is True
        finally:
            job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_update_install_rejects_active_processing_before_network():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        srv._process_jobs.create("busy-project", "source")
        with patch("latexstruct.updater.check_for_updates") as check:
            response = c.post("/api/update/install")
        assert response.status_code == 409
        assert "结构化任务" in response.json()["detail"]
        assert "Token" in response.json()["detail"]
        check.assert_not_called()
        srv._process_jobs.clear()


def test_update_install_rejects_active_ocr_before_network():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with srv._ocr_jobs_lock:
            srv._ocr_jobs["busy-ocr"] = {"status": "running"}
        try:
            with patch("latexstruct.updater.check_for_updates") as check:
                response = c.post("/api/update/install")
            assert response.status_code == 409
            assert "OCR 任务" in response.json()["detail"]
            check.assert_not_called()
        finally:
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop("busy-ocr", None)


def test_update_preparation_blocks_deleting_preserved_ocr_state():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = "preserved-while-updating"
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "status": "done",
                "raw_ready": True,
                "raw_revision": 1,
                "downloaded_revision": 1,
                "imported_revision": 0,
                "usage": {"calls": 1, "total_tokens": 10},
            }
        try:
            with srv._update_state_lock:
                srv._update_preparing = True
            response = c.delete(f"/api/ocr/jobs/{jid}")
            assert response.status_code == 409
            assert "更新包正在准备" in response.json()["detail"]
            with srv._ocr_jobs_lock:
                assert jid in srv._ocr_jobs
        finally:
            srv._cancel_update_preparation()
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)


def test_update_install_preserves_completed_paid_ocr_until_downloaded_or_discarded():
    from latexstruct.updater import UpdateInfo

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with srv._ocr_jobs_lock:
            srv._ocr_jobs["paid-ocr"] = {
                "id": "paid-ocr",
                "status": "done",
                "raw_ready": True,
                "raw_tex": "paid OCR result",
                "raw_revision": 1,
                "downloaded_revision": 0,
                "imported_revision": 0,
                "importing": False,
                "usage": {"calls": 1, "total_tokens": 100},
            }
        try:
            with patch("latexstruct.updater.check_for_updates") as check:
                blocked = c.post("/api/update/install")
            assert blocked.status_code == 409
            assert "尚未保存的 OCR 结果" in blocked.json()["detail"]
            check.assert_not_called()

            # 仅把正文读进 WebView/剪贴板并不能证明文件已落盘；更新仍须阻止。
            assert c.get("/api/ocr/jobs/paid-ocr/result").status_code == 200
            with srv._ocr_jobs_lock:
                assert srv._ocr_jobs["paid-ocr"]["downloaded_revision"] == 0
            with patch(
                "latexstruct.server.downloads.download_root",
                return_value=Path(tmp) / "ocr-downloads",
            ):
                downloaded = c.post("/api/ocr/jobs/paid-ocr/save")
            assert downloaded.status_code == 200
            with srv._ocr_jobs_lock:
                assert srv._ocr_jobs["paid-ocr"]["downloaded_revision"] == 1
            with patch(
                "latexstruct.updater.check_for_updates",
                return_value=UpdateInfo(False, latest="v1.1.1"),
            ) as check:
                latest = c.post("/api/update/install")
            assert latest.status_code == 409
            assert latest.json()["detail"] == "当前已经是最新版本，无需重复安装"
            check.assert_called_once()

            discarded = c.delete("/api/ocr/jobs/paid-ocr")
            assert discarded.status_code == 200
        finally:
            srv._cancel_update_preparation()
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop("paid-ocr", None)


def test_update_install_failures_are_non_200_and_release_reservation():
    from latexstruct.updater import UpdateInfo

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with patch(
            "latexstruct.updater.check_for_updates",
            return_value=UpdateInfo(False, latest="v1.1.1"),
        ):
            response = c.post("/api/update/install")
        assert response.status_code == 409
        assert response.json()["detail"] == "当前已经是最新版本，无需重复安装"
        assert srv._update_preparing is False


def test_update_install_schedules_exit_only_after_verified_download():
    from latexstruct.updater import UpdateInfo

    info = UpdateInfo(
        True,
        latest="v1.2.3",
        url=(
            "https://github.com/Ararataki-number-one/LaTeXStruct/"
            "releases/download/v1.2.3/LaTeXStruct-setup-1.2.3.exe"
        ),
        size=123,
        digest="sha256:" + "a" * 64,
    )
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with (
            patch("latexstruct.updater.check_for_updates", return_value=info),
            patch(
                "latexstruct.updater.download_update",
                return_value="C:/Temp/LaTeXStruct-setup-1.2.3.exe",
            ) as download,
            patch("latexstruct.updater.schedule_installer_after_exit") as schedule,
            patch("latexstruct.updater.request_application_exit") as close_app,
        ):
            response = c.post("/api/update/install")
            assert response.status_code == 202
            job_id = response.json()["job_id"]
            for _ in range(100):
                state = c.get(f"/api/update/status/{job_id}").json()
                if state["status"] == "restarting":
                    break
                time.sleep(0.01)
        assert response.json()["ok"] is True
        assert "installer" not in response.json()  # 不向前端泄露本机临时路径
        assert state["status"] == "restarting"
        assert state["progress"] == 1.0
        args, kwargs = download.call_args
        assert args == (info,) and callable(kwargs["progress"])
        schedule.assert_called_once_with(
            "C:/Temp/LaTeXStruct-setup-1.2.3.exe",
            previous_version="1.1.8",
            expected_version="v1.2.3",
        )
        close_app.assert_called_once_with(delay=1.2)
        srv._cancel_update_preparation()


def test_update_download_reports_progress_and_can_be_cancelled():
    from latexstruct.updater import UpdateInfo

    info = UpdateInfo(
        True,
        latest="v1.2.3",
        url=(
            "https://github.com/Ararataki-number-one/LaTeXStruct/"
            "releases/download/v1.2.3/LaTeXStruct-setup-1.2.3.exe"
        ),
        notes="## 新增\n- 更新弹窗",
        size=100,
        digest="sha256:" + "a" * 64,
    )
    entered = threading.Event()
    release = threading.Event()

    def waiting_download(_info, progress):
        entered.set()
        release.wait(timeout=2)
        progress(25, 100)
        raise AssertionError("取消后的进度回调必须先中止下载")

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with (
            patch("latexstruct.updater.check_for_updates", return_value=info),
            patch("latexstruct.updater.download_update", side_effect=waiting_download),
            patch("latexstruct.updater.schedule_installer_after_exit") as schedule,
        ):
            response = c.post("/api/update/install")
            assert response.status_code == 202
            job_id = response.json()["job_id"]
            assert entered.wait(timeout=2)
            cancelling = c.post(f"/api/update/status/{job_id}/cancel")
            assert cancelling.status_code == 200
            release.set()
            for _ in range(100):
                state = c.get(f"/api/update/status/{job_id}").json()
                if state["status"] == "cancelled":
                    break
                time.sleep(0.01)

        assert state["status"] == "cancelled"
        assert "cancel_requested" not in state
        assert srv._update_preparing is False
        schedule.assert_not_called()


def test_update_result_only_reports_a_real_installer_upgrade():
    from latexstruct import __version__

    current = srv.create_app(updated_from="v0.9.9.0")
    with TestClient(current) as c:
        result = c.get("/api/update/result")
    assert result.status_code == 200
    assert result.json() == {
        "updated": True,
        "previous": "0.9.9",
        "current": __version__,
    }
    assert re.fullmatch(r"\d+\.\d+\.\d+", result.json()["current"])

    invalid = srv.create_app(updated_from="not-a-version")
    with TestClient(invalid) as c:
        assert c.get("/api/update/result").json()["updated"] is False


def test_native_save_repairs_webview_download_and_never_overwrites():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "下载测试", "mode": "rule"}
        ).json()["id"]
        assert c.post(f"/api/projects/{pid}/process").json()["ok"] is True
        downloads = Path(tmp) / "downloads"

        with patch("latexstruct.server.downloads.download_root", return_value=downloads):
            result_first = c.post(f"/api/projects/{pid}/exports/result/save")
            result_second = c.post(f"/api/projects/{pid}/exports/result/save")
            package = c.post(f"/api/projects/{pid}/exports/package/save")
            report = c.post(f"/api/projects/{pid}/exports/report/save")

        assert (
            result_first.status_code
            == result_second.status_code
            == package.status_code
            == report.status_code
            == 200
        )
        assert result_first.json()["folder"] == "下载/LaTeXStruct"
        first_path = downloads / result_first.json()["filename"]
        second_path = downloads / result_second.json()["filename"]
        package_path = downloads / package.json()["filename"]
        report_path = downloads / report.json()["filename"]
        assert first_path != second_path
        assert first_path.read_bytes() == c.get(f"/api/projects/{pid}/export").content
        assert second_path.read_bytes() == first_path.read_bytes()
        with zipfile.ZipFile(package_path) as zf:
            assert zf.read("main.tex") == first_path.read_bytes()
            assert b"v4.7 ElegantBook document class" in zf.read("elegantbook.cls")
            assert "ELEGANTBOOK-LICENSE.txt" in zf.namelist()
        assert report_path.read_bytes() == c.get(f"/api/projects/{pid}/report").content


def test_native_save_is_fail_closed_for_unsafe_or_tampered_artifacts():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        unsafe = (
            "\\documentclass{book}\n\\begin{document}\n"
            "\\[x=y\\tag{1}\\tag{2}\\]\n\\end{document}\n"
        )
        pid = c.post(
            "/api/projects", json={"text": unsafe, "name": "unsafe", "mode": "rule"}
        ).json()["id"]
        assert c.post(f"/api/projects/{pid}/process").json()["ok"] is False
        downloads = Path(tmp) / "downloads"
        with patch("latexstruct.server.downloads.download_root", return_value=downloads):
            blocked = c.post(f"/api/projects/{pid}/exports/result/save")
        assert blocked.status_code == 409
        assert not downloads.exists()

        safe_pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "safe", "mode": "rule"}
        ).json()["id"]
        assert c.post(f"/api/projects/{safe_pid}/process").json()["ok"] is True
        report_path = Path(srv.get_store()._dir(safe_pid)) / "report.md"
        report_path.write_text("tampered", encoding="utf-8")
        with patch("latexstruct.server.downloads.download_root", return_value=downloads):
            tampered = c.post(f"/api/projects/{safe_pid}/exports/report/save")
            invalid = c.post(f"/api/projects/{safe_pid}/exports/not-valid/save")
        assert tampered.status_code == 409
        assert invalid.status_code == 404
        assert not downloads.exists()


def test_native_report_save_accepts_pre_report_hash_legacy_commit():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "legacy", "mode": "rule"}
        ).json()["id"]
        assert c.post(f"/api/projects/{pid}/process").json()["ok"] is True
        marker_path = Path(srv.get_store()._dir(pid)) / "verification.json"
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker.pop("report_sha256")
        marker_path.write_text(json.dumps(marker, ensure_ascii=False), encoding="utf-8")
        downloads = Path(tmp) / "downloads"

        with patch("latexstruct.server.downloads.download_root", return_value=downloads):
            response = c.post(f"/api/projects/{pid}/exports/report/save")

        assert response.status_code == 200
        assert (downloads / response.json()["filename"]).read_text(encoding="utf-8").startswith(
            "# LaTeXStruct"
        )


def test_open_download_folder_has_no_user_controlled_path():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with patch("latexstruct.server.downloads.reveal_download_location") as reveal:
            response = c.post("/api/exports/open-folder", json={"path": "C:/Windows"})
        assert response.status_code == 200
        reveal.assert_called_once_with()


def test_ocr_native_save_blocks_mutations_and_update_until_fully_preserved():
    from latexstruct.updater import UpdateInfo

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = "save-race"
        started = threading.Event()
        release = threading.Event()
        response = {}
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "status": "done",
                "source_type": "image",
                "raw_ready": True,
                "raw_tex": "saved OCR",
                "raw_revision": 1,
                "downloaded_revision": 0,
                "imported_revision": 0,
                "importing": False,
                "saving": False,
                "usage": {"calls": 1},
                "pages": {1: {"status": "done"}},
            }

        def controlled_save(_data, _filename):
            started.set()
            assert release.wait(timeout=3)
            return Path(tmp) / "OCR-save-race.tex"

        def run_save():
            response["value"] = c.post(f"/api/ocr/jobs/{jid}/save")

        try:
            with patch("latexstruct.server.downloads.save_unique_download", controlled_save):
                thread = threading.Thread(target=run_save)
                thread.start()
                assert started.wait(timeout=2)
                assert c.post(f"/api/ocr/jobs/{jid}/save").status_code == 409
                assert c.post(f"/api/ocr/jobs/{jid}/pages/1/retry").status_code == 409
                assert c.post(f"/api/ocr/jobs/{jid}/import").status_code == 409
                assert c.delete(f"/api/ocr/jobs/{jid}").status_code == 409
                with patch(
                    "latexstruct.updater.check_for_updates",
                    return_value=UpdateInfo(False, latest="v1.1.2"),
                ) as check:
                    assert c.post("/api/update/install").status_code == 409
                    check.assert_not_called()
                release.set()
                thread.join(timeout=3)
            assert response["value"].status_code == 200
            assert response["value"].json()["preserved"] is True
            with srv._ocr_jobs_lock:
                assert srv._ocr_jobs[jid]["saving"] is False
                assert srv._ocr_jobs[jid]["downloaded_revision"] == 1
        finally:
            release.set()
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)


def test_ocr_native_save_reports_if_snapshot_changes_before_commit_marker():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = "save-stale"
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "status": "done",
                "source_type": "image",
                "raw_ready": True,
                "raw_tex": "old OCR",
                "raw_revision": 1,
                "downloaded_revision": 0,
                "imported_revision": 0,
                "importing": False,
                "saving": False,
                "usage": {},
                "pages": {},
            }

        def mutate_after_save(_data, _filename):
            with srv._ocr_jobs_lock:
                srv._ocr_jobs[jid]["raw_tex"] = "new OCR"
                srv._ocr_jobs[jid]["raw_revision"] = 2
            return Path(tmp) / "old-OCR.tex"

        try:
            with patch("latexstruct.server.downloads.save_unique_download", mutate_after_save):
                response = c.post(f"/api/ocr/jobs/{jid}/save")
            assert response.status_code == 409
            assert "OCR 已更新" in response.json()["detail"]
            with srv._ocr_jobs_lock:
                assert srv._ocr_jobs[jid]["saving"] is False
                assert srv._ocr_jobs[jid]["downloaded_revision"] == 0
        finally:
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)


def test_ocr_cleanup_never_deletes_unpreserved_paid_terminal_results():
    with WorkspaceTmp() as tmp:
        now = time.time()
        old = now - srv.OCR_JOB_TTL_SECONDS - 60
        cases = {
            "unsaved-raw": {
                "status": "partial", "created": old, "raw_ready": True,
                "raw_revision": 2, "downloaded_revision": 1, "imported_revision": 0,
                "usage": {"calls": 2},
            },
            "paid-failure": {
                "status": "error", "created": old, "raw_ready": False,
                "raw_revision": 0, "downloaded_revision": 0, "imported_revision": 0,
                "usage": {"calls": 1},
            },
            "saved-result": {
                "status": "done", "created": old, "raw_ready": True,
                "raw_revision": 1, "downloaded_revision": 1, "imported_revision": 0,
                "usage": {"calls": 1},
            },
            "stale-paid-state": {
                "status": "partial", "created": old, "raw_ready": True,
                "raw_revision": 1, "downloaded_revision": 1, "imported_revision": 0,
                "usage_revision": 2, "downloaded_usage_revision": 1,
                "page_revision": 2, "downloaded_page_revision": 1,
                "usage": {"calls": 3},
            },
            "empty-ready": {
                "status": "ready", "created": old, "raw_ready": False,
                "raw_revision": 0, "downloaded_revision": 0, "imported_revision": 0,
                "usage": {},
            },
        }
        for jid, state in cases.items():
            directory = Path(tmp) / jid
            directory.mkdir()
            state.update({"id": jid, "dir": str(directory), "saving": False, "importing": False})
        with srv._ocr_jobs_lock:
            srv._ocr_jobs.update(cases)
        try:
            srv._cleanup_ocr_jobs(now=now)
            with srv._ocr_jobs_lock:
                assert "unsaved-raw" in srv._ocr_jobs
                assert "paid-failure" in srv._ocr_jobs
                assert "stale-paid-state" in srv._ocr_jobs
                assert "saved-result" not in srv._ocr_jobs
                assert "empty-ready" not in srv._ocr_jobs
            assert (Path(tmp) / "unsaved-raw").is_dir()
            assert (Path(tmp) / "paid-failure").is_dir()
            assert (Path(tmp) / "stale-paid-state").is_dir()
            assert not (Path(tmp) / "saved-result").exists()
            assert not (Path(tmp) / "empty-ready").exists()
        finally:
            with srv._ocr_jobs_lock:
                for jid in cases:
                    srv._ocr_jobs.pop(jid, None)


def test_ocr_frontend_keeps_job_recovery_and_retry_reconnect_guards():
    root = Path(__file__).resolve().parents[1]
    source = (root / "frontend" / "src" / "Ocr.jsx").read_text(encoding="utf-8")
    api_source = (root / "frontend" / "src" / "api.js").read_text(encoding="utf-8")
    styles = (root / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")

    assert "latexstruct-current-ocr-job-v1" in source
    assert "[0-9a-f]{32}" in source
    assert "rememberedOcrJobId()" in source
    assert "rememberOcrJobId(info.id)" in source
    assert "rememberOcrJobId(id)" in source
    assert "forgetOcrJobId(job.id)" in source
    assert "const [restoreFailed, setRestoreFailed]" in source
    assert "setRestoreNonce((value) => value + 1)" in source
    assert "恢复前不会允许新建任务" in source
    assert "inspectFile(selected, sequence)" in source
    assert "`/api/ocr/jobs/${pdfInfo.jobId}/start`" in source
    assert 'endpoint = "/api/ocr/jobs"' not in source
    assert "ocrSnapshotPreserved(latestJob)" in source
    assert "rawSaved.usage_revision" in source
    assert "rawSaved.page_revision" in source
    assert "refreshRetrySnapshot" in source
    assert 'status: "running", phase: "正在确认单页重试状态"' in source
    assert "if (job?.id)" in source
    assert "Boolean(job?.id)" in source
    assert "请先保存或导入结果，或明确放弃本次任务后再重新开始" in source
    assert "PDF / 图片 → 原始 LaTeX → 结构化审阅" in source
    assert "ocrStatusLabel(job.status)" in source
    assert 'height="clamp(560px, 68vh, 900px)"' in source
    assert "aria-pressed={focusLivePreview}" in source
    assert 'focusLivePreview ? "显示页列表" : "专注预览"' in source
    assert ".ocr-cols.ocr-live-layout" in styles
    assert ".ocr-cols.ocr-page-layout" in styles
    assert ".ocr-cols.ocr-live-layout.ocr-live-focus" in styles
    assert "error.status = res.status" in api_source


def main():
    import traceback

    tests = [
        (k, v)
        for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
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
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()

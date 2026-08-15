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
    srv._active_pipeline_runs = 0
    srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
    srv._config = None
    return TestClient(srv.create_app())


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
        assert "\\begin{theorem}" in result and "（方法）" in result
        report = c.get(f"/api/projects/{pid}/report").text
        assert "机器校验" in report and "内容不变校验：通过" in report
        # diff
        d = c.get(f"/api/projects/{pid}/diff").json()
        assert any(row["type"] == "ins" for row in d["rows"])
        assert d["verification"]["content_invariant"] is True
        # 导出
        e = c.get(f"/api/projects/{pid}/export")
        assert e.status_code == 200
        # 删除
        c.delete(f"/api/projects/{pid}")
        assert c.get(f"/api/projects/{pid}").status_code == 404


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

        committed_text = "VERIFIED\r\n"
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


def test_partial_result_write_cannot_reuse_previous_verification_marker():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects", json={"text": SAMPLE, "name": "partial-write", "mode": "rule"}
        ).json()["id"]
        store = srv.get_store()
        store.set_result(
            pid,
            "OLD",
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

        assert store.read_result(pid) == "NEW"
        blocked = c.get(f"/api/projects/{pid}/export")
        assert blocked.status_code == 409 and "不一致" in blocked.json()["detail"]


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
        response = c.post(
            "/api/ocr/jobs",
            files={"file": ("page.jpg", b"\xff\xd8\xff\xe0" + b"0" * 16, "image/jpeg")},
            data={"pages": "1", "dpi": "200"},
        )
        assert response.status_code == 200
        job_id = response.json()["id"]
        try:
            for _ in range(100):
                state = c.get(f"/api/ocr/jobs/{job_id}").json()
                if state.get("pages"):
                    break
                time.sleep(0.01)
            preview = c.get(f"/api/ocr/jobs/{job_id}/pages/1")
            assert preview.status_code == 200
            assert preview.headers["content-type"].startswith("image/jpeg")
        finally:
            job = srv._ocr_jobs.pop(job_id, {})
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
            with patch("latexstruct.ocr.pdf_page_count_bytes", return_value=396):
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
            assert c.post(f"/api/ocr/jobs/{inspected}/start").status_code == 409
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
            with patch("latexstruct.ocr.pdf_page_count_bytes", return_value=2):
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
            assert state["pages"]["1"]["status"] == "done"
            assert state["pages"]["2"]["status"] == "pending"
            assert state["error"]
            raw = c.get(f"/api/ocr/jobs/{inspected}/result").text
            assert "completed first page" in raw
        finally:
            job = srv._ocr_jobs.pop(inspected, {}) if inspected else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_rejects_malicious_or_excessive_ranges_before_starting_worker():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        before = set(srv._ocr_jobs)
        with patch("latexstruct.ocr.pdf_page_count_bytes", return_value=600):
            huge = c.post(
                "/api/ocr/jobs",
                files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                data={"pages": "1-999999999999999999999"},
            )
            excessive = c.post(
                "/api/ocr/jobs",
                files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                data={"start_page": "1", "end_page": str(srv.MAX_OCR_PAGES_PER_JOB + 1)},
            )
        assert huge.status_code == 400
        assert excessive.status_code == 400
        assert set(srv._ocr_jobs) == before


def test_decisions_and_reject():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.post("/api/projects", json={"text": SAMPLE, "name": "demo2", "mode": "rule"})
        pid = r.json()["id"]
        c.post(f"/api/projects/{pid}/process")
        d = c.get(f"/api/projects/{pid}/decisions").json()
        items = d["items"]
        assert items, "决策清单为空"
        theorem = next(i for i in items if i["env"] == "theorem" and i["status"] == "applied")
        assert "line" in theorem and "section" in theorem
        # 拒绝定理包裹 → 重新整理后该环境消失、内容不变校验仍通过
        r = c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/reject")
        assert r.status_code == 200
        rejected_items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        assert next(i for i in rejected_items if i["candidate_id"] == theorem["candidate_id"])["status"] == "rejected"
        result = c.get(f"/api/projects/{pid}/result").text
        assert "\\begin{theorem}" not in result
        info = json.loads(Path(tmp, "projects", pid, "verification.json").read_text(encoding="utf-8"))
        assert info["verification"]["content_invariant"] is True
        # 双语合并等其他修改保留
        assert "（方法）" in result
        # 撤销拒绝（unreject）：该定理包裹恢复，内容不变校验仍通过
        r = c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/unreject")
        assert r.status_code == 200
        result2 = c.get(f"/api/projects/{pid}/result").text
        assert "\\begin{theorem}" in result2
        info2 = json.loads(Path(tmp, "projects", pid, "verification.json").read_text(encoding="utf-8"))
        assert info2["verification"]["content_invariant"] is True
        assert info2["verification"]["decisions_reused"] is True


def test_rulesets_and_folder_import():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.get("/api/rulesets").json()
        assert "bilingual" in r["packs"] and "academic-paper" in r["packs"]
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
            assert "\\begin{theorem}" in zf.read("chapters/ch01.tex").decode("utf-8")
        # 审阅拒绝会重跑，但逐文件结果和原始二进制资源仍可安全导出。
        items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        theorem = next(i for i in items if i["kind"] == "theorem-like")
        assert c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/reject").status_code == 200
        assert c.get(f"/api/projects/{pid}/export-folder").status_code == 200
        # 文件夹导出同样必须核对 result.tex 与最终 verification marker。
        store = srv.get_store()
        project_dir = Path(store._dir(pid))
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
            assert c.post(f"/api/projects/{pid}/process/resume").status_code == 200
            for _ in range(300):
                state = c.get(f"/api/projects/{pid}/process/status").json()
                if state["status"] in {"done", "error", "cancelled"}:
                    break
                time.sleep(0.01)
        assert state["status"] == "done", state
        assert c.get(f"/api/projects/{pid}/result").status_code == 200


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
        r = c.post("/api/ocr/jobs", files={"file": ("a.png", png, "image/png")})
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
        r = c.post("/api/ocr/jobs", files={"file": ("a.png", png, "image/png")})
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
                created = c.post("/api/ocr/jobs", files={"file": ("a.png", png, "image/png")})
                assert created.status_code == 200
                jid = created.json()["id"]
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)
                assert state["status"] == "done"
                assert c.get(f"/api/ocr/jobs/{jid}/result").status_code == 200
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
            with srv._ocr_jobs_lock:
                saved = srv._ocr_jobs[jid]
                assert saved["importing"] is False
                assert saved["imported_revision"] == saved["raw_revision"] == 1
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
            created = c.post("/api/ocr/jobs", files={"file": ("a.png", png, "image/png")})
            jid = created.json()["id"]
            for _ in range(100):
                state = c.get(f"/api/ocr/jobs/{jid}").json()
                if state["status"] != "running":
                    break
                time.sleep(0.02)
        assert state["status"] == "done"
        assert state["pages"]["1"]["attempts"] == 2
        assert c.get(f"/api/ocr/jobs/{jid}/result").headers["x-latexstruct-ocr-complete"] == "true"

        imported = c.post(f"/api/ocr/jobs/{jid}/import")
        assert imported.status_code == 200
        pid = imported.json()["id"]
        raw = c.get(f"/api/projects/{pid}/source").text
        structured = c.get(f"/api/projects/{pid}/result").text
        assert "Theorem 1." in raw and "\\begin{theorem}" not in raw
        assert "\\begin{theorem}" not in structured
        assert "Theorem 1. A recovered statement." in structured
        assert "\\begin{proof}" in structured
        job = srv._ocr_jobs.pop(jid, {})
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


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
                created = c.post(
                    "/api/ocr/jobs", files={"file": ("a.png", png, "image/png")}
                )
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

            downloaded = c.get("/api/ocr/jobs/paid-ocr/result")
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
        assert response.status_code == 200
        assert response.json()["ok"] is True
        assert "installer" not in response.json()  # 不向前端泄露本机临时路径
        download.assert_called_once_with(info)
        schedule.assert_called_once_with("C:/Temp/LaTeXStruct-setup-1.2.3.exe")
        close_app.assert_called_once_with()
        srv._cancel_update_preparation()


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

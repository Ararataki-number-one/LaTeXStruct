# -*- coding: utf-8 -*-
"""FastAPI 服务接口测试（需要 fastapi + httpx；未安装时自动跳过）。"""

import io
import json
import os
import shutil
import sys
import tempfile
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
            r = c.put("/api/config", json={"decide_api_key": "sk-test", "review_enabled": False})
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
        assert "\\begin{theorem}[1]" in structured
        job = srv._ocr_jobs.pop(jid, {})
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


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

# -*- coding: utf-8 -*-
"""FastAPI 服务接口测试（需要 fastapi + httpx；未安装时自动跳过）。"""

import base64
import gc
import hashlib
import io
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
    "\\documentclass{book}\n\\usepackage{tcolorbox}\n\\begin{document}\n\n"
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
    with srv._project_locks_guard:
        srv._project_locks.clear()
    srv._cancel_update_preparation()
    with srv._update_jobs_lock:
        srv._update_jobs.clear()
    srv._active_pipeline_runs = 0
    srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
    srv._config = None
    return TestClient(srv.create_app())


def test_build_ocr_client_uses_codex_for_vision_without_api_fallback():
    from latexstruct.config import AppConfig
    from latexstruct.core.codex_cli import CodexCLIClient

    cfg = AppConfig(
        analysis_backend="codex_cli",
        codex_model="gpt-5.4",
        codex_reasoning_effort="high",
        ocr_base_url="https://paid.example.invalid/v1",
        ocr_model="paid-vision-model",
        ocr_api_key="stored-paid-secret",
    )

    client, model, backend = srv._build_ocr_client(
        cfg,
        base_url="https://override.example.invalid/v1",
        model="override-paid-model",
        api_key="request-paid-secret",
    )

    assert isinstance(client, CodexCLIClient)
    assert (model, backend) == ("gpt-5.4", "codex_cli")
    assert client.reasoning_effort == "high"
    assert client.cfg.base_url == ""
    assert client.cfg.api_key == ""


def test_build_ocr_client_preserves_compatible_api_selection():
    from latexstruct.config import AppConfig
    from latexstruct.core.ai import LLMClient

    cfg = AppConfig(
        analysis_backend="api",
        ocr_base_url="https://vision.example.invalid/v1",
        ocr_model="stored-model",
        ocr_api_key="stored-secret",
    )

    client, model, backend = srv._build_ocr_client(cfg)

    assert isinstance(client, LLMClient)
    assert (model, backend) == ("stored-model", "api")
    assert client.cfg.base_url == "https://vision.example.invalid/v1"
    assert client.cfg.api_key == "stored-secret"


def test_public_ocr_job_uses_stored_backend_and_never_current_settings():
    from latexstruct.config import AppConfig

    old_config = srv._config
    try:
        srv._config = AppConfig(analysis_backend="api")
        assert srv._public_ocr_job({"status": "done", "backend": "codex_cli"})[
            "backend"
        ] == "codex_cli"
        srv._config = AppConfig(analysis_backend="codex_cli")
        assert srv._public_ocr_job({"status": "done"})["backend"] == "unknown"
    finally:
        srv._config = old_config


def _wait_for_json(client, path, predicate, timeout=15.0, interval=0.02):
    """Poll a background endpoint until its JSON state satisfies ``predicate``."""
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        response = client.get(path)
        assert response.status_code == 200, response.text
        state = response.json()
        if predicate(state):
            return state
        time.sleep(interval)
    return state


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
        assert "\\begin{theorem}[1]" in result and "（方法）" in result
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
            assert "elegantbook.cls" not in zf.namelist()
            assert "ELEGANTBOOK-LICENSE.txt" not in zf.namelist()
            assert "ELEGANTBOOK-BUNDLE-README.md" not in zf.namelist()
            assert zf.read("LATEXSTRUCT-REPORT.md") == c.get(f"/api/projects/{pid}/report").content
        # 删除
        c.delete(f"/api/projects/{pid}")
        assert c.get(f"/api/projects/{pid}").status_code == 404


def test_verified_tex_and_zip_share_exact_provenance_record():
    from latexstruct.core.provenance import (
        PROVENANCE_MANIFEST_NAME,
        parse_tex_provenance,
        strip_tex_provenance,
    )

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "provenance", "mode": "rule"},
        ).json()["id"]
        assert c.post(f"/api/projects/{pid}/process").json()["ok"] is True

        exported = c.get(f"/api/projects/{pid}/export")
        record = parse_tex_provenance(exported.content)
        assert record["verification_status"] == "VERIFIED"
        assert "not_ocr_text_math_or_semantic_accuracy" in record["verification_scope"]
        assert record["app_version"] != "unknown"
        assert record["prompt_version"] == "not-used"
        assert record["build_id"] == (
            os.environ.get("LATEXSTRUCT_BUILD_ID")
            or os.environ.get("GITHUB_RUN_ID")
            or "unknown"
        )
        assert record["commit"] == (
            os.environ.get("LATEXSTRUCT_BUILD_COMMIT")
            or os.environ.get("GITHUB_SHA")
            or "unknown"
        )
        assert strip_tex_provenance(exported.content) == c.get(
            f"/api/projects/{pid}/result"
        ).content

        package = c.get(f"/api/projects/{pid}/export-package")
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            package_record = json.loads(archive.read(PROVENANCE_MANIFEST_NAME))
            assert package_record == parse_tex_provenance(archive.read("main.tex"))
            assert package_record == record


def test_unprocessed_current_tex_and_zip_are_self_describing_unverified_snapshots():
    from latexstruct.core.provenance import (
        PROVENANCE_MANIFEST_NAME,
        parse_tex_provenance,
        strip_tex_provenance,
    )

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "raw-provenance", "mode": "ai"},
        ).json()["id"]

        current = c.get(f"/api/projects/{pid}/export-current")
        record = parse_tex_provenance(current.content)
        assert current.headers["x-latexstruct-verified"] == "false"
        assert record["verification_status"] == "UNVERIFIED"
        assert record["result_sha256"] == "unknown"
        assert record["prompt_version"] == "3.6"
        assert strip_tex_provenance(current.content) == SAMPLE.encode("utf-8")

        package = c.get(f"/api/projects/{pid}/export-current-package")
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            package_record = json.loads(archive.read(PROVENANCE_MANIFEST_NAME))
            assert package_record == parse_tex_provenance(archive.read("main.tex"))
            assert package_record == record


def test_single_file_binary_import_preserves_latin1_bytes_and_encodes_modifications():
    unavailable = {
        "available": False, "ok": None, "pages": 0, "errors": [], "log": "",
    }
    unchanged_raw = (
        "\\documentclass{article}\r\n\\begin{document}\r\n"
        "Caf\xe9.\r\n\\end{document}\r\n"
    ).encode("latin-1")
    modified_raw = (
        "\\documentclass{article}\r\n\\usepackage{amsthm}\r\n"
        "\\newtheorem*{theorem}{Theorem}\r\n\\begin{document}\r\n"
        "Theorem. R\xe9sum\xe9.\r\n\\end{document}\r\n"
    ).encode("latin-1")

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable):
            unchanged = c.post("/api/projects", json={
                "text": "browser preview is not authoritative",
                "name": "latin1-unchanged",
                "mode": "rule",
                "source_file": {
                    "encoding": "base64",
                    "data": base64.b64encode(unchanged_raw).decode("ascii"),
                },
            })
            assert unchanged.status_code == 200, unchanged.text
            unchanged_pid = unchanged.json()["id"]
            processed = c.post(f"/api/projects/{unchanged_pid}/process")
            assert processed.status_code == 200 and processed.json()["ok"] is True
            from latexstruct.core.provenance import strip_tex_provenance

            assert strip_tex_provenance(
                c.get(f"/api/projects/{unchanged_pid}/export").content
            ) == unchanged_raw

            modified = c.post("/api/projects", json={
                "text": "",
                "name": "latin1-modified",
                "mode": "rule",
                "source_file": {
                    "encoding": "base64",
                    "data": base64.b64encode(modified_raw).decode("ascii"),
                },
            })
            modified_pid = modified.json()["id"]
            processed = c.post(f"/api/projects/{modified_pid}/process")
            assert processed.status_code == 200 and processed.json()["ok"] is True
            exported = c.get(f"/api/projects/{modified_pid}/export").content

        decoded = exported.decode("latin-1")
        assert "\\begin{theorem}" in decoded
        assert "R\xe9sum\xe9." in decoded
        assert "\n" not in decoded.replace("\r\n", "")
        assert b"R\xc3\xa9sum\xc3\xa9" not in exported


def test_single_file_unrepresentable_change_is_blocked_as_unverified():
    raw = (
        "\\documentclass{article}\r\n\\begin{document}\r\n"
        "Caf\xe9.\r\n\\end{document}\r\n"
    ).encode("latin-1")
    unavailable = {
        "available": False, "ok": None, "pages": 0, "errors": [], "log": "",
    }
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        created = c.post("/api/projects", json={
            "text": "",
            "name": "latin1-unrepresentable",
            "mode": "rule",
            "source_file": {
                "encoding": "base64",
                "data": base64.b64encode(raw).decode("ascii"),
            },
        })
        pid = created.json()["id"]
        real_pipeline = srv.run_pipeline

        def pipeline_with_unrepresentable_change(*args, **kwargs):
            result = real_pipeline(*args, **kwargs)
            changed = result.result.replace("\\end{document}", "\u4e2d\u6587\n\\end{document}")
            result.result = changed
            result.export_text = changed.replace("\n", result.newline)
            return result

        with patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable), patch.object(
            srv, "run_pipeline", pipeline_with_unrepresentable_change
        ):
            processed = c.post(f"/api/projects/{pid}/process")

        assert processed.status_code == 200
        body = processed.json()
        assert body["ok"] is False
        assert "source-encoding" in body["failed_checks"]
        assert c.get(f"/api/projects/{pid}/export").status_code == 409
        verification = c.get(f"/api/projects/{pid}/decisions").json()["verification"]
        assert verification["source_encoding"]["ok"] is False
        assert "无法表示" in verification["source_encoding"]["error"]


def test_folder_export_preserves_unchanged_gbk_and_encodes_modified_tex_as_gbk():
    unavailable = {
        "available": False, "ok": None, "pages": 0, "errors": [], "log": "",
    }
    main_raw = (
        "\\documentclass{article}\r\n\\usepackage{amsthm}\r\n"
        "\\newtheorem*{theorem}{Theorem}\r\n% GBK \u4e3b\u6587\u4ef6\r\n"
        "\\begin{document}\r\n\\input{chapter}\r\n\\end{document}\r\n"
    ).encode("gbk")
    chapter_raw = "Theorem. \u4e2d\u6587\u5b9a\u7406\u3002\r\n".encode("gbk")
    payload = {
        rel: {
            "encoding": "base64",
            "data": base64.b64encode(data).decode("ascii"),
        }
        for rel, data in {"main.tex": main_raw, "chapter.tex": chapter_raw}.items()
    }

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        created = c.post("/api/projects/folder", json={
            "files": payload,
            "name": "gbk-folder",
            "mode": "rule",
            "defer_process": True,
        })
        assert created.status_code == 200, created.text
        pid = created.json()["id"]
        current = c.get(f"/api/projects/{pid}/export-current-package")
        assert current.status_code == 200
        assert current.headers["x-latexstruct-verified"] == "false"
        with zipfile.ZipFile(io.BytesIO(current.content)) as archive:
            from latexstruct.core.provenance import strip_tex_provenance

            assert strip_tex_provenance(archive.read("main.tex")) == main_raw
            assert archive.read("chapter.tex") == chapter_raw
        with patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable):
            processed = c.post(f"/api/projects/{pid}/process")
        assert processed.status_code == 200 and processed.json()["ok"] is True
        package = c.get(f"/api/projects/{pid}/export-package")
        assert package.status_code == 200, package.text
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            exported_main = archive.read("main.tex")
            exported_chapter = archive.read("chapter.tex")

        assert strip_tex_provenance(exported_main) == main_raw
        chapter_text = exported_chapter.decode("gbk")
        assert "\\begin{theorem}" in chapter_text
        assert "\u4e2d\u6587\u5b9a\u7406" in chapter_text
        assert "\n" not in chapter_text.replace("\r\n", "")


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


def test_incompatible_elegantbook_conversion_is_not_committed_as_verified():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        text = (
            "\\documentclass{beamer}\n\\begin{document}\n"
            "\\begin{frame}Text\\end{frame}\n\\end{document}\n"
        )
        pid = c.post(
            "/api/projects",
            json={
                "text": text,
                "name": "incompatible-template",
                "mode": "rule",
                "template": "elegantbook",
            },
        ).json()["id"]
        compiled = {
            "available": True,
            "ok": True,
            "pages": 1,
            "errors": [],
            "log": "",
        }
        with patch(
            "latexstruct.core.compilecheck.compile_latex",
            return_value=compiled,
        ):
            processed = c.post(f"/api/projects/{pid}/process")

        assert processed.status_code == 200 and processed.json()["ok"] is False
        verification = c.get(f"/api/projects/{pid}/decisions").json()["verification"]
        assert verification["template"]["ok"] is False
        assert verification["safe_to_export"] is False
        assert srv.get_store().read_result(pid) is None
        assert c.get(f"/api/projects/{pid}/export").status_code == 409
        current = c.get(f"/api/projects/{pid}/export-current")
        assert current.status_code == 200
        assert current.headers["x-latexstruct-verified"] == "false"
        from latexstruct.core.provenance import strip_tex_provenance

        assert strip_tex_provenance(current.content).decode("utf-8") == text


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

        # 保持源排版是正式导出模式；只要安全 marker 与内容 hash 匹配即可导出。
        legacy_text = "\\documentclass{book}\n\\begin{document}\nOld\n\\end{document}\n"
        store.set_result(
            pid, legacy_text, "# report", [],
            {"verification": {"safe_to_export": True}},
        )
        legacy = c.get(f"/api/projects/{pid}/export")
        assert legacy.status_code == 200
        from latexstruct.core.provenance import strip_tex_provenance

        assert strip_tex_provenance(legacy.content).decode("utf-8") == legacy_text

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
        from latexstruct.core.provenance import strip_tex_provenance

        assert strip_tex_provenance(restored.content).decode("utf-8") == COMMITTED_ELEGANT


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


def test_codex_status_endpoint_is_read_only_and_returns_public_fields():
    public_status = {
        "available": True,
        "authenticated": True,
        "ready": True,
        "version": "codex-cli test",
        "message": "ready",
        "action": "none",
    }
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with patch("latexstruct.core.codex_cli.codex_status", return_value=public_status) as probe:
            response = c.get("/api/codex/status")
        assert response.status_code == 200
        assert response.json() == public_status
        probe.assert_called_once_with()


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
        render_calls = []

        def fake_render(_path, pages, _dpi):
            render_calls.append(list(pages))
            assert len(pages) == 1
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
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
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
            assert render_calls == [[88], [89], [90]]
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
            assert len(pages) == 1
            if pages == [1]:
                yield 1, b"\x89PNG\r\n\x1a\n" + b"1" * 32
                return
            raise RuntimeError("renderer stopped on second page")

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
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
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
            assert state["progress"] == 1.0
            assert state["pages"]["1"]["status"] == "done"
            assert state["pages"]["2"]["status"] == "error"
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


def test_pdf_render_failure_does_not_block_later_pages_and_retry_rerenders_missing_png():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""
        render_calls = []
        fail_page_two = {"once": True}
        vision_calls = []

        def flaky_render(_path, pages, dpi):
            assert len(pages) == 1
            page_no = pages[0]
            render_calls.append((page_no, dpi))
            if page_no == 2 and fail_page_two["once"]:
                fail_page_two["once"] = False
                raise RuntimeError("synthetic page two raster failure")
            yield page_no, b"\x89PNG\r\n\x1a\n" + bytes([page_no]) * 32

        def fake_vision(client, _system, user, _image):
            page_no = int(re.search(r"第\s*(\d+)\s*页", user).group(1))
            vision_calls.append(page_no)
            client.last_usage = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
            return f"```latex\nA sufficiently long recovered OCR page {page_no} for raster retry.\n```"

        try:
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 3, "outline": []},
            ):
                jid = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                ).json()["id"]
            with (
                patch("latexstruct.ocr.iter_pdf_pages", flaky_render),
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
                patch("latexstruct.core.ai.LLMClient.chat_vision", fake_vision),
            ):
                assert c.post(
                    f"/api/ocr/jobs/{jid}/start", data={"dpi": "180"},
                ).status_code == 200
                for _ in range(150):
                    partial = c.get(f"/api/ocr/jobs/{jid}").json()
                    if partial["status"] == "partial":
                        break
                    time.sleep(0.02)

                assert partial["status"] == "partial", partial
                assert partial["pages"]["1"]["status"] == "done"
                assert partial["pages"]["2"]["status"] == "error"
                assert partial["pages"]["2"]["preview_ready"] is False
                assert partial["pages"]["2"]["can_retry"] is True
                assert partial["pages"]["3"]["status"] == "done"
                assert vision_calls == [1, 3]

                retried = c.post(f"/api/ocr/jobs/{jid}/pages/2/retry")
                assert retried.status_code == 200, retried.text
                body = retried.json()
                assert body["ok"] is True and body["status"] == "done"
                assert body["pages"]["2"]["preview_ready"] is True
                assert render_calls == [(1, 180), (2, 180), (3, 180), (2, 180)]
                assert vision_calls == [1, 3, 2]
                assert c.get(f"/api/ocr/jobs/{jid}/pages/2").status_code == 200
        finally:
            job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_pause_stops_before_next_page_and_resumes_same_job():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""
        first_started = threading.Event()
        release_first = threading.Event()
        calls = []

        def fake_render(_path, pages, _dpi):
            assert len(pages) == 1
            page_no = pages[0]
            yield page_no, b"\x89PNG\r\n\x1a\n" + bytes([page_no]) * 32

        def controlled_vision(client, _system, user, _image):
            page_no = int(re.search(r"第\s*(\d+)\s*页", user).group(1))
            calls.append(page_no)
            client.last_usage = {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
            if page_no == 1:
                first_started.set()
                assert release_first.wait(timeout=3)
            return f"```latex\nA sufficiently long paused OCR result from page {page_no}.\n```"

        with (
            patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 2, "outline": []},
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch("latexstruct.core.ai.LLMClient.chat_vision", controlled_vision),
        ):
            try:
                inspected = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                )
                jid = inspected.json()["id"]
                assert c.post(f"/api/ocr/jobs/{jid}/start").status_code == 200
                assert first_started.wait(timeout=2)

                before = c.get(f"/api/ocr/jobs/{jid}").json()
                requested = c.post(f"/api/ocr/jobs/{jid}/pause")
                assert requested.status_code == 200
                requested_state = requested.json()
                assert requested_state["status"] == "pausing"
                assert requested_state["can_resume"] is True
                assert requested_state["state_revision"] > before["state_revision"]
                assert c.delete(f"/api/ocr/jobs/{jid}").status_code == 409

                release_first.set()
                for _ in range(150):
                    paused = c.get(f"/api/ocr/jobs/{jid}").json()
                    if paused["status"] == "paused":
                        break
                    time.sleep(0.02)
                assert paused["status"] == "paused", paused
                assert paused["can_pause"] is False and paused["can_resume"] is True
                assert calls == [1]
                assert paused["pages"]["1"]["status"] == "done"
                assert paused["pages"]["2"]["status"] == "pending"

                resumed = c.post(f"/api/ocr/jobs/{jid}/resume")
                assert resumed.status_code == 200
                assert resumed.json()["status"] == "running"
                assert resumed.json()["state_revision"] > paused["state_revision"]
                for _ in range(150):
                    final = c.get(f"/api/ocr/jobs/{jid}").json()
                    if final["status"] == "done":
                        break
                    time.sleep(0.02)
                assert final["status"] == "done", final
                assert calls == [1, 2]
                assert final["can_pause"] is False and final["can_resume"] is False
            finally:
                release_first.set()
                if jid:
                    with srv._ocr_jobs_changed:
                        current = srv._ocr_jobs.get(jid)
                        if current:
                            current["pause_requested"] = False
                            srv._ocr_jobs_changed.notify_all()

        job = srv._ocr_jobs.pop(jid, {}) if jid else {}
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_retry_failed_runs_in_background_sequentially_and_can_pause():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""
        phase = {"initial": True}
        retry_started = threading.Event()
        release_retry = threading.Event()
        initial_calls = []
        retry_calls = []

        def fake_render(_path, pages, _dpi):
            page_no = pages[0]
            yield page_no, b"\x89PNG\r\n\x1a\n" + bytes([page_no]) * 32

        def controlled_vision(client, _system, user, _image):
            from latexstruct.core.ai import LLMError

            page_no = int(re.search(r"第\s*(\d+)\s*页", user).group(1))
            client.last_usage = {}
            if phase["initial"]:
                initial_calls.append(page_no)
                raise LLMError("synthetic permanent OCR failure")
            retry_calls.append(page_no)
            if len(retry_calls) == 1:
                retry_started.set()
                assert release_retry.wait(timeout=3)
            return f"```latex\nA sufficiently long batch retry result from page {page_no}.\n```"

        with (
            patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 2, "outline": []},
            ),
            patch("latexstruct.ocr.iter_pdf_pages", fake_render),
            patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
            patch("latexstruct.core.ai.LLMClient.chat_vision", controlled_vision),
        ):
            try:
                jid = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                ).json()["id"]
                assert c.post(f"/api/ocr/jobs/{jid}/start").status_code == 200
                for _ in range(150):
                    failed = c.get(f"/api/ocr/jobs/{jid}").json()
                    if failed["status"] == "partial":
                        break
                    time.sleep(0.02)
                assert failed["status"] == "partial", failed
                assert initial_calls == [1, 2]

                phase["initial"] = False
                started = c.post(f"/api/ocr/jobs/{jid}/retry-failed")
                assert started.status_code == 200
                started_state = started.json()
                assert started_state["status"] == "running"
                assert started_state["retrying_failed"] is True
                assert started_state["retry_total"] == 2
                assert started_state["can_pause"] is True
                assert retry_started.wait(timeout=2)

                assert c.post(f"/api/ocr/jobs/{jid}/pause").json()["status"] == "pausing"
                release_retry.set()
                for _ in range(150):
                    paused = c.get(f"/api/ocr/jobs/{jid}").json()
                    if paused["status"] == "paused":
                        break
                    time.sleep(0.02)
                assert paused["status"] == "paused", paused
                assert paused["retrying_failed"] is True
                assert paused["retry_done"] == 1
                assert retry_calls == [1]

                assert c.post(f"/api/ocr/jobs/{jid}/resume").status_code == 200
                for _ in range(150):
                    final = c.get(f"/api/ocr/jobs/{jid}").json()
                    if final["status"] == "done":
                        break
                    time.sleep(0.02)
                assert final["status"] == "done", final
                assert final["retrying_failed"] is False
                assert final["retry_done"] == 2
                assert retry_calls == [1, 2]
                assert all(not page["retrying"] for page in final["pages"].values())
            finally:
                release_retry.set()
                if jid:
                    with srv._ocr_jobs_changed:
                        current = srv._ocr_jobs.get(jid)
                        if current:
                            current["pause_requested"] = False
                            srv._ocr_jobs_changed.notify_all()

        job = srv._ocr_jobs.pop(jid, {}) if jid else {}
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_preview_revision_grows_after_each_page_without_finishing_early():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        inspected = ""
        second_started = threading.Event()
        third_started = threading.Event()
        allow_second = threading.Event()
        allow_third = threading.Event()
        render_calls = []

        def controlled_render(_path, pages, _dpi):
            render_calls.append(list(pages))
            assert len(pages) == 1
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
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
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
            assert render_calls == [[2], [3], [4]]
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
        theorem = next(i for i in items if i["env"] == "theorem" and i["status"] == "applied")
        assert "line" in theorem and "section" in theorem
        # 拒绝定理包裹 → 重新整理后该环境消失、内容不变校验仍通过
        r = c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/reject")
        assert r.status_code == 200
        assert r.json()["ok"] is True
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


def test_concurrent_rejects_are_serialized_and_keep_both_exclusions():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "concurrent-review", "mode": "rule"},
        ).json()["id"]
        unavailable = {
            "available": False, "ok": None, "pages": 0, "errors": [], "log": "",
        }
        with patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable):
            assert c.post(f"/api/projects/{pid}/process").json()["ok"] is True
        items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        candidate_ids = [item["candidate_id"] for item in items if item["status"] == "applied"][:2]
        assert len(candidate_ids) == 2

        original_pipeline = srv.run_pipeline
        first_entered = threading.Event()
        second_entered = threading.Event()
        release_first = threading.Event()
        call_guard = threading.Lock()
        calls = 0

        def serialized_pipeline(*args, **kwargs):
            nonlocal calls
            with call_guard:
                calls += 1
                call_number = calls
            if call_number == 1:
                first_entered.set()
                assert release_first.wait(3)
            elif call_number == 2:
                second_entered.set()
            return original_pipeline(*args, **kwargs)

        responses = {}

        def reject(label, candidate_id):
            responses[label] = c.post(
                f"/api/projects/{pid}/decisions/{candidate_id}/reject"
            )

        with (
            patch.object(srv, "run_pipeline", serialized_pipeline),
            patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable),
        ):
            first = threading.Thread(target=reject, args=("first", candidate_ids[0]))
            second = threading.Thread(target=reject, args=("second", candidate_ids[1]))
            first.start()
            assert first_entered.wait(1)
            second.start()
            # The second request must not enter the pipeline while the first
            # request still owns the project's meta/result transaction.
            assert not second_entered.wait(0.15)
            release_first.set()
            first.join(timeout=5)
            second.join(timeout=5)

        assert not first.is_alive() and not second.is_alive()
        assert responses["first"].status_code == 200
        assert responses["second"].status_code == 200
        assert second_entered.is_set()
        decision_state = c.get(f"/api/projects/{pid}/decisions").json()
        assert decision_state["excludes"] == sorted(candidate_ids)
        statuses = {
            item["candidate_id"]: item["status"] for item in decision_state["items"]
        }
        assert all(statuses[candidate_id] == "rejected" for candidate_id in candidate_ids)


def test_delete_missing_projects_does_not_retain_project_locks():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        with srv._project_locks_guard:
            baseline = len(srv._project_locks)

        for index in range(100):
            response = c.delete(f"/api/projects/{index:012x}")
            # Missing-project delete historically returns 200. A future 404 is
            # also valid; the regression concerns the lock registry lifetime.
            assert response.status_code in {200, 404}

        gc.collect()
        with srv._project_locks_guard:
            assert len(srv._project_locks) == baseline


def test_concurrent_same_project_waiter_reuses_one_weak_registry_lock():
    with WorkspaceTmp() as tmp:
        _client(tmp)
        pid = "0123456789ab"
        first_entered = threading.Event()
        second_has_reference = threading.Event()
        second_entered = threading.Event()
        release_first = threading.Event()
        locks = {}

        def first_worker():
            lock = srv._project_lock(pid)
            locks["first"] = lock
            with lock:
                first_entered.set()
                assert second_has_reference.wait(2)
                assert not second_entered.wait(0.1)
                assert release_first.wait(2)

        def second_worker():
            assert first_entered.wait(2)
            lock = srv._project_lock(pid)
            locks["second"] = lock
            second_has_reference.set()
            with lock:
                second_entered.set()

        first = threading.Thread(target=first_worker)
        second = threading.Thread(target=second_worker)
        first.start()
        second.start()
        assert first_entered.wait(1)
        assert second_has_reference.wait(1)
        assert locks["first"] is locks["second"]
        assert not second_entered.is_set()
        release_first.set()
        first.join(timeout=3)
        second.join(timeout=3)

        assert not first.is_alive() and not second.is_alive()
        assert second_entered.is_set()


def test_background_process_rejects_review_write_without_waiting_for_project_lock():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "background-review-conflict", "mode": "rule"},
        ).json()["id"]
        unavailable = {
            "available": False, "ok": None, "pages": 0, "errors": [], "log": "",
        }
        with patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable):
            assert c.post(f"/api/projects/{pid}/process").json()["ok"] is True
        candidate_id = next(
            item["candidate_id"]
            for item in c.get(f"/api/projects/{pid}/decisions").json()["items"]
            if item["status"] == "applied"
        )

        original_pipeline = srv.run_pipeline
        entered = threading.Event()
        release = threading.Event()

        def slow_pipeline(*args, **kwargs):
            entered.set()
            assert release.wait(3)
            return original_pipeline(*args, **kwargs)

        with (
            patch.object(srv, "run_pipeline", slow_pipeline),
            patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable),
        ):
            assert c.post(f"/api/projects/{pid}/process/start").status_code == 200
            assert entered.wait(1)
            started = time.monotonic()
            conflict = c.post(
                f"/api/projects/{pid}/decisions/{candidate_id}/reject"
            )
            elapsed = time.monotonic() - started
            assert conflict.status_code == 409
            assert elapsed < 1.0
            release.set()
            state = _wait_for_json(
                c,
                f"/api/projects/{pid}/process/status",
                lambda item: item["status"] in {"done", "blocked", "error", "cancelled"},
            )
        assert state["status"] == "done", state
        assert c.get(f"/api/projects/{pid}/decisions").json()["excludes"] == []


def test_rulesets_and_folder_import():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.get("/api/rulesets").json()
        assert "bilingual" in r["packs"] and "academic-paper" in r["packs"]
        templates = c.get("/api/templates").json()
        assert templates["ocr_default"] == "faithfulbook"
        assert templates["default"] == ""
        assert templates["export_default"] == ""
        assert templates["fixed"] is False
        assert {item["id"] for item in templates["templates"]} == {
            "", "faithfulbook", "elegantbook",
        }
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
        # 显式选择 ElegantBook 时，转换结果和离线资产仍须完整打包。
        r = c.post("/api/projects/folder", json={
            "files": files,
            "name": "book",
            "mode": "rule",
            "template": "elegantbook",
        })
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
        store = srv.get_store()
        project_dir = Path(store._dir(pid))
        # 审阅拒绝会重跑，但逐文件结果和原始二进制资源仍可安全导出。
        items = c.get(f"/api/projects/{pid}/decisions").json()["items"]
        theorem = next(i for i in items if i["kind"] == "theorem-like")
        rejected = c.post(f"/api/projects/{pid}/decisions/{theorem['candidate_id']}/reject")
        assert rejected.status_code == 200 and rejected.json()["ok"] is True
        assert c.get(f"/api/projects/{pid}/export-folder").status_code == 200
        # 文件夹导出同样必须核对 result.tex 与最终 verification marker。
        report_text = store.read_report(pid)
        store._write_text(str(project_dir), "report.md", report_text + "\n篡改")
        stale_report = c.get(f"/api/projects/{pid}/export-folder")
        assert stale_report.status_code == 409 and "汇报" in stale_report.json()["detail"]
        store._write_text(str(project_dir), "report.md", report_text)
        # v1.1.2 的旧 marker 尚无 report_sha256；读取旧项目时继续兼容。
        marker_path = project_dir / "verification.json"
        legacy_marker = json.loads(marker_path.read_text(encoding="utf-8"))
        legacy_marker.pop("report_sha256")
        marker_path.write_text(json.dumps(legacy_marker, ensure_ascii=False), encoding="utf-8")
        assert c.get(f"/api/projects/{pid}/export-folder").status_code == 200
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
        state = _wait_for_json(
            c,
            f"/api/projects/{pid}/process/status",
            lambda item: item["status"] in {"done", "blocked", "error", "cancelled"},
        )
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
            state = _wait_for_json(
                c,
                f"/api/projects/{pid}/process/status",
                lambda item: item["status"] in {"done", "blocked", "error", "cancelled"},
            )
        assert state["status"] == "done", state
        assert c.get(f"/api/projects/{pid}/result").status_code == 200


def test_background_process_freezes_complete_ai_config_at_start():
    """A later settings change cannot alter an already advertised backend/model."""
    from latexstruct.config import AppConfig

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        srv._config = AppConfig(
            analysis_backend="codex_cli",
            codex_model="snapshot-model",
            codex_reasoning_effort="high",
        )
        pid = c.post(
            "/api/projects",
            json={"text": SAMPLE, "name": "frozen-ai-config", "mode": "ai"},
        ).json()["id"]
        worker_entered = threading.Event()
        release_worker = threading.Event()
        captured = {}
        original_pipeline = srv.run_pipeline

        def blocked_begin_pipeline():
            worker_entered.set()
            assert release_worker.wait(3)

        def capture_pipeline(*args, **kwargs):
            ai_config = kwargs["ai_config"]
            captured.update({
                "backend": ai_config.analysis_backend,
                "model": ai_config.codex_model,
                "effort": ai_config.codex_reasoning_effort,
            })
            # Exercise the rest of the transaction without issuing a model request.
            kwargs["mode"] = "rule"
            kwargs["ai_config"] = None
            return original_pipeline(*args, **kwargs)

        unavailable = {
            "available": False, "ok": None, "pages": 0, "errors": [], "log": "",
        }
        with (
            patch.object(srv, "_begin_pipeline_run", blocked_begin_pipeline),
            patch.object(srv, "run_pipeline", capture_pipeline),
            patch("latexstruct.core.compilecheck.compile_latex", return_value=unavailable),
        ):
            started = c.post(f"/api/projects/{pid}/process/start")
            assert started.status_code == 200
            assert started.json()["analysis_backend"] == "codex_cli"
            assert worker_entered.wait(1)

            # Simulate an overlapping settings save mutating the cached object.  The
            # worker must retain the deep copy captured by process/start.
            srv._config.analysis_backend = "api"
            srv._config.codex_model = "changed-after-start"
            srv._config.codex_reasoning_effort = "low"
            release_worker.set()
            state = _wait_for_json(
                c,
                f"/api/projects/{pid}/process/status",
                lambda item: item["status"] in {"done", "blocked", "error", "cancelled"},
            )

        assert state["status"] == "done", state
        assert state["analysis_backend"] == "codex_cli"
        assert captured == {
            "backend": "codex_cli",
            "model": "snapshot-model",
            "effort": "high",
        }


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
            state = _wait_for_json(
                c,
                f"/api/projects/{pid}/process/status",
                lambda item: item["status"] in {"done", "blocked", "error", "cancelled"},
            )

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
            state = _wait_for_json(
                c,
                f"/api/projects/{pid}/process/status",
                lambda item: item["status"] in {"done", "blocked", "error", "cancelled"},
            )

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
            return (
                "```latex\nTheorem 1. A recovered statement.\n\n"
                "Proof. Recovered proof text. This completes the proof.\n```"
            )

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
                review_batch = re.search(
                    r"本请求待复查 candidate 共 \d+ 个：(.*?)。",
                    user,
                )
                review_ids = [
                    candidate_id.strip()
                    for candidate_id in (review_batch.group(1).split(",") if review_batch else [])
                    if candidate_id.strip()
                ]
                return {
                    "findings": [{
                        "candidate_id": candidate_id,
                        "verdict": "ok",
                        "reason": "离线假模型逐项确认结构",
                    } for candidate_id in review_ids]
                }, {"total_tokens": 4}
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
            process = _wait_for_json(
                c,
                f"/api/projects/{pid}/process/status",
                lambda item: item["status"]
                not in {"running", "pausing", "paused", "committing"},
            )
        assert process["status"] == "done", process
        raw = c.get(f"/api/projects/{pid}/source").text
        structured = c.get(f"/api/projects/{pid}/result").text
        assert "Theorem 1." in raw and "\\begin{theorem}" not in raw
        assert "% LaTeXStruct template: faithfulbook v1" in structured
        assert "\\documentclass[10pt,twoside,openany]{book}" in structured
        assert "\\begin{theorem}[1]" in structured
        assert "Theorem 1. A recovered statement." not in structured
        assert "\\begin{proof}" in structured
        project = srv.get_store().get(pid)
        assert project["kind"] == "ocr"
        assert project["mode"] == "ai"
        assert project["template"] == "faithfulbook"
        job = srv._ocr_jobs.pop(jid, {})
        shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_ocr_quality_gate_retry_forwards_controlled_correction_feedback():
    with WorkspaceTmp() as tmp:
        srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
        srv._config = None
        client = TestClient(srv.create_app())
        users = []

        def caption_retry(_self, _system, user, _image):
            users.append(user)
            if len(users) == 1:
                return (
                    r"\includegraphics{images/page_1_1} "
                    r"% figure: Fig. 1.1. Visible caption"
                )
            return "\n".join([
                r"\includegraphics{images/page_1_1} % figure: diagram",
                r"Fig. 1.1. Visible caption",
            ])

        png = b"\x89PNG\r\n\x1a\n" + b"0" * 16
        jid = ""
        try:
            with patch("latexstruct.core.ai.LLMClient.chat_vision", caption_retry):
                created = _inspect_and_start_image(client, "a.png", png, "image/png")
                jid = created.json()["id"]
                for _ in range(100):
                    state = client.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)
            assert state["status"] == "done", state
            assert state["pages"]["1"]["attempts"] == 2
            assert "retry_correction" in users[1]
            assert "Fig. 1.1" in users[1]
            assert "Fig. 1.1. Visible caption" in client.get(
                f"/api/ocr/jobs/{jid}/result"
            ).text
        finally:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_server_forwards_relation_regions_and_retries_to_local_pixel_evidence():
    from latexstruct.ocr import RELATION_VERIFY_SYSTEM_PROMPT

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""
        calls = {"page": 0, "local": 0}
        region = {
            "evidence_id": "p41-relation-3",
            "left": "n",
            "right": "3",
            "reference_operator": ">=",
            "bbox_normalized": [0.104218, 0.486555, 0.299665, 0.525958],
        }

        def fake_render(_path, pages, _dpi):
            assert list(pages) == [41]
            yield 41, b"\x89PNG\r\n\x1a\n" + b"page-pixels"

        def fake_vision(client, system, _user, _image):
            client.last_usage = {"total_tokens": 10}
            if system == RELATION_VERIFY_SYSTEM_PROMPT:
                calls["local"] += 1
                return r"\geq"
            calls["page"] += 1
            if calls["page"] == 1:
                return r"For \(n>3\), this sufficiently long paragraph describes the graph."
            return r"For \(n\geq3\), this sufficiently long paragraph describes the graph."

        try:
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 41, "outline": []},
            ):
                inspected = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                )
            assert inspected.status_code == 200, inspected.text
            jid = inspected.json()["id"]
            with (
                patch("latexstruct.ocr.iter_pdf_pages", fake_render),
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
                patch(
                    "latexstruct.ocr.pdf_page_text_hint",
                    return_value="For n ≥3, this sufficiently long paragraph describes the graph.",
                ),
                patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
                patch(
                    "latexstruct.ocr.pdf_page_relation_regions",
                    return_value=[region],
                ),
                patch(
                    "latexstruct.ocr._crop_normalized_image_region",
                    return_value=(
                        b"\x89PNG\r\n\x1a\n" + b"local-crop",
                        [517, 159],
                        "f" * 64,
                    ),
                ),
                patch("latexstruct.core.ai.LLMClient.chat_vision", fake_vision),
                patch("latexstruct.server.app._ocr_retry_wait", return_value=None),
            ):
                started = c.post(
                    f"/api/ocr/jobs/{jid}/start",
                    data={"start_page": "41", "end_page": "41", "dpi": "300"},
                )
                assert started.status_code == 200, started.text
                for _ in range(150):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)

            assert state["status"] == "done", state
            assert state["pages"]["41"]["attempts"] == 2
            with srv._ocr_jobs_lock:
                internal_page = dict(srv._ocr_jobs[jid]["pages"][41])
            assert calls == {"page": 2, "local": 1}, (
                internal_page.get("text_hint"),
                internal_page.get("relation_regions"),
                internal_page.get("quality_flags"),
            )
            assert state["pages"]["41"]["quality_flag_count"] == 1
            assert state["pages"]["41"]["needs_review"] is False
            assert r"\(n\geq3\)" in c.get(f"/api/ocr/jobs/{jid}/result").text
            flag = dict(internal_page["quality_flags"][0])
            assert flag["status"] == "corrected_after_local_visual_retry"
            assert flag["local_visual_operator"] == ">="
            assert flag["crop_sha256"] == "f" * 64
        finally:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_server_forwards_divider_regions_and_records_retry_evidence():
    from latexstruct.ocr import DIVIDER_VERIFY_SYSTEM_PROMPT

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""
        calls = {"page": 0, "local": 0}
        region = {
            "evidence_id": "p36-divider-1",
            "source_center_glyph_count": 2,
            "source_left_rule_glyph_count": 5,
            "source_right_rule_glyph_count": 5,
            "bbox_normalized": [0.34, 0.73, 0.66, 0.79],
            "line_bbox_normalized": [0.38, 0.75, 0.62, 0.77],
            "source": "pdf_text_span_geometry",
        }
        incomplete = "\n".join([
            "A sufficiently long exercise paragraph remains visible on this page.",
            r"\begin{center}",
            r"\rule{0.12\linewidth}{0.4pt}\(\wr\)\rule{0.12\linewidth}{0.4pt}",
            r"\end{center}",
        ])
        complete = incomplete.replace(r"\(\wr\)", r"\(\wr\wr\)")

        def fake_render(_path, pages, _dpi):
            assert list(pages) == [36]
            yield 36, b"\x89PNG\r\n\x1a\n" + b"page-pixels"

        def fake_vision(client, system, _user, _image):
            client.last_usage = {"total_tokens": 10}
            if system == DIVIDER_VERIFY_SYSTEM_PROMPT:
                calls["local"] += 1
                return "COMPLETE_DOUBLE_DIVIDER"
            calls["page"] += 1
            return incomplete if calls["page"] == 1 else complete

        try:
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 36, "outline": []},
            ):
                inspected = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                )
            assert inspected.status_code == 200, inspected.text
            jid = inspected.json()["id"]
            with (
                patch("latexstruct.ocr.iter_pdf_pages", fake_render),
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[]),
                patch(
                    "latexstruct.ocr.pdf_page_text_hint",
                    return_value="A sufficiently long exercise paragraph remains visible on this page.",
                ),
                patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
                patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
                patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[region]),
                patch(
                    "latexstruct.ocr._crop_normalized_image_region",
                    return_value=(
                        b"\x89PNG\r\n\x1a\n" + b"divider-crop",
                        [720, 180],
                        "d" * 64,
                    ),
                ),
                patch("latexstruct.core.ai.LLMClient.chat_vision", fake_vision),
                patch("latexstruct.server.app._ocr_retry_wait", return_value=None),
            ):
                started = c.post(
                    f"/api/ocr/jobs/{jid}/start",
                    data={"start_page": "36", "end_page": "36", "dpi": "300"},
                )
                assert started.status_code == 200, started.text
                for _ in range(150):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)

            assert state["status"] == "done", state
            assert state["pages"]["36"]["attempts"] == 2
            assert calls == {"page": 2, "local": 1}
            with srv._ocr_jobs_lock:
                internal_page = dict(srv._ocr_jobs[jid]["pages"][36])
            assert internal_page["divider_regions"] == [region]
            flag = dict(internal_page["quality_flags"][0])
            assert flag["status"] == "corrected_after_local_visual_retry"
            assert flag["active_wr_count"] == 2
            assert flag["crop_sha256"] == "d" * 64
            assert r"\(\wr\wr\)" in c.get(f"/api/ocr/jobs/{jid}/result").text
        finally:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_pdf_ocr_server_forwards_footnote_regions_and_records_retry_evidence():
    from latexstruct.ocr import FOOTNOTE_VERIFY_SYSTEM_PROMPT

    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""
        calls = {"page": 0, "local": 0}
        region = {
            "evidence_id": "p55-footnote-1",
            "marker_hint": "1",
            "reference_count": 2,
            "reference_bboxes_normalized": [
                [0.717655, 0.194633, 0.726686, 0.205102],
                [0.545468, 0.468331, 0.554499, 0.4788],
            ],
            "definition_bbox_normalized": [0.105618, 0.864932, 0.740983, 0.895532],
            "bbox_normalized": [0.070194, 0.849921, 0.768294, 0.910544],
            "rule_present": True,
            "rule_bbox_normalized": [0.097506, 0.870013, 0.210884, 0.870013],
            "font_evidence": {
                "reference_pt": 6.974,
                "note_body_pt": 8.966,
                "reference_fonts": ["CMR7"],
                "note_fonts": ["CMR9", "CMMI9"],
            },
            "source": "pdf_text_font_geometry_plus_optional_vector_rule",
        }
        manual = (
            r"A sufficiently long paragraph has a first mark\textsuperscript{1}. "
            r"A later sentence repeats it\textsuperscript{1}. "
            r"\rule{0.12\linewidth}{0.4pt}\textsuperscript{1} Note body."
        )
        semantic = (
            r"A sufficiently long paragraph has a first mark\footnote[1]{Note body.} "
            r"A later sentence repeats it\footnotemark[1]."
        )

        def fake_render(_path, pages, _dpi):
            assert list(pages) == [55]
            yield 55, b"\x89PNG\r\n\x1a\n" + b"page-pixels"

        def fake_vision(client, system, _user, _image):
            client.last_usage = {"total_tokens": 10}
            if system == FOOTNOTE_VERIFY_SYSTEM_PROMPT:
                calls["local"] += 1
                return "FOOTNOTE_DEFINITION"
            calls["page"] += 1
            return manual if calls["page"] == 1 else semantic

        try:
            with patch(
                "latexstruct.ocr.pdf_document_info_bytes",
                return_value={"pages": 55, "outline": []},
            ):
                inspected = c.post(
                    "/api/ocr/inspect",
                    files={"file": ("book.pdf", b"%PDF-1.7\nfake", "application/pdf")},
                )
            assert inspected.status_code == 200, inspected.text
            jid = inspected.json()["id"]
            with (
                patch("latexstruct.ocr.iter_pdf_pages", fake_render),
                patch(
                    "latexstruct.ocr.pdf_page_text_hint",
                    return_value="A sufficiently long paragraph with a repeated footnote.",
                ),
                patch("latexstruct.ocr.pdf_page_italic_terms", return_value=[]),
                patch("latexstruct.ocr.pdf_page_relation_regions", return_value=[]),
                patch("latexstruct.ocr.pdf_page_divider_regions", return_value=[]),
                patch("latexstruct.ocr.pdf_page_framed_insets", return_value=[]),
                patch("latexstruct.ocr.pdf_page_footnote_regions", return_value=[region]),
                patch(
                    "latexstruct.ocr._crop_normalized_image_region",
                    return_value=(
                        b"\x89PNG\r\n\x1a\n" + b"footnote-crop",
                        [698, 221],
                        "e" * 64,
                    ),
                ),
                patch("latexstruct.core.ai.LLMClient.chat_vision", fake_vision),
                patch("latexstruct.server.app._ocr_retry_wait", return_value=None),
            ):
                started = c.post(
                    f"/api/ocr/jobs/{jid}/start",
                    data={"start_page": "55", "end_page": "55", "dpi": "300"},
                )
                assert started.status_code == 200, started.text
                for _ in range(150):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] != "running":
                        break
                    time.sleep(0.02)

            assert state["status"] == "done", state
            assert state["pages"]["55"]["attempts"] == 2
            assert calls == {"page": 2, "local": 1}
            with srv._ocr_jobs_lock:
                live_job = srv._ocr_jobs[jid]
                internal_page = dict(live_job["pages"][55])
                snapshot = srv._snapshot_ocr_bundle_job(live_job)
            assert internal_page["footnote_regions"] == [region]
            assert snapshot["pages"][55]["footnote_regions"] == [region]
            flag = dict(internal_page["quality_flags"][0])
            assert flag["status"] == "corrected_after_local_visual_retry"
            assert flag["source_reference_count"] == 2
            assert flag["active_reference_count"] == 2
            assert flag["active_body_count"] == 1
            assert flag["crop_sha256"] == "e" * 64
            result = c.get(f"/api/ocr/jobs/{jid}/result").text
            assert result.count(r"\footnote[1]") == 1
            assert result.count(r"\footnotemark[1]") == 1
            assert r"\textsuperscript" not in result
        finally:
            with srv._ocr_jobs_lock:
                job = srv._ocr_jobs.pop(jid, {}) if jid else {}
            shutil.rmtree(job.get("dir", ""), ignore_errors=True)


def test_ocr_manifest_records_local_relation_pixel_evidence():
    flag = {
        "type": "relation_local_visual_evidence",
        "status": "corrected_after_local_visual_retry",
        "needs_review": False,
        "left": "n",
        "right": "2",
        "occurrence": 1,
        "reference_operator": ">=",
        "visual_operator": "",
        "initial_page_visual_operator": ">",
        "local_visual_operator": ">=",
        "evidence_id": "p29-relation-2",
        "crop_bbox_normalized": [0.221115, 0.553063, 0.459414, 0.593684],
        "crop_size_pixels": [629, 162],
        "crop_sha256": "b" * 64,
        "verifier": "reference_free_local_pixel_crop",
    }
    records = srv._ocr_manifest_page_records({
        "pages": {
            29: {
                "image_size_pixels": [1343, 2036],
                "text_hint_chars": 1234,
                "text_hint_sha256": "a" * 64,
                "figures": [],
                "quality_flags": [flag],
                "needs_review": False,
            },
        },
    })

    assert records[0]["source_page"] == 29
    assert records[0]["needs_review"] is False
    assert records[0]["quality_flags"] == [flag]


def test_publication_formula_evidence_uses_stored_hash_and_exports_no_private_path():
    import latexstruct.core.ocrformula as formula

    class MultiImageClient:
        def chat_vision_structured_images_bytes(self, *_args):
            raise AssertionError("preparation must not invoke the model")

    class Region:
        region_id = "p0085-f001"
        bbox_points = (100.0, 200.0, 300.0, 260.0)

    class Evidence:
        region = Region()
        crop_bbox_points = (80.0, 180.0, 320.0, 280.0)
        image_sha256 = "b" * 64
        dpi = 420
        image_size_pixels = (1400, 580)
        crop_path = Path("C:/private/formula-crops/p0085-f001.png")

    captured = {}

    def fake_render(_source, source_sha256, regions, _directory, *, dpi):
        captured["source_sha256"] = source_sha256
        captured["regions"] = list(regions)
        captured["dpi"] = dpi
        return [Evidence()]

    region = Region()
    with tempfile.TemporaryDirectory(prefix="ls-formula-test-") as temp_dir:
        job = {
            "quality_profile": "publication",
            "source_type": "pdf",
            "target": str(Path(temp_dir) / "source.pdf"),
            "dir": temp_dir,
            "_source_sha256": "a" * 64,
            "client": MultiImageClient(),
        }
        with (
            patch.object(formula, "detect_pdf_formula_regions", return_value=[region]),
            patch.object(formula, "render_pdf_formula_evidence", side_effect=fake_render),
            patch.object(
                formula,
                "target_bbox_normalized",
                return_value=(0.083333, 0.2, 0.916667, 0.8),
            ),
        ):
            internal = srv._prepare_page_formula_evidence(job, 85)

    assert captured == {
        "source_sha256": "a" * 64,
        "regions": [region],
        "dpi": 420,
    }
    assert Path(internal[0]["crop_path"]).as_posix().startswith("C:/private")
    public_record = {
        **internal[0],
        "attached": True,
        "untrusted_extra": "must-not-export",
    }
    records = srv._ocr_manifest_page_records({
        "pages": {85: {
            "png": "C:/private/page-85.png",
            "status": "done",
            "visual_input_sha256": "c" * 64,
            "formula_evidence": [public_record],
        }},
    })
    formula_record = records[0]["formula_visual_evidence"][0]
    assert formula_record == {
        "id": "p0085-f001",
        "target_bbox_normalized_in_crop": [0.083333, 0.2, 0.916667, 0.8],
        "source_bbox_points": [100.0, 200.0, 300.0, 260.0],
        "crop_bbox_points": [80.0, 180.0, 320.0, 280.0],
        "crop_sha256": "b" * 64,
        "dpi": 420,
        "attached": True,
        "image_size_pixels": [1400, 580],
    }
    assert records[0]["visual_input_sha256"] == "c" * 64
    assert "private" not in json.dumps(records)
    assert "untrusted_extra" not in json.dumps(records)


def test_formula_crop_preparation_is_noop_without_codex_multi_image_support():
    import latexstruct.core.ocrformula as formula

    job = {
        "quality_profile": "publication",
        "source_type": "pdf",
        "client": object(),
    }
    with patch.object(
        formula,
        "detect_pdf_formula_regions",
        side_effect=AssertionError("API publication must not render unused crops"),
    ):
        assert srv._prepare_page_formula_evidence(job, 1) == []

        class MultiImageClient:
            def chat_vision_structured_images_bytes(self, *_args):
                return None

        standard_job = {
            "quality_profile": "standard",
            "source_type": "pdf",
            "client": MultiImageClient(),
        }
        assert srv._prepare_page_formula_evidence(standard_job, 1) == []


def test_ocr_manifest_records_divider_integrity_evidence():
    flag = {
        "type": "divider_integrity_evidence",
        "status": "corrected_after_local_visual_retry",
        "needs_review": False,
        "evidence_id": "p36-divider-1",
        "source_center_glyph_count": 2,
        "source_left_rule_glyph_count": 5,
        "source_right_rule_glyph_count": 5,
        "active_wr_count": 2,
        "active_rule_count": 2,
        "local_visual_status": "COMPLETE_DOUBLE_DIVIDER",
        "line_bbox_normalized": [0.38, 0.75, 0.62, 0.77],
        "crop_bbox_normalized": [0.34, 0.73, 0.66, 0.79],
        "crop_size_pixels": [720, 180],
        "crop_sha256": "c" * 64,
        "verifier": "reference_free_local_pixel_crop",
        "source": "pdf_text_span_geometry",
    }
    records = srv._ocr_manifest_page_records({
        "pages": {36: {
            "image_size_pixels": [2197, 3331],
            "text_hint_chars": 1000,
            "text_hint_sha256": "a" * 64,
            "figures": [],
            "quality_flags": [flag],
            "needs_review": False,
        }},
    })

    stored = records[0]["quality_flags"][0]
    for key, value in flag.items():
        assert stored[key] == value


def test_ocr_manifest_records_only_bounded_framed_inset_evidence():
    flag = {
        "type": "framed_inset_vector_evidence",
        "status": "source_geometry_and_active_match",
        "needs_review": False,
        "evidence_id": "p58-framed-inset-1",
        "title": "Proof Technique: Induction",
        "title_visible": True,
        "position": "closed",
        "environment": "lsframedinset",
        "frame_bbox_normalized": [0.09393, 0.08132, 0.90329, 0.9001],
        "model_bbox_normalized": [0.094, 0.081, 0.903, 0.9],
        "model_bbox_pixels": [206, 271, 1984, 2998],
        "title_bbox_normalized": [0.12, 0.095, 0.47, 0.112],
        "edge_presence": {
            "top": True, "left": True, "right": True, "bottom": True,
            "unexpected": True,
        },
        "stroke_width_pt": 0.405,
        "title_font_evidence": "small_caps_font",
        "verifier": "pdf_vector_geometry_plus_structured_codex_output",
        "untrusted_extra": "must not enter manifest",
    }
    records = srv._ocr_manifest_page_records({
        "pages": {58: {
            "image_size_pixels": [2197, 3331],
            "text_hint_chars": 1000,
            "text_hint_sha256": "a" * 64,
            "figures": [],
            "quality_flags": [flag],
            "needs_review": False,
        }},
    })

    stored = records[0]["quality_flags"][0]
    for key in (
        "type", "status", "needs_review", "evidence_id", "title",
        "title_visible", "position",
        "environment", "frame_bbox_normalized", "model_bbox_normalized",
        "model_bbox_pixels", "title_bbox_normalized", "stroke_width_pt",
        "title_font_evidence", "verifier",
    ):
        assert stored[key] == flag[key]
    assert stored["edge_presence"] == {
        "top": True, "left": True, "right": True, "bottom": True,
    }
    assert "untrusted_extra" not in stored


def test_ocr_manifest_records_only_bounded_footnote_evidence():
    region = {
        "evidence_id": "p55-footnote-1",
        "marker_hint": "1",
        "reference_count": 2,
        "reference_bboxes_normalized": [
            [0.71, 0.19, 0.72, 0.20],
            [0.54, 0.46, 0.55, 0.47],
            *[[0.1, 0.1, 0.2, 0.2] for _ in range(7)],
        ],
        "definition_bbox_normalized": [0.10, 0.86, 0.74, 0.90],
        "rule_present": True,
        "rule_bbox_normalized": [0.09, 0.87, 0.21, 0.87],
        "font_evidence": {
            "reference_pt": 6.974,
            "note_body_pt": 8.966,
            "reference_fonts": ["CMR7"],
            "note_fonts": ["CMR9", "CMMI9"],
        },
        "source": "pdf_text_font_geometry_plus_optional_vector_rule",
        "body_text": "must never enter a manifest",
        "untrusted_extra": "must never enter a manifest",
    }
    flag = {
        "type": "footnote_structure_evidence",
        "status": "corrected_after_local_visual_retry",
        "needs_review": False,
        "evidence_id": "p55-footnote-1",
        "marker": "1",
        "source_reference_count": 2,
        "active_reference_count": 2,
        "active_body_count": 1,
        "reference_bboxes_normalized": [
            [0.71, 0.19, 0.72, 0.20],
            [0.54, 0.46, 0.55, 0.47],
            [float("nan"), 0.1, 0.2, 0.3],
        ],
        "body_bbox_normalized": [0.10, 0.86, 0.74, 0.90],
        "rule_bbox_normalized": [0.09, 0.87, 0.21, 0.87],
        "rule_present": True,
        "marker_font": "CMR7",
        "body_font": "CMR9,CMMI9",
        "marker_size_pt": 6.974,
        "body_size_pt": 8.966,
        "body_chars": 93,
        "body_sha256": "b" * 64,
        "crop_bbox_normalized": [0.07, 0.84, 0.77, 0.91],
        "crop_size_pixels": [698, 221],
        "crop_sha256": "c" * 64,
        "verifier": "reference_free_local_pixel_crop",
        "source": "pdf_text_font_geometry_plus_optional_vector_rule",
        "body_text": "must never enter a manifest",
        "untrusted_extra": "must never enter a manifest",
    }
    records = srv._ocr_manifest_page_records({
        "pages": {55: {
            "image_size_pixels": [2197, 3331],
            "text_hint_chars": 1000,
            "text_hint_sha256": "a" * 64,
            "figures": [],
            "footnote_regions": [region],
            "quality_flags": [flag],
            "needs_review": False,
        }},
    })

    source = records[0]["footnote_source_evidence"][0]
    stored = records[0]["quality_flags"][0]
    assert len(source["reference_bboxes_normalized"]) == 8
    assert len(stored["reference_bboxes_normalized"]) == 2
    assert stored["source_reference_count"] == 2
    assert stored["active_reference_count"] == 2
    assert stored["active_body_count"] == 1
    assert stored["body_sha256"] == "b" * 64
    for item in (source, stored):
        assert "body_text" not in item
        assert "untrusted_extra" not in item


def test_ocr_import_rejects_unknown_structure_mode():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        response = c.post("/api/ocr/jobs/missing/import?mode=freeform-agent")
        assert response.status_code == 400
        assert "AI 或规则" in response.json()["detail"]


def test_ocr_import_never_opens_review_with_unresolved_images():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = "unresolved-ocr"
        job_dir = tempfile.mkdtemp(prefix="ocr-unresolved-", dir=tmp)
        page_path = Path(job_dir, "page-1.png")
        page_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 24)
        with srv._ocr_jobs_lock:
            srv._ocr_jobs[jid] = {
                "id": jid,
                "status": "done",
                "raw_ready": True,
                "raw_tex": "% Page 1\n\\includegraphics{images/page_1_1}",
                "raw_revision": 1,
                "usage_revision": 0,
                "page_revision": 1,
                "downloaded_revision": 0,
                "imported_revision": 0,
                "importing": False,
                "saving": False,
                "usage": {},
                "selected_pages": [1],
                "pages": {1: {"png": str(page_path), "status": "done"}},
                "dir": job_dir,
            }
        try:
            with patch(
                "latexstruct.server.app._preserve_ocr_resources",
                return_value={
                    "assets": [],
                    "source_pages": [],
                    "unresolved": ["images/page_1_1"],
                    "errors": ["synthetic extraction failure"],
                },
            ):
                response = c.post(f"/api/ocr/jobs/{jid}/import")

            assert response.status_code == 409
            assert "未进入分析与审阅" in response.json()["detail"]
            assert srv.get_store().list() == []
            with srv._ocr_jobs_lock:
                assert srv._ocr_jobs[jid]["status"] == "done"
                assert srv._ocr_jobs[jid]["importing"] is False
                assert srv._ocr_jobs[jid].get("imported_project_id", "") == ""
        finally:
            with srv._ocr_jobs_lock:
                srv._ocr_jobs.pop(jid, None)
            shutil.rmtree(job_dir, ignore_errors=True)


def test_ocr_import_blocks_every_active_noncanonical_image_reference():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        for index, image_path in enumerate(
            ("figure.png", "images/diagram", "images/page_1_1.pdf"),
            start=1,
        ):
            jid = f"unsupported-ocr-image-{index}"
            job_dir = tempfile.mkdtemp(prefix="ocr-unsupported-", dir=tmp)
            page_path = Path(job_dir, "page-1.png")
            page_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 24)
            with srv._ocr_jobs_lock:
                srv._ocr_jobs[jid] = {
                    "id": jid,
                    "status": "done",
                    "raw_ready": True,
                    "raw_tex": f"% Page 1\n\\includegraphics{{{image_path}}}",
                    "raw_revision": 1,
                    "usage_revision": 0,
                    "page_revision": 1,
                    "downloaded_revision": 0,
                    "imported_revision": 0,
                    "importing": False,
                    "saving": False,
                    "usage": {},
                    "selected_pages": [1],
                    "pages": {1: {"png": str(page_path), "status": "done"}},
                    "dir": job_dir,
                }
            try:
                response = c.post(f"/api/ocr/jobs/{jid}/import")

                assert response.status_code == 409
                assert image_path in response.json()["detail"]
                assert "未进入分析与审阅" in response.json()["detail"]
                assert srv.get_store().list() == []
            finally:
                with srv._ocr_jobs_lock:
                    srv._ocr_jobs.pop(jid, None)
                shutil.rmtree(job_dir, ignore_errors=True)


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


def test_ocr_structured_model_output_is_preserved_and_marked_for_review():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        jid = ""

        def structured_output(_self, _system, _user, _image):
            return (
                "```latex\n\\section{Visible source heading}\n"
                "This non-empty OCR text must be retained instead of failing the whole page.\n```"
            )

        try:
            with patch("latexstruct.core.ai.LLMClient.chat_vision", structured_output):
                created = _inspect_and_start_image(
                    c, "a.png", b"\x89PNG\r\n\x1a\n" + b"0" * 24, "image/png",
                )
                jid = created.json()["id"]
                for _ in range(100):
                    state = c.get(f"/api/ocr/jobs/{jid}").json()
                    if state["status"] == "done":
                        break
                    time.sleep(0.02)
            assert state["status"] == "done", state
            page = state["pages"]["1"]
            assert page["status"] == "done"
            assert page["needs_review"] is True
            assert page["low_conf"] is True
            assert "\\section{Visible source heading}" in c.get(
                f"/api/ocr/jobs/{jid}/result"
            ).text
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
        for status in ("running", "pausing", "paused"):
            with srv._ocr_jobs_lock:
                srv._ocr_jobs["busy-ocr"] = {"status": status}
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
            browser_package = c.get("/api/ocr/jobs/paid-ocr/package")
            assert browser_package.status_code == 200
            assert browser_package.headers["x-latexstruct-ocr-complete"] == "true"
            with zipfile.ZipFile(io.BytesIO(browser_package.content)) as archive:
                from latexstruct.core.provenance import strip_tex_provenance

                assert strip_tex_provenance(archive.read("ocr.tex")) == b"paid OCR result"
                assert "OCR-MANIFEST.json" in archive.namelist()
            with srv._ocr_jobs_lock:
                assert srv._ocr_jobs["paid-ocr"]["downloaded_revision"] == 0
            with patch(
                "latexstruct.server.downloads.download_root",
                return_value=Path(tmp) / "ocr-downloads",
            ):
                downloaded = c.post("/api/ocr/jobs/paid-ocr/save")
            assert downloaded.status_code == 200
            assert downloaded.json()["filename"].endswith(".zip")
            saved_package = Path(tmp, "ocr-downloads", downloaded.json()["filename"])
            with zipfile.ZipFile(saved_package) as archive:
                from latexstruct.core.provenance import strip_tex_provenance

                assert strip_tex_provenance(archive.read("ocr.tex")) == b"paid OCR result"
                assert "OCR-MANIFEST.json" in archive.namelist()
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
    from latexstruct import __version__
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
            previous_version=__version__,
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
            assert "elegantbook.cls" not in zf.namelist()
            assert "ELEGANTBOOK-LICENSE.txt" not in zf.namelist()
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
            "paused-active": {
                "status": "paused", "created": old, "raw_ready": False,
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
                assert "paused-active" in srv._ocr_jobs
                assert "saved-result" not in srv._ocr_jobs
                assert "empty-ready" not in srv._ocr_jobs
            assert (Path(tmp) / "unsaved-raw").is_dir()
            assert (Path(tmp) / "paid-failure").is_dir()
            assert (Path(tmp) / "stale-paid-state").is_dir()
            assert (Path(tmp) / "paused-active").is_dir()
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
    assert 'api("/api/templates")' in source
    assert 'fd.append("quality_profile", qualityProfile)' in source
    assert 'fd.append("output_template", outputTemplate)' in source
    assert 'useState(OCR_QUALITY_PUBLICATION)' in source
    assert 'qualityReport?.page_gate_passed !== true' in source
    assert "页级质量门未通过，暂不能进入审阅" in source
    assert "未测量文字或数学准确率，也不代表出版就绪" in source
    assert 'const importTemplate = "faithfulbook"' not in source
    assert "bondybook" not in source
    assert ".ocr-quality-gate" in styles
    assert ".ocr-output-template" in styles
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

# -*- coding: utf-8 -*-
"""OCR 结构失败的可恢复闭环测试。"""

from __future__ import annotations

import io
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from latexstruct.core.ocrstruct import (
    build_ocr_structure_ops,
    check_ocr_structure,
    encode_ocr_metadata,
)
from latexstruct.core.patch import Decision, apply_patches, validate_ops
from latexstruct.core.verify import (
    check_display_tag_safety,
    check_env_balance,
    compare_env_balance,
    verification_failures,
)
from latexstruct.server.app import _ocr_bundle_bytes, _preserve_ocr_resources
import latexstruct.server.app as server_app
from latexstruct.server.process_jobs import ProcessJobManager
from latexstruct.store import ProjectStore


def _apply_structure_ops(text: str) -> str:
    ops, _notes = build_ocr_structure_ops(text)
    lines = text.split("\n")
    planned, rejected = validate_ops(
        lines,
        [(Decision(candidate_id="ocr-recovery", action="none"), ops)],
    )
    assert rejected == []
    out, applied, rejected = apply_patches(lines, planned)
    assert applied and rejected == []
    return "\n".join(out)


def _png_bytes(label: bytes = b"page") -> bytes:
    # Resource preservation identifies the actual raster format from its magic.
    return b"\x89PNG\r\n\x1a\n" + label


def test_duplicate_model_page_comment_does_not_corrupt_outline_or_manual_toc():
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "First chapter", "page": 5},
            {"level": 1, "title": "Main method", "page": 5},
        ],
        "book",
        [1, 5],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 1",
            r"\section*{Contents}",
            r"1 \textbf{First chapter} \dotfill 5",
            r"\quad 1.1 Main method \dotfill 5",
            r"\vfill",
            r"\hbox{ii}",
            r"\clearpage",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 5",
            # 视觉模型偶尔会把印刷页码再次写成 Page 注释；这不是权威 PDF 页码。
            r"% Page 2",
            r"\section*{1 First chapter}",
            r"\subsection*{1.1 Main method}",
            "Body.",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert r"\tableofcontents" in repaired
    assert r"\dotfill" not in repaired
    assert r"\chapter{First chapter}" in repaired
    assert r"\section{Main method}" in repaired
    assert check_ocr_structure(repaired)["ok"] is True


def test_ocr_structure_ops_repair_outer_environment_closed_inside_math():
    metadata = encode_ocr_metadata([], "book", [1], False)
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 1",
            r"\begin{theorem*}[1]",
            "A statement with a display:",
            r"\[",
            r"\end{theorem*}",
            r"x=y",
            r"\]",
            r"\begin{theorem*}[2]",
            r"\begin{equation}",
            r"a=b",
            r"\end{theorem*}",
            r"\tag{2}",
            r"\end{equation}",
            r"\end{document}",
        ]
    )

    repaired = _apply_structure_ops(source)

    assert repaired.index(r"\]") < repaired.index(r"\end{theorem*}")
    first_end = repaired.index(r"\end{theorem*}")
    second_begin = repaired.index(r"\begin{theorem*}[2]")
    assert first_end < second_begin
    assert repaired.rindex(r"\end{equation}") < repaired.rindex(r"\end{theorem*}")
    assert check_env_balance(repaired)["ok"] is True
    assert check_display_tag_safety(repaired)["ok"] is True


def test_display_safety_allows_legal_matrix_environment_inside_brackets():
    text = "\n".join(
        [
            r"\[",
            r"A=\begin{pmatrix}1&0\\0&1\end{pmatrix}",
            r"\]",
        ]
    )
    assert check_display_tag_safety(text)["ok"] is True


def test_verification_failures_explain_actions_and_exact_relative_resources():
    failures = verification_failures(
        {
            "checks": [
                {"id": "outline", "label": "章节树与目录对应 PDF 大纲", "ok": False},
                {"id": "resources", "label": "图片资源真实存在且位于项目内", "ok": False},
                {"id": "compile", "label": "编译器可用时结果必须成功", "ok": False},
            ],
            "ocr_structure": {
                "issues": [{"line": 42, "reason": r"标题层级错误：应为 \section"}],
            },
            "resources": {
                "missing": ["images/page_08_01"],
                "unsafe": [],
            },
            "compile_after": {
                "errors": ["Missing $ inserted. @l.401"],
            },
        }
    )

    assert [item["id"] for item in failures] == ["outline", "resources", "compile"]
    assert failures[0]["details"][0]["line"] == 42
    assert "images/page_08_01" in failures[1]["summary"]
    assert "l.401" in failures[2]["summary"]
    assert all(item["action"] for item in failures)


def test_environment_failure_keeps_line_and_compile_error_redacts_only_local_path():
    compared = compare_env_balance(
        r"\begin{document}\end{document}",
        "\n".join([r"\begin{document}", r"\begin{theorem}", r"\end{document}"]),
    )
    failures = verification_failures(
        {
            "checks": [
                {"id": "environments", "label": "环境配平未恶化", "ok": False},
                {"id": "compile", "label": "编译器结果", "ok": False},
            ],
            "env_balance": compared,
            "compile_after": {
                "errors": [
                    r"C:\Users\Example\AppData\Local\Temp\job\main.tex:401: "
                    r"Missing $ inserted near \end{theorem}"
                ]
            },
        }
    )

    assert failures[0]["details"]
    assert failures[0]["details"][0]["line"] in {2, 3}
    assert "Example" not in failures[1]["summary"]
    assert "<local-file>:401" in failures[1]["summary"]
    assert r"\end{theorem}" in failures[1]["summary"]


def test_blocked_job_is_not_reported_done_and_keeps_last_structured_draft():
    manager = ProcessJobManager()
    job = manager.create("ocr-project", "original")
    manager.update(
        job["id"],
        "draft",
        0.84,
        "结构化草稿已生成",
        {"preview": "structured draft"},
    )
    manager.update(
        job["id"],
        "report",
        0.97,
        "安全检查未通过",
        {"preview": "original", "safe_to_export": False},
    )
    manager.update(
        job["id"],
        "ready",
        1.0,
        "安全检查完成，保留原文",
        {"preview": "original", "safe_to_export": False},
    )
    manager.complete(
        job["id"],
        {
            "ok": False,
            "failure_summary": "图片缺失：images/page_08_01",
            "failed_checks": ["resources"],
        },
    )

    public = manager.public(job)
    assert public["status"] == "blocked"
    assert public["phase"] == "verification_failed"
    assert public["message"] == "图片缺失：images/page_08_01"
    assert manager.preview(job) == "structured draft"
    assert "仅供检查" in public["preview_label"]


def test_pdf_resource_import_uses_physical_chunk_page_and_preserves_real_images():
    class FakePage:
        def __init__(self, xrefs):
            self.xrefs = xrefs

        def get_images(self, full=True):
            assert full is True
            return [(xref,) for xref in self.xrefs]

    class FakeDocument:
        page_count = 20

        def __getitem__(self, index):
            # 图片文件名中的 08/15 是书本印刷页码，权威物理页来自 OCR 段首。
            assert index in (10, 17)
            return FakePage([101, 102] if index == 10 else [201])

        def extract_image(self, xref):
            return {"ext": "png", "image": b"PNG" + str(xref).encode("ascii")}

        def close(self):
            pass

    class FakeFitz:
        @staticmethod
        def open(_path):
            return FakeDocument()

    raw = "\n".join(
        [
            r"% Page 11",
            r"% Page 8",  # 模型从页脚复制的印刷页码，不能覆盖物理页。
            r"\includegraphics{images/page_08_01}",
            r"\includegraphics{images/page_08_02}",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 18",
            r"% Page 15",
            r"\includegraphics{images/page_15_0}",
            # 页面 15 只有一张可提取的真实图；第二个引用必须显式保持 unresolved。
            r"\includegraphics{images/page_15_1}",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {"fitz": FakeFitz}):
        target = Path(tmp, "source.pdf")
        target.write_bytes(b"%PDF-test")
        project = Path(tmp, "project")
        project.mkdir()
        result = _preserve_ocr_resources(
            {"source_type": "pdf", "target": str(target)},
            raw,
            project,
        )

        assert [item["path"] for item in result["assets"]] == [
            "images/page_08_01.png",
            "images/page_08_02.png",
            "images/page_15_0.png",
        ]
        assert result["unresolved"] == ["images/page_15_1"]
        assert Path(project, "images", "page_08_01.png").read_bytes() == b"PNG101"
        assert all("sha256" in item and item["bytes"] > 0 for item in result["assets"])
        assert [item["source_page"] for item in result["assets"]] == [11, 11, 18]
        assert [item["printed_page"] for item in result["assets"]] == [8, 8, 15]


def test_explicit_png_reference_is_preserved_exactly_once_with_source_preview():
    raw = "\n".join(
        [
            r"% Page 1",
            r"\includegraphics{images/page_1_1.png}",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp, "source.png")
        source.write_bytes(_png_bytes(b"source"))
        page = Path(tmp, "page-1.img")
        page.write_bytes(_png_bytes(b"preview"))
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources(
            {
                "source_type": "image",
                "target": str(source),
                "selected_pages": [1],
                "pages": {1: {"png": str(page)}},
            },
            raw,
            project,
        )

        assert result["unresolved"] == []
        assert [item["path"] for item in result["assets"]] == [
            "images/page_1_1.png"
        ]
        assert not Path(project, "images", "page_1_1.png.png").exists()
        assert Path(project, "images", "page_1_1.png").read_bytes() == source.read_bytes()
        assert result["source_pages"][0]["path"] == "source-pages/page_0001.png"
        assert result["source_pages"][0]["sha256"] == hashlib.sha256(
            page.read_bytes()
        ).hexdigest()


def test_ocr_resource_scan_ignores_commented_and_verbatim_image_examples():
    raw = r"""% Page 1
% \includegraphics{figure.png}
\begin{verbatim}
\includegraphics{images/diagram}
\includegraphics{images/page_1_1.pdf}
\end{verbatim}
\verb|\includegraphics{also-not-active.png}|
Plain OCR text.
"""
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources({}, raw, project)

    assert result["unresolved"] == []
    assert result["assets"] == []


def test_missing_figure_uses_hash_marked_source_page_fallback_and_bundle():
    raw = "\n".join(
        [
            r"% Page 3",
            r"\includegraphics{images/page_99_1}",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp, "page-3.img")
        page.write_bytes(_png_bytes(b"physical-page-3"))
        job = {
            "source_type": "pdf",
            "target": str(Path(tmp, "unavailable.pdf")),
            "status": "done",
            "selected_start": 3,
            "selected_end": 3,
            "selected_pages": [3],
            "raw_revision": 4,
            "usage_revision": 2,
            "page_revision": 5,
            "pages": {3: {"png": str(page)}},
        }
        project = Path(tmp, "project")
        project.mkdir()

        result = _preserve_ocr_resources(job, raw, project)
        assert result["unresolved"] == []
        assert result["assets"][0]["kind"] == "page_fallback"
        assert result["assets"][0]["source_page"] == 3
        assert result["assets"][0]["path"] == "images/page_99_1.png"
        assert Path(project, "images", "page_99_1.png").read_bytes() == page.read_bytes()

        bundle, manifest = _ocr_bundle_bytes(job, raw)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            assert archive.read("ocr.tex").decode("utf-8") == raw
            assert archive.read("images/page_99_1.png") == page.read_bytes()
            assert archive.read("source-pages/page_0003.png") == page.read_bytes()
            disk_manifest = json.loads(archive.read("OCR-MANIFEST.json"))
        assert disk_manifest == manifest
        assert manifest["resources"]["assets"][0]["kind"] == "page_fallback"
        assert manifest["resources"]["unresolved"] == []


def test_failed_attempt_does_not_replace_previous_verified_commit():
    with tempfile.TemporaryDirectory() as tmp:
        store = ProjectStore(tmp)
        pid = store.create("source", "safe")
        store.set_result(
            pid,
            "verified result",
            "verified report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        marker_before = Path(tmp, pid, "verification.json").read_bytes()

        store.record_failed_attempt(
            pid,
            "unsafe diagnostic draft",
            "failure report",
            {"verification": {"safe_to_export": False}, "failures": [{"id": "compile"}]},
        )

        assert store.read_result(pid) == "verified result"
        assert Path(tmp, pid, "verification.json").read_bytes() == marker_before
        failed = store.read_failed_attempt(pid)
        assert failed["details"]["failures"] == [{"id": "compile"}]
        assert failed["draft"] == "unsafe diagnostic draft"


def test_failed_draft_endpoint_survives_restart_but_never_replaces_export():
    from fastapi.testclient import TestClient

    with tempfile.TemporaryDirectory() as tmp:
        store = ProjectStore(tmp)
        pid = store.create("original source", "failed-recovery")
        verified_result = (
            r"\documentclass[lang=en,11pt]{elegantbook}"
            "\n"
            r"\begin{document}previous verified result\end{document}"
        )
        store.set_result(
            pid,
            verified_result,
            "previous verified report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        store.record_failed_attempt(
            pid,
            "latest unsafe draft",
            "actionable failure report",
            {
                "verification": {"safe_to_export": False},
                "failures": [{"id": "compile", "summary": "l.42"}],
            },
        )
        # 新建 app 模拟应用重启：进程内 job 已丢失，只依赖磁盘快照恢复。
        server_app._store = store
        server_app._process_jobs.clear()
        client = TestClient(server_app.create_app())

        response = client.get(f"/api/projects/{pid}/failed-draft")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        payload = response.json()
        assert payload["attempt"] == "blocked"
        assert payload["draft"] == "latest unsafe draft"
        assert payload["report"] == "actionable failure report"
        assert payload["details"]["failures"][0]["summary"] == "l.42"

        assert client.get(f"/api/projects/{pid}/result").text == verified_result
        exported = client.get(f"/api/projects/{pid}/export")
        assert exported.status_code == 200
        assert exported.text == verified_result

        current_tex = client.get(f"/api/projects/{pid}/export-current")
        assert current_tex.status_code == 200
        assert current_tex.headers["x-latexstruct-verified"] == "false"
        assert current_tex.text == "latest unsafe draft"
        current_report = client.get(f"/api/projects/{pid}/export-current-report")
        assert current_report.status_code == 200
        assert current_report.headers["x-latexstruct-verified"] == "false"
        assert current_report.text == "actionable failure report"
        current_package = client.get(f"/api/projects/{pid}/export-current-package")
        assert current_package.status_code == 200
        assert current_package.headers["x-latexstruct-verified"] == "false"
        with zipfile.ZipFile(io.BytesIO(current_package.content)) as archive:
            assert archive.read("main.tex") == b"latest unsafe draft"
            assert archive.read("LATEXSTRUCT-REPORT.md") == b"actionable failure report"
            assert "LATEXSTRUCT-UNVERIFIED.txt" in archive.namelist()

        native_dir = Path(tmp, "native-current")

        def save_current(data, filename):
            native_dir.mkdir()
            path = native_dir / filename
            path.write_bytes(data)
            return path

        for artifact, extension in (
            ("current", ".tex"),
            ("current-report", ".md"),
            ("current-package", ".zip"),
        ):
            with patch(
                "latexstruct.server.downloads.save_unique_download",
                save_current,
            ):
                native = client.post(f"/api/projects/{pid}/exports/{artifact}/save")
            assert native.status_code == 200
            assert native.json()["verified"] is False
            assert native.json()["filename"].endswith(extension)
            # Allow the next artifact helper invocation to create its isolated directory.
            for item in native_dir.iterdir():
                item.unlink()
            native_dir.rmdir()

        Path(tmp, pid, "last-failed-draft.tex").write_text(
            "tampered diagnostic", encoding="utf-8"
        )
        assert client.get(f"/api/projects/{pid}/failed-draft").status_code == 404
        assert client.get(f"/api/projects/{pid}/result").text == verified_result
        assert client.get(f"/api/projects/{pid}/export-current").status_code == 409


def test_ocr_package_contains_hash_verified_preserved_images():
    from fastapi.testclient import TestClient

    with tempfile.TemporaryDirectory() as tmp:
        store = ProjectStore(str(Path(tmp, "projects")))
        server_app._store = store
        server_app._process_jobs.clear()
        pid = store.create(
            r"\documentclass{book}\begin{document}source\end{document}",
            "ocr-assets",
            mode="ai",
            template="elegantbook",
            kind="ocr",
        )
        project_dir = Path(store._dir(pid))
        image = b"real-png-resource"
        image_path = project_dir / "images" / "page_08_01.png"
        image_path.parent.mkdir(parents=True)
        image_path.write_bytes(image)
        meta_path = project_dir / "meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["ocr_resources"] = {
            "assets": [{
                "path": "images/page_08_01.png",
                "bytes": len(image),
                "sha256": hashlib.sha256(image).hexdigest(),
                "source_page": 8,
                "source_index": 1,
            }],
            "unresolved": [],
            "errors": [],
        }
        store._write_json(str(project_dir), "meta.json", meta)
        result = "\n".join(
            [
                r"\documentclass[lang=en,11pt]{elegantbook}",
                r"\usepackage{graphicx}",
                r"\begin{document}",
                r"\includegraphics{images/page_08_01}",
                r"\end{document}",
            ]
        )
        store.set_result(
            pid,
            result,
            "safe report",
            [],
            {"verification": {"safe_to_export": True}},
        )
        client = TestClient(server_app.create_app())

        package = client.get(f"/api/projects/{pid}/export-package")
        assert package.status_code == 200, package.text
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            assert archive.read("images/page_08_01.png") == image

        current = client.get(f"/api/projects/{pid}/export-current")
        assert current.status_code == 200
        assert current.headers["x-latexstruct-verified"] == "true"
        current_package = client.get(f"/api/projects/{pid}/export-current-package")
        assert current_package.status_code == 200
        assert current_package.headers["x-latexstruct-verified"] == "true"
        with zipfile.ZipFile(io.BytesIO(current_package.content)) as archive:
            assert "LATEXSTRUCT-UNVERIFIED.txt" not in archive.namelist()

        image_path.write_bytes(b"tampered")
        blocked = client.get(f"/api/projects/{pid}/export-package")
        assert blocked.status_code == 409
        assert "校验失败" in blocked.json()["detail"]

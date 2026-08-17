# -*- coding: utf-8 -*-
"""项目存储与配置测试（纯标准库，无 FastAPI 依赖）。"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.patch import AppliedPatch, Decision  # noqa: E402
from latexstruct.store import ProjectStore  # noqa: E402

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


class WorkspaceTmp:
    """工作区内的临时目录（沙箱下 TEMP 指向受限路径，不能用系统默认 tempfile）。"""

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="ls-test-", dir=_TESTS_DIR)
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)


def test_store_roundtrip():
    with WorkspaceTmp() as tmp:
        store = ProjectStore(root=tmp)
        pid = store.create("\\documentclass{book}\n\\begin{document}\nTheorem. X.\n\\end{document}\n",
                           name="测试书", mode="ai")
        assert store.get(pid)["name"] == "测试书"
        assert store.get(pid)["mode"] == "ai"
        assert "Theorem" in store.read_source(pid)
        assert store.read_result(pid) is None
        store.set_result(pid, "RESULT", "# 汇报", [{"a": 1}], {"ok": True})
        assert store.read_result(pid) == "RESULT"
        assert store.read_report(pid) == "# 汇报"
        assert store.read_decisions(pid) == [{"a": 1}]
        assert store.get(pid)["has_result"] is True
        store.set_mode(pid, "rule")
        assert store.get(pid)["mode"] == "rule"
        assert len(store.list()) == 1
        store.delete(pid)
        assert store.list() == []


def test_store_name_sanitized():
    with WorkspaceTmp() as tmp:
        store = ProjectStore(root=tmp)
        pid = store.create("x", name="../../危险/名字", mode="rule")
        assert store.get(pid)["name"] == "_危险_名字"
        assert store.get(pid)["source_size"] == 1


def test_store_rejects_path_like_project_ids():
    with WorkspaceTmp() as tmp:
        store = ProjectStore(root=tmp)
        for pid in ("../outside", "..\\outside", "", "a" * 13):
            try:
                store.get(pid)
            except ValueError:
                pass
            else:
                raise AssertionError(f"应拒绝非法项目 ID：{pid!r}")


def test_set_result_commits_result_and_report_hashes():
    with WorkspaceTmp() as tmp:
        store = ProjectStore(root=tmp)
        pid = store.create("SOURCE")
        result = "RESULT\n含中文"
        report = "# 汇报\n\n- 通过"

        store.set_result(pid, result, report, [], {"ok": True})

        marker_path = os.path.join(tmp, pid, "verification.json")
        with open(marker_path, encoding="utf-8") as f:
            marker = json.load(f)
        assert marker["result_sha256"] == hashlib.sha256(result.encode("utf-8")).hexdigest()
        assert marker["report_sha256"] == hashlib.sha256(report.encode("utf-8")).hexdigest()


def test_set_result_failure_restores_previous_commit_marker():
    with WorkspaceTmp() as tmp:
        store = ProjectStore(root=tmp)
        pid = store.create("SOURCE")
        store.set_result(pid, "OLD RESULT", "# OLD REPORT", [], {"ok": True})
        project_dir = Path(tmp) / pid
        committed_names = ("result.tex", "report.md", "decisions.json", "verification.json")
        previous_bytes = {name: (project_dir / name).read_bytes() for name in committed_names}
        marker_path = os.path.join(tmp, pid, "verification.json")
        with open(marker_path, encoding="utf-8") as f:
            previous_marker = json.load(f)

        original_write_json = store._write_json

        def fail_final_marker(directory, name, obj):
            if name == "verification.json":
                raise OSError("simulated final marker failure")
            return original_write_json(directory, name, obj)

        store._write_json = fail_final_marker
        try:
            store.set_result(pid, "NEW RESULT", "# NEW REPORT", [{"new": True}], {"ok": True})
        except OSError as exc:
            assert "simulated final marker failure" in str(exc)
        else:
            raise AssertionError("最终提交标记写入失败时必须向调用方报错")

        with open(marker_path, encoding="utf-8") as f:
            restored_marker = json.load(f)
        assert restored_marker == previous_marker
        restored_bytes = {name: (project_dir / name).read_bytes() for name in committed_names}
        assert restored_bytes == previous_bytes
        assert not any(name.endswith(".previous") for name in os.listdir(os.path.join(tmp, pid)))


def test_set_result_rejects_runtime_objects_before_touching_previous_commit():
    with WorkspaceTmp() as tmp:
        store = ProjectStore(root=tmp)
        pid = store.create("SOURCE")
        store.set_result(pid, "OLD RESULT", "# OLD REPORT", [{"old": True}], {"ok": True})
        project_dir = Path(tmp) / pid
        names = ("result.tex", "report.md", "decisions.json", "verification.json")
        before = {name: (project_dir / name).read_bytes() for name in names}
        runtime_patch = AppliedPatch(
            decision=Decision(candidate_id="runtime", action="none"),
            edits=[],
        )

        try:
            store.set_result(
                pid,
                "NEW RESULT",
                "# NEW REPORT",
                [{"new": True}],
                {"review": {"applied": [runtime_patch]}},
            )
        except TypeError as exc:
            assert "AppliedPatch" in str(exc)
        else:
            raise AssertionError("运行时补丁对象不得进入项目 JSON")

        after = {name: (project_dir / name).read_bytes() for name in names}
        assert after == before


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

# -*- coding: utf-8 -*-
"""项目存储与配置测试（纯标准库，无 FastAPI 依赖）。"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

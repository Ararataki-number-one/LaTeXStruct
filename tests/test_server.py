# -*- coding: utf-8 -*-
"""FastAPI 服务接口测试（需要 fastapi + httpx；未安装时自动跳过）。"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

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
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)


try:
    from fastapi.testclient import TestClient

    import latexstruct.server.app as srv
except ImportError:  # 依赖未安装 → 跳过
    sys.exit(0)


def _client(tmp):
    srv._store = srv.ProjectStore(root=os.path.join(tmp, "projects"))
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
        c = TestClient(srv.create_app())
        r = c.put("/api/config", json={"decide_api_key": "sk-test", "review_enabled": False})
        assert r.status_code == 200
        masked = c.get("/api/config").json()
        assert masked["decide_api_key"] == "已配置"
        assert masked["review_enabled"] is False
        r = c.put("/api/config", json={"decide_api_key": "", "review_enabled": True})
        assert r.status_code == 200


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
        result = c.get(f"/api/projects/{pid}/result").text
        assert "\\begin{theorem}" not in result
        info = json.loads(Path(tmp, "projects", pid, "verification.json").read_text(encoding="utf-8"))
        assert info["verification"]["content_invariant"] is True
        # 双语合并等其他修改保留
        assert "（方法）" in result


def test_rulesets_and_folder_import():
    with WorkspaceTmp() as tmp:
        c = _client(tmp)
        r = c.get("/api/rulesets").json()
        assert "bilingual" in r["packs"] and "academic-paper" in r["packs"]
        # 文件夹导入：main + chapters 两文件
        files = {
            "main.tex": "\\documentclass{book}\n\\begin{document}\n\\input{chapters/ch01}\n\\end{document}\n",
            "chapters/ch01.tex": "\\section{One}\n\nTheorem 1. A statement.\n\nProof. By definition.\n",
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

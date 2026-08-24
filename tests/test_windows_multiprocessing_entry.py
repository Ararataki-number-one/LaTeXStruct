from __future__ import annotations

import builtins
import importlib.util
import multiprocessing
import runpy
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
FROZEN_ENTRY = REPO_ROOT / "packaging" / "run.py"
SOURCE_ENTRY = REPO_ROOT / "latexstruct" / "__main__.py"


def test_pyinstaller_spec_uses_the_freeze_safe_entrypoint():
    spec_text = (REPO_ROOT / "packaging" / "LaTeXStruct.spec").read_text(encoding="utf-8")

    assert 'packaging_dir / "run.py"' in spec_text


def test_frozen_parent_calls_freeze_support_before_importing_or_running_app(monkeypatch):
    import latexstruct.__main__ as application_entry

    events: list[str] = []
    original_import = builtins.__import__

    def traced_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "latexstruct.__main__":
            events.append("import-application")
        return original_import(name, globals, locals, fromlist, level)

    def fake_main():
        events.append("run-application")
        return 23

    monkeypatch.setattr(builtins, "__import__", traced_import)
    monkeypatch.setattr(multiprocessing, "freeze_support", lambda: events.append("freeze-support"))
    monkeypatch.setattr(application_entry, "main", fake_main)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(FROZEN_ENTRY), run_name="__main__")

    assert exc_info.value.code == 23
    assert events == ["freeze-support", "import-application", "run-application"]


def test_frozen_worker_diverts_before_importing_application(monkeypatch):
    imported_application = False
    original_import = builtins.__import__

    def traced_import(name, globals=None, locals=None, fromlist=(), level=0):
        nonlocal imported_application
        if name == "latexstruct.__main__":
            imported_application = True
        return original_import(name, globals, locals, fromlist, level)

    def divert_frozen_worker():
        # PyInstaller's multiprocessing runtime hook handles the worker and
        # terminates instead of returning to the desktop application entry.
        raise SystemExit(0)

    monkeypatch.setattr(builtins, "__import__", traced_import)
    monkeypatch.setattr(multiprocessing, "freeze_support", divert_frozen_worker)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(FROZEN_ENTRY), run_name="__main__")

    assert exc_info.value.code == 0
    assert imported_application is False


def test_importing_source_entry_has_no_startup_side_effects(monkeypatch):
    freeze_calls = 0

    def unexpected_freeze_support():
        nonlocal freeze_calls
        freeze_calls += 1

    monkeypatch.setattr(multiprocessing, "freeze_support", unexpected_freeze_support)
    spec = importlib.util.spec_from_file_location("latexstruct_entry_import_probe", SOURCE_ENTRY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert callable(module.main)
    assert freeze_calls == 0


def test_source_module_help_remains_a_non_frozen_no_op_startup():
    completed = subprocess.run(
        [sys.executable, "-m", "latexstruct", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0
    assert "--server" in completed.stdout
    assert "--port" in completed.stdout

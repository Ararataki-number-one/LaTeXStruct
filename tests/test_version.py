# -*- coding: utf-8 -*-
"""版本号单一事实来源测试。"""

import os
import json
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import latexstruct  # noqa: E402
import latexstruct._version as ver  # noqa: E402
from latexstruct.elegantbook import (  # noqa: E402
    ELEGANTBOOK_COMMIT,
    ELEGANTBOOK_VERSION,
    elegantbook_class_bytes,
    elegantbook_license_bytes,
)


def test_version_single_source():
    # __init__ 必须从 _version 导入，且符合语义化版本
    assert latexstruct.__version__ == ver.__version__
    assert re.match(r"^\d+\.\d+\.\d+$", latexstruct.__version__)


def test_pyproject_reads_version():
    # pyproject 应声明 dynamic 版本并指向 _version 属性（不硬编码五份版本号）
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as f:
        content = f.read()
    assert 'dynamic = ["version"]' in content
    assert 'version = {attr = "latexstruct._version.__version__"}' in content
    assert 'version = "0.1.0"' not in content


def test_python_package_includes_bundled_frontends():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as f:
        content = f.read()
    assert "[tool.setuptools.package-data]" in content
    assert '"latexstruct.server"' in content
    assert '"assets/elegantbook/*"' in content
    assert '"static/*"' in content
    assert '"static-react/assets/*"' in content


def test_bundled_elegantbook_snapshot_is_present_and_hash_verified():
    assert ELEGANTBOOK_VERSION == "4.7"
    assert ELEGANTBOOK_COMMIT == "8b90c11e4a5ffd9d1e07174011303c133093d09c"
    class_bytes = elegantbook_class_bytes()
    license_bytes = elegantbook_license_bytes()
    assert b"v4.7 ElegantBook document class" in class_bytes
    assert b"The LaTeX Project Public License" in license_bytes

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".gitattributes"), encoding="utf-8") as f:
        attributes = f.read()
    for path in (
        "latexstruct/assets/elegantbook/elegantbook.cls",
        "latexstruct/assets/elegantbook/ELEGANTBOOK-LICENSE.txt",
    ):
        rule = next(line for line in attributes.splitlines() if line.startswith(path + " "))
        assert " -text " in f" {rule} ", "Windows checkout must preserve reviewed bytes"


def test_workspace_reuses_monaco_models_until_editor_widget_is_disposed():
    """Guard the @monaco-editor/react DiffEditor unmount-order workaround."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "frontend", "src", "Workspace.jsx"), encoding="utf-8") as f:
        workspace = f.read()
    assert 'ORIGINAL_MODEL_PATH = "inmemory://latexstruct/workspace/source.tex"' in workspace
    assert 'MODIFIED_MODEL_PATH = "inmemory://latexstruct/workspace/result.tex"' in workspace
    assert "originalModelPath={ORIGINAL_MODEL_PATH}" in workspace
    assert "modifiedModelPath={MODIFIED_MODEL_PATH}" in workspace
    assert "keepCurrentOriginalModel" in workspace
    assert "keepCurrentModifiedModel" in workspace
    assert "keepCurrentModel" in workspace


def test_workspace_layout_prioritizes_a_large_stable_preview():
    """Keep the workbench wide and preserve the explicit focus/panorama modes."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "frontend", "src", "Workspace.jsx"), encoding="utf-8") as f:
        workspace = f.read()
    with open(os.path.join(root, "frontend", "src", "styles.css"), encoding="utf-8") as f:
        styles = f.read()
    with open(os.path.join(root, "frontend", "src", "App.jsx"), encoding="utf-8") as f:
        app = f.read()

    assert 'EDITOR_HEIGHT = "clamp(560px, 68vh, 900px)"' in workspace
    assert "height={EDITOR_HEIGHT}" in workspace
    assert 'aria-label="审阅布局"' in workspace
    assert "aria-pressed={!focusPreview}" in workspace
    assert "aria-pressed={focusPreview}" in workspace
    assert 'review-main ${focusPreview ? "focus-preview" : ""}' in workspace
    assert 'review-bottom ${focusPreview ? "focus-hidden" : ""}' in workspace
    assert "grid-template-columns: minmax(210px, 250px) minmax(0, 1fr)" in styles
    assert ".review-main.focus-preview > .tree { display: none; }" in styles
    assert ".review-bottom.focus-hidden { display: none; }" in styles
    assert "content-workbench" in app
    assert ".content.content-workbench" in styles


def test_ci_installs_texlive_distribution_packages():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".github", "workflows", "build.yml"), encoding="utf-8") as f:
        workflow = f.read()
    assert "install xetex elegantbook amsmath amsfonts amscls geometry tcolorbox graphics" in workflow
    assert "titlesec" in workflow
    assert "install amsmath amssymb amsthm" not in workflow
    assert "kpsewhich.exe" in workflow
    assert "amsthm.sty" in workflow and "amssymb.sty" in workflow
    assert "titlesec.sty" in workflow
    assert "elegantbook.cls" in workflow


def test_elegantbook_is_the_fixed_frontend_export_template():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "frontend", "src", "Projects.jsx"), encoding="utf-8") as f:
        projects = f.read()
    with open(os.path.join(root, "frontend", "src", "Ocr.jsx"), encoding="utf-8") as f:
        ocr = f.read()

    assert 'const template = "elegantbook"' in projects
    assert 'ElegantBook 专业讲义（固定）' in projects
    assert 'const importTemplate = "elegantbook"' in ocr
    assert 'ElegantBook 专业讲义（固定）' in ocr
    assert 'const [importMode, setImportMode] = useState("ai")' in ocr
    assert '<option value="ai">AI 深度整理（推荐）</option>' in ocr
    assert '<option value="rule">规则整理（快速）</option>' in ocr
    assert 'mode: importMode' in ocr
    assert "章节、目录与定理先做结构校正" in ocr


def test_release_metadata_matches_app_version():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    version = latexstruct.__version__
    with open(os.path.join(root, "frontend", "package.json"), encoding="utf-8") as f:
        package = json.load(f)
    with open(os.path.join(root, "frontend", "package-lock.json"), encoding="utf-8") as f:
        package_lock = json.load(f)
    assert package["version"] == version
    assert package_lock["version"] == version
    assert package_lock["packages"][""]["version"] == version

    with open(os.path.join(root, "packaging", "version_info.txt"), encoding="utf-8") as f:
        resource = f.read()
    major, minor, patch = version.split(".")
    assert resource.count(f"({major}, {minor}, {patch}, 0)") == 2
    assert resource.count(f"u'{version}'") == 2

    with open(os.path.join(root, "packaging", "installer.iss"), encoding="utf-8") as f:
        installer = f.read()
    assert "#error AppVersion must be supplied" in installer
    assert '#define AppVersion "0.2.0"' not in installer

    with open(os.path.join(root, "scripts", "build.ps1"), encoding="utf-8") as f:
        build_script = f.read()
    assert '[string]$Version = ""' in build_script
    assert "packaging/sync_version.py" in build_script
    assert "npm" in build_script and "run build" in build_script


def test_release_build_safety_guards():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "scripts", "build.ps1"), encoding="utf-8-sig") as f:
        build_script = f.read()
    assert "与 latexstruct._version" in build_script
    assert "Remove-StaleDistOutput $portableExe" in build_script
    assert "Remove-StaleDistOutput $installerExe" in build_script
    assert "$pyInstallerExit -ne 0" in build_script
    assert "$isccExit -ne 0" in build_script

    with open(os.path.join(root, ".github", "workflows", "build.yml"), encoding="utf-8") as f:
        workflow = f.read()
    assert "$observedVersion -eq $env:APP_VERSION" in workflow
    assert "安装版没有提供 React 工作台" in workflow
    assert "React 资源名未带内容哈希" in workflow
    assert "http://127.0.0.1:8099$assetPath" in workflow
    assert '$pageResponse = Invoke-WebRequest "http://127.0.0.1:8099/"' in workflow
    assert "$home = Invoke-WebRequest" not in workflow
    assert "v1.1.5 运行中 → 当前版本" in workflow
    assert "/api/update/result" in workflow
    assert "body_path: dist/RELEASE_NOTES.md" in workflow

    with open(os.path.join(root, "packaging", "LaTeXStruct.spec"), encoding="utf-8") as f:
        pyinstaller_spec = f.read()
    assert "Path(SPECPATH).resolve().parent" in pyinstaller_spec
    assert 'react_index.is_file()' in pyinstaller_spec
    assert 'react_assets_dir.is_dir()' in pyinstaller_spec
    assert '(str(react_static_dir), "latexstruct/server/static-react")' in pyinstaller_spec
    assert 'elegantbook_class.is_file()' in pyinstaller_spec
    assert '(str(elegantbook_assets_dir), "latexstruct/assets/elegantbook")' in pyinstaller_spec
    assert 'os.path.exists("../latexstruct/server/static-react")' not in pyinstaller_spec

    with open(os.path.join(root, "latexstruct", "server", "app.py"), encoding="utf-8") as f:
        server_app = f.read()
    assert 'getattr(sys, "frozen", False) and not react_ready' in server_app
    assert "发布包缺少 React 前端资源" in server_app

    with open(os.path.join(root, "latexstruct", "__main__.py"), encoding="utf-8") as f:
        launcher = f.read()
    assert "MessageBoxW" in launcher
    assert "请从官方发布页重新下载安装完整版本" in launcher
    assert "重新安装不会删除本地项目" in launcher
    assert '"--updated-from"' in launcher

    with open(os.path.join(root, "packaging", "installer.iss"), encoding="utf-8") as f:
        installer = f.read()
    assert "GetVersionNumbersString" in installer
    assert "UpdateLaunchParameters" in installer
    assert '--updated-from "' in installer

    with open(os.path.join(root, ".gitignore"), encoding="utf-8") as f:
        gitignore = f.read().splitlines()
    assert "*.pfx" in gitignore
    assert "*.p12" in gitignore


def test_update_dialog_has_progress_cancel_and_success_states():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "frontend", "src", "App.jsx"), encoding="utf-8") as f:
        app = f.read()
    with open(os.path.join(root, "frontend", "src", "styles.css"), encoding="utf-8") as f:
        styles = f.read()

    for marker in (
        "发现新版本",
        "更新成功！",
        "update-progress",
        "/api/update/status/${updateJobId}",
        "/api/update/status/${updateJobId}/cancel",
        "/api/update/result",
        "SHA-256",
    ):
        assert marker in app
    assert 'role="dialog"' in app and 'aria-modal="true"' in app
    assert ".update-overlay" in styles
    assert ".update-dialog" in styles
    assert ".update-progress.indeterminate" in styles


def test_version_resource_sync_rejects_bad_versions():
    import importlib.util

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "packaging", "sync_version.py")
    spec = importlib.util.spec_from_file_location("latexstruct_sync_version", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    sample = "filevers=(1, 2, 3, 0)\nprodvers=(1, 2, 3, 0)\n" \
        "StringStruct(u'FileVersion', u'1.2.3')\n" \
        "StringStruct(u'ProductVersion', u'1.2.3')\n"
    assert module.sync_text(sample, "2.0.1").count("(2, 0, 1, 0)") == 2
    try:
        module.sync_text(sample, "2.0")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid versions must be rejected")
    package = module.sync_package_data({"name": "demo", "version": "1.0.0"}, "2.0.1")
    assert package["version"] == "2.0.1"
    lock = module.sync_package_data(
        {"version": "1.0.0", "packages": {"": {"version": "1.0.0"}}},
        "2.0.1",
        lock=True,
    )
    assert lock["version"] == "2.0.1" and lock["packages"][""]["version"] == "2.0.1"


def test_windows_powershell_scripts_are_utf8_bom():
    # Windows PowerShell 5.1 treats BOM-less UTF-8 as the active ANSI code page;
    # Chinese messages can then corrupt quote parsing before the build even starts.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("build.ps1", "sign_local.ps1"):
        with open(os.path.join(root, "scripts", name), "rb") as f:
            assert f.read(3) == b"\xef\xbb\xbf", name


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

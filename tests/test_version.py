# -*- coding: utf-8 -*-
"""版本号单一事实来源测试。"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import latexstruct  # noqa: E402
import latexstruct._version as ver  # noqa: E402


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

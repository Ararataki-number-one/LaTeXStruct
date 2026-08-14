# -*- coding: utf-8 -*-
"""版本号单一事实来源（Single Source of Truth）。

- pyproject.toml 通过 setuptools 动态读取本文件（[tool.setuptools.dynamic]）；
- latexstruct/__init__.py 从这里导入；
- CI 校验 Git tag ↔ 本文件；安装器/版本资源由 CI 用 tag 生成。
修改版本只改这一个文件。
"""

__version__ = "1.0.0"

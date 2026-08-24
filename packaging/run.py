# -*- coding: utf-8 -*-
"""PyInstaller 入口。"""

import sys

if __name__ == "__main__":
    # This must run before importing any application module.  In a frozen
    # ProcessPoolExecutor child PyInstaller consumes its private worker
    # command line here and exits after the worker has finished, so the child
    # never starts the desktop window or local server again.  In the original
    # parent process (and in a non-frozen Python process) it is an idempotent
    # no-op.
    from multiprocessing import freeze_support

    freeze_support()

    from latexstruct.__main__ import main

    sys.exit(main())

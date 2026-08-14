# -*- coding: utf-8 -*-
"""cProfile 定位扫描瓶颈。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

path = sys.argv[1]
doc = parse_latex(open(path, encoding="utf-8").read())
import cProfile
import pstats

pr = cProfile.Profile()
pr.enable()
res = scan(doc)
pr.disable()
st = pstats.Stats(pr, stream=sys.stdout)
st.sort_stats("cumtime").print_stats(18)

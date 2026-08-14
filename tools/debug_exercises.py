# -*- coding: utf-8 -*-
"""摸底：习题候选来源与节标题全貌。"""

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

path = sys.argv[1]
doc = parse_latex(open(path, encoding="utf-8").read())
res = scan(doc)

ex = [c for c in res.candidates if c.kind == "exercise-section"]
print("exercise candidates:", len(ex))
for c in ex[:8]:
    print(
        f"  title={c.title_text[:50]!r} span={c.span.start_line}-{c.span.end_line} "
        f"items={len(c.payload['item_lines'])} first={c.payload['item_lines'][:4]}"
    )

secs = [(s.cmd, s.title[:50], s.span.start_line, s.starred) for s in doc.sections]
print("sections:", len(secs))
print("按标题前缀分类:")
cnt = collections.Counter()
for cmd, title, _, _ in secs:
    key = title[:12]
    cnt[key] += 1
for k, v in cnt.most_common(20):
    print(f"  {v:4d} × {k!r}")
print("样例（含 Exercises 词）:")
n = 0
for cmd, title, line, starred in secs:
    if "xercis" in title or "练习" in title or "习题" in title:
        print(f"  [{line}] star={starred} {title!r}")
        n += 1
        if n >= 15:
            break

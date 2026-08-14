# -*- coding: utf-8 -*-
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

for name in ["godsil_2", "extremal_6", "holdout_godsil_4", "holdout_extremal_12"]:
    gdir = Path("benchmark/golden-holdout") if name.startswith("holdout") else Path("benchmark/golden")
    g = gdir / (name + ".json")
    data = json.loads(g.read_text(encoding="utf-8"))
    print(f"=== {name}（标签 {len(data['labels'])}）===")
    for lb in data["labels"][:6]:
        kind = lb["kind"] if lb["kind"] != "theorem-like" else lb["env"]
        print(f"  [{kind:10s}] {lb['needle'][:60]}")

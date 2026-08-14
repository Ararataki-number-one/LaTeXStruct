# -*- coding: utf-8 -*-
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.benchmark import GOLDEN_DIR, evaluate_golden, locate_line, load_golden

for name in ["godsil_2", "extremal_1"]:
    r = evaluate_golden(GOLDEN_DIR / f"{name}.json")
    print(name, "by_kind:", r["by_kind"], "label_errors:", r["label_errors"][:3])
    data = load_golden(GOLDEN_DIR / f"{name}.json")
    missing = [lb["needle"] for lb in data["labels"] if locate_line(data["_tex"], lb["needle"]) is None]
    print(" 未定位 needle 数:", len(missing), missing[:2])

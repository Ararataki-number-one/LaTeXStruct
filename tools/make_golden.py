# -*- coding: utf-8 -*-
"""从真实书稿切章节切片并生成金标 JSON（needle 标签，生成后需人工抽查）。

用法：python tools/make_golden.py
配置见下方 SLICES 列表。切片写入 tests/samples/，金标写入 benchmark/golden[-holdout]/。
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402
from tools.make_excerpt import make_excerpt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GODSIL = r"C:\Users\ZQY\Desktop\deepseek\corpus\godsil\Algebraic-Graph-Theory-by-Chris-Godsil.tex"
EXTREMAL = r"C:\Users\ZQY\Desktop\deepseek\corpus\extremal\Extremal_Combinatorics_With_Applications_in_Computer_Science_Texts_in_Theoretical_Computer_Sci.tex"

# (书, 行范围, 切片名, 金标目录 dev/holdout, 说明)
SLICES = [
    (GODSIL, (3089, 3535), "godsil_1_8", "dev", "1.8 Planar Graphs"),
    (GODSIL, (3536, 4385), "godsil_2", "dev", "第 2 章 Groups"),
    (GODSIL, (4386, 5100), "godsil_3", "dev", "第 3 章开头"),
    (GODSIL, (12799, 13350), "godsil_8", "dev", "第 8 章 Matrix Theory 开头"),
    (GODSIL, (16887, 17450), "godsil_10", "dev", "第 10 章开头"),
    (EXTREMAL, (2278, 3752), "extremal_1", "dev", "第 1 章 Counting"),
    (EXTREMAL, (3753, 4300), "extremal_2", "dev", "第 2 章 Advanced Counting 开头"),
    (EXTREMAL, (5028, 5600), "extremal_3", "dev", "第 3 章 Probabilistic Counting 开头"),
    (EXTREMAL, (7737, 8250), "extremal_6", "dev", "第 6 章 Sunflowers"),
    (EXTREMAL, (8927, 9450), "extremal_8", "dev", "第 8 章 Chains and Antichains 开头"),
    (GODSIL, (6122, 6600), "holdout_godsil_4", "holdout", "HOLD-OUT：第 4 章开头（不用于开发调试）"),
    (EXTREMAL, (12662, 13100), "holdout_extremal_12", "holdout", "HOLD-OUT：第 12 章 Designs（不用于开发调试）"),
]


def main():
    total = 0
    for book, (a, b), name, kind, note in SLICES:
        tex = make_excerpt(book, [(a, b)])
        sample = ROOT / "tests" / "samples" / f"{name}.tex"
        sample.write_text(tex, encoding="utf-8")
        doc = parse_latex(tex)
        res = scan(doc)
        lines = tex.split("\n")
        labels = []
        for c in res.candidates:
            if c.kind == "theorem-like":
                needle = c.title_text.split("\n")[0][:60]
                labels.append({"needle": needle, "kind": "theorem-like", "env": c.env_hint,
                               "line": c.span.start_line})
            elif c.kind == "proof":
                labels.append({"needle": c.title_text.split("\n")[0][:60], "kind": "proof",
                               "line": c.span.start_line})
            elif c.kind == "exercise-section":
                # 用节标题整行做 needle（"Exercises" 等词可能出现在正文）
                labels.append({"needle": lines[c.span.start_line - 1].strip(), "kind": "exercise-section",
                               "line": c.span.start_line})
        # 行号锚定（needle 仅作可读性标识）：全部标签以候选行号定位
        cleaned = labels
        gdir = ROOT / "benchmark" / ("golden" if kind == "dev" else "golden-holdout")
        gdir.mkdir(parents=True, exist_ok=True)
        data = {
            "name": name,
            "sample": f"../../tests/samples/{name}.tex",
            "pack": "bilingual",
            "mode": "rule",
            "labels": cleaned,
        }
        (gdir / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        total += len(cleaned)
        print(f"{kind:8s} {name:22s} 行 {a}-{b} 标签 {len(cleaned)}  | {note}")
    print(f"\n总计标签: {total}")


if __name__ == "__main__":
    main()

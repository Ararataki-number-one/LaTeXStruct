# -*- coding: utf-8 -*-
"""逐阶段计时（定位真实书稿上的性能瓶颈）。"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import latexstruct.core.parser as P  # noqa: E402


def step(name, t0):
    t = time.time()
    print(f"[{t - t0:7.2f}s] {name}", file=sys.stderr, flush=True)
    return t


def main():
    path = sys.argv[1]
    t = open(path, encoding="utf-8").read()
    t0 = time.time()
    print(f"read {len(t)} chars", file=sys.stderr, flush=True)
    t1 = t0
    t1 = step("normalize", t1)
    tn = P.normalize_newlines(t)
    t1 = step("mask_comments", t1)
    m1 = P.mask_comments(tn)
    t1 = step("find_env_ranges", t1)
    ranges, ub, ue = P.find_env_ranges(m1)
    print(f"   -> {len(ranges)} ranges, ub={len(ub)}, ue={len(ue)}", file=sys.stderr, flush=True)
    t1 = step("mask_protected", t1)
    m2 = P.mask_protected(m1, ranges)
    t1 = step("mask_inline_verb", t1)
    m3 = P.mask_inline_verb(m2)
    t1 = step("find_display_spans", t1)
    spans = P.find_display_spans(m3)
    print(f"   -> {len(spans)} display spans", file=sys.stderr, flush=True)
    t1 = step("line_starts", t1)
    starts = P.line_starts(tn)
    t1 = step("_build_sections", t1)
    secs = P._build_sections(m3, starts)
    print(f"   -> {len(secs)} sections", file=sys.stderr, flush=True)
    t1 = step("_sweep_blocks", t1)
    blocks = P._sweep_blocks(tn, m3, starts, ranges, spans, None)
    print(f"   -> {len(blocks)} blocks", file=sys.stderr, flush=True)
    t1 = step("_assign_section_paths", t1)
    P._assign_section_paths(blocks, secs)
    t1 = step("done", t1)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""多文件 LaTeX 项目支持（评审 P1 最大价值项）。

流程：发现 main.tex → 解析 \\input/\\include 依赖图（循环/缺失检测）→
带标记展开为单一文本（% === LATEXSTRUCT-FILE-START/END ===）→ 复用单文件流水线
（解析/扫描/决策/补丁/多层校验全部生效）→ 按标记拆分回各文件 → 导出到副本目录。

关键点：展开只发生在内存中；\\input/\\include 行保留在 main 文本里，
拆分后各文件内容各自回到原文件，项目结构不变。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

INPUT_RE = re.compile(r"\\(?:input|include)\s*\{([^{}]*)\}")
MARKER_START = "% === LATEXSTRUCT-FILE-START: {} ==="
MARKER_END = "% === LATEXSTRUCT-FILE-END: {} ==="


@dataclass
class ProjectGraph:
    root: Path
    main_rel: str
    files: List[str] = field(default_factory=list)  # 依赖序（主文件在前）
    missing: List[str] = field(default_factory=list)
    cycles: List[List[str]] = field(default_factory=list)


def read_tex(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def discover_main(root: Path) -> Optional[str]:
    """优先根目录 main.tex；否则找含 \\documentclass 的 .tex；再退回第一个 .tex。"""
    candidates = sorted(root.glob("*.tex"))
    if not candidates and (root / "chapters").exists():
        candidates = sorted((root / "chapters").glob("*.tex"))
    if not candidates:
        return None
    for c in candidates:
        if c.name.lower() in ("main.tex", "book.tex", "thesis.tex"):
            return c.name
    for c in candidates:
        try:
            if "\\documentclass" in read_tex(c):
                return str(c.relative_to(root))
        except OSError:
            continue
    return candidates[0].name


def _resolve(root: Path, cur_rel: str, target: str) -> Optional[str]:
    # LaTeX 语义：\input/\include 路径相对主文件目录（编译工作目录）解析
    for name in (target, target + ".tex"):
        p = root / name
        try:
            rp = p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        if p.is_file() and rp.lower().endswith(".tex"):
            return rp
    return None


def parse_includes(text: str) -> List[str]:
    return [m.group(1) for m in INPUT_RE.finditer(text)]


def build_project_graph(root: Path, main_rel: str) -> ProjectGraph:
    g = ProjectGraph(root=root, main_rel=main_rel)
    visited = {main_rel}
    seen_pairs = set()

    def walk(cur_rel: str, chain: List[str]):
        text = read_tex(root / cur_rel)
        for target in parse_includes(text):
            nxt = _resolve(root, cur_rel, target)
            if nxt is None:
                g.missing.append(f"{cur_rel} -> {target}")
                continue
            if nxt in chain:
                g.cycles.append(chain[chain.index(nxt) :] + [nxt])
                continue
            if (cur_rel, nxt) in seen_pairs:
                continue
            seen_pairs.add((cur_rel, nxt))
            if nxt not in visited:
                visited.add(nxt)
                g.files.append(nxt)
            walk(nxt, chain + [nxt])

    walk(main_rel, [main_rel])
    return g


def flatten_project(root: Path, main_rel: str) -> Tuple[str, ProjectGraph]:
    """展开为单一文本；主文件中的 \\input 行保留，子文件内容以标记包裹内联其后。"""
    g = build_project_graph(root, main_rel)
    texts: Dict[str, str] = {main_rel: read_tex(root / main_rel)}
    for rel in g.files:
        texts[rel] = read_tex(root / rel)

    def expand(rel: str, chain: List[str]) -> str:
        out_lines = []
        for line in texts[rel].split("\n"):
            m = INPUT_RE.search(line)
            if not m:
                out_lines.append(line)
                continue
            target = m.group(1)
            nxt = _resolve(root, rel, target)
            out_lines.append(line)  # 保留 \input 行
            if nxt is None or nxt in chain:
                continue  # 缺失/循环：跳过展开（已记录）
            out_lines.append(MARKER_START.format(nxt))
            out_lines.extend(expand(nxt, chain + [nxt]).split("\n"))
            out_lines.append(MARKER_END.format(nxt))
        return "\n".join(out_lines)

    return expand(main_rel, [main_rel]), g


def split_project(flattened: str) -> Dict[str, str]:
    """按标记拆分：返回 {相对路径: 文本}；主文件部分以 "" 返回。"""
    out: Dict[str, str] = {"": []}
    cur = ""
    for line in flattened.split("\n"):
        s = re.match(r"% === LATEXSTRUCT-FILE-START: (.+) ===$", line)
        e = re.match(r"% === LATEXSTRUCT-FILE-END: (.+) ===$", line)
        if s:
            cur = s.group(1)
            out.setdefault(cur, [])
        elif e:
            cur = ""
        else:
            out.setdefault(cur, []).append(line)
    return {k: "\n".join(v) for k, v in out.items()}


@dataclass
class ProjectResult:
    graph: ProjectGraph
    flattened: str
    pipeline: object  # PipelineResult
    per_file: Dict[str, str]


def process_project(
    root,
    mode: str = "rule",
    rule_config=None,
    ai_config=None,
    ai_client=None,
    review_client=None,
    template: str = None,
    compile_check: bool = False,
) -> ProjectResult:
    """多文件项目处理：发现 → 展开 → 单文件流水线 → 拆分。"""
    from .pipeline import run_pipeline

    root = Path(root)
    main_rel = discover_main(root)
    if main_rel is None:
        raise ValueError(f"未在 {root} 中找到 .tex 主文件")
    flat, g = flatten_project(root, main_rel)
    pr = run_pipeline(
        flat, mode=mode, rule_config=rule_config, ai_config=ai_config,
        ai_client=ai_client, review_client=review_client, template=template,
        compile_check=compile_check,
    )
    per_file = split_project(pr.result)
    return ProjectResult(graph=g, flattened=flat, pipeline=pr, per_file=per_file)


def export_project(root: Path, outdir: Path, main_rel: str, per_file: Dict[str, str],
                   graph: ProjectGraph):
    """把拆分结果写到副本目录；未参与展开的文件原样复制。"""
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / main_rel).parent.mkdir(parents=True, exist_ok=True)
    (outdir / main_rel).write_text(per_file.get("", ""), encoding="utf-8", newline="")
    for rel in graph.files:
        if rel in per_file:
            p = outdir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(per_file[rel], encoding="utf-8", newline="")
    # 其余文件（图片/bib/样式等）原样复制
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if rel in per_file or rel == main_rel:
            continue
        dst = outdir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            dst.write_bytes(p.read_bytes())
        except OSError:
            continue

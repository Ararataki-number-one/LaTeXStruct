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
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

INPUT_RE = re.compile(
    r"\\(?:input|include)\s*(?:\{([^{}\r\n]*)\}|([^\s%{}]+))"
)
MARKER_START = "% === LATEXSTRUCT-FILE-START: {} ==="
MARKER_END = "% === LATEXSTRUCT-FILE-END: {} ==="
MARKER_RE = re.compile(r"% === LATEXSTRUCT-FILE-(?:START|END): .+ ===$")


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
    candidates = sorted(root.rglob("*.tex"), key=lambda p: (len(p.relative_to(root).parts), p.as_posix()))
    if not candidates:
        return None
    for preferred in ("main.tex", "book.tex", "thesis.tex"):
        for c in candidates:
            if c.name.lower() == preferred:
                return c.relative_to(root).as_posix()
    for c in candidates:
        try:
            if "\\documentclass" in read_tex(c):
                return c.relative_to(root).as_posix()
        except OSError:
            continue
    return candidates[0].relative_to(root).as_posix()


def safe_project_relpath(rel: str) -> str:
    """把浏览器/zip 提供的路径规范为安全 POSIX 相对路径。"""
    raw = str(rel or "").replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
        or any(":" in part or "\x00" in part for part in path.parts)
    ):
        raise ValueError(f"不安全的项目路径：{rel!r}")
    return path.as_posix()


def _resolve(root: Path, cur_rel: str, target: str) -> Optional[str]:
    # LaTeX 语义：\input/\include 路径相对主文件目录（编译工作目录）解析
    target = (target or "").strip()
    if not target or "\x00" in target:
        return None
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
    # 注释、verbatim/minted 与 \verb 内的示例命令不属于真实依赖。
    from .parser import parse_latex

    masked = parse_latex(text).masked
    return [(m.group(1) or m.group(2)).strip() for m in INPUT_RE.finditer(masked)]


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
    for rel, content in texts.items():
        if any(MARKER_RE.fullmatch(line) for line in content.splitlines()):
            raise ValueError(f"文件包含 LaTeXStruct 保留标记，无法安全展开：{rel}")

    expanded_files = {main_rel}

    def expand(rel: str, chain: List[str]) -> str:
        out_lines = []
        source = texts[rel]
        from .parser import parse_latex

        masked_lines = parse_latex(source).masked.split("\n")
        for line, masked_line in zip(source.split("\n"), masked_lines):
            matches = list(INPUT_RE.finditer(masked_line))
            if not matches:
                out_lines.append(line)
                continue
            out_lines.append(line)  # 保留 \input 行
            for m in matches:
                target = (m.group(1) or m.group(2)).strip()
                nxt = _resolve(root, rel, target)
                if nxt is None or nxt in chain or nxt in expanded_files:
                    continue  # 缺失/循环/重复引用：保留命令，但只展开文件一次
                expanded_files.add(nxt)
                out_lines.append(MARKER_START.format(nxt))
                out_lines.extend(expand(nxt, chain + [nxt]).split("\n"))
                out_lines.append(MARKER_END.format(nxt))
        return "\n".join(out_lines)

    return expand(main_rel, [main_rel]), g


def split_project(flattened: str) -> Dict[str, str]:
    """按标记拆分：返回 {相对路径: 文本}；主文件部分以 "" 返回。"""
    out: Dict[str, str] = {"": []}
    stack = [""]
    for line in flattened.split("\n"):
        s = re.match(r"% === LATEXSTRUCT-FILE-START: (.+) ===$", line)
        e = re.match(r"% === LATEXSTRUCT-FILE-END: (.+) ===$", line)
        if s:
            rel = safe_project_relpath(s.group(1))
            stack.append(rel)
            out.setdefault(rel, [])
        elif e:
            rel = safe_project_relpath(e.group(1))
            if len(stack) == 1 or stack[-1] != rel:
                raise ValueError(f"项目文件标记不匹配：{rel}")
            stack.pop()
        else:
            out.setdefault(stack[-1], []).append(line)
    if len(stack) != 1:
        raise ValueError(f"项目文件结束标记缺失：{stack[-1]}")
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
    template_context: dict = None,
    compile_check: bool = False,
    pack=None,
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
        template_context=template_context,
        compile_check=compile_check, pack=pack,
    )
    per_file = split_project(pr.result)
    expected = {"", *g.files}
    project_check = {
        "ok": set(per_file) == expected and not g.missing and not g.cycles,
        "before_file_count": len(expected),
        "after_file_count": len(per_file),
        "file_set_equal": set(per_file) == expected,
        "missing_includes": list(g.missing),
        "cycles": list(g.cycles),
    }
    pr.verification["project"] = project_check
    pr.verification.setdefault("checks", []).append(
        {"id": "project", "label": "项目文件与依赖完整", "ok": project_check["ok"]}
    )
    pr.verification["safe_to_export"] = bool(
        pr.verification.get("safe_to_export", pr.ok) and project_check["ok"]
    )
    pr.ok = bool(pr.ok and project_check["ok"])
    pr.verification["export_blocked"] = not pr.verification["safe_to_export"]
    if not project_check["ok"]:
        pr.report_md += (
            "\n\n## 项目安全检查\n\n"
            "- ❌ 依赖图或文件集合不完整，本次结果不可导出；请先修复缺失/循环引用。\n"
            f"- 文件数量：{len(expected)} → {len(per_file)}\n"
        )
    return ProjectResult(graph=g, flattened=flat, pipeline=pr, per_file=per_file)


def export_project(root: Path, outdir: Path, main_rel: str, per_file: Dict[str, str],
                   graph: ProjectGraph):
    """把拆分结果写到副本目录；未参与展开的文件原样复制。"""
    main_rel = safe_project_relpath(main_rel)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / main_rel).parent.mkdir(parents=True, exist_ok=True)
    (outdir / main_rel).write_text(per_file.get("", ""), encoding="utf-8", newline="")
    for rel in graph.files:
        if rel in per_file:
            rel = safe_project_relpath(rel)
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

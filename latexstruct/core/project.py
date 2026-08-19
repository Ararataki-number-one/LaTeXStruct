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
CLASS_RE = re.compile(
    r"\\(?:documentclass|LoadClass(?:WithOptions)?)"
    r"\s*(?:\[[^\]]*\])?\s*\{([^{}\r\n]+)\}"
)
PACKAGE_RE = re.compile(
    r"\\(?:usepackage|RequirePackage(?:WithOptions)?)"
    r"\s*(?:\[[^\]]*\])?\s*\{([^{}\r\n]+)\}"
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


@dataclass(frozen=True)
class TexFileFormat:
    """Decoded TEX plus the byte-level format required for a safe write-back."""

    text: str
    encoding: str
    bom: bytes
    newline: str
    raw: bytes = field(repr=False)

    def metadata(self) -> Dict[str, str | bool]:
        return {
            "encoding": self.encoding,
            "bom": self.bom.hex(),
            "newline": {"\r\n": "crlf", "\r": "cr", "\n": "lf"}.get(
                self.newline, "none"
            ),
        }


_TEX_ENCODING_RE = re.compile(
    rb"(?:!\s*T[eE]X\s+encoding|coding)\s*[:=]\s*([A-Za-z0-9._-]+)",
    re.I,
)


def _canonical_encoding(name: str) -> str:
    compact = str(name or "").strip().lower().replace("_", "-")
    aliases = {
        "utf8": "utf-8",
        "utf-8-sig": "utf-8",
        "cp936": "gbk",
        "gb2312": "gbk",
        "gb18030": "gb18030",
        "latin1": "latin-1",
        "iso-8859-1": "latin-1",
        "windows-1252": "cp1252",
    }
    return aliases.get(compact, compact)


def _dominant_newline(text: str) -> str:
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    cr = text.count("\r") - crlf
    counts = [(crlf, "\r\n"), (lf, "\n"), (cr, "\r")]
    count, newline = max(counts, key=lambda item: item[0])
    return newline if count else ""


def decode_tex_bytes(raw: bytes) -> TexFileFormat:
    """Strictly decode common TEX encodings without replacement characters.

    UTF BOMs and an explicit TeX/coding directive take precedence.  Without an
    explicit signal, valid UTF-8 wins; GBK/GB18030 wins only when it produces
    actual CJK text, otherwise the byte-preserving Latin-1 fallback is used.
    """
    raw = bytes(raw)
    bom = b""
    body = raw
    encoding = ""
    for marker, candidate in (
        (b"\xef\xbb\xbf", "utf-8"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    ):
        if raw.startswith(marker):
            bom, body, encoding = marker, raw[len(marker):], candidate
            break

    if not encoding:
        declared = _TEX_ENCODING_RE.search(raw[:4096])
        if declared:
            encoding = _canonical_encoding(declared.group(1).decode("ascii"))

    if encoding:
        try:
            text = body.decode(encoding)
        except (LookupError, UnicodeDecodeError) as exc:
            raise ValueError(f"TEX 声明的编码 {encoding!r} 与文件字节不一致") from exc
    else:
        try:
            text = raw.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = ""
            for candidate in ("gbk", "gb18030"):
                try:
                    decoded = raw.decode(candidate)
                except UnicodeDecodeError:
                    continue
                if any("\u3400" <= char <= "\u9fff" for char in decoded):
                    text, encoding = decoded, candidate
                    break
            if not encoding:
                text = raw.decode("latin-1")
                encoding = "latin-1"

    return TexFileFormat(
        text=text,
        encoding=encoding,
        bom=bom,
        newline=_dominant_newline(text),
        raw=raw,
    )


def encode_tex_like_original(text: str, original: bytes) -> bytes:
    """Encode processed text using the source format, reusing unchanged bytes."""
    from .parser import normalize_newlines

    fmt = decode_tex_bytes(original)
    if normalize_newlines(text) == normalize_newlines(fmt.text):
        return fmt.raw
    newline = fmt.newline or "\n"
    restored = normalize_newlines(text).replace("\n", newline)
    try:
        encoded = restored.encode(fmt.encoding)
    except (LookupError, UnicodeEncodeError) as exc:
        raise ValueError(
            f"修改后的 TEX 含有 {fmt.encoding} 无法表示的字符，已阻止改写原文件"
        ) from exc
    return fmt.bom + encoded


def encode_project_files(
    original_files: Dict[str, bytes],
    main_rel: str,
    per_file: Dict[str, str],
) -> Dict[str, bytes]:
    """Return encoded bytes for every processed file or fail before any write."""
    main_rel = safe_project_relpath(main_rel)
    mapped = {main_rel: per_file.get("", "")}
    mapped.update(
        {safe_project_relpath(rel): text for rel, text in per_file.items() if rel}
    )
    missing = sorted(rel for rel in mapped if rel not in original_files)
    if missing:
        raise ValueError("缺少用于编码保真的原始文件：" + "、".join(missing[:5]))
    return {
        rel: encode_tex_like_original(text, original_files[rel])
        for rel, text in mapped.items()
    }


def read_tex(path: Path) -> str:
    return decode_tex_bytes(path.read_bytes()).text


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


def collect_project_structured_envs(root: Path, main_rel: str) -> set[str]:
    """Return theorem-like environments explicitly declared by reachable support files.

    Only local ``.cls``/``.sty`` files selected by class/package commands and their
    recursively referenced local support files are inspected.  Unreferenced project
    files and globally installed TeX packages are intentionally ignored: treating an
    environment as structural without source evidence would create an unsafe stop.
    Declarations in the flattened ``.tex`` graph are parsed later by the pipeline.
    """
    from .parser import parse_latex
    from .scanner import _declared_theorem_envs

    root = Path(root).resolve()
    main_rel = safe_project_relpath(main_rel)
    pending: List[Path] = [root / main_rel]
    visited: set[Path] = set()
    declared: set[str] = set()

    def local_file(raw_name: str, suffixes: Tuple[str, ...]) -> Optional[Path]:
        raw_name = str(raw_name or "").strip().replace("\\", "/")
        if not raw_name or "\x00" in raw_name:
            return None
        names = [raw_name] if Path(raw_name).suffix else [raw_name + s for s in suffixes]
        for name in names:
            try:
                rel = safe_project_relpath(name)
                candidate = (root / rel).resolve()
                candidate.relative_to(root)
            except (OSError, ValueError):
                continue
            if candidate.is_file():
                return candidate
        return None

    while pending:
        path = pending.pop()
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved in visited or not resolved.is_file():
            continue
        visited.add(resolved)
        masked = parse_latex(read_tex(resolved)).masked
        declared.update(_declared_theorem_envs(masked))

        for match in CLASS_RE.finditer(masked):
            dependency = local_file(match.group(1), (".cls",))
            if dependency is not None:
                pending.append(dependency)
        for match in PACKAGE_RE.finditer(masked):
            for package in match.group(1).split(","):
                dependency = local_file(package, (".sty",))
                if dependency is not None:
                    pending.append(dependency)
        # Support files commonly split theorem declarations into a local .tex file.
        # Resolve only an explicit project-local target and never search the system tree.
        if resolved.suffix.lower() in {".cls", ".sty", ".tex"}:
            for target in parse_includes(masked):
                dependency = local_file(target, (".tex", ".sty", ".cls"))
                if dependency is not None:
                    pending.append(dependency)

    return declared


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
    per_file_bytes: Dict[str, bytes] = field(default_factory=dict)


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
    compile_files: Dict[str, bytes] = None,
    pack=None,
) -> ProjectResult:
    """多文件项目处理：发现 → 展开 → 单文件流水线 → 拆分。"""
    from .pipeline import run_pipeline

    root = Path(root)
    main_rel = discover_main(root)
    if main_rel is None:
        raise ValueError(f"未在 {root} 中找到 .tex 主文件")
    flat, g = flatten_project(root, main_rel)
    known_structured_envs = collect_project_structured_envs(root, main_rel)
    if compile_check and compile_files is None:
        compile_files = {}
        resolved_root = root.resolve()
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                resolved = path.resolve()
                relative = resolved.relative_to(resolved_root).as_posix()
            except ValueError:
                raise ValueError(f"项目文件越出根目录：{path}") from None
            compile_files[safe_project_relpath(relative)] = resolved.read_bytes()
    pr = run_pipeline(
        flat, mode=mode, rule_config=rule_config, ai_config=ai_config,
        ai_client=ai_client, review_client=review_client, template=template,
        template_context=template_context,
        compile_check=compile_check, compile_extra_files=compile_files,
        compile_project_main_rel=main_rel if compile_check else None, pack=pack,
        known_structured_envs=known_structured_envs,
    )
    per_file = split_project(pr.result)
    original_tex = {
        rel: (root / rel).read_bytes() for rel in {main_rel, *g.files}
    }
    encoding_error = ""
    try:
        per_file_bytes = encode_project_files(original_tex, main_rel, per_file)
    except ValueError as exc:
        per_file_bytes = {}
        encoding_error = str(exc)
    expected = {"", *g.files}
    project_check = {
        "ok": (
            set(per_file) == expected
            and not g.missing
            and not g.cycles
            and not encoding_error
        ),
        "before_file_count": len(expected),
        "after_file_count": len(per_file),
        "file_set_equal": set(per_file) == expected,
        "missing_includes": list(g.missing),
        "cycles": list(g.cycles),
        "encoding_error": encoding_error,
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
    return ProjectResult(
        graph=g,
        flattened=flat,
        pipeline=pr,
        per_file=per_file,
        per_file_bytes=per_file_bytes,
    )


def export_project(root: Path, outdir: Path, main_rel: str, per_file: Dict[str, str],
                   graph: ProjectGraph):
    """把拆分结果写到副本目录；未参与展开的文件原样复制。"""
    main_rel = safe_project_relpath(main_rel)
    original_tex = {
        rel: (root / rel).read_bytes() for rel in {main_rel, *graph.files}
    }
    encoded = encode_project_files(original_tex, main_rel, per_file)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / main_rel).parent.mkdir(parents=True, exist_ok=True)
    (outdir / main_rel).write_bytes(encoded[main_rel])
    for rel in graph.files:
        if rel in per_file:
            rel = safe_project_relpath(rel)
            p = outdir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(encoded[rel])
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

# -*- coding: utf-8 -*-
"""多层内容不变量校验（评审 P2 · Level 3/4）。

结构化编辑绝不触碰以下对象，因此它们构成"内容不变"的强验证：
- 数学公式 token 多重集（行内 \\(...\\) / $...$、显示 \\[...\\] / $$...$$、数学环境）；
- \\label / \\ref 系列 / \\cite 系列 / \\includegraphics 路径 集合。

整理前后这些集合必须完全一致；任何不一致都说明内容被改动。
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Dict, List

from .parser import find_env_ranges
from .verify import _masked

MATH_ENVS = {
    "equation", "equation*", "align", "align*", "gather", "gather*",
    "multline", "multline*", "eqnarray", "eqnarray*", "alignat", "alignat*",
    "flalign", "flalign*",
}

INLINE_PAREN_RE = re.compile(r"\\\((.*?)\\\)", re.S)
INLINE_DOLLAR_RE = re.compile(r"(?<!\\)\$([^$\n]+)\$")
DISPLAY_BRACKET_RE = re.compile(r"\\\[(.*?)\\\]", re.S)
DISPLAY_DOLLAR_RE = re.compile(r"\$\$(.*?)\$\$", re.S)
LABEL_RE = re.compile(r"\\label\s*\{([^{}]*)\}")
REF_RE = re.compile(r"\\(?:ref|eqref|pageref|autoref|cref|Cref)\s*\{([^{}]*)\}")
CITE_RE = re.compile(
    r"\\(?:cite|citep|citet|citealp|citealt|parencite|footcite)"
    r"(?:\s*\[[^\]]*\]){0,2}\s*\{([^{}]*)\}"
)
IMG_RE = re.compile(r"\\includegraphics\*?(?:\s*\[[^\]]*\])?\s*\{([^{}]*)\}")
GRAPHICSPATH_RE = re.compile(
    r"\\graphicspath\s*\{((?:\s*\{[^{}]*\}\s*)+)\}"
)
_BODY_FORMAL_KINDS = (
    "theorem|lemma|proposition|corollary|conjecture|claim|fact|definition|"
    "remark|observation|note|example|problem|question|exercise"
)
_BODY_TOKEN_RE = re.compile(r"\\[A-Za-z@]+|\\[^\s]|[^\W_]+|_|[^\s]", re.UNICODE)
_BODY_ENV_RE = re.compile(
    rf"\\(?:begin|end)\{{(?:{_BODY_FORMAL_KINDS}|proof)\*?\}}"
    r"(?:[ \t]*\[[^\]\r\n]*\])?",
    re.IGNORECASE,
)
_BODY_TEXT_STYLE_RE = re.compile(
    r"\\(?P<name>textbf|textit|emph|textsc|textrm|textsf|texttt|underline)"
    r"\s*\{",
    re.IGNORECASE,
)


def _norm(s: str) -> str:
    return " ".join(s.split())


def math_tokens(text: str, masked: str = None) -> List[str]:
    """数学公式 token 多重集（排序后的可哈希列表）。"""
    masked = masked if masked is not None else _masked(text)
    toks: List[str] = []
    for m in DISPLAY_DOLLAR_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    for m in DISPLAY_BRACKET_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    for m in INLINE_PAREN_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    for m in INLINE_DOLLAR_RE.finditer(masked):
        toks.append(_norm(m.group(1)))
    ranges, _, _ = find_env_ranges(masked)
    for name, bs, be, es, ee in ranges:
        if name in MATH_ENVS:
            toks.append(_norm(masked[be:es]))
    return sorted(toks)


def _collect(text: str, pattern, masked: str = None) -> List[str]:
    # 保留重复次数：重复 label/ref/cite/image 的增删同样属于内容变化。
    masked = masked if masked is not None else _masked(text)
    return sorted(m.group(1) for m in pattern.finditer(masked))


def labels(text: str) -> List[str]:
    return _collect(text, LABEL_RE)


def refs(text: str) -> List[str]:
    return _collect(text, REF_RE)


def cites(text: str) -> List[str]:
    return _collect(text, CITE_RE)


def image_paths(text: str) -> List[str]:
    return _collect(text, IMG_RE)


def _diff(before: List[str], after: List[str]) -> Dict:
    b, a = Counter(before), Counter(after)
    missing = sorted((b - a).elements())
    extra = sorted((a - b).elements())
    return {
        "equal": missing == [] and extra == [],
        "before_count": len(before),
        "after_count": len(after),
        "missing": missing[:10],
        "extra": extra[:10],
    }


def _document_body(text: str) -> str:
    begin = re.search(r"\\begin\{document\}", text)
    if begin is None:
        return text
    end = re.search(r"\\end\{document\}", text[begin.end():])
    if end is None:
        return text[begin.end():]
    return text[begin.end():begin.end() + end.start()]


def _balanced_group_end(text: str, opening_brace: int) -> int | None:
    depth = 0
    for index in range(opening_brace, len(text)):
        if text[index] not in "{}":
            continue
        slash_count = 0
        cursor = index - 1
        while cursor >= 0 and text[cursor] == "\\":
            slash_count += 1
            cursor -= 1
        if slash_count % 2:
            continue
        depth += 1 if text[index] == "{" else -1
        if depth == 0:
            return index + 1
    return None


def _unwrap_body_text_styles(text: str) -> str:
    """Drop presentation wrappers while preserving every balanced group body."""
    output: List[str] = []
    cursor = 0
    while True:
        match = _BODY_TEXT_STYLE_RE.search(text, cursor)
        if match is None:
            output.append(text[cursor:])
            break
        opening = text.find("{", match.start(), match.end())
        end = _balanced_group_end(text, opening)
        if end is None:
            output.append(text[cursor:])
            break
        output.append(text[cursor:match.start()])
        body = _unwrap_body_text_styles(text[opening + 1:end - 1])
        # Spaces keep a preceding control word (for example ``\noindent``)
        # from merging with the unwrapped text.  They do not add body tokens.
        output.append(" " + body + " ")
        cursor = end
    return "".join(output)


def _strip_scanner_semantic_prefixes(text: str, pack=None) -> str:
    """Use the production scanner's exact title/proof vocabulary and bounds."""
    from .scanner import _proof_metadata, _title_metadata
    from .ruleset import load_pack

    title_res = load_pack(pack).title_res
    lines = text.splitlines(keepends=True)
    output: List[str] = []
    for index, line in enumerate(lines):
        ending = ""
        content = line
        if content.endswith("\r\n"):
            content, ending = content[:-2], "\r\n"
        elif content.endswith(("\n", "\r")):
            content, ending = content[:-1], content[-1]
        # Give the title probe the same bounded multi-line view as the scanner.
        # This matters for named headings containing a footnote or nested macro.
        probe_lines = []
        for candidate_line in lines[index:index + 24]:
            probe_lines.append(candidate_line.rstrip("\r\n"))
        title = _title_metadata("\n".join(probe_lines), title_res)
        if title is not None:
            _kind, _number, prefix, _remainder, old, new = title
        else:
            prefix, _arg, _remainder, old, new = _proof_metadata(content)
        if old and new and content == old:
            content = new
        elif prefix and content.startswith(prefix):
            content = content[len(prefix):]
        output.append(content + ending)
    return "".join(output)


def body_text_tokens(text: str, pack=None) -> List[str]:
    """Ordered BODY_TEXT tokens after removing only known structure wrappers."""
    value = _masked(_document_body(text))
    value = _strip_scanner_semantic_prefixes(value, pack=pack)
    value = _unwrap_body_text_styles(value)
    value = _BODY_ENV_RE.sub(" ", value)
    value = re.sub(
        r"\\ifcsname\s+qedsymbol\\endcsname\s*"
        r"\\let\\qedsymbol\\empty\\fi",
        " ",
        value,
        flags=re.IGNORECASE,
    )
    # A heading's terminal punctuation can sit immediately outside its bold
    # group.  It is structural punctuation, not statement prose.
    value = re.sub(r"(?m)^\s*[.:]\s*", " ", value)
    return _BODY_TOKEN_RE.findall(value)


def _ordered_diff(before: List[str], after: List[str]) -> Dict:
    first_difference = None
    for index, (left, right) in enumerate(zip(before, after)):
        if left != right:
            first_difference = index
            break
    if first_difference is None and len(before) != len(after):
        first_difference = min(len(before), len(after))
    return {
        "checked": True,
        "equal": before == after,
        "before_count": len(before),
        "after_count": len(after),
        "first_difference_index": first_difference,
    }


def check_invariants(
    before: str,
    after: str,
    *,
    check_body_text: bool = False,
    pack=None,
) -> Dict:
    """返回各不变量对比结果；ok=True 表示全部一致。"""
    before_masked = _masked(before)
    after_masked = _masked(after)
    out = {
        "math": _diff(math_tokens(before, before_masked), math_tokens(after, after_masked)),
        "labels": _diff(_collect(before, LABEL_RE, before_masked), _collect(after, LABEL_RE, after_masked)),
        "refs": _diff(_collect(before, REF_RE, before_masked), _collect(after, REF_RE, after_masked)),
        "cites": _diff(_collect(before, CITE_RE, before_masked), _collect(after, CITE_RE, after_masked)),
        "images": _diff(_collect(before, IMG_RE, before_masked), _collect(after, IMG_RE, after_masked)),
    }
    if check_body_text:
        out["body_text"] = _ordered_diff(
            body_text_tokens(before, pack=pack),
            body_text_tokens(after, pack=pack),
        )
    else:
        out["body_text"] = {
            "checked": False,
            "equal": True,
            "before_count": 0,
            "after_count": 0,
            "first_difference_index": None,
        }
    out["ok"] = all(v["equal"] for v in out.values())
    return out


def check_image_resources(text: str, root: str | None) -> Dict:
    """确认每个 includegraphics 都能在项目根内解析到真实普通文件。"""
    paths = image_paths(text)
    if root is None:
        return {
            "checked": False,
            "ok": True,
            "count": len(paths),
            "missing": [],
            "unsafe": [],
        }
    base = Path(root).resolve()
    missing, unsafe = [], []
    search_roots = [base]
    masked = _masked(text)
    for match in GRAPHICSPATH_RE.finditer(masked):
        for raw_dir in re.findall(r"\{([^{}]*)\}", match.group(1)):
            normalized_dir = raw_dir.replace("\\", "/").strip()
            relative_dir = Path(normalized_dir)
            if (
                not normalized_dir
                or "://" in normalized_dir
                or relative_dir.is_absolute()
                or ".." in relative_dir.parts
            ):
                unsafe.append(f"graphicspath:{raw_dir}")
                continue
            candidate_root = (base / relative_dir).resolve()
            try:
                candidate_root.relative_to(base)
            except ValueError:
                unsafe.append(f"graphicspath:{raw_dir}")
                continue
            search_roots.append(candidate_root)
    extensions = (".pdf", ".png", ".jpg", ".jpeg", ".eps")
    for raw in paths:
        normalized = raw.replace("\\", "/").strip()
        if not normalized or "://" in normalized:
            unsafe.append(raw)
            continue
        relative = Path(normalized)
        if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
            unsafe.append(raw)
            continue
        # graphicx only tries its default extension list when the TEX reference
        # itself has no suffix.  Trying ``.png`` after an explicit ``foo.png``
        # incorrectly accepts a physically different ``foo.png.png`` file.
        candidate_suffixes = ("",) if relative.suffix else ("", *extensions)
        found = False
        for search_root in search_roots:
            for suffix in candidate_suffixes:
                candidate = (search_root / (normalized + suffix)).resolve()
                try:
                    candidate.relative_to(base)
                except ValueError:
                    unsafe.append(raw)
                    found = True
                    break
                if candidate.is_file():
                    found = True
                    break
            if found:
                break
        if not found:
            missing.append(raw)
    return {
        "checked": True,
        "ok": not missing and not unsafe,
        "count": len(paths),
        "missing": sorted(set(missing))[:50],
        "unsafe": sorted(set(unsafe))[:50],
    }
